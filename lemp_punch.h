// lemp_punch.h — NAT traversal for mp_save.asi: STUN, UDP hole punching and a
// loopback proxy, so a host behind NAT is joined without a forwarded port.
// This is the client half: a local proxy in the ASI. No game packet goes to
// the master server; it only passes the two endpoints (lemp_online.h).
//
// The game's own socket is never touched. Each side runs a proxy socket of
// ours, on an ephemeral port, that does the punching and then carries the
// game's datagrams unchanged:
//
//   joiner game -> 127.0.0.1:<loop>  [joiner proxy] ==internet== [host proxy]
//     -> one 127.0.0.1 socket per joiner -> 127.0.0.1:<game port, 3659> host game
//
// The joiner's game is sent to 127.0.0.1:<loop> instead of the host's address
// (the search's JOIN answer, lemp_online.h). The host's game sees each joiner
// as 127.0.0.1:<its own local port>, stable for the life of the peer (a
// pinggy stall once showed a changing source port breaking a running
// connection).
//
// Gate: nothing reaches the host's game from an endpoint that has not shown a
// token the master server issued for this lobby and signalled to the host.
//
// Control packets are exactly kCtlLen bytes, "LEMP", version, type, two zero
// bytes, the 16-byte token. Everything else between authenticated proxies is
// a game datagram, passed as is (no header, so no MTU cost). STUN (RFC 5389
// Binding) is asked from the same socket that punches, so the endpoint it
// reports is the one the peer must aim at.
//
// One thread does all the socket work; the API only changes state under the
// lock and never waits on the network (the game thread calls it).
//
// Builds on Windows (mp_save.asi, tests under Wine) and POSIX (the native
// test, test_lemp_punch.cpp).
#pragma once
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mstcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <cerrno>
#endif
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace punch {

// ---- platform ------------------------------------------------------------------

#ifdef _WIN32
typedef SOCKET sock_t;
static const sock_t kBad = INVALID_SOCKET;
static void CloseSock(sock_t s) { closesocket(s); }
static void SetNonBlocking(sock_t s) { u_long on = 1; ioctlsocket(s, FIONBIO, &on); }
static bool WouldBlock() { return WSAGetLastError() == WSAEWOULDBLOCK; }
static uint64_t NowMs() { return GetTickCount64(); }
static void SleepMs(int ms) { Sleep((DWORD)ms); }
struct Lock {
    CRITICAL_SECTION cs;
    Lock() { InitializeCriticalSection(&cs); }
    void lock() { EnterCriticalSection(&cs); }
    void unlock() { LeaveCriticalSection(&cs); }
};
typedef DWORD(WINAPI* ThreadFn)(LPVOID);
#define PUNCH_THREAD(name) static DWORD WINAPI name(LPVOID)
#define PUNCH_THREAD_RETURN return 0
static bool StartThread(ThreadFn f) {
    HANDLE t = CreateThread(nullptr, 0, f, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
    return t != nullptr;
}
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
// Windows reports an ICMP port-unreachable on a UDP socket as WSAECONNRESET
// on its next receive: the game's port closed for a map change, or a peer gone.
// Off, so one dead endpoint cannot stall the loop; errors are ignored anyway.
static void NoConnReset(sock_t s) {
    BOOL off = FALSE;
    DWORD got = 0;
    WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof off, nullptr, 0, &got, nullptr, nullptr);
}
static bool NetInit() { WSADATA w; return WSAStartup(MAKEWORD(2, 2), &w) == 0; }
#else
typedef int sock_t;
static const sock_t kBad = -1;
static void CloseSock(sock_t s) { close(s); }
static void SetNonBlocking(sock_t s) { fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK); }
static bool WouldBlock() { return errno == EAGAIN || errno == EWOULDBLOCK; }
static uint64_t NowMs() {
    timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void SleepMs(int ms) { usleep(ms * 1000); }
struct Lock {
    pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    void lock() { pthread_mutex_lock(&m); }
    void unlock() { pthread_mutex_unlock(&m); }
};
typedef void* (*ThreadFn)(void*);
#define PUNCH_THREAD(name) static void* name(void*)
#define PUNCH_THREAD_RETURN return nullptr
static bool StartThread(ThreadFn f) {
    pthread_t t;
    if (pthread_create(&t, nullptr, f, nullptr) != 0) return false;
    pthread_detach(t);
    return true;
}
static void NoConnReset(sock_t) {}
static bool NetInit() { return true; }
#endif

struct Guard {
    Lock& l;
    explicit Guard(Lock& x) : l(x) { l.lock(); }
    ~Guard() { l.unlock(); }
};

typedef void (*LogFn)(const char* fmt, ...);

// ---- endpoints ---------------------------------------------------------------------

struct Ep {
    uint32_t ip = 0;     // network order
    uint16_t port = 0;   // host order
    bool ok() const { return ip != 0 && port != 0; }
    bool operator==(const Ep& o) const { return ip == o.ip && port == o.port; }
    bool operator!=(const Ep& o) const { return !(*this == o); }
};

static std::string EpStr(const Ep& e) {
    if (!e.ok()) return "";
    const unsigned char* b = (const unsigned char*)&e.ip;
    char s[32];
    snprintf(s, sizeof s, "%u.%u.%u.%u:%u", b[0], b[1], b[2], b[3], e.port);
    return s;
}
static bool ParseEp(const std::string& s, Ep& e) {
    unsigned a, b, c, d, p;
    char tail;
    if (sscanf(s.c_str(), "%u.%u.%u.%u:%u%c", &a, &b, &c, &d, &p, &tail) != 5) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255 || p == 0 || p > 65535) return false;
    unsigned char ip[4] = {(unsigned char)a, (unsigned char)b, (unsigned char)c, (unsigned char)d};
    memcpy(&e.ip, ip, 4);
    e.port = (uint16_t)p;
    return e.ok();
}
static sockaddr_in ToSa(const Ep& e) {
    sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = e.ip;
    a.sin_port = htons(e.port);
    return a;
}
static Ep FromSa(const sockaddr_in& a) {
    Ep e;
    e.ip = a.sin_addr.s_addr;
    e.port = ntohs(a.sin_port);
    return e;
}
static Ep Loopback(uint16_t port) {
    Ep e;
    e.ip = htonl(0x7f000001);
    e.port = port;
    return e;
}

// A UDP socket bound to addr:0 (or a given port), non-blocking.
static sock_t OpenUdp(uint32_t addr, uint16_t port, uint16_t& bound) {
    sock_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == kBad) return kBad;
    sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = addr;
    a.sin_port = htons(port);
    socklen_t len = sizeof a;
    if (bind(s, (sockaddr*)&a, sizeof a) != 0 || getsockname(s, (sockaddr*)&a, &len) != 0) {
        CloseSock(s);
        return kBad;
    }
    bound = ntohs(a.sin_port);
    SetNonBlocking(s);
    NoConnReset(s);
    return s;
}

static void SendTo(sock_t s, const Ep& to, const void* p, int n) {
    if (s == kBad || !to.ok()) return;
    sockaddr_in a = ToSa(to);
    sendto(s, (const char*)p, n, 0, (sockaddr*)&a, sizeof a);
}

// ---- tokens and control packets -----------------------------------------------------

struct Token {
    unsigned char b[16] = {0};
    bool operator==(const Token& o) const { return memcmp(b, o.b, 16) == 0; }
};
static bool ParseToken(const std::string& hex, Token& t) {
    if (hex.size() != 32) return false;
    for (int i = 0; i < 16; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            char c = hex[i * 2 + k];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0';
            else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else return false;
        }
        t.b[i] = (unsigned char)v;
    }
    return true;
}

enum Type { PUNCH = 1, ACK = 2, KEEPALIVE = 3, BYE = 4 };
static const int kCtlLen = 24;
static const unsigned char kVersion = 1;

static void SendCtl(sock_t s, const Ep& to, Type type, const Token& t) {
    unsigned char p[kCtlLen] = {'L', 'E', 'M', 'P', kVersion, (unsigned char)type, 0, 0};
    memcpy(p + 8, t.b, 16);
    SendTo(s, to, p, kCtlLen);
}
static bool ParseCtl(const unsigned char* p, int n, Type& type, Token& t) {
    if (n != kCtlLen || memcmp(p, "LEMP", 4) != 0 || p[4] != kVersion || p[5] < PUNCH || p[5] > BYE) return false;
    type = (Type)p[5];
    memcpy(t.b, p + 8, 16);
    return true;
}

// ---- STUN (RFC 5389 Binding) ---------------------------------------------------------

static const uint32_t kCookie = 0x2112A442;

static void StunRequest(unsigned char out[20], const unsigned char tx[12]) {
    out[0] = 0x00; out[1] = 0x01;            // Binding request
    out[2] = 0x00; out[3] = 0x00;            // no attributes
    uint32_t c = htonl(kCookie);
    memcpy(out + 4, &c, 4);
    memcpy(out + 8, tx, 12);
}
static bool IsStun(const unsigned char* p, int n) {
    uint32_t c;
    if (n < 20) return false;
    memcpy(&c, p + 4, 4);
    return (p[0] & 0xC0) == 0 && ntohl(c) == kCookie;
}
// A Binding success answering tx: the mapped address, XOR-MAPPED-ADDRESS
// first. Bounded by the packet's own length, never the attribute's word.
static bool StunMapped(const unsigned char* p, int n, const unsigned char tx[12], Ep& out) {
    if (!IsStun(p, n) || p[0] != 0x01 || p[1] != 0x01 || memcmp(p + 8, tx, 12) != 0) return false;
    int len = (p[2] << 8) | p[3];
    if (20 + len > n) return false;
    Ep plain, xored;
    for (int at = 20; at + 4 <= 20 + len;) {
        int type = (p[at] << 8) | p[at + 1], alen = (p[at + 2] << 8) | p[at + 3];
        const unsigned char* v = p + at + 4;
        if (at + 4 + alen > 20 + len) break;
        if ((type == 0x0020 || type == 0x0001) && alen >= 8 && v[1] == 0x01) {   // IPv4
            uint16_t port = (uint16_t)((v[2] << 8) | v[3]);
            uint32_t ip;
            memcpy(&ip, v + 4, 4);
            if (type == 0x0020) {
                port ^= (uint16_t)(kCookie >> 16);
                ip ^= htonl(kCookie);
                xored.ip = ip; xored.port = port;
            } else {
                plain.ip = ip; plain.port = port;
            }
        }
        at += 4 + ((alen + 3) & ~3);
    }
    out = xored.ok() ? xored : plain;
    return out.ok();
}

// One socket's view of itself from outside: asks two STUN servers at once.
// Same mapped endpoint from both: the NAT maps endpoint-independently ("eim"),
// so a peer can reach what we report. Different: "symmetric", and what we
// report is only right for the STUN server; punching then works only when
// the other side's NAT is open enough.
struct Stun {
    Ep server[2];
    unsigned char tx[2][12];
    Ep got[2];
    uint64_t start = 0, lastSend = 0, refreshAt = 0;
    int sends = 0;
    bool done = false;
    Ep mapped;
    std::string nat;
};

// ---- state ---------------------------------------------------------------------------

// Timings. Punching sends a packet every kPunchEveryMs for kPunchForMs; a
// connected pair keeps both NATs' mappings with a keep-alive when it has sent
// nothing for kKeepaliveMs (map loads stop the game's traffic for tens of
// seconds; many NATs forget a UDP mapping after 30 s). A peer is dropped
// when its game side has been silent for kGameIdleMs — longer than a map load.
static const int kPunchEveryMs = 100;
static const int kPunchForMs = 12000;
static const int kKeepaliveMs = 4000;
static const int kGameIdleMs = 180000;
static const int kPeerSilentMs = 60000;
static const int kStunWaitMs = 2500;
static const int kStunResendMs = 400;
// The host's re-ask doubles as the keep-alive of its waiting mapping. 25 s was
// too slow for a real CGNAT: its idle
// mapping lasted 16-23 s, every re-ask came back on a new port, and a joiner
// told the 23 s old one could not get in. 5 s, like kKeepaliveMs once connected.
static const int kStunRefreshMs = 5000;
static const int kMaxPeers = 16;

struct Peer {               // host side: one joiner
    Token token;
    std::vector<Ep> targets;  // where the server says it is
    Ep actual;                // where its packets come from, once authenticated
    bool authed = false;
    sock_t local = kBad;      // 127.0.0.1:<port> -> the game's port; the game's view of this peer
    uint16_t localPort = 0;
    uint64_t punchUntil = 0, nextPunch = 0, lastRecv = 0, lastSend = 0, lastGame = 0;
};

struct Host {
    bool on = false;
    int gamePort = 3659;
    sock_t pub = kBad;
    uint16_t localPort = 0;
    Stun stun;
    std::vector<Peer> peers;
};

enum JoinState { JOIN_PUNCHING = 0, JOIN_CONNECTED = 1, JOIN_FAILED = 2, JOIN_CLOSED = 3 };

struct Join {
    unsigned id = 0;
    Token token;
    std::vector<Ep> targets;
    Ep actual;
    sock_t pub = kBad, loop = kBad;
    uint16_t pubPort = 0, loopPort = 0;
    Ep game;                  // the game's socket, as seen on loop
    int state = JOIN_CLOSED;
    Stun stun;
    uint64_t started = 0, deadline = 0, nextPunch = 0, lastRecv = 0, lastSend = 0, lastGame = 0;
};

struct State {
    Lock lock;
    LogFn log = nullptr;
    bool started = false;
    std::vector<std::string> stunNames;
    std::vector<Ep> stunServers;   // resolved, IPv4
    bool resolved = false;
    Host host;
    Join join;
    unsigned joinGen = 0;
    unsigned hostGen = 0;          // bumped when what the lobby must say changes
};
static State g;

#define PLOG(...) do { if (g.log) g.log(__VA_ARGS__); } while (0)

static void RandomBytes(unsigned char* p, int n) {
    static uint64_t x = 0;
    if (!x) x = NowMs() * 0x9E3779B97F4A7C15ull ^ (uint64_t)(uintptr_t)&x;
    for (int i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        p[i] = (unsigned char)(x >> 24);
    }
}

// ---- STUN, per socket ---------------------------------------------------------------------

static void StunBegin(Stun& s, uint64_t now) {
    Stun fresh;
    fresh.mapped = s.mapped;   // a refresh keeps what was known until it hears otherwise
    fresh.nat = s.nat;
    s = fresh;
    if (g.stunServers.empty()) return;
    s.server[0] = g.stunServers[0];
    // A second server, at another address if there is one, for the NAT's
    // mapping behaviour (a symmetric NAT maps per destination address).
    for (size_t i = 1; i < g.stunServers.size() && !s.server[1].ok(); i++)
        if (g.stunServers[i].ip != s.server[0].ip) s.server[1] = g.stunServers[i];
    if (!s.server[1].ok() && g.stunServers.size() > 1) s.server[1] = g.stunServers[1];
    RandomBytes(&s.tx[0][0], 24);
    s.start = now;
}

static void StunTick(Stun& s, sock_t sock, uint64_t now, bool refresh) {
    if (!s.start) {
        if (!g.stunServers.empty()) StunBegin(s, now);
        else return;
    }
    if (!s.done) {
        if (s.got[0].ok() && (s.got[1].ok() || !s.server[1].ok())) s.done = true;
        else if (now - s.start > (uint64_t)kStunWaitMs) s.done = true;
        if (s.done) {
            Ep m = s.got[0].ok() ? s.got[0] : s.got[1];
            if (m.ok()) s.mapped = m;
            if (s.got[0].ok() && s.got[1].ok()) s.nat = s.got[0] == s.got[1] ? "eim" : "symmetric";
            s.refreshAt = now + kStunRefreshMs;
            return;
        }
        if (now - s.lastSend >= (uint64_t)kStunResendMs) {
            s.lastSend = now;
            for (int i = 0; i < 2; i++) {
                if (!s.server[i].ok() || s.got[i].ok()) continue;
                unsigned char req[20];
                StunRequest(req, s.tx[i]);
                SendTo(sock, s.server[i], req, 20);
            }
        }
    } else if (refresh && now >= s.refreshAt) {
        // Keeps the mapping (the host waits minutes for joiners) and notices
        // when it moves.
        StunBegin(s, now);
    }
}

static bool StunReceive(Stun& s, const unsigned char* p, int n) {
    if (!IsStun(p, n)) return false;
    for (int i = 0; i < 2; i++) {
        Ep m;
        if (s.server[i].ok() && StunMapped(p, n, s.tx[i], m)) s.got[i] = m;
    }
    return true;
}

// ---- host side -------------------------------------------------------------------------

static Peer* PeerByToken(const Token& t) {
    for (auto& p : g.host.peers) if (p.token == t) return &p;
    return nullptr;
}

static void ClosePeer(Peer& p, bool bye) {
    if (bye && p.authed) SendCtl(g.host.pub, p.actual, BYE, p.token);
    if (p.local != kBad) CloseSock(p.local);
    p.local = kBad;
}

static void HostReceive(uint64_t now) {
    unsigned char buf[2048];
    for (int i = 0; i < 256; i++) {
        sockaddr_in from;
        socklen_t flen = sizeof from;
        int n = (int)recvfrom(g.host.pub, (char*)buf, sizeof buf, 0, (sockaddr*)&from, &flen);
        if (n < 0) { if (WouldBlock()) break; continue; }
        Ep src = FromSa(from);
        if (StunReceive(g.host.stun, buf, n)) continue;
        Type type;
        Token tok;
        if (ParseCtl(buf, n, type, tok)) {
            Peer* p = PeerByToken(tok);
            if (!p) continue;   // not (yet) signalled by the server: the joiner keeps trying
            if (type == PUNCH || type == ACK) {
                if (!p->authed || p->actual != src) {
                    PLOG("punch: host: joiner %s connected", EpStr(src).c_str());
                    if (p->local == kBad) {
                        p->local = OpenUdp(htonl(0x7f000001), 0, p->localPort);
                        if (p->local != kBad) {
                            sockaddr_in game = ToSa(Loopback((uint16_t)g.host.gamePort));
                            connect(p->local, (sockaddr*)&game, sizeof game);
                        }
                    }
                    p->lastGame = now;
                }
                p->authed = true;
                p->actual = src;
                p->lastRecv = now;
                if (type == PUNCH) { SendCtl(g.host.pub, src, ACK, tok); p->lastSend = now; }
            } else if (type == KEEPALIVE && p->authed && p->actual == src) {
                p->lastRecv = now;
            } else if (type == BYE && p->authed && p->actual == src) {
                PLOG("punch: host: joiner %s left", EpStr(src).c_str());
                ClosePeer(*p, false);
                p->authed = false;
                p->punchUntil = 0;
            }
            continue;
        }
        // A game datagram: only from an authenticated joiner (the token gate).
        for (auto& p : g.host.peers) {
            if (p.authed && p.actual == src && p.local != kBad) {
                send(p.local, (const char*)buf, n, 0);
                p.lastRecv = now;
                break;
            }
        }
    }
}

static void PeerReceive(Peer& p, uint64_t now) {
    unsigned char buf[2048];
    for (int i = 0; i < 256; i++) {
        int n = (int)recv(p.local, (char*)buf, sizeof buf, 0);
        if (n < 0) { if (WouldBlock()) break; continue; }   // e.g. the game's port closed for a map change
        p.lastGame = now;
        if (p.authed) { SendTo(g.host.pub, p.actual, buf, n); p.lastSend = now; }
    }
}

static void HostTimers(uint64_t now) {
    StunTick(g.host.stun, g.host.pub, now, true);
    for (size_t i = 0; i < g.host.peers.size();) {
        Peer& p = g.host.peers[i];
        if (!p.authed && now < p.punchUntil && now >= p.nextPunch) {
            for (auto& t : p.targets) SendCtl(g.host.pub, t, PUNCH, p.token);
            p.nextPunch = now + kPunchEveryMs;
            p.lastSend = now;
        }
        if (p.authed && now - p.lastSend >= (uint64_t)kKeepaliveMs) {
            SendCtl(g.host.pub, p.actual, KEEPALIVE, p.token);
            p.lastSend = now;
        }
        bool drop = false;
        if (!p.authed && now > p.punchUntil + 5000) drop = true;
        if (p.authed && (now - p.lastRecv > (uint64_t)kPeerSilentMs || now - p.lastGame > (uint64_t)kGameIdleMs)) {
            PLOG("punch: host: joiner %s dropped (%s)", EpStr(p.actual).c_str(),
                 now - p.lastRecv > (uint64_t)kPeerSilentMs ? "its proxy went silent" : "no game traffic");
            drop = true;
        }
        if (drop) {
            ClosePeer(p, true);
            g.host.peers.erase(g.host.peers.begin() + i);
        } else {
            i++;
        }
    }
}

// ---- join side ---------------------------------------------------------------------------

static void CloseJoin(bool bye) {
    Join& j = g.join;
    if (bye && j.state == JOIN_CONNECTED) SendCtl(j.pub, j.actual, BYE, j.token);
    if (j.pub != kBad) CloseSock(j.pub);
    if (j.loop != kBad) CloseSock(j.loop);
    j.pub = j.loop = kBad;
    if (j.state == JOIN_PUNCHING || j.state == JOIN_CONNECTED) j.state = JOIN_CLOSED;
}

static void JoinReceive(uint64_t now) {
    Join& j = g.join;
    unsigned char buf[2048];
    for (int i = 0; i < 256; i++) {
        sockaddr_in from;
        socklen_t flen = sizeof from;
        int n = (int)recvfrom(j.pub, (char*)buf, sizeof buf, 0, (sockaddr*)&from, &flen);
        if (n < 0) { if (WouldBlock()) break; continue; }
        Ep src = FromSa(from);
        if (StunReceive(j.stun, buf, n)) continue;
        Type type;
        Token tok;
        if (ParseCtl(buf, n, type, tok)) {
            if (!(tok == j.token)) continue;
            if (type == PUNCH || type == ACK) {
                // The host's proxy may answer from another port than the one
                // the server named (its NAT maps per destination): adopt it.
                if (j.state == JOIN_PUNCHING) PLOG("punch: join: host %s answered", EpStr(src).c_str());
                if (j.state == JOIN_PUNCHING || j.state == JOIN_CONNECTED) {
                    j.state = JOIN_CONNECTED;
                    j.actual = src;
                    j.lastRecv = now;
                    if (type == PUNCH) { SendCtl(j.pub, src, ACK, j.token); j.lastSend = now; }
                }
            } else if (type == KEEPALIVE && src == j.actual) {
                j.lastRecv = now;
            } else if (type == BYE && src == j.actual) {
                PLOG("punch: join: the host closed the connection");
                CloseJoin(false);
                return;
            }
            continue;
        }
        if (j.state == JOIN_CONNECTED && src == j.actual) {
            j.lastRecv = now;
            if (j.game.ok()) SendTo(j.loop, j.game, buf, n);
        }
    }
}

static void LoopReceive(uint64_t now) {
    Join& j = g.join;
    unsigned char buf[2048];
    for (int i = 0; i < 256; i++) {
        sockaddr_in from;
        socklen_t flen = sizeof from;
        int n = (int)recvfrom(j.loop, (char*)buf, sizeof buf, 0, (sockaddr*)&from, &flen);
        if (n < 0) { if (WouldBlock()) break; continue; }
        // The game's socket. A reconnect (after a map change) may come from a
        // new port; the latest one wins.
        Ep src = FromSa(from);
        if (src.ip != htonl(0x7f000001)) continue;
        if (j.game != src) j.game = src;
        j.lastGame = now;
        if (j.state == JOIN_CONNECTED) { SendTo(j.pub, j.actual, buf, n); j.lastSend = now; }
    }
}

static void JoinTimers(uint64_t now) {
    Join& j = g.join;
    StunTick(j.stun, j.pub, now, false);
    if (j.state == JOIN_PUNCHING) {
        if (now >= j.nextPunch) {
            for (auto& t : j.targets) SendCtl(j.pub, t, PUNCH, j.token);
            j.nextPunch = now + kPunchEveryMs;
            j.lastSend = now;
        }
        if (now > j.deadline) {
            PLOG("punch: join: no answer from the host's proxy");
            CloseJoin(false);
            j.state = JOIN_FAILED;
        }
        return;
    }
    if (j.state != JOIN_CONNECTED) return;
    if (now - j.lastSend >= (uint64_t)kKeepaliveMs) {
        SendCtl(j.pub, j.actual, KEEPALIVE, j.token);
        j.lastSend = now;
    }
    if (now - j.lastRecv > (uint64_t)kPeerSilentMs) {
        PLOG("punch: join: the host's proxy went silent");
        CloseJoin(false);
    } else if (now - j.lastGame > (uint64_t)kGameIdleMs) {
        PLOG("punch: join: closed, no game traffic");
        CloseJoin(true);
    }
}

// ---- the threads -------------------------------------------------------------------------

PUNCH_THREAD(ProxyThread) {
    for (;;) {
        fd_set rd;
        FD_ZERO(&rd);
        int maxfd = 0, count = 0;
        auto add = [&](sock_t s) {
            if (s == kBad) return;
            FD_SET(s, &rd);
            count++;
            if ((int)s > maxfd) maxfd = (int)s;
        };
        {
            Guard lk(g.lock);
            add(g.host.pub);
            for (auto& p : g.host.peers) add(p.local);
            add(g.join.pub);
            add(g.join.loop);
        }
        if (count == 0) {
            SleepMs(50);
        } else {
            timeval tv = {0, 20000};
            select(maxfd + 1, &rd, nullptr, nullptr, &tv);
        }
        Guard lk(g.lock);
        uint64_t now = NowMs();
        // Readiness is re-checked by the non-blocking reads themselves: a
        // socket closed by the API since the select is simply skipped.
        if (g.host.pub != kBad) {
            std::string before = EpStr(g.host.stun.mapped) + g.host.stun.nat;
            HostReceive(now);
            for (auto& p : g.host.peers) if (p.local != kBad) PeerReceive(p, now);
            HostTimers(now);
            if (EpStr(g.host.stun.mapped) + g.host.stun.nat != before) {
                g.hostGen++;
                PLOG("punch: host: proxy %s seen as %s (%s)", std::to_string(g.host.localPort).c_str(),
                     EpStr(g.host.stun.mapped).c_str(), g.host.stun.nat.empty() ? "NAT type unknown" : g.host.stun.nat.c_str());
            }
        }
        if (g.join.pub != kBad) {
            JoinReceive(now);
            if (g.join.loop != kBad) LoopReceive(now);
            if (g.join.pub != kBad) JoinTimers(now);
        }
    }
    PUNCH_THREAD_RETURN;
}

// Resolves the STUN servers once, off the game thread; retried while none answers DNS.
PUNCH_THREAD(ResolveThread) {
    for (int attempt = 0; attempt < 20; attempt++) {
        std::vector<std::string> names;
        { Guard lk(g.lock); names = g.stunNames; }
        std::vector<Ep> eps;
        for (auto& n : names) {
            size_t colon = n.rfind(':');
            std::string host = colon == std::string::npos ? n : n.substr(0, colon);
            std::string port = colon == std::string::npos ? "3478" : n.substr(colon + 1);
            addrinfo hints;
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            addrinfo* res = nullptr;
            if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) continue;
            Ep e = FromSa(*(sockaddr_in*)res->ai_addr);
            freeaddrinfo(res);
            bool dup = false;
            for (auto& x : eps) dup = dup || x == e;
            if (!dup) eps.push_back(e);
        }
        if (!eps.empty()) {
            Guard lk(g.lock);
            g.stunServers = eps;
            g.resolved = true;
            std::string list;
            for (auto& e : eps) list += (list.empty() ? "" : " ") + EpStr(e);
            PLOG("punch: STUN servers %s", list.c_str());
            PUNCH_THREAD_RETURN;
        }
        SleepMs(attempt < 3 ? 2000 : 30000);
    }
    PLOG("punch: no STUN server resolves: hosts behind NAT cannot be joined");
    PUNCH_THREAD_RETURN;
}

// ---- API ----------------------------------------------------------------------------------

static const char* kDefaultStun[] = {
    "stun.cloudflare.com:3478",
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
};

// stunNames: "host:port" each; empty means the defaults.
static void Init(const std::vector<std::string>& stunNames, LogFn log) {
    Guard lk(g.lock);
    if (g.started) return;
    g.log = log;
    g.stunNames = stunNames;
    if (g.stunNames.empty()) for (auto n : kDefaultStun) g.stunNames.push_back(n);
    if (!NetInit()) { PLOG("punch: no sockets: hole punching is off"); return; }
    g.started = StartThread(ProxyThread) && StartThread(ResolveThread);
}

// The proxies' preferred ports (an ephemeral one when taken, e.g. a second
// instance on one machine). Fixed, so a player can forward one by hand and a
// router that keeps only permanent UPnP mappings reuses one (lemp_upnp.h).
static const uint16_t kHostPort = 3660, kJoinPort = 3661;

static sock_t OpenPreferred(uint16_t port, uint16_t& bound) {
    sock_t s = OpenUdp(INADDR_ANY, port, bound);
    return s != kBad ? s : OpenUdp(INADDR_ANY, 0, bound);
}

// The hosted lobby's proxy, forwarding to the game listening on gamePort.
static bool HostStart(int gamePort) {
    Guard lk(g.lock);
    g.host.gamePort = gamePort;
    if (g.host.on) return true;
    g.host.pub = OpenPreferred(kHostPort, g.host.localPort);
    if (g.host.pub == kBad) { PLOG("punch: host: no socket"); return false; }
    g.host.on = true;
    g.host.stun = Stun();
    g.hostGen++;
    PLOG("punch: host: proxy on port %s -> game port %s", std::to_string(g.host.localPort).c_str(), std::to_string(gamePort).c_str());
    return true;
}

static void HostStop() {
    Guard lk(g.lock);
    if (!g.host.on) return;
    for (auto& p : g.host.peers) ClosePeer(p, true);
    g.host.peers.clear();
    CloseSock(g.host.pub);
    g.host = Host();
    g.hostGen++;
    PLOG("punch: host: proxy closed");
}

struct HostInfo {
    bool on = false;
    std::string mapped;     // "ip:port" as STUN saw it, "" unknown
    int localPort = 0;
    std::string nat;        // "eim" | "symmetric" | ""
    bool stunDone = false;
    unsigned gen = 0;
};
static HostInfo GetHostInfo() {
    Guard lk(g.lock);
    HostInfo h;
    h.on = g.host.on;
    h.mapped = EpStr(g.host.stun.mapped);
    h.localPort = g.host.localPort;
    h.nat = g.host.stun.nat;
    h.stunDone = g.host.stun.done;
    h.gen = g.hostGen;
    return h;
}

// The server's signal: a joiner holding this token is punching from these
// endpoints; punch back, and let it in.
static bool HostExpect(const std::string& tokenHex, const std::vector<std::string>& targets) {
    Token t;
    if (!ParseToken(tokenHex, t)) return false;
    Guard lk(g.lock);
    if (!g.host.on) return false;
    Peer* p = PeerByToken(t);
    if (!p) {
        if ((int)g.host.peers.size() >= kMaxPeers) {
            // The oldest that never connected makes room.
            for (size_t i = 0; i < g.host.peers.size(); i++)
                if (!g.host.peers[i].authed) { ClosePeer(g.host.peers[i], false); g.host.peers.erase(g.host.peers.begin() + i); break; }
            if ((int)g.host.peers.size() >= kMaxPeers) return false;
        }
        g.host.peers.push_back(Peer());
        p = &g.host.peers.back();
        p->token = t;
    }
    for (auto& s : targets) {
        Ep e;
        bool have = false;
        if (!ParseEp(s, e)) continue;
        for (auto& x : p->targets) have = have || x == e;
        if (!have) p->targets.push_back(e);
    }
    uint64_t now = NowMs();
    p->punchUntil = now + kPunchForMs;
    p->nextPunch = now;
    PLOG("punch: host: told to punch to %s", targets.empty() ? "(nowhere: it will be adopted when it arrives)" : targets[0].c_str());
    return true;
}

// Starts punching to the host's proxy; replaces an earlier join. Returns its
// id (0: no socket).
static unsigned JoinStart(const std::string& tokenHex, const std::string& target) {
    Token t;
    Ep e;
    if (!ParseToken(tokenHex, t) || !ParseEp(target, e)) return 0;
    Guard lk(g.lock);
    CloseJoin(true);
    Join& j = g.join;
    j = Join();
    j.pub = OpenPreferred(kJoinPort, j.pubPort);
    j.loop = OpenUdp(htonl(0x7f000001), 0, j.loopPort);
    if (j.pub == kBad || j.loop == kBad) {
        CloseJoin(false);
        j.state = JOIN_FAILED;
        return 0;
    }
    j.id = ++g.joinGen;
    j.token = t;
    j.targets.push_back(e);
    j.state = JOIN_PUNCHING;
    uint64_t now = NowMs();
    j.started = j.nextPunch = j.lastGame = now;
    j.deadline = now + kPunchForMs;
    PLOG("punch: join: punching to %s from port %s", target.c_str(), std::to_string(j.pubPort).c_str());
    return j.id;
}

struct JoinInfo {
    int state = JOIN_CLOSED;
    std::string mapped;      // our proxy socket as STUN saw it
    int pubPort = 0;         // its local port (for a host behind the same NAT)
    int loopPort = 0;        // where the game connects
    bool stunDone = false;
    std::string nat;
};
static JoinInfo GetJoinInfo(unsigned id) {
    Guard lk(g.lock);
    JoinInfo r;
    if (id != g.join.id) return r;
    r.state = g.join.state;
    r.mapped = EpStr(g.join.stun.mapped);
    r.pubPort = g.join.pubPort;
    r.loopPort = g.join.loopPort;
    r.stunDone = g.join.stun.done || (g.resolved && g.stunServers.empty());
    r.nat = g.join.stun.nat;
    return r;
}

// The NAT's mapping behaviour as the join proxy's STUN saw it, whichever
// join is up ("" before STUN answered, or with no join). Host migration's
// order (lemp_online.h HostQuality).
static std::string JoinNat() {
    Guard lk(g.lock);
    return g.join.stun.nat;
}

static void JoinStop(unsigned id) {
    Guard lk(g.lock);
    if (id != g.join.id) return;
    CloseJoin(true);
}

// Whether one of the proxies' public-side sockets is open on this port
// (lemp_upnp.h drops a mapping whose socket closed).
static bool PortOpen(uint16_t port) {
    Guard lk(g.lock);
    return (g.host.on && g.host.localPort == port) || (g.join.pub != kBad && g.join.pubPort == port);
}

}  // namespace punch
