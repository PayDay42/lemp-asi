// lemp_punch.h on loopback, natively or under Wine: two fake STUN servers, a
// fake host game that echoes, the joiner's proxy, a second joiner made by
// hand, and the token gate. No NAT is involved: this checks the protocol and
// the forwarding, not traversal itself (that needs two networks).
//   g++ -std=c++17 -O2 -pthread -o test_lemp_punch test_lemp_punch.cpp && ./test_lemp_punch
//   x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -o test_lemp_punch.exe test_lemp_punch.cpp -lws2_32 && wine test_lemp_punch.exe
#include "lemp_punch.h"
#include <cstdarg>
#include <cstdio>
#include <set>

using namespace punch;

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } else printf("ok   %s\n", #c); } while (0)

static void Log(const char* fmt, ...) {
    va_list a; va_start(a, fmt); printf("  log: "); vprintf(fmt, a); va_end(a); printf("\n"); fflush(stdout);
}

static sock_t Udp(uint16_t& port) { return OpenUdp(htonl(0x7f000001), 0, port); }

static int RecvWait(sock_t s, unsigned char* buf, int cap, Ep* from, int ms) {
    for (int t = 0; t < ms; t += 5) {
        sockaddr_in a;
        socklen_t len = sizeof a;
        int n = (int)recvfrom(s, (char*)buf, cap, 0, (sockaddr*)&a, &len);
        if (n >= 0) { if (from) *from = FromSa(a); return n; }
        SleepMs(5);
    }
    return -1;
}

// A STUN server: answers each Binding request with the source it saw.
static sock_t g_stun[2];
static uint16_t g_stunPort[2];
static Lock g_stunLock;
static std::vector<std::pair<uint16_t, uint64_t>> g_stunAsked;   // server 0: (source port, when)
PUNCH_THREAD(StunServer) {
    unsigned char buf[512];
    for (;;) {
        for (int i = 0; i < 2; i++) {
            sockaddr_in a;
            socklen_t len = sizeof a;
            int n = (int)recvfrom(g_stun[i], (char*)buf, sizeof buf, 0, (sockaddr*)&a, &len);
            if (n < 20 || buf[0] != 0 || buf[1] != 1) continue;
            if (i == 0) { Guard lk(g_stunLock); g_stunAsked.push_back({ntohs(a.sin_port), NowMs()}); }
            unsigned char out[32] = {0x01, 0x01, 0x00, 0x0c};
            memcpy(out + 4, buf + 4, 16);
            out[20] = 0x00; out[21] = 0x20; out[22] = 0x00; out[23] = 0x08;
            out[24] = 0; out[25] = 1;
            uint16_t port = ntohs(a.sin_port) ^ (uint16_t)(kCookie >> 16);
            out[26] = port >> 8; out[27] = port & 0xff;
            uint32_t ip = a.sin_addr.s_addr ^ htonl(kCookie);
            memcpy(out + 28, &ip, 4);
            sendto(g_stun[i], (const char*)out, 32, 0, (sockaddr*)&a, len);
        }
        SleepMs(2);
    }
    PUNCH_THREAD_RETURN;
}

// The host's game: echoes "echo:" + payload, and remembers who sent.
static sock_t g_game;
static uint16_t g_gamePort;
static Lock g_seenLock;
static std::set<uint16_t> g_seen;
PUNCH_THREAD(GameServer) {
    unsigned char buf[2048];
    for (;;) {
        sockaddr_in a;
        socklen_t len = sizeof a;
        int n = (int)recvfrom(g_game, (char*)buf + 5, sizeof buf - 5, 0, (sockaddr*)&a, &len);
        if (n < 0) { SleepMs(2); continue; }
        { Guard lk(g_seenLock); g_seen.insert(ntohs(a.sin_port)); }
        memcpy(buf, "echo:", 5);
        sendto(g_game, (const char*)buf, n + 5, 0, (sockaddr*)&a, len);
    }
    PUNCH_THREAD_RETURN;
}

int main() {
    NetInit();
    // Units first.
    Ep e;
    CHECK(ParseEp("203.0.113.5:3659", e) && EpStr(e) == "203.0.113.5:3659");
    CHECK(!ParseEp("203.0.113.5", e) && !ParseEp("256.0.0.1:1", e) && !ParseEp("1.2.3.4:0", e) && !ParseEp("1.2.3.4:5x", e));
    Token tk;
    CHECK(ParseToken(std::string(32, 'a'), tk) && !ParseToken(std::string(31, 'a'), tk) && !ParseToken(std::string(32, 'g'), tk));
    {
        unsigned char tx[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, req[20];
        StunRequest(req, tx);
        CHECK(IsStun(req, 20));
        // A truncated answer whose attribute claims more than the packet holds.
        unsigned char bad[24] = {0x01, 0x01, 0x00, 0x40};
        memcpy(bad + 4, req + 4, 16);
        CHECK(!StunMapped(bad, 24, tx, e));
    }

    for (int i = 0; i < 2; i++) g_stun[i] = Udp(g_stunPort[i]);
    g_game = Udp(g_gamePort);
    StartThread(StunServer);
    StartThread(GameServer);

    std::vector<std::string> stun = {"127.0.0.1:" + std::to_string(g_stunPort[0]), "127.0.0.1:" + std::to_string(g_stunPort[1])};
    Init(stun, Log);
    CHECK(HostStart(g_gamePort));
    HostInfo h;
    for (int t = 0; t < 5000 && !(h = GetHostInfo()).stunDone; t += 20) SleepMs(20);
    CHECK(h.stunDone);
    CHECK(h.mapped == "127.0.0.1:" + std::to_string(h.localPort));
    CHECK(h.nat == "eim");

    // The host re-asks STUN every kStunRefreshMs: the keep-alive of its
    // waiting mapping, which a CGNAT forgot in under 25 s.
    {
        auto asked = [&] {
            Guard lk(g_stunLock);
            std::vector<uint64_t> v;
            for (auto& r : g_stunAsked) if (r.first == h.localPort) v.push_back(r.second);
            return v;
        };
        std::vector<uint64_t> v;
        for (int t = 0; t < 7000 && (v = asked()).size() < 2; t += 50) SleepMs(50);
        CHECK(v.size() >= 2);
        if (v.size() >= 2) {
            uint64_t gap = v[1] - v[0];
            printf("host STUN re-ask after %llu ms\n", (unsigned long long)gap);
            CHECK(gap >= (uint64_t)kStunRefreshMs && gap < (uint64_t)kStunRefreshMs + 1000);
        }
        CHECK(GetHostInfo().mapped == h.mapped);   // same socket, same mapping
    }

    // The joiner's proxy punches before the host is told: nothing yet.
    std::string tokenA = "0123456789abcdef0123456789abcdef";
    unsigned id = JoinStart(tokenA, h.mapped);
    CHECK(id != 0);
    JoinInfo j;
    for (int t = 0; t < 5000 && !(j = GetJoinInfo(id)).stunDone; t += 20) SleepMs(20);
    CHECK(j.stunDone && j.mapped == "127.0.0.1:" + std::to_string(j.pubPort));
    SleepMs(300);
    CHECK(GetJoinInfo(id).state == JOIN_PUNCHING);

    // The server's signal reaches the host: both sides connect.
    CHECK(HostExpect(tokenA, {j.mapped}));
    for (int t = 0; t < 3000 && GetJoinInfo(id).state != JOIN_CONNECTED; t += 20) SleepMs(20);
    CHECK(GetJoinInfo(id).state == JOIN_CONNECTED);

    // The joiner's game talks to 127.0.0.1:<loop> and hears the host's game.
    uint16_t gp;
    sock_t game = Udp(gp);
    Ep loop = Loopback((uint16_t)j.loopPort);
    unsigned char buf[2048];
    SendTo(game, loop, "hello", 5);
    int n = RecvWait(game, buf, sizeof buf, nullptr, 2000);
    CHECK(n == 10 && memcmp(buf, "echo:hello", 10) == 0);
    // Large datagrams pass unchanged.
    std::string big(1400, 'x');
    SendTo(game, loop, big.data(), (int)big.size());
    n = RecvWait(game, buf, sizeof buf, nullptr, 2000);
    CHECK(n == 1405);

    // A second joiner, by hand: its own token, its own local port at the game.
    uint16_t p2;
    sock_t j2 = OpenUdp(INADDR_ANY, 0, p2);
    std::string tokenB = "fedcba9876543210fedcba9876543210";
    Token tb;
    ParseToken(tokenB, tb);
    Ep hostEp;
    ParseEp(h.mapped, hostEp);
    // Data before any punch: dropped (the gate).
    SendTo(j2, hostEp, "sneak", 5);
    CHECK(RecvWait(j2, buf, sizeof buf, nullptr, 300) < 0);
    // A punch with a token the host was never told of: no answer.
    SendCtl(j2, hostEp, PUNCH, tb);
    CHECK(RecvWait(j2, buf, sizeof buf, nullptr, 300) < 0);
    CHECK(HostExpect(tokenB, {"127.0.0.1:" + std::to_string(p2)}));
    // The host punches to it; it answers.
    Ep from;
    n = RecvWait(j2, buf, sizeof buf, &from, 1000);
    Type ty;
    Token got;
    CHECK(n == kCtlLen && ParseCtl(buf, n, ty, got) && ty == PUNCH && got == tb);
    SendCtl(j2, from, PUNCH, tb);
    bool acked = false;
    for (int k = 0; k < 20 && !acked; k++) {
        n = RecvWait(j2, buf, sizeof buf, nullptr, 200);
        acked = n == kCtlLen && ParseCtl(buf, n, ty, got) && ty == ACK;
    }
    CHECK(acked);
    SendTo(j2, from, "two", 3);
    bool echoed = false;
    for (int k = 0; k < 40 && !echoed; k++) {
        n = RecvWait(j2, buf, sizeof buf, nullptr, 100);
        echoed = n == 8 && memcmp(buf, "echo:two", 8) == 0;   // punches/keep-alives in between are skipped
    }
    CHECK(echoed);
    {
        Guard lk(g_seenLock);
        CHECK(g_seen.size() == 2);   // two joiners, two distinct sources at the game
    }

    // Leaving: the joiner says BYE, the host drops it; hosting stops cleanly.
    JoinStop(id);
    CHECK(GetJoinInfo(id).state == JOIN_CLOSED);
    HostStop();
    CHECK(!GetHostInfo().on);

    printf("%s (%d failed)\n", fails ? "FAILED" : "PASSED", fails);
    return fails ? 1 : 0;
}
