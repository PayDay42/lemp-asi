// test_lemp_voice_net.cpp — lemp_voice.cpp's socket layer as the host runs it,
// on real loopback UDP sockets (Wine or Windows):
//   x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -I<miniaudio> -I<opus/include>
//     -o t.exe test_lemp_voice_net.cpp lemp_voice_audio.cpp -L<opus build> -lopus -lole32 -lws2_32
// The host's game socket H goes through HookSendTo/HookRecvFrom; joiners A and
// B are plain sockets. Checks: peers form from two-way game traffic (with junk
// in sin_zero on the send side), a voice frame from A is consumed, played and
// relayed to B only, marked relayed, and the game's recvfrom gets the next
// game datagram instead; an empty socket returns WSAEWOULDBLOCK.
#include "lemp_voice.cpp"
#include <cstdio>

// lemp.cpp's helpers, for this test. This test does not exercise Install()/
// Thread(), so a null GNatives and "never exiting" are both fine stand-ins.
const std::wstring& LempDir() { static std::wstring d = L"."; return d; }
void LempLogV(const char* module, const char* fmt, va_list a) { printf("%s  ", module); vprintf(fmt, a); printf("\n"); }
void** LempGNatives() { return nullptr; }
namespace lemp { bool Exiting() { return false; } }

static int g_fail = 0, g_pass = 0;
#define CHECK(c) do { if (c) ++g_pass; else { ++g_fail; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static SOCKET Udp(sockaddr_in& at) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, (sockaddr*)&a, sizeof(a));
    int len = sizeof(at); getsockname(s, (sockaddr*)&at, &len);
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
    return s;
}
static int Recv(SOCKET s, char* buf, int cap, sockaddr_in* from) {
    for (int i = 0; i < 200; ++i) {
        int fl = sizeof(*from);
        int n = recvfrom(s, buf, cap, 0, (sockaddr*)from, &fl);
        if (n > 0) return n;
        Sleep(5);
    }
    return -1;
}
static int HookRecv(SOCKET s, char* buf, int cap, sockaddr_in* from) {
    for (int i = 0; i < 200; ++i) {
        int fl = sizeof(*from);
        int n = HookRecvFrom(s, buf, cap, 0, (sockaddr*)from, &fl);
        if (n > 0) return n;
        Sleep(5);
    }
    return -1;
}

int main() {
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    InitializeCriticalSection(&g_cs);
    g_realRecvFrom = (RecvFromFn)&recvfrom;
    g_realSendTo = (SendToFn)&sendto;

    sockaddr_in hA, aA, bA;
    SOCKET h = Udp(hA), a = Udp(aA), b = Udp(bA);
    char buf[1500]; sockaddr_in from;

    // Game traffic both ways; the host's sends carry junk in sin_zero.
    for (SOCKET j : {a, b}) {
        sockaddr_in to = (j == a) ? aA : bA;
        memset(to.sin_zero, 0xAB, sizeof(to.sin_zero));
        CHECK(HookSendTo(h, "game-h", 6, 0, (sockaddr*)&to, sizeof(to)) == 6);
        CHECK(Recv(j, buf, sizeof(buf), &from) == 6);
        CHECK(sendto(j, "game-j", 6, 0, (sockaddr*)&hA, sizeof(hA)) == 6);
        CHECK(HookRecv(h, buf, sizeof(buf), &from) == 6 && memcmp(buf, "game-j", 6) == 0);
    }
    {
        Lock l;
        CHECK(g_peerSocket.size() == 2);
        CHECK(g_engine.Peers(Now()).size() == 2);
    }

    // A sends a voice frame, then a game datagram. The host's game must see
    // only the game datagram; the frame is queued to play and relayed to B.
    g_engine.SetLocalId(100);
    voice::Frame f; f.sender = 1; f.seq = 7; f.payload = std::vector<uint8_t>(40, 0x5A);
    auto vb = voice::Encode(f);
    CHECK(sendto(a, (const char*)vb.data(), (int)vb.size(), 0, (sockaddr*)&hA, sizeof(hA)) == (int)vb.size());
    CHECK(sendto(a, "game-2", 6, 0, (sockaddr*)&hA, sizeof(hA)) == 6);
    Sleep(20);
    int n = HookRecv(h, buf, sizeof(buf), &from);
    CHECK(n == 6 && memcmp(buf, "game-2", 6) == 0);
    {
        Lock l;
        CHECK(g_heard.size() == 1 && g_heard.front().sender == 1 && g_heard.front().seq == 7);
    }
    n = Recv(b, buf, sizeof(buf), &from);
    voice::Frame r;
    CHECK(n == (int)vb.size() && voice::Decode((uint8_t*)buf, n, r));
    CHECK((r.flags & voice::kFlagRelayed) && r.sender == 1 && r.payload == f.payload);
    CHECK(Recv(a, buf, sizeof(buf), &from) < 0);   // not back to the sender

    // A lone voice frame: consumed, and the game is told "nothing", not blocked.
    f.seq = 8; vb = voice::Encode(f);
    sendto(a, (const char*)vb.data(), (int)vb.size(), 0, (sockaddr*)&hA, sizeof(hA));
    Sleep(20);
    int fl = sizeof(from);
    n = HookRecvFrom(h, buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
    CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
    n = Recv(b, buf, sizeof(buf), &from);           // ... and relayed to B as usual
    CHECK(n == (int)vb.size() && voice::Decode((uint8_t*)buf, n, r) && r.seq == 8);

    // Voice from a stranger (not a peer of the game's) is dropped, not relayed.
    sockaddr_in cA; SOCKET c = Udp(cA);
    f.sender = 3; f.seq = 1; vb = voice::Encode(f);
    sendto(c, (const char*)vb.data(), (int)vb.size(), 0, (sockaddr*)&hA, sizeof(hA));
    Sleep(20);
    fl = sizeof(from);
    HookRecvFrom(h, buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
    CHECK(Recv(b, buf, sizeof(buf), &from) < 0);   // nothing relayed to B
    { Lock l; CHECK(g_heard.size() == 2); }   // only A's two frames

    // The host's own frame goes to both joiners.
    std::vector<voice::Send> sends;
    { Lock l; sends = g_engine.LocalFrame(std::vector<uint8_t>(30, 1), Now()); }
    SendAll(sends);
    CHECK(Recv(a, buf, sizeof(buf), &from) == (int)(voice::kHeaderLen + 30));
    CHECK(Recv(b, buf, sizeof(buf), &from) == (int)(voice::kHeaderLen + 30));

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
