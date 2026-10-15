// Hole punching end to end under Wine, against a running master server
// (a local development instance): a hosted lobby registers its proxy and opens its
// signal socket; a search is JOINed to it with a token, punches, and is
// handed 127.0.0.1:<port>; a game datagram sent there comes back from the
// host's (fake) game through both proxies. STUN is two fake servers in this
// process (LEMP\stun.txt), so everything runs on this machine: `wrangler dev`
// sees one address for all, and the punch goes to the host's LAN endpoint.
//   x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -municode -o test_lemp_nat.exe test_lemp_nat.cpp -lwinhttp -lws2_32 -lbcrypt
//   wine test_lemp_nat.exe <dir with server.txt = http://127.0.0.1:8787>
#include <winsock2.h>
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include "lemp_online.h"

static void Log(const char* fmt, ...) {
    va_list a; va_start(a, fmt); printf("  log: "); vprintf(fmt, a); va_end(a); printf("\n"); fflush(stdout);
}
static std::string g_build;
static std::string GetBuild() { return g_build; }
static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } else printf("ok   %s\n", #c); } while (0)

using punch::sock_t;

static sock_t g_stun[2];
static DWORD WINAPI StunServer(LPVOID) {
    unsigned char buf[512];
    for (;;) {
        for (int i = 0; i < 2; i++) {
            sockaddr_in a;
            int len = sizeof a;
            int n = recvfrom(g_stun[i], (char*)buf, sizeof buf, 0, (sockaddr*)&a, &len);
            if (n < 20 || buf[0] != 0 || buf[1] != 1) continue;
            unsigned char out[32] = {0x01, 0x01, 0x00, 0x0c};
            memcpy(out + 4, buf + 4, 16);
            out[21] = 0x20; out[23] = 0x08; out[25] = 1;
            uint16_t port = ntohs(a.sin_port) ^ (uint16_t)(punch::kCookie >> 16);
            out[26] = port >> 8; out[27] = port & 0xff;
            uint32_t ip = a.sin_addr.s_addr ^ htonl(punch::kCookie);
            memcpy(out + 28, &ip, 4);
            sendto(g_stun[i], (const char*)out, 32, 0, (sockaddr*)&a, len);
        }
        Sleep(2);
    }
}

static sock_t g_game;
static DWORD WINAPI GameServer(LPVOID) {
    unsigned char buf[2048];
    for (;;) {
        sockaddr_in a;
        int len = sizeof a;
        int n = recvfrom(g_game, (char*)buf + 5, sizeof buf - 5, 0, (sockaddr*)&a, &len);
        if (n < 0) { Sleep(2); continue; }
        memcpy(buf, "echo:", 5);
        sendto(g_game, (const char*)buf, n + 5, 0, (sockaddr*)&a, len);
    }
}

static int WaitOutcome(int ms) {
    for (int t = 0; t < ms; t += 100) {
        int o = online::PollSearch();
        if (o != online::IN_PROGRESS) return o;
        Sleep(100);
    }
    return online::IN_PROGRESS;
}

int wmain(int argc, wchar_t** argv) {
    std::wstring dir = argc > 1 ? argv[1] : L".";
    char b[64]; snprintf(b, sizeof b, "LEMPBuild=nattest%lu", GetTickCount());
    g_build = b;
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    uint16_t sp[2], gp;
    for (int i = 0; i < 2; i++) g_stun[i] = punch::OpenUdp(htonl(0x7f000001), 0, sp[i]);
    g_game = punch::OpenUdp(htonl(INADDR_ANY), 0, gp);
    CreateThread(nullptr, 0, StunServer, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, GameServer, nullptr, 0, nullptr);
    {
        std::string text = "127.0.0.1:" + std::to_string(sp[0]) + "\r\n127.0.0.1:" + std::to_string(sp[1]) + "\r\n";
        HANDLE h = CreateFileW((dir + L"\\stun.txt").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
        DWORD put = 0;
        WriteFile(h, text.data(), (DWORD)text.size(), &put, nullptr);
        CloseHandle(h);
    }
    online::Init(dir, Log, nullptr, GetBuild);
    online::SetVersion("0.1.0");

    // Host: the lobby, its proxy (to the fake game's port), its signal socket.
    std::string opts = "?create=1?private=0?open=1?map=0?enemy=0?difficulty=1?players=1?max=4?port=" + std::to_string(gp);
    CHECK(online::UpdateLobby(opts) == 0);
    std::string st; int reach = -1;
    for (int t = 0; t < 8000; t += 100) { st = online::LobbyStatus(reach); if (st.find("?code=") == 0 && st.find("?code=?") != 0) break; Sleep(100); }
    CHECK(st.find("?code=") == 0 && st.find("?code=?") != 0);
    for (int t = 0; t < 8000 && !online::g_ws; t += 100) Sleep(100);
    CHECK(online::g_ws != nullptr);
    punch::HostInfo hi;
    for (int t = 0; t < 5000 && !(hi = punch::GetHostInfo()).stunDone; t += 100) Sleep(100);
    printf("     host proxy %s local %d nat %s\n", hi.mapped.c_str(), hi.localPort, hi.nat.c_str());
    CHECK(hi.on && !hi.mapped.empty());

    // The keep-alive: pings sent beside the pending receive come back as pongs.
    online::g_wsPingMs = 400;
    Sleep(3000);
    printf("     pongs %d\n", online::g_wsPongs);
    CHECK(online::g_wsPongs >= 3);
    CHECK(online::g_ws != nullptr);
    online::g_wsPingMs = 30000;
    Sleep(1500);   // the heartbeat has the proxy's endpoint by now

    // Joiner: JOIN with a token, punched, handed the local proxy.
    CHECK(online::StartSearch("?map=0?enemy=0?difficulty=-1") == 0);
    int o = WaitOutcome(25000);
    std::string text = online::SearchText();
    printf("     outcome %d %s\n", o, text.c_str());
    CHECK(o == online::JOIN);
    CHECK(text.find("?address=127.0.0.1:") == 0);

    // The joiner's game, through both proxies, to the host's game and back.
    auto m = online::ParseOptions(text);
    punch::Ep via;
    CHECK(punch::ParseEp(m["address"], via) && via.port != gp);
    uint16_t cp;
    sock_t client = punch::OpenUdp(htonl(0x7f000001), 0, cp);
    bool echoed = false;
    unsigned char buf[2048];
    for (int k = 0; k < 20 && !echoed; k++) {
        punch::SendTo(client, via, "hello", 5);
        for (int t = 0; t < 200 && !echoed; t += 5) {
            int n = recv(client, (char*)buf, sizeof buf, 0);
            if (n == 10 && memcmp(buf, "echo:hello", 10) == 0) echoed = true;
            else Sleep(5);
        }
    }
    CHECK(echoed);

    // Leaving: the lobby goes, its signal socket is closed by the server, the proxy stops.
    CHECK(online::DestroyLobby() == 0);
    for (int t = 0; t < 5000 && (online::g_ws || punch::GetHostInfo().on); t += 100) Sleep(100);
    CHECK(online::g_ws == nullptr);
    CHECK(!punch::GetHostInfo().on);

    printf("%s (%d failed)\n", fails ? "FAILED" : "PASSED", fails);
    fflush(stdout);
    ExitProcess(fails ? 1 : 0);
}
