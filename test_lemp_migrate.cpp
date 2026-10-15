// Host migration end to end under Wine, against a running master server
// (a local development instance). One process
// plays every part in turn, as test_lemp_nat does (fake STUN and a fake game
// here; the punch goes to the LAN endpoint): a host registers a match with
// its migration key; a player's claim is refused while the host is still
// there; the host leaves and the claim takes the lobby over under the same
// code, with a new id and key, and its proxy and signal socket come up; a
// second player waits for it until it says it is up, is then handed it as a
// JOIN, punched through, and a game datagram makes the round trip; a wrong
// key is refused.
//   x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -municode -o test_lemp_migrate.exe test_lemp_migrate.cpp -lwinhttp -lws2_32 -lbcrypt
//   wine test_lemp_migrate.exe <dir with server.txt = http://127.0.0.1:8787>
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

static std::string Code() {
    int reach = -1;
    std::string st = online::LobbyStatus(reach);
    auto m = online::ParseOptions(st);
    return m.count("code") ? m["code"] : "";
}

int wmain(int argc, wchar_t** argv) {
    std::wstring dir = argc > 1 ? argv[1] : L".";
    char b[64]; snprintf(b, sizeof b, "LEMPBuild=migtest%lu", GetTickCount());
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
    // Allowed online only as the server's exact REQUIRED_VERSION: run the
    // server with `wrangler dev --var REQUIRED_VERSION:0.1.0`, as test_lemp_nat.
    online::SetVersion("0.1.0");

    // The old host: a match in progress (state 3), registered, signal socket open.
    CHECK(online::MigrationTicket().empty());   // not hosting
    std::string port = std::to_string(gp);
    CHECK(online::UpdateLobby("?create=1?private=1?open=1?state=3?map=0?enemy=2?difficulty=1?players=2?max=4?port=" + port) == 0);
    std::string code;
    for (int t = 0; t < 8000 && (code = Code()).empty(); t += 100) Sleep(100);
    printf("     code %s\n", code.c_str());
    CHECK(!code.empty());
    for (int t = 0; t < 8000 && !online::g_ws; t += 100) Sleep(100);
    CHECK(online::g_ws != nullptr);
    std::string ticket = online::MigrationTicket();
    auto tk = online::ParseOptions(ticket);
    std::string oldLobby = tk["lobby"], oldKey = tk["key"];
    printf("     ticket lobby %s\n", oldLobby.c_str());
    CHECK(oldLobby.size() == 32 && oldKey.size() == 32);

    // A player whose own connection broke claims while the host is still
    // there: refused (the server hears from the host), so it waits.
    std::string mig = "?migrate=" + oldLobby + "?key=" + oldKey + "?private=1?map=0?enemy=2?difficulty=1?players=1?max=4?state=3?port=" + port;
    CHECK(online::StartSearch(mig + "?rank=0") == 0);
    CHECK(WaitOutcome(4000) == online::IN_PROGRESS);
    // ...and says so, so script plays on quietly.
    CHECK(online::SearchText() == "?phase=alive");
    // A player further down the line asks /rejoin: the server says alive too.
    online::CancelSearch();
    CHECK(online::StartSearch(mig + "?rank=1") == 0);
    CHECK(WaitOutcome(3000) == online::IN_PROGRESS);
    CHECK(online::SearchText() == "?phase=alive");
    online::CancelSearch();
    CHECK(online::StartSearch(mig + "?rank=0") == 0);
    CHECK(WaitOutcome(3000) == online::IN_PROGRESS);

    // The host leaves: the claim goes through, under the same code.
    CHECK(online::DestroyLobby() == 0);
    int o = WaitOutcome(20000);
    std::string text = online::SearchText();
    printf("     claim outcome %d %s\n", o, text.c_str());
    CHECK(o == online::CREATE);
    CHECK(online::ParseOptions(text)["code"] == code);
    CHECK(Code() == code);
    auto tk2 = online::ParseOptions(online::MigrationTicket());
    CHECK(tk2["lobby"].size() == 32 && tk2["lobby"] != oldLobby);
    CHECK(tk2["key"].size() == 32 && tk2["key"] != oldKey);
    // The new host's proxy and signal socket (the next player is punched through them).
    for (int t = 0; t < 8000 && !online::g_ws; t += 100) Sleep(100);
    CHECK(online::g_ws != nullptr);
    punch::HostInfo hi;
    for (int t = 0; t < 5000 && !(hi = punch::GetHostInfo()).stunDone; t += 100) Sleep(100);
    CHECK(hi.on && hi.localPort != 0);
    Sleep(1500);   // the heartbeat carries the proxy's endpoint

    // The second player: the new host is loading, so it waits...
    CHECK(online::StartSearch(mig + "?rank=1") == 0);
    CHECK(WaitOutcome(4000) == online::IN_PROGRESS);
    // ...until the new host's map is up (SFXGameInfoMP.LEMPMigratedHostReady).
    CHECK(online::UpdateLobby("?ready=1?open=0?state=3?players=1") == 0);
    o = WaitOutcome(25000);
    text = online::SearchText();
    printf("     rejoin outcome %d %s\n", o, text.c_str());
    CHECK(o == online::JOIN);
    CHECK(text.find("?address=127.0.0.1:") == 0);
    CHECK(online::ParseOptions(text)["lobby"] == tk2["lobby"]);

    // Its game, through both proxies, to the new host's game and back.
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

    // A key the server never saw: refused (after its grace for a DELETE in flight).
    std::string bad = "?migrate=" + oldLobby + "?key=" + std::string(32, '0') + "?rank=1?port=" + port;
    CHECK(online::StartSearch(bad) == 0);
    o = WaitOutcome(20000);
    printf("     wrong key outcome %d %s\n", o, online::SearchText().c_str());
    CHECK(o == online::FAILED);
    // A malformed one never starts.
    CHECK(online::StartSearch("?migrate=nothex?key=" + oldKey) == 1);

    CHECK(online::DestroyLobby() == 0);
    for (int t = 0; t < 5000 && (online::g_ws || punch::GetHostInfo().on); t += 100) Sleep(100);
    CHECK(!punch::GetHostInfo().on);

    // A migration left waiting (the host still alive) is cancelled when this
    // player hosts a lobby of its own, and a later claim does not take that
    // registration over (once, the stale claim swapped the new lobby
    // for the migrated one, never readied, and no search found it).
    CHECK(online::UpdateLobby("?create=1?private=0?open=1?state=1?map=0?enemy=0?difficulty=0?players=1?max=4?port=" + port) == 0);
    std::string code3;
    for (int t = 0; t < 8000 && (code3 = Code()).empty(); t += 100) Sleep(100);
    auto tk3 = online::ParseOptions(online::MigrationTicket());
    CHECK(!code3.empty() && tk3["lobby"].size() == 32);
    for (int t = 0; t < 8000 && !online::g_ws; t += 100) Sleep(100);   // the server counts it alive
    CHECK(online::g_ws != nullptr);
    std::string mig3 = "?migrate=" + tk3["lobby"] + "?key=" + tk3["key"] + "?private=0?map=0?enemy=0?difficulty=0?players=1?max=4?state=1?port=" + port;
    CHECK(online::StartSearch(mig3 + "?rank=0") == 0);
    CHECK(WaitOutcome(4000) == online::IN_PROGRESS);
    CHECK(online::UpdateLobby("?create=1?private=0?open=1?state=1?map=0?enemy=0?difficulty=0?players=1?max=4?port=" + port) == 0);
    CHECK(online::PollSearch() == -1);
    // The lobby goes; a migration still running would now claim it.
    CHECK(online::DestroyLobby() == 0);
    Sleep(8000);
    CHECK(online::PollSearch() == -1);
    CHECK(online::MigrationTicket().empty());   // hosting nothing: no claimed lobby
    for (int t = 0; t < 5000 && (online::g_ws || punch::GetHostInfo().on); t += 100) Sleep(100);
    CHECK(!punch::GetHostInfo().on);

    printf("%s (%d failed)\n", fails ? "FAILED" : "PASSED", fails);
    fflush(stdout);
    ExitProcess(fails ? 1 : 0);
}
