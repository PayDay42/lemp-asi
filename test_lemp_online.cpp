// lemp_online.h under Wine, against a running master server (a local
// development instance). Exercises the ops exactly as mp_save.asi's ServeOnline calls them,
// minus the game: host a lobby, search and be sent to it, report the join
// failed, search again (the lobby is now skipped, so: told to CREATE); then
// the leaderboards: report, read the window around the player.
//   x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -municode -o test_lemp_online.exe test_lemp_online.cpp -lwinhttp -lws2_32 -lbcrypt
//   wine test_lemp_online.exe <server dir holding server.txt, or "">
#include <winsock2.h>
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include "lemp_online.h"

static void Log(const char* fmt, ...) {
    va_list a; va_start(a, fmt); vprintf(fmt, a); va_end(a); printf("\n"); fflush(stdout);
}
static std::string g_build;
static std::string GetBuild() { return g_build; }
static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } else printf("ok   %s\n", #c); } while (0)

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
    char b[64]; snprintf(b, sizeof b, "LEMPBuild=winetest%lu", GetTickCount());
    g_build = b;
    online::Init(dir, Log, nullptr, GetBuild);

    // The release check (ops 39-41). With the server run as
    // `wrangler dev --var REQUIRED_VERSION:0.1.0`, another release is refused too.
    auto versionText = []() {
        std::string v;
        for (int t = 0; t < 5000 && (v = online::VersionText()).empty(); t += 100) Sleep(100);
        return v;
    };
    CHECK(online::SetVersion("0.0.1") == 0);
    std::string vt = versionText();
    printf("     release check %s\n", vt.c_str());
    CHECK(vt.find("?status=") == 0);
    // the server's required version (exact; the JSON field
    // is still "minimum"), or one given with --var: 0.0.1 is never it.
    size_t mpos = vt.find("?minimum=");
    std::string minimum;
    if (mpos != std::string::npos && vt.find("?minimum=?") == std::string::npos) {
        minimum = vt.substr(mpos + 9, vt.find('?', mpos + 1) - mpos - 9);
        CHECK(vt.find("?status=required") == 0);
        CHECK(online::StartSearch("?map=0?enemy=0?difficulty=-1") == 0);
        CHECK(WaitOutcome(5000) == online::FAILED);
        printf("     refused: %s\n", online::SearchText().c_str());
        CHECK(online::SearchText().find("needs LEMP " + minimum + ".") != std::string::npos);
    }
    // The rest runs as the required release; with none named, as one newer
    // than any (a required version is exact: 99.0.0 would be refused).
    CHECK(online::SetVersion(minimum.empty() ? "99.0.0" : minimum.c_str()) == 0);
    vt = versionText();
    CHECK(vt.find("?status=") == 0 && vt.find("?status=required") == std::string::npos);

    CHECK(online::RenewLobby() == 7);   // not hosting yet
    CHECK(online::UpdateLobby("?create=1?private=0?open=1?map=0?enemy=0?difficulty=1?players=1?max=4?port=3659") == 0);
    // The heartbeat thread registers it.
    std::string st; int reach = -1;
    for (int t = 0; t < 5000; t += 100) { st = online::LobbyStatus(reach); if (st.find("?code=") == 0 && st.find("?code=?") != 0) break; Sleep(100); }
    printf("     status %s\n", st.c_str());
    CHECK(st.find("?code=") == 0 && st.find("?code=?") != 0);

    // Lobby codes: six characters, hex from the current
    // server, letters and digits from the one before (also run against it); a
    // search with ?code= ends as JOIN at the lobby, typed in any case, private
    // or public.
    std::string code = st.substr(6, st.find('?', 1) - 6);
    printf("     code %s\n", code.c_str());
    CHECK(code.size() == 6 && code.find_first_not_of("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") == std::string::npos);
    std::string lower = code;
    for (auto& c : lower) c = (char)tolower((unsigned char)c);
    CHECK(online::StartSearch("?code=" + lower) == 0);
    int co = WaitOutcome(8000);
    printf("     code outcome %d %s\n", co, online::SearchText().c_str());
    CHECK(co == online::JOIN);
    CHECK(online::SearchText().find("?address=") == 0);
    CHECK(online::StartSearch(std::string("?code=") + (code == "000000" ? "000001" : "000000")) == 0);
    co = WaitOutcome(8000);
    printf("     wrong code %d %s\n", co, online::SearchText().c_str());
    CHECK(co == online::FAILED && online::SearchText() == "?message=No lobby has that code.");
    CHECK(online::StartSearch("?code=XYZ") == 1);
    CHECK(online::StartSearch("?code=AB-123") == 1);
    CHECK(online::UpdateLobby("?private=1") == 0);
    Sleep(1500);
    CHECK(online::StartSearch("?code=" + code) == 0);
    co = WaitOutcome(8000);
    CHECK(co == online::JOIN);
    CHECK(online::UpdateLobby("?private=0") == 0);
    Sleep(1500);

    // Online statistics: the first call starts the fetch, a later one has it.
    std::string stats = online::StatsText();
    for (int t = 0; t < 5000 && (stats.empty() || stats.find("?players=") != 0); t += 100) { Sleep(100); stats = online::StatsText(); }
    printf("     stats %s\n", stats.c_str());
    CHECK(stats.find("?players=") == 0 && stats.find("?lobbies=") != std::string::npos);
    // Filtered: "any" finds the one lobby, map 4 does not (the lobby is map 0).
    online::SetStatsFilter("?map=0?enemy=127?difficulty=127");
    stats = online::StatsText();
    for (int t = 0; t < 5000 && stats.find("?mlobbies=") == std::string::npos; t += 100) { Sleep(100); stats = online::StatsText(); }
    printf("     stats (any) %s\n", stats.c_str());
    CHECK(stats.find("?mlobbies=1?mplayers=1") != std::string::npos);
    online::SetStatsFilter("?map=4?enemy=127?difficulty=127");
    stats = online::StatsText();
    for (int t = 0; t < 5000 && stats.find("?mlobbies=") == std::string::npos; t += 100) { Sleep(100); stats = online::StatsText(); }
    printf("     stats (map 4) %s\n", stats.c_str());
    CHECK(stats.find("?mlobbies=0?mplayers=0") != std::string::npos);
    online::SetStatsFilter("");

    // Join-in-progress: the match sends only what it knows (open, 2012's game
    // status, players); the lobby's privacy/port/size are merged from before.
    // The lobby is now a game, still matched: the search below JOINs it.
    CHECK(online::UpdateLobby("?open=1?state=4?players=2") == 0);
    Sleep(1500);   // the heartbeat thread PUTs a changed body within 0.5 s
    online::SetStatsFilter("?map=0?enemy=127?difficulty=127");
    stats = online::StatsText();
    for (int t = 0; t < 8000 && stats.find("?mgames=") == std::string::npos; t += 100) { Sleep(100); stats = online::StatsText(); }
    printf("     stats (in a match) %s\n", stats.c_str());
    CHECK(stats.find("?lobbies=0?games=1") != std::string::npos);
    CHECK(stats.find("?mlobbies=0?mplayers=2?mgames=1") != std::string::npos);
    online::SetStatsFilter("");

    CHECK(online::StartSearch("?map=0?enemy=0?difficulty=-1") == 0);
    int o = WaitOutcome(8000);
    std::string text = online::SearchText();
    printf("     outcome %d %s\n", o, text.c_str());
    CHECK(o == online::JOIN);
    // Direct (the lobby's port), or through the punched proxy (lemp_punch.h,
    // test_lemp_nat.cpp): the host here runs its proxy too.
    CHECK(text.find("?address=") == 0 && (text.find(":3659?lobby=") != std::string::npos || text.find("?address=127.0.0.1:") == 0));

    CHECK(online::ReportJoinFailed() == 0);
    Sleep(1500);
    // The next heartbeat hears of it.
    online::UpdateLobby("?private=0?open=1?map=0?enemy=0?difficulty=1?players=3?max=4?port=3659");   // changed: PUT at once
    for (int t = 0; t < 5000; t += 100) { online::LobbyStatus(reach); if (reach == 0) break; Sleep(100); }
    CHECK(reach == 0);

    // The only lobby is skipped now: after ~5 s this searcher is told CREATE.
    CHECK(online::StartSearch("?map=4?enemy=2?difficulty=1") == 0);
    o = WaitOutcome(12000);
    text = online::SearchText();
    printf("     outcome %d %s\n", o, text.c_str());
    CHECK(o == online::CREATE);
    CHECK(text == "?map=4?enemy=2?difficulty=1");

    // Cancel: the outcome goes back to none.
    CHECK(online::StartSearch("") == 0);
    Sleep(300);
    online::CancelSearch();
    CHECK(online::PollSearch() == -1);

    CHECK(online::DestroyLobby() == 0);
    Sleep(1500);
    CHECK(online::RenewLobby() == 7);

    // The leaderboards: a new player file is made, the values reported, and
    // the window around the player read back with its row in it. The player
    // file goes in the given dir (a test one, never a real Save\ME3).
    std::wstring pf = dir + L"\\LEMP_player.txt";
    DeleteFileW(pf.c_str());
    online::SetPlayerFile(pf);
    char name[64]; snprintf(name, sizeof name, "wine %lu", GetTickCount());
    char rep[128]; snprintf(rep, sizeof rep, "?name=%s?n7=%d?cp=%d", name, 4242, 17);
    CHECK(online::ReportStats(rep) == 0);
    Sleep(2000);
    CHECK(GetFileAttributesW(pf.c_str()) != INVALID_FILE_ATTRIBUTES);
    CHECK(online::StartBoard("?board=n7?center=1?count=7") == 0);
    std::string lb;
    for (int t = 0; t < 5000 && (lb = online::BoardText()).empty(); t += 100) Sleep(100);
    printf("     board %s\n", lb.c_str());
    CHECK(lb.find("?total=") == 0 && lb.find("?rank=-1") == std::string::npos);
    CHECK(lb.find(std::string("\t") + name + "\t4242") != std::string::npos);
    CHECK(online::StartBoard("?board=cp?start=1?count=3") == 0);
    for (int t = 0; t < 5000 && (lb = online::BoardText()).empty(); t += 100) Sleep(100);
    CHECK(lb.find("?total=") == 0 && lb.find("?top=1") != std::string::npos);
    CHECK(online::StartBoard("?board=zz") == 3);
    printf(fails ? "%d FAILED\n" : "all passed\n", fails);
    return fails != 0;
}
