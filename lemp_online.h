// lemp_online.h — mp_save.asi's side of matchmaking: the master server's
// client (the server is a Cloudflare Worker).
//
// 2012's lobby called EA's Blaze client (SFXOnlineComponentBlazeGame:
// QuickMatch, CreateOnlineGame, UpdateOnlineGame, AllowMatchmaking,
// CancelFindOnlineGames), which answered through delegates. LE3's Blaze client
// is gutted. Our lobby (the DLC's
// SFXGameInfoMP_Lobby) keeps 2012's flow and calls these ops instead,
// through SFXMPLocalSave.AsiCall like the save ops.
//
// Script's calls come on the game thread, inside SaveConfig, and must never
// wait on the network. So an op only reads or changes the state below; two
// threads of ours do the HTTP: one per search, and one for the hosted lobby's
// heartbeat. Script polls for the search's outcome (op 21) from a timer, as
// 2012's delegate would have fired.
//
// The server's address: the first line of Documents\BioWare\Mass Effect
// Legendary Edition\LEMP\server.txt, else kDefaultServer (the deployed
// Worker). A missing server.txt is written with kDefaultServer so players can
// find the setting and edit it; an existing one is never rewritten.
//
// NAT traversal (lemp_punch.h): a hosted lobby also
// registers its proxy's public endpoint and holds a WebSocket to the server
// (SignalThread), on which it hears "a joiner is punching from here". A JOIN
// that carries a token is punched before script hears of it, and script is
// sent to the local proxy (127.0.0.1:<port>) instead of the host's address —
// script itself does not change. If punching fails, the direct address
// stands (a forwarded or mapped port still works, as before). Where the
// router speaks UPnP-IGD, each proxy's port is also mapped (lemp_upnp.h) and
// the mapped endpoint is preferred: reachable from any NAT.
//
// Host migration: a hosted lobby also
// registers a migration key, which script hands to the players in its match
// (op 43/44, SFXPlayerControllerMP). When the host goes, a search with
// ?migrate= (Migrate below) either takes the lobby over, and this player
// hosts it, or waits for whoever did and joins it. 2012's Blaze did this.
#pragma once
#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <string>
#include "online_format.h"
#include "lemp_punch.h"
#include "lemp_upnp.h"

namespace online {

static const char* kDefaultServer = "https://lemp-master.me-legendary-mp.workers.dev";

// The LEMP release this lemp.asi was built for (build.sh, from VERSION). The
// DLC and lemp.asi ship as a pair: script hands over the DLC's release (op 39)
// and reads this one (ops 55/56). "" in a build without it (the tests): no check.
#ifndef LEMP_RELEASE
#define LEMP_RELEASE ""
#endif
static const char* kRelease = LEMP_RELEASE;

// 2012's SFXOnlineEvent_QuickMatch.SFXOnlineQuickMatchOutcome, as script's
// OnQuickMatchComplete takes it.
enum Outcome { IN_PROGRESS = 0, CREATE = 1, JOIN = 2, SEARCH_TIMEOUT = 3, FAILED = 4 };

typedef void (*LogFn)(const char* fmt, ...);

struct Rules { long long map = 0, enemy = 0, difficulty = -1; };

struct State {
    CRITICAL_SECTION cs;
    LogFn log = nullptr;
    ServerUrl server;
    bool serverOk = false;
    std::string build;           // the join identity (build_key.h JoinOptions)
    std::string version;         // the mod's release, from script (op 39): X-LEMP-Version
    std::string dlcRelease;      // what op 39 said, also when it is not kRelease
    bool releaseMismatch = false;
    HANDLE buildReady = nullptr; // mp_save's key thread
    std::string (*getBuild)() = nullptr;
    HINTERNET session = nullptr;

    // The search. One at a time; a new one cancels the old.
    unsigned searchGen = 0;      // bumped per search; a thread whose gen is stale stops
    int outcome = -1;            // -1 none, else Outcome
    std::string resultText;      // op 22/23
    std::string ticket;          // the search's
    std::string joinLobby;       // the lobby a JOIN pointed at, for a failure report
    unsigned punchJoin = 0;      // the JOIN's proxy (lemp_punch.h), 0 none
    std::string createTicket;    // a CREATE's, handed to the lobby it creates
    Rules rules;

    // The hosted lobby.
    bool hosting = false;
    bool dirty = false;
    bool destroy = false;
    std::string lobbyId, lobbySecret, lobbyCode, lobbyJson, lobbyTicket;
    std::string migrationKey;    // given to the lobby's players: lets one of them take it over
    std::map<std::string, std::string> lobbyOpts;   // the options last sent, merged into (26)
    DWORD leaseAt = 0, lastPut = 0;
    DWORD leaseExtraMs = 0;      // a migration's new host: its map loads before script renews
    int reachable = -1;          // -1 unknown, 1, 0 (a join failed to reach it)
    HANDLE hostThread = nullptr;
    std::string punchSent;       // the proxy fields the server last heard (WithPunch)
    std::string menuSession;     // Session(): this launch, on the Multiplayer page's count
};
static State g;

static void Log(const char* fmt, const char* a = "", const char* b = "") {
    if (g.log) g.log(fmt, a, b);
}

// ---- HTTP ----------------------------------------------------------------

static std::wstring Widen(const std::string& s) { return std::wstring(s.begin(), s.end()); }

// One request; false on a transport failure (no answer at all).
static bool Http(const wchar_t* method, const std::string& path, const std::string& body,
                 const std::string& bearer, int& status, std::string& resp) {
    status = 0;
    resp.clear();
    if (!g.serverOk || !g.session) return false;
    HINTERNET c = WinHttpConnect(g.session, Widen(g.server.host).c_str(), (INTERNET_PORT)g.server.port, 0);
    if (!c) return false;
    HINTERNET r = WinHttpOpenRequest(c, method, Widen(g.server.base + path).c_str(), nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, g.server.https ? WINHTTP_FLAG_SECURE : 0);
    bool ok = false;
    if (r) {
        std::wstring headers = L"Content-Type: application/json\r\n";
        if (!bearer.empty()) headers += L"Authorization: Bearer " + Widen(bearer) + L"\r\n";
        EnterCriticalSection(&g.cs);
        std::string version = g.version;
        LeaveCriticalSection(&g.cs);
        if (!version.empty()) headers += L"X-LEMP-Version: " + Widen(version) + L"\r\n";
        if (WinHttpSendRequest(r, headers.c_str(), (DWORD)-1L, (LPVOID)(body.empty() ? nullptr : body.data()),
                               (DWORD)body.size(), (DWORD)body.size(), 0)
            && WinHttpReceiveResponse(r, nullptr)) {
            DWORD code = 0, len = sizeof(code);
            WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                                &code, &len, WINHTTP_NO_HEADER_INDEX);
            status = (int)code;
            for (;;) {
                DWORD avail = 0;
                if (!WinHttpQueryDataAvailable(r, &avail) || avail == 0) break;
                if (resp.size() + avail > 65536) break;   // the server sends a few hundred bytes
                std::string chunk(avail, '\0');
                DWORD got = 0;
                if (!WinHttpReadData(r, &chunk[0], avail, &got) || got == 0) break;
                resp.append(chunk.data(), got);
            }
            ok = true;
        }
        WinHttpCloseHandle(r);
    }
    WinHttpCloseHandle(c);
    return ok;
}

static bool HttpJson(const wchar_t* method, const std::string& path, const std::string& body,
                     const std::string& bearer, int& status, JsonFields& f) {
    std::string resp;
    if (!Http(method, path, body, bearer, status, resp)) return false;
    ParseJsonObject(resp, f);
    return true;
}

// ---- helpers -----------------------------------------------------------------

static std::string RandomHex(int bytes) {
    unsigned char b[32] = {0};
    if (bytes > 32) bytes = 32;
    if (BCryptGenRandom(nullptr, b, (ULONG)bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        // Not expected; still unique enough to key a lobby for a session.
        LARGE_INTEGER t; QueryPerformanceCounter(&t);
        for (int i = 0; i < bytes; i++) b[i] = (unsigned char)(t.QuadPart >> ((i % 8) * 8)) ^ (unsigned char)(GetCurrentProcessId() >> (i % 4));
    }
    static const char* hex = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < bytes; i++) { s += hex[b[i] >> 4]; s += hex[b[i] & 15]; }
    return s;
}

// The Multiplayer page's player count includes those idle on it — sitting
// in the idle menu, and shown once they click Matchmaking (server
// Matchmaker.idle). Only
// from the page Matchmaking opens: StatsThread sends it while that page's
// op 34 is fresh (g_statsPageAt), not from the entry dialog before it. The page
// refreshes the statistics once per statsMs anyway; the refresh carries a
// random id made once per launch, which says nothing of the player (not the
// leaderboard's id). A search, a code join and the hosted lobby carry it too,
// so the server stops counting it as idle the moment the ticket or the lobby
// counts it instead. Under g.cs.
static const std::string& Session() {
    if (g.menuSession.empty()) g.menuSession = RandomHex(16);
    return g.menuSession;
}

// This machine's address on its LAN: the source address the OS would use to
// reach the internet (a UDP "connect" sends nothing). Handed to the server so
// a joiner behind the same router gets it instead of the shared public one,
// which many routers do not loop back.
static std::string LanAddress() {
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return "";
    std::string out;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s != INVALID_SOCKET) {
        sockaddr_in to = {};
        to.sin_family = AF_INET;
        to.sin_port = htons(53);
        inet_pton(AF_INET, "192.0.2.1", &to.sin_addr);   // TEST-NET-1: routed, never answered
        sockaddr_in me = {};
        int len = sizeof(me);
        if (connect(s, (sockaddr*)&to, sizeof(to)) == 0 && getsockname(s, (sockaddr*)&me, &len) == 0) {
            char buf[INET_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET, &me.sin_addr, buf, sizeof buf) && strcmp(buf, "0.0.0.0") != 0) out = buf;
        }
        closesocket(s);
    }
    WSACleanup();
    return out;
}

static std::string g_lan;
static std::string Lan() {
    if (g_lan.empty()) g_lan = LanAddress();   // once; a UDP socket, no traffic
    return g_lan;
}

static std::string Build() {
    if (g.buildReady) WaitForSingleObject(g.buildReady, 60000);
    return g.getBuild ? g.getBuild() : "";
}

// ---- hole punching: the joiner (lemp_punch.h) ---------------------------------------

static bool SearchCurrent(unsigned gen);

// Punches to the host's proxy and returns where the game should connect
// ("127.0.0.1:<port>"), or "" when it did not connect: the direct address
// then stands. On the search thread; gives up when the search is cancelled.
static std::string PunchToHost(const std::string& lobby, const std::string& token, const std::string& target, unsigned gen) {
    unsigned id = punch::JoinStart(token, target);
    if (!id) return "";
    upnp::Want(upnp::JOIN, (uint16_t)punch::GetJoinInfo(id).pubPort);   // dropped when the socket closes
    EnterCriticalSection(&g.cs);
    g.punchJoin = id;
    LeaveCriticalSection(&g.cs);
    // Our proxy's endpoint as STUN sees it: the host punches back to it.
    punch::JoinInfo j;
    for (int t = 0; t < 4000; t += 50) {
        j = punch::GetJoinInfo(id);
        if (j.stunDone || j.state != punch::JOIN_PUNCHING) break;
        Sleep(50);
    }
    // And its UPnP mapping, if the router makes one in time: the host can then
    // reach us even when our NAT maps per destination.
    std::string alt;
    if (upnp::Usable()) {
        for (int t = 0; t < 1500 && alt.empty(); t += 50) {
            alt = punch::EpStr(upnp::Mapped(upnp::JOIN));
            if (alt.empty()) Sleep(50);
        }
    }
    std::string lan = Lan().empty() ? "" : Lan() + ":" + std::to_string(j.pubPort);
    std::string body = JsonObject().Str("token", token).Str("endpoint", j.mapped).Str("lan", lan).Str("alt", alt).Done();
    bool told = false;
    DWORD askAt = 0;
    int asks = 0;
    for (;;) {
        j = punch::GetJoinInfo(id);
        if (j.state != punch::JOIN_PUNCHING || !SearchCurrent(gen)) break;
        // The host is told through the server. Asked again while it has no
        // signal socket (reconnecting), a few times; the token is good for a minute.
        if (!told && asks < 4 && GetTickCount() - askAt >= 2000) {
            askAt = GetTickCount();
            asks++;
            int status = 0;
            JsonFields f;
            bool answered = HttpJson(L"POST", "/v1/lobbies/" + lobby + "/punch", body, "", status, f);
            told = answered && status == 200 && f.Int("signalled", 0) > 0;
            if (asks == 1 || told)
                Log("online: punch: %s (we are %s)", told ? "the host was told" : answered ? ("not told: HTTP " + std::to_string(status) + (status == 200 ? ", no signal socket" : "")).c_str() : "no answer",
                    j.mapped.empty() ? "unknown to STUN" : j.mapped.c_str());
        }
        Sleep(50);
    }
    if (j.state == punch::JOIN_CONNECTED && SearchCurrent(gen)) {
        Log("online: punch: connected; the game goes through 127.0.0.1:%s", std::to_string(j.loopPort).c_str());
        return "127.0.0.1:" + std::to_string(j.loopPort);
    }
    punch::JoinStop(id);
    if (SearchCurrent(gen)) Log("online: punch: no connection to the host's proxy; trying its address directly");
    return "";
}

// ---- the search ----------------------------------------------------------------

// A host migration (op 20 with ?migrate=): the lobby the host left, its key
// (op 43 on the old host, handed over in the game), this player's place in
// the order of who claims it (0 first), and the options its new lobby gets.
struct Migration { std::string lobby, key; long long rank = 0; std::map<std::string, std::string> opts; };
struct SearchArgs { unsigned gen; Rules rules; std::string code; Migration mig; };

static bool SearchCurrent(unsigned gen) {
    EnterCriticalSection(&g.cs);
    bool cur = g.searchGen == gen;
    LeaveCriticalSection(&g.cs);
    return cur;
}

// ---- host migration ----------------------------

// The player ranked r claims the lobby r * kClaimStepMs after its host went,
// if no one before it has (the server's claimMigration); until
// then, and after losing a claim, it asks /rejoin for whoever did.
static const DWORD kClaimStepMs = 15000;
// All of it: a host the server still hears from is not replaced for 45 s
// (hostAliveMs), and the new host then loads the match map.
static const DWORD kMigrationTimeoutMs = 150000;
// The new host's lease before script renews it from the new map (kLeaseMs is
// counted from the claim, and a map load can take most of a minute).
static const DWORD kMigrationLeaseExtraMs = 120000;

static DWORD WINAPI HostThread(LPVOID);
static std::string LobbyBody(const std::map<std::string, std::string>& m, const std::string& lan, const std::string& build);

// Becomes the host of the lobby just claimed: what UpdateLobby's ?create=1
// sets up, under the claimed id and the server's code.
static void HostClaimed(const std::string& id, const std::string& secret, const std::string& key, const std::string& code,
                        const std::map<std::string, std::string>& opts, const std::string& build) {
    std::string lan = Lan();
    EnterCriticalSection(&g.cs);
    g.lobbyId = id;
    g.lobbySecret = secret;
    g.migrationKey = key;
    g.lobbyCode = code;
    g.lobbyTicket.clear();
    g.hosting = true;
    g.destroy = false;
    g.reachable = -1;
    g.lobbyOpts = opts;
    g.lobbyJson = LobbyBody(opts, lan, build);
    g.punchSent.clear();
    g.dirty = false;                 // the claim registered it; the heartbeat follows
    g.lastPut = GetTickCount();
    g.leaseAt = GetTickCount();
    g.leaseExtraMs = kMigrationLeaseExtraMs;
    if (!g.hostThread) g.hostThread = CreateThread(nullptr, 0, HostThread, nullptr, 0, nullptr);
    LeaveCriticalSection(&g.cs);
    punch::HostStart((int)OptInt(opts, "port", 3659));
    upnp::Want(upnp::HOST, (uint16_t)punch::GetHostInfo().localPort);
}

// Outcome CREATE: this player claimed the lobby and hosts it now ("?code=");
// script loads the match as a listen server with ?HostMigration. JOIN: another
// player did, and its map is up ("?address=?lobby=", punched like a search's
// JOIN). FAILED with a message otherwise.
//
// While it runs, the search text says how it stands (script reads it,
// SFXPlayerControllerMP.LEMPPollMigration): "?phase=alive" while the server
// still hears from the old host, "?phase=changing" once it does not. A player
// that went quiet on its own keeps playing through "alive" and, should the host
// be heard again, cancels this.
static void MigrationPhase(unsigned gen, const char* phase) {
    EnterCriticalSection(&g.cs);
    if (g.searchGen == gen && g.outcome == IN_PROGRESS) g.resultText = std::string("?phase=") + phase;
    LeaveCriticalSection(&g.cs);
}
// The old host's proxy (a punched JOIN): closed once the old host is out of
// the picture, and not before. A fixed mistake: it was closed as the
// migration began, so a player whose watch fired while the host was only
// stalled lost a working connection: the host's log has its BYE ("joiner …
// left") 10 s into the stall.
static void DropOldHost(unsigned pj) {
    if (!pj) return;
    EnterCriticalSection(&g.cs);
    if (g.punchJoin == pj) g.punchJoin = 0;
    LeaveCriticalSection(&g.cs);
    punch::JoinStop(pj);   // a no-op once another join replaced it
}
static int Migrate(const SearchArgs& a, const std::string& build, std::string& text, unsigned oldJoin) {
    const Migration& mg = a.mig;
    std::string id = RandomHex(16), secret = RandomHex(16), key = RandomHex(16);
    std::map<std::string, std::string> opts = mg.opts;
    opts["ready"] = "0";
    opts["open"] = "0";
    EnterCriticalSection(&g.cs);
    std::string saveKey = g.migrationKey;
    g.migrationKey = key;            // LobbyBody reads it
    std::string claimBody = LobbyBody(opts, Lan(), build);
    g.migrationKey = saveKey;
    LeaveCriticalSection(&g.cs);
    claimBody = claimBody.substr(0, claimBody.size() - 1) + ",\"key\":" + JsonString(mg.key) + ",\"id\":" + JsonString(id)
              + ",\"secret\":" + JsonString(secret) + "}";
    std::string rejoinBody = JsonObject().Str("key", mg.key).Str("build", build).Done();

    DWORD start = GetTickCount();
    DWORD claimFrom = (DWORD)(mg.rank < 0 ? 0 : mg.rank > 3 ? 3 : mg.rank) * kClaimStepMs;
    DWORD nextClaim = 0;
    bool claimed = false;            // someone else has it: only rejoin
    DWORD unknownSince = 0;
    int failures = 0;
    Log("online: migration: the host of lobby %s is gone; this player is %s", mg.lobby.c_str(),
        mg.rank == 0 ? "first to take it over" : ("number " + std::to_string(mg.rank + 1) + " in line").c_str());
    for (;;) {
        if (!SearchCurrent(a.gen)) return FAILED;
        DWORD t = GetTickCount() - start;
        if (t > kMigrationTimeoutMs) {
            Log("online: migration: gave up after %s s", std::to_string(t / 1000).c_str());
            text = Opt("message", "The game could not change hosts.");
            return FAILED;
        }
        bool claimNow = !claimed && t >= claimFrom && t >= nextClaim;
        int status = 0;
        JsonFields f;
        bool answered = claimNow
            ? HttpJson(L"POST", "/v1/lobbies/" + mg.lobby + "/migrate", claimBody, "", status, f)
            : HttpJson(L"POST", "/v1/lobbies/" + mg.lobby + "/rejoin", rejoinBody, "", status, f);
        if (!answered || status >= 500) {
            if (++failures >= 10) {
                text = Opt("message", "The LEMP server " + g.server.host + " does not answer.");
                return FAILED;
            }
            Sleep(1000);
            continue;
        }
        failures = 0;
        if (status == 429) {
            long long ms = f.Int("retryMs", 2000);
            Sleep((DWORD)(ms < 500 ? 500 : ms > 10000 ? 10000 : ms));
            continue;
        }
        if (status == 426) {
            Log("online: migration refused: %s", f.Str("message").c_str());
            text = Opt("message", f.Str("message"));
            return FAILED;
        }
        if (status == 404) {
            // The server does not know the lobby or the key: a host from
            // before migration, or the departure already over. Given a few
            // seconds, in case the host's own DELETE is still on its way.
            if (!unknownSince) unknownSince = GetTickCount();
            MigrationPhase(a.gen, "changing");
            if (GetTickCount() - unknownSince > 10000) {
                Log("online: migration: the server has no lobby %s to take over", mg.lobby.c_str());
                text = Opt("message", "The host left, and the game cannot change hosts.");
                return FAILED;
            }
            if (claimNow) nextClaim = t + 1000;
            Sleep(1000);
            continue;
        }
        unknownSince = 0;
        if (claimNow) {
            if (status == 200 && !f.Str("code").empty()) {
                // Hosting a lobby of its own (UpdateLobby ?create=1) cancels
                // this; a claim answered after that must not take its
                // registration over. The claimed lobby lapses unrenewed.
                if (!SearchCurrent(a.gen)) {
                    Log("online: migration: lobby %s claimed after this player moved on; not hosting it", mg.lobby.c_str());
                    return FAILED;
                }
                DropOldHost(oldJoin);
                HostClaimed(id, secret, key, f.Str("code"), opts, build);
                Log("online: migration: this player hosts lobby %s now (code %s)", id.c_str(), f.Str("code").c_str());
                text = Opt("code", f.Str("code"));
                return CREATE;
            }
            std::string err = f.Str("error");
            if (status == 409 && err == "claimed") {
                Log("online: migration: another player took the lobby over; joining it");
                MigrationPhase(a.gen, "changing");
                claimed = true;
                continue;
            }
            if (status == 409 && err == "alive") {
                // The server still hears from the host: it may be leaving (its
                // DELETE comes in a moment), only this player's connection
                // broke, or the host's game stalled. Asked again; rejoin meanwhile.
                if (nextClaim == 0) Log("online: migration: the server still hears from the host; waiting");
                MigrationPhase(a.gen, "alive");
                nextClaim = t + 2000;
                continue;
            }
            Log("online: migration: claim refused (HTTP %s %s)", std::to_string(status).c_str(), err.c_str());
            text = Opt("message", "The game could not change hosts.");
            return FAILED;
        }
        // Rejoin.
        if (status == 200 && f.Bool("waiting", false)) {
            // A server from before "alive" (0.3.27's) never says it: changing.
            MigrationPhase(a.gen, f.Bool("alive", false) ? "alive" : "changing");
            long long ms = f.Int("retryMs", 2000);
            Sleep((DWORD)(ms < 500 ? 500 : ms > 5000 ? 5000 : ms));
            continue;
        }
        if (status == 200 && f.Has("address")) {
            std::string address = f.Str("address") + ":" + std::to_string(f.Int("port", 3659));
            DropOldHost(oldJoin);
            if (!f.Str("token").empty() && !f.Str("punch").empty()) {
                std::string via = PunchToHost(f.Str("lobby"), f.Str("token"), f.Str("punch"), a.gen);
                if (!SearchCurrent(a.gen)) return FAILED;
                if (!via.empty()) address = via;
            }
            Log("online: migration: the new host of lobby %s is up; joining", f.Str("lobby").c_str());
            EnterCriticalSection(&g.cs);
            if (g.searchGen == a.gen) g.joinLobby = f.Str("lobby");
            LeaveCriticalSection(&g.cs);
            text = Opt("address", address) + Opt("lobby", f.Str("lobby"));
            return JOIN;
        }
        Log("online: migration: rejoin refused (HTTP %s %s)", std::to_string(status).c_str(), f.Str("error").c_str());
        text = Opt("message", f.Str("error") == "build" ? "The new host runs another LEMP build." : "The game could not change hosts.");
        return FAILED;
    }
}

static DWORD WINAPI SearchThread(LPVOID p) {
    SearchArgs a = *(SearchArgs*)p;
    delete (SearchArgs*)p;
    std::string build = Build();
    if (!a.mig.lobby.empty()) {
        std::string text = build.empty() ? Opt("message", "this install has no build identity (debug log)") : "";
        EnterCriticalSection(&g.cs);
        unsigned oldJoin = g.punchJoin;
        LeaveCriticalSection(&g.cs);
        int outcome = build.empty() ? FAILED : Migrate(a, build, text, oldJoin);
        EnterCriticalSection(&g.cs);
        bool cur = g.searchGen == a.gen;
        if (cur) { g.outcome = outcome; g.resultText = text; g.ticket.clear(); }
        LeaveCriticalSection(&g.cs);
        // Given up for real: the host-left message follows, and the old host's
        // proxy goes. Cancelled (the host came back): it stays.
        if (cur && outcome == FAILED) DropOldHost(oldJoin);
        return 0;
    }
    std::string ticket;
    int failures = 0;
    int outcome = FAILED;
    std::string text;
    EnterCriticalSection(&g.cs);
    std::string session = Session();
    LeaveCriticalSection(&g.cs);
    if (build.empty()) {
        text = Opt("message", "this install has no build identity (debug log)");
    } else {
        for (;;) {
            if (!SearchCurrent(a.gen)) break;
            int status = 0;
            JsonFields f;
            bool answered;
            if (!a.code.empty()) {
                // A lobby code: one lookup, answered
                // as a JOIN is; no ticket, nothing to poll.
                answered = HttpJson(L"POST", "/v1/code/" + a.code, JsonObject().Str("build", build).Str("session", session).Done(), "", status, f);
                if (answered && (status == 404 || status == 409 || status == 403)) {
                    Log("online: code %s: %s", a.code.c_str(), f.Str("error").c_str());
                    text = Opt("message", f.Str("message").empty() ? "No lobby has that code." : f.Str("message"));
                    outcome = FAILED;
                    break;
                }
                if (answered && status == 200 && f.Has("address")) f.v["outcome"] = std::to_string(JOIN);
            } else {
                JsonObject rules;
                rules.Int("map", a.rules.map).Int("enemy", a.rules.enemy).Int("difficulty", a.rules.difficulty);
                JsonObject body;
                if (!ticket.empty()) body.Str("ticket", ticket);
                body.Str("build", build).Raw("rules", rules.Done()).Bool("canHost", true).Str("session", session);
                answered = HttpJson(L"POST", "/v1/quickmatch", body.Done(), "", status, f);
            }
            if (answered && status == 429) {   // the server's rate limit: wait as told, not a failure
                long long ms = f.Int("retryMs", 2000);
                Sleep((DWORD)(ms < 500 ? 500 : ms > 30000 ? 30000 : ms));
                continue;
            }
            if (answered && status == 426) {   // below the release the server requires
                Log("online: search refused: %s", f.Str("message").c_str());
                text = Opt("message", f.Str("message"));
                outcome = FAILED;
                break;
            }
            if (!answered || status != 200 || !f.Has("outcome")) {
                if (++failures >= 3) {
                    Log("online: search: the MP server does not answer (%s)", status ? ("HTTP " + std::to_string(status)).c_str() : "no connection");
                    text = Opt("message", "The LEMP server " + g.server.host + ":" + std::to_string(g.server.port) + " does not answer.");
                    outcome = FAILED;
                    break;
                }
                Sleep(1000);
                continue;
            }
            failures = 0;
            ticket = f.Str("ticket");
            int o = (int)f.Int("outcome", FAILED);
            if (o == IN_PROGRESS) {
                long long ms = f.Int("retryMs", 1000);
                Sleep((DWORD)(ms < 250 ? 250 : ms > 30000 ? 30000 : ms));   // the server stretches it under load
                continue;
            }
            outcome = o;
            if (o == JOIN) {
                std::string direct = f.Str("address") + ":" + std::to_string(f.Int("port", 3659));
                std::string address = direct;
                if (!f.Str("token").empty() && !f.Str("punch").empty()) {
                    std::string via = PunchToHost(f.Str("lobby"), f.Str("token"), f.Str("punch"), a.gen);
                    if (!SearchCurrent(a.gen)) break;
                    if (!via.empty()) address = via;
                }
                text = Opt("address", address) + Opt("lobby", f.Str("lobby"));
            } else if (o == CREATE) {
                text = Opt("map", f.Int("map", 0)) + Opt("enemy", f.Int("enemy", 0)) + Opt("difficulty", f.Int("difficulty", 0));
            } else {
                text = Opt("message", f.Str("message"));
            }
            Log("online: search: outcome %s %s", std::to_string(o).c_str(), text.c_str());
            EnterCriticalSection(&g.cs);
            if (g.searchGen == a.gen) {
                g.ticket = ticket;
                if (o == JOIN) g.joinLobby = f.Str("lobby");
                if (o == CREATE) g.createTicket = ticket;
            }
            LeaveCriticalSection(&g.cs);
            break;
        }
    }
    EnterCriticalSection(&g.cs);
    bool cur = g.searchGen == a.gen;
    if (cur) { g.outcome = outcome; g.resultText = text; }
    LeaveCriticalSection(&g.cs);
    if (!cur && !ticket.empty()) {
        int status = 0; std::string resp;
        Http(L"DELETE", "/v1/quickmatch/" + ticket, "", "", status, resp);
        Log("online: search cancelled (ticket %s, HTTP %s)", ticket.c_str(), std::to_string(status).c_str());
    }
    return 0;
}

// ---- the hosted lobby --------------------------------------------------------------

// How long the lobby stays registered with no word from script. Script renews
// it every 10 s from SFXGameInfoMP (lobby and match alike, on the listen
// server); leaving multiplayer stops that, and the ASI unregisters.
static const DWORD kLeaseMs = 60000;
// The heartbeat interval is the server's (heartbeatMs in each answer: 30 s,
// stretched when the server's daily request budget runs short).
static DWORD g_heartbeatMs = 30000;

// The lobby's body plus what the server needs for hole punching: the proxy's
// endpoint as STUN saw it, its local port (for joiners behind the same NAT)
// and the NAT's mapping behaviour. Nothing when the proxy is not up.
// A UPnP mapping, when there is one, is the endpoint given out: open to every
// NAT, where the STUN one is open only to those the proxy has sent to.
static std::string PunchFields(const punch::HostInfo& h) {
    if (!h.on) return "";
    std::string mapped = punch::EpStr(upnp::Mapped(upnp::HOST));
    if (mapped.empty()) mapped = h.mapped;
    std::string extra = ",\"punchPort\":" + std::to_string(h.localPort);
    if (!mapped.empty()) extra += ",\"punch\":" + JsonString(mapped);
    if (!h.nat.empty()) extra += ",\"nat\":" + JsonString(h.nat);
    return extra;
}
static std::string WithPunch(const std::string& body, const punch::HostInfo& h) {
    if (!h.on || body.size() < 2 || body.back() != '}') return body;
    std::string extra = PunchFields(h);
    return body.substr(0, body.size() - 1) + extra + "}";
}

// The lobby's PUT carries the session (Session): its host is off the
// Multiplayer page's idle count. Under g.cs.
static std::string WithSession(const std::string& body) {
    if (body.size() < 2 || body.back() != '}') return body;
    return body.substr(0, body.size() - 1) + "," + JsonString("session") + ":" + JsonString(Session()) + "}";
}

// ---- the signal socket (hole punching: the host) ------------------------------------

// A WebSocket to GET /v1/lobbies/:id/signal while a lobby is registered. The
// server pushes {"type":"punch","token":..,"targets":"ip:port[,..]"} when a
// joiner starts punching; the proxy then punches back (punch::HostExpect).
// It hibernates on the server: idle, it costs nothing there. Kept alive by a
// "ping" every g_wsPingMs from the host thread (the server answers "pong"
// without waking); WinHTTP allows one send beside one pending receive.
static DWORD g_wsPingMs = 30000;
static CRITICAL_SECTION g_wsCs;     // g_ws: set/cleared by SignalThread, used by the ping
static HINTERNET g_ws = nullptr;
static DWORD g_wsPingAt = 0;

static void SignalPing() {
    EnterCriticalSection(&g_wsCs);
    if (g_ws && GetTickCount() - g_wsPingAt >= g_wsPingMs) {
        g_wsPingAt = GetTickCount();
        WinHttpWebSocketSend(g_ws, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE, (PVOID) "ping", 4);
    }
    LeaveCriticalSection(&g_wsCs);
}

static int g_wsPongs = 0;   // tests: the keep-alive works beside a pending receive

static void SignalMessage(const std::string& msg) {
    if (msg == "pong") { g_wsPongs++; return; }
    JsonFields f;
    ParseJsonObject(msg, f);
    if (f.Str("type") != "punch") return;
    std::vector<std::string> targets;
    std::string list = f.Str("targets");
    for (size_t at = 0; at < list.size();) {
        size_t c = list.find(',', at);
        if (c == std::string::npos) c = list.size();
        if (c > at) targets.push_back(list.substr(at, c - at));
        at = c + 1;
    }
    punch::HostExpect(f.Str("token"), targets);
}

static DWORD WINAPI SignalThread(LPVOID) {
    DWORD backoff = 2000;
    int lastBad = 0;
    for (;;) {
        EnterCriticalSection(&g.cs);
        bool ready = g.hosting && !g.lobbyCode.empty();   // registered: the server knows the lobby
        std::string id = g.lobbyId, secret = g.lobbySecret, version = g.version;
        LeaveCriticalSection(&g.cs);
        if (!ready) { Sleep(500); continue; }
        HINTERNET c = WinHttpConnect(g.session, Widen(g.server.host).c_str(), (INTERNET_PORT)g.server.port, 0);
        HINTERNET r = c ? WinHttpOpenRequest(c, L"GET", Widen(g.server.base + "/v1/lobbies/" + id + "/signal").c_str(), nullptr,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, g.server.https ? WINHTTP_FLAG_SECURE : 0)
                        : nullptr;
        HINTERNET ws = nullptr;
        DWORD status = 0;
        if (r && WinHttpSetOption(r, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) {
            std::wstring headers = L"Authorization: Bearer " + Widen(secret) + L"\r\n";
            if (!version.empty()) headers += L"X-LEMP-Version: " + Widen(version) + L"\r\n";
            if (WinHttpSendRequest(r, headers.c_str(), (DWORD)-1L, nullptr, 0, 0, 0) && WinHttpReceiveResponse(r, nullptr)) {
                DWORD len = sizeof(status);
                WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                                    &status, &len, WINHTTP_NO_HEADER_INDEX);
                if (status == 101) ws = WinHttpWebSocketCompleteUpgrade(r, 0);
            }
        }
        if (r) WinHttpCloseHandle(r);
        if (!ws) {
            int bad = status ? (int)status : -1;
            if (bad != lastBad) {
                Log("online: signal socket for lobby %s failed (%s); joiners behind NAT cannot reach this lobby until it connects",
                    id.c_str(), status ? ("HTTP " + std::to_string(status)).c_str() : "no connection");
                lastBad = bad;
            }
            if (c) WinHttpCloseHandle(c);
            Sleep(backoff);
            backoff = backoff * 2 > 60000 ? 60000 : backoff * 2;
            continue;
        }
        if (lastBad != 101) Log("online: signal socket for lobby %s open", id.c_str());
        lastBad = 101;
        backoff = 2000;
        EnterCriticalSection(&g_wsCs);
        g_ws = ws;
        g_wsPingAt = GetTickCount();
        LeaveCriticalSection(&g_wsCs);
        std::string msg;
        for (;;) {
            char buf[1024];
            DWORD got = 0;
            WINHTTP_WEB_SOCKET_BUFFER_TYPE type;
            if (WinHttpWebSocketReceive(ws, buf, sizeof buf, &got, &type) != ERROR_SUCCESS) break;
            if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) break;
            if (msg.size() + got > 8192) msg.clear();   // the server sends ~150 bytes
            msg.append(buf, got);
            if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE || type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE) {
                SignalMessage(msg);
                msg.clear();
            }
            EnterCriticalSection(&g.cs);
            bool same = g.hosting && g.lobbyId == id;
            LeaveCriticalSection(&g.cs);
            if (!same) break;   // the ping's pong brings us here within g_wsPingMs
        }
        EnterCriticalSection(&g_wsCs);
        g_ws = nullptr;
        LeaveCriticalSection(&g_wsCs);
        WinHttpWebSocketClose(ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
        WinHttpCloseHandle(ws);
        WinHttpCloseHandle(c);
        EnterCriticalSection(&g.cs);
        bool still = g.hosting && g.lobbyId == id;
        LeaveCriticalSection(&g.cs);
        if (still) { Log("online: signal socket for lobby %s closed; reconnecting", id.c_str()); Sleep(1000); }
    }
    return 0;
}

static DWORD WINAPI HostThread(LPVOID) {
    DWORD backoffUntil = 0;
    HANDLE st = CreateThread(nullptr, 0, SignalThread, nullptr, 0, nullptr);
    if (st) CloseHandle(st);
    for (;;) {
        Sleep(500);
        SignalPing();
        punch::HostInfo ph = punch::GetHostInfo();
        EnterCriticalSection(&g.cs);
        DWORD now = GetTickCount();
        bool hosting = g.hosting;
        bool lapsed = hosting && now - g.leaseAt > kLeaseMs + g.leaseExtraMs;
        bool doDelete = hosting && (g.destroy || lapsed);
        // The proxy's endpoint came in from STUN or UPnP, or moved: said at once.
        std::string fields = PunchFields(ph);
        bool punchNews = ph.on && fields != g.punchSent && (ph.stunDone || !ph.mapped.empty());
        bool doPut = hosting && !doDelete && (g.dirty || punchNews || now - g.lastPut >= g_heartbeatMs) && (int)(now - backoffUntil) >= 0;
        std::string id = g.lobbyId, secret = g.lobbySecret, body = WithSession(WithPunch(g.lobbyJson, ph));
        if (doDelete) { g.hosting = false; g.destroy = false; g.reachable = -1; }
        if (doPut) { g.dirty = false; g.lastPut = now; g.punchSent = fields; }
        LeaveCriticalSection(&g.cs);
        if (doDelete) {
            punch::HostStop();
            int status = 0; std::string resp;
            Http(L"DELETE", "/v1/lobbies/" + id, "", secret, status, resp);
            Log("online: lobby %s unregistered (%s)", id.c_str(), lapsed ? "no word from script for 60 s" : "asked");
        } else if (doPut) {
            int status = 0;
            JsonFields f;
            bool answered = HttpJson(L"PUT", "/v1/lobbies/" + id, body, secret, status, f);
            EnterCriticalSection(&g.cs);
            if (answered && status == 200) {
                long long hb = f.Int("heartbeatMs", 30000);
                g_heartbeatMs = (DWORD)(hb < 5000 ? 5000 : hb > 300000 ? 300000 : hb);
            }
            if (answered && status == 429 && g.lobbyId == id) {
                g.dirty = true;   // said again once the wait is over
                long long ms = f.Int("retryMs", 5000);
                backoffUntil = GetTickCount() + (DWORD)(ms < 1000 ? 1000 : ms > 60000 ? 60000 : ms);
            } else if (answered && status == 200 && g.lobbyId == id) {
                if (g.lobbyCode.empty()) Log("online: lobby %s registered, code %s", id.c_str(), f.Str("code").c_str());
                g.lobbyCode = f.Str("code");
                int was = g.reachable;
                g.reachable = f.Bool("reachable", true) ? 1 : 0;
                if (was != g.reachable && g.reachable == 0) Log("online: lobby %s: a join failed to reach it", id.c_str());
                // The code rides along from now on, so a server restart keeps it.
                if (g.lobbyJson.find("\"code\"") == std::string::npos && !g.lobbyCode.empty())
                    g.lobbyJson = g.lobbyJson.substr(0, g.lobbyJson.size() - 1) + ",\"code\":" + JsonString(g.lobbyCode) + "}";
            } else if (g.lobbyId == id) {
                // Said once per change: two hosted lobbies once vanished from
                // the server with nothing in either log.
                static int lastBad = 0;
                int bad = answered ? status : -1;
                if (bad != lastBad) {
                    Log("online: lobby %s heartbeat failed (%s)", id.c_str(),
                        answered ? ("HTTP " + std::to_string(status)).c_str() : "no answer");
                    lastBad = bad;
                }
                g.dirty = true;
                backoffUntil = GetTickCount() + 5000;
                if (answered && status == 403) {
                    Log("online: lobby %s refused by the server", id.c_str());
                    g.hosting = false;
                }
                if (answered && status == 426) {   // this release is below the server's minimum
                    Log("online: lobby %s not registered: %s", id.c_str(), f.Str("message").c_str());
                    g.hosting = false;
                }
                if (!g.hosting) { LeaveCriticalSection(&g.cs); punch::HostStop(); EnterCriticalSection(&g.cs); }
            }
            LeaveCriticalSection(&g.cs);
        }
    }
    return 0;
}

// ---- online statistics ---------------------------------------------

// Cached, refreshed in the background: the op answers at once with whatever is
// known ("" before the first answer) and starts a refresh when it is older
// than kStatsMaxAgeMs. "?players=?lobbies=?games=?searching=", or
// "?error=unreachable".
// The server's statsMs (60 s, stretched under budget), not less than 10 s.
static DWORD g_statsMaxAgeMs = 60000;
static std::string g_stats;
static DWORD g_statsAt = 0;
static bool g_statsFetching = false;
// The search settings page's filter (op 34): "" none, else "?map=?enemy=
// ?difficulty=" as a search sends them. With one, the counts also carry what
// a search with it would find: "?mlobbies=?mplayers=": the total count,
// then the filtered count in brackets.
static std::string g_statsFilter;
static unsigned g_statsGen = 0;   // bumped by a filter change: a stale answer is dropped
// A filter change is fetched once it has held for kStatsSettleMs: clicking
// through the settings page's maps costs one request, not one per click. The
// totals stay shown meanwhile; only the bracketed counts wait.
static const DWORD kStatsSettleMs = 2000;
static DWORD g_statsFilterAt = 0;
// When the Multiplayer page (or its Mission Setup) last set the filter (op 34;
// SFXGUI_MPLobby.UpdateLEMPOnlineLine, every second in state MultiplayerMenu).
// The entry dialog before Matchmaking reads the counts (op 32) but never sets
// a filter, so a fresh stamp means the player has clicked Matchmaking.
static DWORD g_statsPageAt = 0;
static const DWORD kStatsPageMs = 5000;

static DWORD WINAPI StatsThread(LPVOID p) {
    unsigned gen = (unsigned)(uintptr_t)p;
    EnterCriticalSection(&g.cs);
    std::string filter = g_statsFilter;
    // Idle on the Multiplayer page only: a searcher is counted by its ticket,
    // a host by its lobby, and the entry dialog before Matchmaking not at all.
    bool onPage = g_statsPageAt && GetTickCount() - g_statsPageAt < kStatsPageMs;
    std::string session = !onPage || g.hosting || g.outcome == IN_PROGRESS ? "" : Session();
    LeaveCriticalSection(&g.cs);
    int status = 0;
    JsonFields f;
    std::string text;
    bool ok;
    // Always a POST with the build; rules only with a filter. The totals are
    // every build's, so the player base is not split;
    // a server that answers matching counts without rules ("any") has them
    // shown only with a filter.
    JsonObject body;
    body.Str("build", Build());
    if (!session.empty()) body.Str("session", session);
    if (!filter.empty()) {
        auto m = ParseOptions(filter);
        JsonObject rules;
        rules.Int("map", OptInt(m, "map", 0)).Int("enemy", OptInt(m, "enemy", 0)).Int("difficulty", OptInt(m, "difficulty", -1));
        body.Raw("rules", rules.Done());
    }
    ok = HttpJson(L"POST", "/v1/stats", body.Done(), "", status, f);
    if (ok && status == 200 && f.Has("players")) {
        text = Opt("players", f.Int("players")) + Opt("lobbies", f.Int("lobbies")) + Opt("games", f.Int("games"))
             + Opt("searching", f.Int("searching"));
        if (!filter.empty() && f.Has("matchingLobbies"))
            text += Opt("mlobbies", f.Int("matchingLobbies")) + Opt("mplayers", f.Int("matchingPlayers"))
                  + Opt("mgames", f.Int("matchingGames"));
        long long ms = f.Int("statsMs", 60000);
        g_statsMaxAgeMs = (DWORD)(ms < 10000 ? 10000 : ms > 300000 ? 300000 : ms);
    } else if (ok && status == 429) {
        EnterCriticalSection(&g.cs);
        text = g_stats;           // rate limited: keep what is shown, ask again later
        LeaveCriticalSection(&g.cs);
    } else {
        text = Opt("error", "unreachable");
    }
    EnterCriticalSection(&g.cs);
    if (gen == g_statsGen) { g_stats = text; g_statsAt = GetTickCount(); }
    g_statsFetching = false;
    LeaveCriticalSection(&g.cs);
    return 0;
}

// 32/33.
static std::string StatsText() {
    EnterCriticalSection(&g.cs);
    std::string s = g_stats;
    DWORD now = GetTickCount();
    bool settled = now - g_statsFilterAt >= kStatsSettleMs;
    bool refresh = g.serverOk && !g_statsFetching && settled && (g_statsAt == 0 || now - g_statsAt > g_statsMaxAgeMs);
    if (refresh) g_statsFetching = true;
    LeaveCriticalSection(&g.cs);
    unsigned gen = g_statsGen;
    if (refresh) {
        HANDLE t = CreateThread(nullptr, 0, StatsThread, (LPVOID)(uintptr_t)gen, 0, nullptr);
        if (t) CloseHandle(t);
        else { EnterCriticalSection(&g.cs); g_statsFetching = false; LeaveCriticalSection(&g.cs); }
    }
    if (!g.serverOk) s = Opt("error", "no server address");
    return s;
}
// 34: set the filter ("" clears it). A change drops the cached counts, so
// the next 32 starts a fetch at once.
static void SetStatsFilter(const std::string& filter) {
    EnterCriticalSection(&g.cs);
    // Arriving on the page: fetch at once, so this player is counted (and
    // sees itself) now, not at the entry dialog's answer's expiry.
    DWORD now = GetTickCount();
    // An answer in flight without the session is dropped (gen), as a filter
    // change drops one.
    if (!g_statsPageAt || now - g_statsPageAt >= kStatsPageMs) { ++g_statsGen; g_statsAt = 0; g_statsFetching = false; }
    g_statsPageAt = now ? now : 1;
    if (filter != g_statsFilter) {
        g_statsFilter = filter;
        ++g_statsGen;
        // Keep the totals; drop only what answered the old filter.
        size_t m = g_stats.find("?mlobbies=");
        if (m != std::string::npos) g_stats.resize(m);
        g_statsAt = 0;
        g_statsFilterAt = GetTickCount();
        g_statsFetching = false;
    }
    LeaveCriticalSection(&g.cs);
}

// ---- the leaderboards -------------------------------

// 2012's two boards came from Blaze's stats component, fed by the end-of-match
// game report (NRAT, NCHP). Here the player reports its own values (op 35) and
// the lobby's Leaderboards screen reads a window of ranks (op 36, then 37/38).
//
// The player is a random id and secret in Save\ME3\LEMP_player.txt, beside
// the MP save the EA app syncs, so a player keeps one entry across machines.
// Made on the first report; the server registers the pair then.
static std::wstring g_playerFile;
static std::string g_playerId, g_playerSecret;

static void SetPlayerFile(const std::wstring& path) { g_playerFile = path; }

// On a worker thread: reads the file, or makes it.
static bool PlayerIdentity(std::string& id, std::string& secret) {
    EnterCriticalSection(&g.cs);
    id = g_playerId; secret = g_playerSecret;
    LeaveCriticalSection(&g.cs);
    if (!id.empty()) return true;
    if (g_playerFile.empty()) return false;
    std::string text;
    HANDLE h = CreateFileW(g_playerFile.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[256] = {0}; DWORD got = 0;
        ReadFile(h, buf, sizeof buf - 1, &got, nullptr);
        CloseHandle(h);
        text.assign(buf, got);
    }
    auto hex = [](const std::string& x) { return x.size() == 32 && x.find_first_not_of("0123456789abcdef") == std::string::npos; };
    size_t sp = text.find(' ');
    std::string i = sp == std::string::npos ? "" : text.substr(0, sp);
    std::string k = sp == std::string::npos ? "" : text.substr(sp + 1, 32);
    if (!hex(i) || !hex(k)) {
        if (!text.empty()) Log("online: leaderboard: %s is not an id and secret; making a new player", "LEMP_player.txt");
        i = RandomHex(16);
        k = RandomHex(16);
        std::string line = i + " " + k + "\r\n";
        HANDLE w = CreateFileW(g_playerFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
        DWORD put = 0;
        bool ok = w != INVALID_HANDLE_VALUE && WriteFile(w, line.data(), (DWORD)line.size(), &put, nullptr) && put == line.size();
        if (w != INVALID_HANDLE_VALUE) CloseHandle(w);
        if (!ok) { Log("online: leaderboard: could not write %s", "LEMP_player.txt"); return false; }
        Log("online: leaderboard: new player %s", i.c_str());
    }
    EnterCriticalSection(&g.cs);
    g_playerId = id = i; g_playerSecret = secret = k;
    LeaveCriticalSection(&g.cs);
    return true;
}

// 35: the player's values, "?name=?n7=?cp=". Sent when they differ from what
// the server last took, by one thread that re-sends whatever is newest.
static std::string g_reportWant, g_reportSent;
static bool g_reportBusy = false;

static void ReportIdle() {
    EnterCriticalSection(&g.cs);
    g_reportBusy = false;
    LeaveCriticalSection(&g.cs);
}

static DWORD WINAPI ReportThread(LPVOID) {
    for (int failures = 0;;) {
        EnterCriticalSection(&g.cs);
        std::string want = g_reportWant;
        bool done = want == g_reportSent;
        if (done) g_reportBusy = false;
        LeaveCriticalSection(&g.cs);
        if (done) return 0;
        std::string id, secret;
        if (!PlayerIdentity(id, secret)) { ReportIdle(); return 0; }
        auto m = ParseOptions(want);
        auto it = m.find("name");
        std::string body = JsonObject().Str("name", it == m.end() ? "" : it->second)
                                       .Int("n7", OptInt(m, "n7", 0)).Int("cp", OptInt(m, "cp", 0)).Done();
        int status = 0;
        JsonFields f;
        bool answered = HttpJson(L"PUT", "/v1/players/" + id, body, secret, status, f);
        if (answered && status == 200) {
            Log("online: leaderboard: reported %s (N7 rank %s)", want.c_str(), std::to_string(f.Int("n7Rank", -1)).c_str());
            EnterCriticalSection(&g.cs);
            g_reportSent = want;
            LeaveCriticalSection(&g.cs);
            failures = 0;
            continue;
        }
        if (answered && status == 429 && failures++ < 3) { Sleep(5000); continue; }
        // Refused (another secret: the file came from someone else's
        // machine), or no server: logged, and tried again at the next report.
        Log("online: leaderboard: report failed (%s)", answered ? ("HTTP " + std::to_string(status)).c_str() : "no answer");
        if (++failures >= 2 || answered) { ReportIdle(); return 0; }
        Sleep(3000);
    }
}
static int ReportStats(const std::string& opts) {
    if (!g.serverOk) return 2;
    EnterCriticalSection(&g.cs);
    g_reportWant = opts;
    bool start = !g_reportBusy && opts != g_reportSent;
    if (start) g_reportBusy = true;
    LeaveCriticalSection(&g.cs);
    if (start) {
        HANDLE t = CreateThread(nullptr, 0, ReportThread, nullptr, 0, nullptr);
        if (!t) { ReportIdle(); return 2; }
        CloseHandle(t);
    }
    return 0;
}

// 36: read a window of a board: "?board=n7|cp?count=N" and "?start=R", or
// "?center=1" for the window around this player. 37/38 then give "" while it
// is on its way, "?error=<message>", or "?total=?top=?rank=" and a line per
// row: rank TAB name TAB value (rank is this player's, -1 if not on the board).
static unsigned g_boardGen = 0;
static std::string g_boardText;

struct BoardArgs { unsigned gen; std::string board; long long start, count; bool center; };

static DWORD WINAPI BoardThread(LPVOID p) {
    BoardArgs a = *(BoardArgs*)p;
    delete (BoardArgs*)p;
    std::string id, secret, text;
    bool haveId = PlayerIdentity(id, secret);
    JsonObject body;
    body.Int("count", a.count);
    if (a.center && haveId) body.Str("center", id);
    else { body.Int("start", a.start); if (haveId) body.Str("me", id); }
    for (int tries = 0;; tries++) {
        int status = 0;
        JsonFields f;
        bool answered = HttpJson(L"POST", "/v1/leaderboard/" + a.board, body.Done(), "", status, f);
        if (answered && status == 429 && tries < 3) {
            long long ms = f.Int("retryMs", 2000);
            Sleep((DWORD)(ms < 500 ? 500 : ms > 10000 ? 10000 : ms));
            continue;
        }
        if (!answered) text = Opt("error", "The LEMP server " + g.server.host + ":" + std::to_string(g.server.port) + " does not answer.");
        else if (status != 200) text = Opt("error", "The LEMP server refused (HTTP " + std::to_string(status) + ").");
        else text = Opt("total", f.Int("total", 0)) + Opt("top", f.Int("top", 0)) + Opt("rank", f.Int("rank", -1)) + "\n" + f.Str("rows");
        break;
    }
    EnterCriticalSection(&g.cs);
    if (a.gen == g_boardGen) g_boardText = text;
    LeaveCriticalSection(&g.cs);
    return 0;
}
static int StartBoard(const std::string& opts) {
    auto m = ParseOptions(opts);
    std::string board = m.count("board") ? m["board"] : "n7";
    if (board != "n7" && board != "cp") return 3;
    long long count = OptInt(m, "count", 30);
    BoardArgs* a = new BoardArgs{0, board, OptInt(m, "start", 1), count < 1 ? 1 : count > 100 ? 100 : count, OptInt(m, "center", 0) != 0};
    EnterCriticalSection(&g.cs);
    a->gen = ++g_boardGen;
    g_boardText = g.serverOk ? "" : Opt("error", "No LEMP server is set (LEMP server.txt).");
    LeaveCriticalSection(&g.cs);
    if (!g.serverOk) { delete a; return 0; }
    HANDLE t = CreateThread(nullptr, 0, BoardThread, a, 0, nullptr);
    if (!t) { delete a; return 2; }
    CloseHandle(t);
    return 0;
}
static std::string BoardText() {
    EnterCriticalSection(&g.cs);
    std::string s = g_boardText;
    LeaveCriticalSection(&g.cs);
    return s;
}

// ---- the release check ---------------------------------

// 2012's IsOnLatestMultiplayerVersion, asked of the Worker: GET /v1/version
// with this install's release, once per release set (op 39), in the
// background. Ops 40/41: "" while it is asked, then "?status=ok|update|
// required?latest=?minimum=?message=", or "?error=unreachable" /
// "?error=no server address" (script then goes on as if all is well).
static std::string g_versionText;
static bool g_versionAsked = false;

static DWORD WINAPI VersionThread(LPVOID) {
    int status = 0;
    JsonFields f;
    std::string text;
    if (HttpJson(L"GET", "/v1/version", "", "", status, f) && status == 200 && f.Has("status"))
        text = Opt("status", f.Str("status")) + Opt("latest", f.Str("latest")) + Opt("minimum", f.Str("minimum"))
             + Opt("message", f.Str("message"));
    else
        text = Opt("error", "unreachable");
    Log("online: release check: %s", text.c_str());
    EnterCriticalSection(&g.cs);
    g_versionText = text;
    LeaveCriticalSection(&g.cs);
    return 0;
}
// 39: the release, as script has it (the DLC's config); a change asks again.
// Another release than kRelease is a DLC and lemp.asi of two releases: every
// join fails on the build key (it hashes lemp.asi), and the server would be
// told a release this ASI is not. So no X-LEMP-Version is sent (the server
// refuses a request without one) and ops 40/41 answer "required" without
// asking: a DLC whose script predates the check still greys out Matchmaking.
static int SetVersion(const std::string& version) {
    bool mismatch = *kRelease && version != kRelease;
    EnterCriticalSection(&g.cs);
    bool changed = version != g.dlcRelease;
    if (changed) {
        g.dlcRelease = version;
        g.releaseMismatch = mismatch;
        g.version = mismatch ? "" : version;
        g_versionAsked = false;
        g_versionText.clear();
    }
    LeaveCriticalSection(&g.cs);
    if (changed && mismatch)
        Log("online: release mismatch: the DLC is %s, lemp.asi %s; online requests go without a release", version.c_str(), kRelease);
    return 0;
}
// 55/56.
static std::string Release() { return kRelease; }
// 40/41.
static std::string VersionText() {
    EnterCriticalSection(&g.cs);
    bool mismatch = g.releaseMismatch;
    LeaveCriticalSection(&g.cs);
    // An older script reads this as the server's verdict: "This is LEMP <the
    // DLC's>; Matchmaking needs LEMP <kRelease>.", then the message (the box
    // shows two lines of ~68 characters).
    if (mismatch)
        return Opt("status", "required") + Opt("latest", kRelease) + Opt("minimum", kRelease)
             + Opt("message", std::string("lemp.asi is ") + kRelease + ": install the DLC and lemp.asi from one release.");
    if (!g.serverOk) return Opt("error", "no server address");
    EnterCriticalSection(&g.cs);
    bool ask = !g_versionAsked;
    g_versionAsked = true;
    std::string s = g_versionText;
    LeaveCriticalSection(&g.cs);
    if (ask) {
        HANDLE t = CreateThread(nullptr, 0, VersionThread, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
        else { EnterCriticalSection(&g.cs); g_versionText = Opt("error", "unreachable"); LeaveCriticalSection(&g.cs); }
    }
    return s;
}

// ---- setup ---------------------------------------------------------------------

static void Init(const std::wstring& dir, LogFn log, HANDLE buildReady, std::string (*getBuild)()) {
    InitializeCriticalSection(&g.cs);
    g.log = log;
    g.buildReady = buildReady;
    g.getBuild = getBuild;
    std::string url = kDefaultServer;
    HANDLE h = CreateFileW((dir + L"\\server.txt").c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[512] = {0}; DWORD got = 0;
        ReadFile(h, buf, sizeof buf - 1, &got, nullptr);
        CloseHandle(h);
        std::string line(buf, got);
        size_t nl = line.find_first_of("\r\n");
        if (nl != std::string::npos) line.resize(nl);
        if (!line.empty()) url = line;
    } else if (GetLastError() == ERROR_FILE_NOT_FOUND) {
        h = CreateFileW((dir + L"\\server.txt").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            std::string text = std::string(kDefaultServer) + "\r\n";
            DWORD put = 0;
            WriteFile(h, text.data(), (DWORD)text.size(), &put, nullptr);
            CloseHandle(h);
        }
    }
    g.serverOk = ParseServerUrl(url, g.server);
    // STUN servers for hole punching: LEMP\stun.txt, one host:port a line,
    // if it exists (tests, or a player whose network blocks the defaults);
    // else lemp_punch.h's list.
    std::vector<std::string> stun;
    h = CreateFileW((dir + L"\\stun.txt").c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[2048] = {0}; DWORD got = 0;
        ReadFile(h, buf, sizeof buf - 1, &got, nullptr);
        CloseHandle(h);
        std::string text(buf, got), line;
        for (size_t i = 0; i <= text.size(); i++) {
            char ch = i < text.size() ? text[i] : '\n';
            if (ch == '\r' || ch == '\n') { if (!line.empty() && line[0] != '#') stun.push_back(line); line.clear(); }
            else if (ch != ' ' && ch != '\t') line += ch;
        }
    }
    InitializeCriticalSection(&g_wsCs);
    punch::Init(stun, log);
    upnp::Start(log);   // finds the router in the background; maps only while hosting or joining
    g.session = WinHttpOpen(L"LEMP/1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (g.session) WinHttpSetTimeouts(g.session, 5000, 5000, 5000, 8000);
    Log("online: MP server %s%s", url.c_str(), g.serverOk ? "" : " (not a URL: matchmaking is off)");
    Log("online: lemp.asi release %s", *kRelease ? kRelease : "(none built in)");
}

// ---- the ops, on the game thread: never block -------------------------------------

// 20: start a search. Options: ?map= ?enemy= ?difficulty= (difficulty -1 = any).
// Or ?code=: join the lobby with that code; it ends as a search does, JOIN or
// FAILED with a message (op 22). Six letters or digits, any case (hex from
// the current server, 31 letters and digits from an earlier one); 1 when malformed.
//
// Or ?migrate=<lobby>?key=<key>?rank=<n> (host migration, Migrate above), with
// the new lobby's options beside them: ?private=?map=?enemy=?difficulty=
// ?players=?max=?port=?state=. 1 when the lobby or key is malformed.
static int StartSearch(const std::string& opts) {
    auto m = ParseOptions(opts);
    Migration mig;
    if (m.count("migrate")) {
        auto hex = [](const std::string& x, size_t lo, size_t hi) {
            return x.size() >= lo && x.size() <= hi && x.find_first_not_of("0123456789abcdef") == std::string::npos;
        };
        mig.lobby = m["migrate"];
        mig.key = m.count("key") ? m["key"] : "";
        if (!hex(mig.lobby, 16, 64) || !hex(mig.key, 32, 32)) return 1;
        mig.rank = OptInt(m, "rank", 0);
        for (const char* k : {"private", "map", "enemy", "difficulty", "players", "max", "port", "state"})
            if (m.count(k)) mig.opts[k] = m[k];
    }
    std::string code = m.count("code") ? m["code"] : "";
    for (auto& c : code) c = (char)toupper((unsigned char)c);
    if (m.count("code") && (code.size() != 6 || code.find_first_not_of("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") != std::string::npos)) return 1;
    Rules r;
    r.map = OptInt(m, "map", 0);
    r.enemy = OptInt(m, "enemy", 0);
    r.difficulty = OptInt(m, "difficulty", -1);
    if (!g.serverOk) return 2;
    EnterCriticalSection(&g.cs);
    unsigned gen = ++g.searchGen;
    g.outcome = IN_PROGRESS;
    g.resultText.clear();
    g.ticket.clear();
    g.joinLobby.clear();
    g.rules = r;
    LeaveCriticalSection(&g.cs);
    HANDLE t = CreateThread(nullptr, 0, SearchThread, new SearchArgs{gen, r, code, mig}, 0, nullptr);
    if (!t) return 2;
    CloseHandle(t);
    // The key stays out of the log.
    Log("online: search started %s", mig.lobby.empty() ? opts.c_str() : ("?migrate=" + mig.lobby + "?rank=" + std::to_string(mig.rank)).c_str());
    return 0;
}
// 21: the outcome, -1 if no search.
static int PollSearch() {
    EnterCriticalSection(&g.cs);
    int o = g.outcome;
    LeaveCriticalSection(&g.cs);
    return o;
}
// 22/23: the outcome's text.
static std::string SearchText() {
    EnterCriticalSection(&g.cs);
    std::string s = g.resultText;
    LeaveCriticalSection(&g.cs);
    return s;
}
// 24: cancel (2012's CancelFindOnlineGames). The thread sees the stale gen
// and withdraws its ticket.
static void CancelSearch() {
    EnterCriticalSection(&g.cs);
    ++g.searchGen;
    g.outcome = -1;
    g.resultText.clear();
    LeaveCriticalSection(&g.cs);
}
// 25: the last JOIN did not connect; tell the server, so it stops sending
// players there and the host hears of it.
static DWORD WINAPI JoinFailedThread(LPVOID p) {
    std::string* s = (std::string*)p;
    size_t bar = s->find('|');
    std::string lobby = s->substr(0, bar), ticket = s->substr(bar + 1);
    delete s;
    int status = 0; std::string resp;
    Http(L"POST", "/v1/lobbies/" + lobby + "/failed", JsonObject().Str("ticket", ticket).Done(), "", status, resp);
    Log("online: reported a failed join to lobby %s (HTTP %s)", lobby.c_str(), std::to_string(status).c_str());
    return 0;
}
static int ReportJoinFailed() {
    EnterCriticalSection(&g.cs);
    std::string lobby = g.joinLobby, ticket = g.ticket;
    g.joinLobby.clear();
    unsigned pj = g.punchJoin;
    g.punchJoin = 0;
    LeaveCriticalSection(&g.cs);
    if (pj) punch::JoinStop(pj);
    if (lobby.empty()) return 7;
    HANDLE t = CreateThread(nullptr, 0, JoinFailedThread, new std::string(lobby + "|" + ticket), 0, nullptr);
    if (t) CloseHandle(t);
    return 0;
}

// The hosted lobby's JSON body, from its merged options (UpdateLobby) and what
// the ASI holds itself. Under g.cs. ready: false only for a migration's new
// host until script says its map is up (the server's Lobby.ready).
static std::string LobbyBody(const std::map<std::string, std::string>& m, const std::string& lan, const std::string& build) {
    JsonObject j;
    j.Str("build", build)
     .Str("lanAddress", lan)
     .Int("port", OptInt(m, "port", 3659))
     .Bool("private", OptInt(m, "private", 1) != 0)
     .Bool("open", OptInt(m, "open", 0) != 0)
     .Int("state", OptInt(m, "state", 1))
     .Int("map", OptInt(m, "map", 0))
     .Int("enemy", OptInt(m, "enemy", 0))
     .Int("difficulty", OptInt(m, "difficulty", 0))
     .Int("players", OptInt(m, "players", 1))
     .Int("maxPlayers", OptInt(m, "max", 4));
    if (!g.migrationKey.empty()) j.Str("migrationKey", g.migrationKey);
    if (OptInt(m, "ready", 1) == 0) j.Bool("ready", false);
    // The public statistics, from the match's
    // heartbeat only (SFXGameInfoMP.UpdateLEMPMatchOnline): the outcome, the
    // wave, every player's kit ("AdeptHumanMale,SoldierKrogan"), and the
    // weapons, weapon mods and equipment in the match (class names).
    if (m.count("result")) j.Int("result", OptInt(m, "result", 0));
    if (m.count("wave")) j.Int("wave", OptInt(m, "wave", 0));
    for (const char* k : {"kits", "weapons", "mods", "equipment"})
        if (m.count(k)) j.Str(k, m.at(k));
    if (!g.lobbyTicket.empty()) j.Str("ticket", g.lobbyTicket);
    if (!g.lobbyCode.empty()) j.Str("code", g.lobbyCode);
    return j.Done();
}

// 26: the hosted lobby's state (2012's CreateOnlineGame / UpdateOnlineGame /
// AllowMatchmaking). ?create=1 registers a new lobby; otherwise an existing
// registration is updated, and 7 means there is none. Options: ?private=
// ?open= ?state= ?map= ?enemy= ?difficulty= ?players= ?max= ?port=, and from a
// match ?result= ?wave= ?kits= ?weapons= ?mods= ?equipment= (the statistics,
// LobbyBody). An update
// is merged over the options last sent, so the match (SFXGameInfoMP
// .UpdateLEMPMatchOnline) sends what it knows — open, state, players, the
// map it plays — and the lobby's privacy, port and size stand. ?state= is
// 2012's SFXOnlineGameStatus (join-in-progress).
static int UpdateLobby(const std::string& opts) {
    auto given = ParseOptions(opts);
    bool create = OptInt(given, "create", 0) != 0;
    if (!g.serverOk) return 2;
    EnterCriticalSection(&g.cs);
    if (!create && !g.hosting) { LeaveCriticalSection(&g.cs); return 7; }
    // A search still running is over once this player hosts: above all a
    // migration left waiting ("the server still hears from the host") when
    // the player went back to the menu. Once, one claimed the old
    // lobby 5 s after a new one was registered, HostClaimed swapped the
    // registration for the migrated lobby (ready=0, never readied), and no
    // search found the new one. A finished search (CREATE of a migration,
    // whose host then registers here) is not touched.
    if (create && g.outcome == IN_PROGRESS) {
        ++g.searchGen;
        g.outcome = -1;
        g.resultText.clear();
        Log("online: hosting: the search still running is cancelled");
    }
    if (create) {
        if (!g.hosting || g.lobbyId.empty()) {
            g.lobbyId = RandomHex(16);
            g.lobbySecret = RandomHex(16);
            g.migrationKey = RandomHex(16);
            g.lobbyCode.clear();
        }
        g.lobbyTicket = g.createTicket;   // the CREATE this answers, if any
        g.createTicket.clear();
        g.hosting = true;
        g.reachable = -1;
        g.lobbyOpts.clear();
    }
    for (auto& kv : given) g.lobbyOpts[kv.first] = kv.second;
    auto m = g.lobbyOpts;
    LeaveCriticalSection(&g.cs);
    std::string lan = Lan();
    punch::HostStart((int)OptInt(m, "port", 3659));   // idempotent; follows a port change
    upnp::Want(upnp::HOST, (uint16_t)punch::GetHostInfo().localPort);
    std::string build = g.getBuild ? g.getBuild() : "";
    EnterCriticalSection(&g.cs);
    std::string body = LobbyBody(m, lan, build);
    bool changed = body != g.lobbyJson;
    g.lobbyJson = body;
    g.dirty = g.dirty || changed;
    g.leaseAt = GetTickCount();
    if (!g.hostThread) g.hostThread = CreateThread(nullptr, 0, HostThread, nullptr, 0, nullptr);
    LeaveCriticalSection(&g.cs);
    if (create) Log("online: hosting %s", opts.c_str());
    return 0;
}
// 27: renew the lease only (SFXGameInfoMP's timer); 7 when not hosting.
static int RenewLobby() {
    EnterCriticalSection(&g.cs);
    bool h = g.hosting;
    if (h) { g.leaseAt = GetTickCount(); g.leaseExtraMs = 0; }
    LeaveCriticalSection(&g.cs);
    return h ? 0 : 7;
}
// 28: stop hosting.
static int DestroyLobby() {
    EnterCriticalSection(&g.cs);
    bool h = g.hosting;
    if (h) g.destroy = true;
    LeaveCriticalSection(&g.cs);
    return h ? 0 : 7;
}
// 43/44: what this host's players need to take its lobby over if it goes
// (host migration): "?lobby=<id>?key=<key>", or "" before the server has
// registered the lobby (no code yet) or when not hosting.
static std::string MigrationTicket() {
    EnterCriticalSection(&g.cs);
    std::string s = g.hosting && !g.lobbyCode.empty() && !g.migrationKey.empty()
        ? Opt("lobby", g.lobbyId) + Opt("key", g.migrationKey) : "";
    LeaveCriticalSection(&g.cs);
    return s;
}
// 53/54: how well this machine could take its host's game over (host
// migration's order, SFXGameInfoMP.LEMPComputeMigrationOrder):
// "?nat=<eim|symmetric|>?upnp=<1|0>". nat: the mapping behaviour STUN saw for
// the join proxy, else for the host proxy, "" unknown (a symmetric NAT is one
// others can hardly punch to); upnp: the router can map ports, so a lobby
// hosted here is given out on a mapped endpoint, open to every NAT
// (PunchFields).
static std::string HostQuality() {
    std::string nat = punch::JoinNat();
    if (nat.empty()) nat = punch::GetHostInfo().nat;
    return Opt("nat", nat) + Opt("upnp", (long long)(upnp::Usable() ? 1 : 0));
}
// 29/30: the hosted lobby's status: ?code= ?reachable= (-1 unknown, 1, 0).
static std::string LobbyStatus(int& reachable) {
    EnterCriticalSection(&g.cs);
    reachable = g.hosting ? g.reachable : -1;
    std::string s = g.hosting ? Opt("code", g.lobbyCode) + Opt("reachable", (long long)g.reachable) : "";
    LeaveCriticalSection(&g.cs);
    return s;
}

}  // namespace online
