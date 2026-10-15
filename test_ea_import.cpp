// ea_lsx.h and ea_import.h, natively, offline:
//   g++ -std=c++17 -O2 -pthread -o test_ea_import test_ea_import.cpp && ./test_ea_import
// - AES-128 against FIPS-197; MS rand() and the LSX session key against
//   origin-sdk's own test vectors (src/random.rs, src/crypto.rs);
// - the LSX client against a stand-in EA app that answers the way Maxima's
//   server does (maxima-lib/src/lsx/connection.rs: challenge, session key from
//   the client's key, encrypted hex after ChallengeAccepted);
// - MapSettings on Pocket Relay-shaped settings (Pocket Relay's src/database/seed.rs).
// The real EA app and EA's server are only reached in game, by the player.
#include "ea_import.h"
#include <cstdio>
#include <thread>
#include <netinet/in.h>
#include <arpa/inet.h>
using namespace ea;

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } else printf("ok   %s\n", #c); } while (0)

// ---- the stand-in EA app ----
static bool SendZ(int s, const std::string& m) { std::string w = m; w.push_back('\0'); return send(s, w.data(), w.size(), 0) == (ssize_t)w.size(); }
static bool RecvZ(int s, std::string& buf, std::string& m) {
    for (;;) {
        size_t z = buf.find('\0');
        if (z != std::string::npos) { m = buf.substr(0, z); buf.erase(0, z + 1); return true; }
        char t[4096]; ssize_t k = recv(s, t, sizeof t, 0); if (k <= 0) return false; buf.append(t, k);
    }
}
static std::string g_serverSaw;   // what the stand-in decrypted, for the checks
static void FakeEaApp(int listener, bool giveToken) {
    int c = accept(listener, nullptr, nullptr);
    if (c < 0) return;
    std::string buf, m;
    SendZ(c, "<LSX><Event sender=\"EALS\"><Challenge build=\"release\" key=\"cacf897a20b6d612ad0c05e011df52bb\" version=\"10,5,30,15625\"/></Event></LSX>");
    if (!RecvZ(c, buf, m)) { close(c); return; }
    std::string resp, key, ver;
    lsx::Attr(m, "response", resp); lsx::Attr(m, "key", key); lsx::Attr(m, "version", ver);
    uint8_t k0[16]; lsx::MakeKey(0, k0);
    Bytes want = AesEcbEncrypt(k0, "cacf897a20b6d612ad0c05e011df52bb");
    if (resp != Hex(want.data(), want.size())) { g_serverSaw = "bad response"; close(c); return; }
    // Maxima: the accept key is hex(AES(client's key)); seed from its first two characters (version 3).
    Bytes acc = AesEcbEncrypt(k0, key);
    std::string accept = Hex(acc.data(), acc.size());
    uint8_t sk[16]; lsx::MakeKey(ver == "3" ? (((uint32_t)(uint8_t)accept[0] << 8) | (uint8_t)accept[1]) : 0, sk);
    SendZ(c, "<LSX><Response sender=\"EALS\" id=\"0\"><ChallengeAccepted response=\"" + accept + "\"/></Response></LSX>");
    // An unrelated event first, then the answer.
    Bytes ev = AesEcbEncrypt(sk, "<LSX><Event sender=\"EbisuSDK\"><Login IsLoggedIn=\"true\"/></Event></LSX>");
    if (!RecvZ(c, buf, m)) { close(c); return; }
    Bytes ct; std::string plain;
    if (!FromHex(m, ct) || !AesEcbDecrypt(sk, ct, plain)) { g_serverSaw = "undecryptable request"; close(c); return; }
    g_serverSaw = plain;
    std::string id; lsx::Attr(plain, "id", id);
    SendZ(c, Hex(ev.data(), ev.size()));
    std::string answer = giveToken
        ? "<LSX><Response sender=\"EbisuSDK\" id=\"" + id + "\"><AuthToken value=\"QVVUSF9UT0tFTg&amp;x\"/></Response></LSX>"
        : "<LSX><Response sender=\"EbisuSDK\" id=\"" + id + "\"><ErrorSuccess Code=\"-1610612729\" Description=\"\"/></Response></LSX>";
    Bytes out = AesEcbEncrypt(sk, answer);
    SendZ(c, Hex(out.data(), out.size()));
    close(c);
}
static int Listen(uint16_t& port) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    bind(l, (sockaddr*)&a, sizeof a); listen(l, 1);
    socklen_t n = sizeof a; getsockname(l, (sockaddr*)&a, &n); port = ntohs(a.sin_port);
    return l;
}

int main() {
    {   // FIPS-197 C.1
        uint8_t key[16], blk[16];
        for (int i = 0; i < 16; ++i) { key[i] = (uint8_t)i; blk[i] = (uint8_t)(i * 0x11); }
        Aes128 a(key); a.Encrypt(blk);
        CHECK(Hex(blk, 16) == "69c4e0d86a7b0430d8cdb78070b4c55a");
        a.Decrypt(blk);
        CHECK(Hex(blk, 16) == "00112233445566778899aabbccddeeff");
        std::string p;
        CHECK(AesEcbDecrypt(key, AesEcbEncrypt(key, "hello world"), p) && p == "hello world");
        CHECK(AesEcbEncrypt(key, std::string(16, 'x')).size() == 32);   // a full block of padding
    }
    {   // origin-sdk's vectors
        lsx::MsRand r{1337};
        CHECK(r.Next() == 4404);
        CHECK(r.Next() == 25954);
        uint8_t k[16]; lsx::MakeKey(1337, k);
        static const uint8_t want[16] = { 251,135,22,197,214,181,148,115,149,93,40,78,123,141,60,108 };
        CHECK(!memcmp(k, want, 16));
        lsx::MakeKey(0, k);
        CHECK(k[0] == 0 && k[15] == 15);
    }
    {   // the client against the stand-in
        uint16_t port; int l = Listen(port);
        std::thread t(FakeEaApp, l, true);
        lsx::Client app; app.port = port;
        std::string token;
        bool ok = app.Connect() && app.GetAuthToken(token);
        if (!ok) printf("     %s\n", app.err.c_str());
        t.join(); close(l);
        CHECK(ok);
        CHECK(token == "QVVUSF9UT0tFTg&x");
        CHECK(g_serverSaw.find("recipient=\"EbisuSDK\"") != std::string::npos && g_serverSaw.find("<GetAuthToken/>") != std::string::npos);
    }
    {   // a refusal is reported without a token
        uint16_t port; int l = Listen(port);
        std::thread t(FakeEaApp, l, false);
        lsx::Client app; app.port = port;
        std::string token;
        bool ok = app.Connect() && app.GetAuthToken(token);
        t.join(); close(l);
        CHECK(!ok && app.err.find("ErrorSuccess") != std::string::npos);
    }
    {   // nothing listening
        uint16_t port; int l = Listen(port); close(l);
        lsx::Client app; app.port = port;
        CHECK(!app.Connect() && app.err.find("not running") != std::string::npos);
    }
    {   // MapSettings
        std::map<std::string, std::string> s = {
            {"Base", "20;4;21474;-1;0;0;0;50;180000;0;111111"}, {"FaceCodes", "20;"}, {"NewItem", "20;4;12 271"},
            {"class1", "20;4;Adept;20;0.0000;50"}, {"class2", "20;4;Soldier;1;0.0000;0"},
            {"char0", "20;4;AdeptHumanMale;A;0"}, {"char2", "20;4;AdeptAsari;C;0"}, {"char10", "20;4;SoldierKrogan;K;0"},
            {"char1", "20;4;AdeptHumanFemale;B;0"},
            {"Completion", "22,0,1"}, {"Progress", "22,5"}, {"csreward", "3"}, {"cstimestamps", "1,2"},
            {"GAW_SomethingElse", "ignored"} };
        MPSaveData d; std::string why, summary;
        CHECK(MapSettings(s, d, why, summary));
        CHECK(d.base == u"20;4;21474;-1;0;0;0;50;180000;0;111111");
        CHECK(d.reinforcements == u"20;4;12 271" && d.facecodes == u"20;" && d.selected.empty());
        CHECK(d.classes.size() == 2 && d.classes[1] == u"20;4;Soldier;1;0.0000;0");
        CHECK(d.characters.size() == 4 && d.characters[1] == u"20;4;AdeptHumanFemale;B;0" && d.characters[3] == u"20;4;SoldierKrogan;K;0");
        CHECK(d.challenges.size() == 8 && d.challenges[0] == u"1" && d.challenges[1] == u"22,0,1" && d.challenges[3] == u""
              && d.challenges[4] == u"3" && d.challenges[5] == u"1,2" && d.challenges[7] == u"");
        printf("     summary: %s\n", summary.c_str());
        // The save round-trips through the file format.
        MPSaveData back; std::string pw;
        CHECK(mpsave::Parse(mpsave::Serialize(d), back, pw) && back.characters == d.characters && back.challenges == d.challenges);

        auto s2 = s; s2["class3"] = "21;4;Engineer;1;0;0";
        CHECK(!MapSettings(s2, d, why, summary) && why.find("class3") != std::string::npos);
        auto s3 = s; s3.erase("Base");
        why.clear();
        CHECK(!MapSettings(s3, d, why, summary) && why.find("no ME3 multiplayer profile") != std::string::npos);
        auto s4 = s; s4.erase("Completion"); s4.erase("Progress"); s4.erase("csreward"); s4.erase("cstimestamps");
        why.clear();
        CHECK(MapSettings(s4, d, why, summary) && d.challenges.empty());
        auto s5 = s; s5["char3"] = std::string("20;4;X;\xff;0");
        why.clear();
        CHECK(!MapSettings(s5, d, why, summary) && why.find("UTF-8") != std::string::npos);
        auto s6 = s; s6["char4"] = "20;4;Named \xc3\xa9;0";   // UTF-8 names survive
        why.clear();
        CHECK(MapSettings(s6, d, why, summary) && d.characters.size() == 5 && d.characters[3] == u"20;4;Named é;0");   // char4, before char10
    }
    printf("%s (%d failure(s))\n", fails ? "FAILED" : "all passed", fails);
    return fails ? 1 : 0;
}
