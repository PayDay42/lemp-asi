// n7hq_import.h, natively, offline:
//   g++ -std=c++17 -O2 -pthread -o test_n7hq test_n7hq.cpp && ./test_n7hq
// - the URL, redirect and page helpers on pages shaped like N7 HQ's (the
//   tab links of a profile, the "not currently available" page, the code
//   exchange's error page);
// - the two LSX requests (GetProfile, GetAuthCode) against a stand-in EA app
//   with the handshake test_ea_import's uses: a code, a refusal, no user id.
// N7 HQ, EA's sign-in and the real EA app are only reached in game.
#include "n7hq_import.h"
#include <cstdio>
#include <thread>
#include <netinet/in.h>
#include <arpa/inet.h>
using namespace ea;

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } else printf("ok   %s\n", #c); } while (0)

// ---- the stand-in EA app: the handshake, then one answer per request ----
static bool SendZ(int s, const std::string& m) { std::string w = m; w.push_back('\0'); return send(s, w.data(), w.size(), 0) == (ssize_t)w.size(); }
static bool RecvZ(int s, std::string& buf, std::string& m) {
    for (;;) {
        size_t z = buf.find('\0');
        if (z != std::string::npos) { m = buf.substr(0, z); buf.erase(0, z + 1); return true; }
        char t[4096]; ssize_t k = recv(s, t, sizeof t, 0); if (k <= 0) return false; buf.append(t, k);
    }
}
enum class App { Code, Refuse, NoUser };
static std::vector<std::string> g_saw;   // each request the stand-in decrypted
static void FakeEaApp(int listener, App mode) {
    int c = accept(listener, nullptr, nullptr);
    if (c < 0) return;
    std::string buf, m;
    SendZ(c, "<LSX><Event sender=\"EALS\"><Challenge build=\"release\" key=\"cacf897a20b6d612ad0c05e011df52bb\" version=\"10,5,30,15625\"/></Event></LSX>");
    if (!RecvZ(c, buf, m)) { close(c); return; }
    std::string key, ver;
    lsx::Attr(m, "key", key); lsx::Attr(m, "version", ver);
    uint8_t k0[16]; lsx::MakeKey(0, k0);
    Bytes acc = AesEcbEncrypt(k0, key);
    std::string accept = Hex(acc.data(), acc.size());
    uint8_t sk[16]; lsx::MakeKey(ver == "3" ? (((uint32_t)(uint8_t)accept[0] << 8) | (uint8_t)accept[1]) : 0, sk);
    SendZ(c, "<LSX><Response sender=\"EALS\" id=\"0\"><ChallengeAccepted response=\"" + accept + "\"/></Response></LSX>");
    while (RecvZ(c, buf, m)) {
        Bytes ct; std::string plain;
        if (!FromHex(m, ct) || !AesEcbDecrypt(sk, ct, plain)) break;
        g_saw.push_back(plain);
        std::string id; lsx::Attr(plain, "id", id);
        std::string body;
        if (plain.find("<GetProfile") != std::string::npos)
            body = mode == App::NoUser ? "<ErrorSuccess Code=\"-1\" Description=\"\"/>"
                                       : "<GetProfileResponse UserIndex=\"0\" UserId=\"1000123456789\" PersonaId=\"42\" Persona=\"Someone\"/>";
        else if (plain.find("<GetAuthCode") != std::string::npos)
            body = mode == App::Code ? "<AuthCode value=\"QUN&amp;0de\"/>" : "<AuthCode value=\"invalid\"/>";
        else if (plain.find("<GetAccessToken") != std::string::npos)
            body = plain.find("Scope=") != std::string::npos ? "<AuthToken value=\"QVQ0scoped\"/>"
                                                             : "<LSXError error=\"MissingScope\"/>";
        else body = "<ErrorSuccess Code=\"-1610612729\" Description=\"\"/>";
        Bytes out = AesEcbEncrypt(sk, "<LSX><Response sender=\"EbisuSDK\" id=\"" + id + "\">" + body + "</Response></LSX>");
        SendZ(c, Hex(out.data(), out.size()));
    }
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
    using namespace ea::n7hq;
    {   // platforms and names
        CHECK(FindPlatform("xbox") && std::string(FindPlatform("xbox")->label) == "Xbox 360");
        CHECK(FindPlatform("ps3") && FindPlatform("wiiu"));
        CHECK(FindPlatform("pc") && std::string(FindPlatform("pc")->label) == "PC/Origin");
        CHECK(!FindPlatform("") && !FindPlatform("XBOX"));
        CHECK(ValidName("shepard117") && ValidName("Major Tom 7") && ValidName("_Garrus_7_") && ValidName("a.b-c"));
        CHECK(!ValidName("") && !ValidName("   ") && !ValidName("abcdefghijklmnopq") && !ValidName("a?b") && !ValidName("a&b") && !ValidName("n\xC3\xA4me"));
    }
    {   // encoding and query parameters
        CHECK(UrlEncode("Major Tom") == "Major%20Tom" && UrlEncode("Major Tom", true) == "Major+Tom");
        CHECK(UrlEncode("a&b=c/d") == "a%26b%3Dc%2Fd");
        CHECK(UrlDecode("Major+Tom%21") == "Major Tom!");
        CHECK(QueryParam("/home/overview/?name=garrus_7&platform=pc", "name") == "garrus_7");
        CHECK(QueryParam("/home/overview/?platform=xbox&amp;name=Tali2185", "name") == "Tali2185");
        CHECK(QueryParam("/x?a=1&b=2#c", "b") == "2" && QueryParam("/x?a=1", "b") == "" && QueryParam("/x", "a") == "");
    }
    {   // the redirect: only a code for N7 HQ's own callback counts
        std::string code;
        CHECK(CodeFromRedirect("https://n7hq.masseffect.com/auth/success?code=QUN0de1&state=x", code) && code == "QUN0de1");
        CHECK(!CodeFromRedirect("https://evil.example/auth/success?code=QUN0de1", code) && code.empty());
        CHECK(!CodeFromRedirect("https://n7hq.masseffect.com.evil.example/auth/success?code=Q", code));
        CHECK(!CodeFromRedirect("https://n7hq.masseffect.com/auth/success?error=access_denied", code));
        CHECK(!CodeFromRedirect("https://signin.ea.com/p/juno/login?fid=abc", code));
        CHECK(HostOf("https://Signin.EA.com/p/juno/login?fid=x") == "signin.ea.com" && HostOf("/x/") == "");
        CHECK(N7Path("https://n7hq.masseffect.com/home/overview/?name=a&platform=xbox") == "/home/overview/?name=a&platform=xbox");
        CHECK(N7Path("/home/overview/?name=a") == "/home/overview/?name=a");
        CHECK(N7Path("https://n7hq.masseffect.com") == "/");
        CHECK(N7Path("https://elsewhere.example/x/") == "");
    }
    {   // pages
        std::string shell = "<html><head><style>p{}</style></head><body><a href=\"/auth/login\">Login</a>"
                            "<form action=\"/account/language/?uri=%2Fhome%2Fcharacters%2F%3Fname%3Dx\"></form>"
                            "<div>The profile you are trying to view is not currently available.</div></body></html>";
        std::string profile = "<a href=\"/auth/logout\">Logout</a><a href=\"/home/overview/?platform=xbox&name=Tali2185\">Overview</a>"
                              "<a href=\"/home/inventory/?platform=xbox&name=Tali2185\">Inventory</a>";
        std::string odd = "<html><body>Maintenance</body></html>";
        CHECK(ClassifyProfile(shell) == Page::Unavailable);
        CHECK(ClassifyProfile(profile) == Page::Profile);
        CHECK(ClassifyProfile(odd) == Page::Unknown);
        CHECK(SignedIn(shell) == 0 && SignedIn(profile) == 1 && SignedIn(odd) == -1);
        std::string exch = "<body><script>var x='<b>';</script><p>An error occurred trying to exchange an auth code. Error: invalid_request : code is not issued to this environment</p>"
                           "<p>&copy; 2026 Electronic Arts Inc.</p></body>";
        CHECK(ExchangeError(exch).find("invalid_request : code is not issued to this environment") == 0);
        CHECK(ExchangeError(profile).empty());
        CHECK(TextOf("<p>a&amp;b</p>\n\n<SCRIPT>x</SCRIPT><i>c</i>") == "a&b c");
        CHECK(FilePart("Major Tom/..\\x") == "Major_Tom_.._x");
    }
    {   // the failure texts fit the box: under 60 characters a line, longest name and console
        Outcome o;
        Fail(o, "N7 HQ: no public " + std::string("PlayStation 3") + " profile '" + std::string(16, 'W') + "'.", "Check the name and console, or make it public there.", "");
        CHECK(o.line1.size() < 60 && o.line2.size() < 60 && !o.ok);
        const char* lines[] = {
            "The EA app did not answer. Is it running?", "Start ME LE from the EA app and try again.",
            "The EA app refused LEMP's connection.", "Restart the EA app, details in mp_save.log.",
            "The EA app gave no sign-in. Are you signed in?", "Sign in to the EA app (not offline mode).",
            "EA asked for a fresh sign-in.", "Sign out and in again in the EA app, then retry.",
            "EA refused the EA app's sign-in for N7 HQ.", "Could not reach EA's sign-in (accounts.ea.com).",
            "Check your internet connection and firewall.", "N7 HQ did not answer (n7hq.masseffect.com).",
            "The site may be down, try again later.", "N7 HQ refused the EA sign-in.", "Try again, and if it repeats, send mp_save.log.",
            "N7 HQ is busy (too many requests).", "Wait a minute and try again.", "N7 HQ did not keep the sign-in.",
            "N7 HQ stopped answering at the Achievements page.", "Try again later, the saved pages are kept.",
            "N7 HQ's pages look different from what LEMP knows.", "Send mp_save.log and the LEMP\\n7hq folder.",
            "Could not save the pages to LEMP\\n7hq.", "Check that Documents is writable (antivirus?).",
            "N7 HQ sent the sign-in somewhere else.", "N7 HQ had a server error after the sign-in.", "Send mp_save.log, nothing was changed.", "That name cannot be a console name.", "Use letters, digits, space, - _ . (up to 16).",
        };
        bool fit = true;
        for (const char* l : lines) if (strlen(l) >= 60 || strchr(l, ';')) { printf("     too long or has ';': %s\n", l); fit = false; }
        CHECK(fit);
    }
    {   // the cookie jar: N7 HQ's session, as its Set-Cookie headers give it
        CookieJar j;
        j.Take("ME3N7HQSID=rm6509nc3mbafean6cg3bm6nj5; path=/; domain=.n7hq.masseffect.com");
        CHECK(j.Header() == "ME3N7HQSID=rm6509nc3mbafean6cg3bm6nj5" && j.Names() == "ME3N7HQSID");
        j.Take("lang=1; path=/");
        j.Take("ME3N7HQSID=newer; path=/");
        CHECK(j.Header() == "ME3N7HQSID=newer; lang=1");
        j.Take("lang=deleted; expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0");
        CHECK(j.Header() == "ME3N7HQSID=newer");
        j.Take("=x; path=/"); j.Take("novalue");
        CHECK(j.c.size() == 1);
        CHECK(CookieJar().Names() == "none");
        CHECK(SearchMiss("<p>No profile was found on Xbox 360 with the name Shepard117.</p><p>&copy; 2026</p>")
              == "No profile was found on Xbox 360 with the name Shepard117.");
        CHECK(SearchMiss("<p>Search results</p>").empty());
        CHECK(Lower("Shepard117") == "shepard117");
    }
    {   // the ways to a code: each one's connect/auth query
        CHECK(kTryCount == 8 && std::string(kTries[0].id) == "B1" && std::string(kTries[3].id) == "A1");
        CHECK(std::string(kTries[6].id) == "A4" && !kTries[6].fromToken && kTries[6].aRedirect);
        CHECK(std::string(kTries[7].id) == "B4" && kTries[7].fromToken && kTries[7].scopedTok);
        std::string b1 = AuthPath(kTries[0], "AT+0/x", "code");
        CHECK(b1.find("/connect/auth?client_id=ME3-N7HQ-WEB-CLIENT&response_type=code") == 0);
        CHECK(b1.find("&redirect_uri=https%3A%2F%2Fn7hq.masseffect.com%2Fauth%2Fsuccess") != std::string::npos);
        CHECK(b1.find("&scope=basic.identity%20basic.persona") != std::string::npos);
        CHECK(b1.find("&access_token=AT%2B0%2Fx") != std::string::npos && b1.find("nonce") == std::string::npos);
        std::string b2 = AuthPath(kTries[1], "T", "code", "77");
        CHECK(b2.find("redirect_uri") == std::string::npos && b2.find("&scope=") != std::string::npos
              && b2.find("&sbiod_enabled=false&locale=en_US&nonce=77") != std::string::npos);
        std::string b3 = AuthPath(kTries[2], "T", "code");
        CHECK(b3.find("scope") == std::string::npos && b3.find("redirect_uri") != std::string::npos);
        CHECK(AuthPath(kTries[0], "T", "token").find("&response_type=token") != std::string::npos);
        CHECK(!kTries[3].fromToken && kTries[3].scope && !kTries[3].append && kTries[4].append && !kTries[5].scope);
    }
    {   // a token out of a redirect: only N7 HQ's own callback
        std::string t;
        CHECK(TokenFromRedirect("https://n7hq.masseffect.com/auth/success#access_token=QVQx%2B&token_type=Bearer&expires_in=3599", t) && t == "QVQx+");
        CHECK(TokenFromRedirect("https://n7hq.masseffect.com/auth/success?access_token=Q2", t) && t == "Q2");
        CHECK(!TokenFromRedirect("https://n7hq.masseffect.com/auth/successX?access_token=Q2", t) && t.empty());
        CHECK(!TokenFromRedirect("https://n7hq.masseffect.com.evil.example/auth/success#access_token=Q", t));
        CHECK(!TokenFromRedirect("https://n7hq.masseffect.com/auth/success?code=QUN", t));
        CHECK(!TokenFromRedirect("https://n7hq.masseffect.com/auth/success", t));
    }
    {   // tokeninfo, as the log gets it: no account id values
        std::string info = "{\"client_id\":\"JUNO_PC_CLIENT\",\"scope\":\"signin basic.identity\",\"expires_in\": 3599 ,"
                           "\"pid_id\":\"1000123456789\",\"pid_type\":\"NUCLEUS\",\"user_id\":\"1000123456789\",\"persona_id\":null,\"is_underage\":false}";
        CHECK(JsonField(info, "client_id") == "JUNO_PC_CLIENT" && JsonField(info, "expires_in") == "3599");
        CHECK(JsonField(info, "persona_id") == "" && JsonField(info, "missing") == "" && JsonField(info, "is_underage") == "false");
        CHECK(JsonField("{\"a\":\"x\\\"y\"}", "a") == "x\"y");
        std::string d = DescribeTokenInfo(200, info);
        CHECK(d == "client JUNO_PC_CLIENT, scope 'signin basic.identity', pid_type NUCLEUS, expires_in 3599, is_underage false, pid_id/user_id present");
        CHECK(d.find("1000123456789") == std::string::npos);
        CHECK(DescribeTokenInfo(400, "{\"error\":\"invalid_request\",\"error_description\":\"access_token is invalid\",\"code\":100103}")
              == "HTTP 400 invalid_request: access_token is invalid (100103)");
        CHECK(DescribeTokenInfo(500, "") == "HTTP 500");
    }
    {   // a profile's summary stat, as a signed-in overview has it
        std::string full = "<td>Time played:</td>\n<td><div class=\"playerstat pstimeplayed\">432H 32M 54S</div></td>";
        std::string empty = "<td><div class=\"playerstat pstimeplayed\">0</div></td>";
        CHECK(PlayerStat(full, "pstimeplayed") == "432H 32M 54S");
        CHECK(PlayerStat(empty, "pstimeplayed") == "0");
        CHECK(PlayerStat("<p>no stats</p>", "pstimeplayed") == "");
    }
    {   // the identity service's personas, as the log gets them
        std::string ok = "{\"personas\":{\"persona\":[{\"personaId\":1000111,\"pidId\":1000123456789,\"displayName\":\"Someone\",\"name\":\"someone\","
                         "\"namespaceName\":\"cem_ea_id\",\"isVisible\":true},{\"personaId\":222,\"displayName\":\"Major Tom 7\",\"namespaceName\":\"xbox\"}]}}";
        CHECK(DescribePersonas(200, ok) == "2 persona(s): cem_ea_id 'Someone', xbox 'Major Tom 7'");
        CHECK(DescribePersonas(200, ok).find("1000123456789") == std::string::npos);
        CHECK(DescribePersonas(403, "{\"error\":\"insufficient_scope\",\"error_description\":\"basic.persona\"}")
              == "HTTP 403, error insufficient_scope, error_description basic.persona");
        CHECK(DescribePersonas(200, "{\"personas\":{\"persona\":[]}}") == "0 persona(s)");
    }
    {   // GetAuthCode with no scope and AppendAuthSource, as A2/A3 send it
        uint16_t port; int l = Listen(port);
        g_saw.clear();
        std::thread t(FakeEaApp, l, App::Code);
        lsx::Client app; app.port = port; app.timeoutMs = 3000;
        std::string code, reply;
        CHECK(app.Connect() && LsxAuthCode(app, "1000123456789", code, reply, "", true) && code == "QUN&0de");
        CHECK(g_saw.size() == 1 && g_saw[0].find("Scope=\"\" AppendAuthSource=\"true\"") != std::string::npos);
        CHECK(g_saw[0].find("RedirectUri") == std::string::npos);
        app.Close();
        t.join(); close(l);
    }
    {   // A4: GetAuthCode with RedirectUri set to N7 HQ's callback
        uint16_t port; int l = Listen(port);
        g_saw.clear();
        std::thread t(FakeEaApp, l, App::Code);
        lsx::Client app; app.port = port; app.timeoutMs = 3000;
        std::string code, reply;
        CHECK(app.Connect() && LsxAuthCode(app, "1000123456789", code, reply, kScope, false, kRedirect) && code == "QUN&0de");
        CHECK(g_saw.size() == 1 && g_saw[0].find("RedirectUri=\"https://n7hq.masseffect.com/auth/success\"") != std::string::npos);
        app.Close();
        t.join(); close(l);
    }
    {   // GetAccessToken: a scoped token when Scope is sent, its reply element otherwise
        uint16_t port; int l = Listen(port);
        g_saw.clear();
        std::thread t(FakeEaApp, l, App::Code);
        lsx::Client app; app.port = port; app.timeoutMs = 3000;
        std::string tok, reply;
        CHECK(app.Connect());
        CHECK(LsxAccessToken(app, "", "", tok, reply) && tok.empty() && reply == "<LSXError>");
        CHECK(LsxAccessToken(app, kScope, "JWS", tok, reply) && tok == "QVQ0scoped" && reply.empty());
        CHECK(g_saw.back().find("Scope=\"basic.identity") != std::string::npos && g_saw.back().find("TokenFormat=\"JWS\"") != std::string::npos);
        app.Close();
        t.join(); close(l);
    }
    for (App mode : {App::Code, App::Refuse, App::NoUser}) {   // the two LSX requests
        uint16_t port; int l = Listen(port);
        g_saw.clear();
        std::thread t(FakeEaApp, l, mode);
        lsx::Client app; app.port = port; app.timeoutMs = 3000;
        std::string uid, reply, code;
        bool ok = app.Connect() && LsxUserId(app, uid, reply);
        CHECK(ok);
        if (mode == App::NoUser) {
            CHECK(uid.empty() && reply == "<ErrorSuccess>");
        } else {
            CHECK(uid == "1000123456789");
            CHECK(LsxAuthCode(app, uid, code, reply));
            if (mode == App::Code) CHECK(code == "QUN&0de" && reply.empty());
            else CHECK(code.empty() && reply == "<AuthCode> 'invalid'");
            CHECK(g_saw.size() == 2 && g_saw[1].find("ClientId=\"ME3-N7HQ-WEB-CLIENT\"") != std::string::npos
                  && g_saw[1].find("UserId=\"1000123456789\"") != std::string::npos
                  && g_saw[1].find("Scope=\"basic.identity basic.persona") != std::string::npos);
        }
        CHECK(g_saw.size() >= 1 && g_saw[0].find("<GetProfile index=\"0\"/>") != std::string::npos);
        app.Close();
        t.join(); close(l);
    }
    {   // a reconnect after the app dropped the connection starts clean
        uint16_t port; int l = Listen(port);
        std::thread t([l] { int c = accept(l, nullptr, nullptr); if (c >= 0) close(c); FakeEaApp(l, App::Code); });
        lsx::Client app; app.port = port; app.timeoutMs = 3000;
        CHECK(!app.Connect() && !app.err.empty());
        std::string uid, reply;
        CHECK(app.Connect() && app.err.empty() && LsxUserId(app, uid, reply) && uid == "1000123456789");
        app.Close();
        t.join(); close(l);
    }
    printf("%s (%d failure(s))\n", fails ? "FAILED" : "all passed", fails);
    return fails ? 1 : 0;
}
