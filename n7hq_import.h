// n7hq_import.h — reading a console player's ME3 profile from N7 HQ
// (n7hq.masseffect.com), signed in through the EA app.
//
// N7 HQ signs in with EA's OAuth code flow: /auth/login redirects to
//   accounts.ea.com/connect/auth?client_id=ME3-N7HQ-WEB-CLIENT&scope=...
//     &response_type=code&redirect_uri=https://n7hq.masseffect.com/auth/success
// and /auth/success?code=... trades the code for the site's session cookie
// (ME3N7HQSID). Profiles are addressed by name and platform
// (/home/<tab>/?name=...&platform=xbox|ps3|pc|wiiu), and viewing one needs a
// signed-in session; anonymous requests get "The profile you are trying to
// view is not currently available." The search box (POST /search/,
// player_name + platform) redirects to the profile's overview.
//
// The code comes from the EA app the player is signed in to, never from a
// password:
//   A. LSX <GetAuthCode UserId=.. ClientId=.. Scope=.. AppendAuthSource=../>
//      (origin-sdk's protocol; Maxima's EA app answers it with
//      connect/auth?access_token=<the account's>, the code taken from the
//      redirect's Location).
//   B. The EA app's GetAuthToken token as connect/auth's access_token, with
//      N7 HQ's client id (EA reads that parameter: a bad one is answered with
//      "access_token is invalid", code 100103), redirects not followed.
// N7 HQ took both kinds of code, then answered 500 on every page of the
// session, while a browser's session reads them with its cookie alone. So
// several variants of A and B are tried in turn (kTries), each in a session
// of its own, and tokeninfo is asked what the EA app's token holds.
// The code, the token and the cookie are credentials. They go to
// accounts.ea.com and n7hq.masseffect.com only, over HTTPS with WinHTTP's
// certificate check, and are never logged or written to disk.
//
// The profile's pages are saved, then converted into the local save
// (n7hq_convert.h, n7hq_synth.h). A pasted session token skips the EA app.
#pragma once
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include "ea_lsx.h"   // the EA app (portable: its tests run natively)
#include "console_probe.h"   // EA's ME3 servers for the consoles

namespace ea {
namespace n7hq {

static const char kClientId[] = "ME3-N7HQ-WEB-CLIENT";
static const char kScope[] = "basic.identity basic.persona basic.entitlement openid signin offline search.identity";
static const char kHost[] = "n7hq.masseffect.com";
static const char kRedirect[] = "https://n7hq.masseffect.com/auth/success";
static const char kEaHost[] = "accounts.ea.com";
static const char kTabRoot[] = "/home/";   // N7 HQ's profile pages, /home/<tab>/?name=..&platform=..

// The platforms N7 HQ lists (its search box's <select name="platform">). PC
// is here too, beside the EA import (ea_import.h), which copies a PC profile
// exactly where this one converts N7 HQ's pages.
struct Platform { const char* id; const char* label; };
inline const Platform* FindPlatform(const std::string& id) {
    static const Platform k[] = { {"xbox", "Xbox 360"}, {"ps3", "PlayStation 3"}, {"wiiu", "Wii U"}, {"pc", "PC/Origin"} };
    for (const Platform& p : k) if (id == p.id) return &p;
    return nullptr;
}

// Gamertags, PSN IDs and Nintendo Network IDs: up to 16 of letters, digits,
// space, '-', '_' and '.', not blank.
static const size_t kMaxName = 16;
inline bool ValidName(const std::string& n) {
    if (n.empty() || n.size() > kMaxName) return false;
    bool any = false;
    for (char c : n) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ' || c == '-' || c == '_' || c == '.';
        if (!ok) return false;
        if (c != ' ') any = true;
    }
    return any;
}

// Percent-encoding; `form` writes a space as '+' (application/x-www-form-urlencoded).
inline std::string UrlEncode(const std::string& s, bool form = false) {
    static const char* hex = "0123456789ABCDEF";
    std::string o;
    for (unsigned char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') o += (char)c;
        else if (c == ' ' && form) o += '+';
        else { o += '%'; o += hex[c >> 4]; o += hex[c & 15]; }
    }
    return o;
}
inline std::string UrlDecode(const std::string& s) {
    std::string o;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '+') o += ' ';
        else if (s[i] == '%' && i + 2 < s.size() && isxdigit((unsigned char)s[i + 1]) && isxdigit((unsigned char)s[i + 2])) {
            o += (char)strtol(s.substr(i + 1, 2).c_str(), nullptr, 16); i += 2;
        } else o += s[i];
    }
    return o;
}
// One query parameter of a URL ("" when absent), decoded. "&amp;" counts as
// '&' (an HTML page's link).
inline std::string QueryParam(const std::string& url, const std::string& key) {
    size_t q = url.find('?');
    if (q == std::string::npos) return "";
    std::string rest = url.substr(q + 1);
    size_t h = rest.find('#');
    if (h != std::string::npos) rest.resize(h);
    for (size_t p; (p = rest.find("&amp;")) != std::string::npos;) rest.replace(p, 5, "&");
    size_t i = 0;
    while (i <= rest.size()) {
        size_t e = rest.find('&', i);
        if (e == std::string::npos) e = rest.size();
        std::string part = rest.substr(i, e - i);
        size_t eq = part.find('=');
        if (part.substr(0, eq) == key) return eq == std::string::npos ? "" : UrlDecode(part.substr(eq + 1));
        i = e + 1;
    }
    return "";
}
// The code out of connect/auth's redirect. Only a redirect to N7 HQ's own
// callback counts: a code meant for anywhere else is not used.
inline bool CodeFromRedirect(const std::string& location, std::string& code) {
    code.clear();
    std::string base = std::string(kRedirect) + "?";
    if (location.compare(0, base.size(), base) != 0) return false;
    code = QueryParam(location, "code");
    return !code.empty();
}
// A Location's host ("" for a relative one), lower case.
inline std::string HostOf(const std::string& url) {
    size_t s = url.find("://");
    if (s == std::string::npos) return "";
    size_t b = s + 3, e = url.find_first_of("/?#", b);
    std::string h = url.substr(b, e == std::string::npos ? std::string::npos : e - b);
    for (char& c : h) c = (char)tolower((unsigned char)c);
    return h;
}
// The path and query of a Location on N7 HQ ("" if it points elsewhere).
inline std::string N7Path(const std::string& location) {
    if (!location.empty() && location[0] == '/') return location;
    if (HostOf(location) != kHost) return "";
    size_t b = location.find('/', location.find("://") + 3);
    return b == std::string::npos ? "/" : location.substr(b);
}

// Case-insensitive prefix compare of n bytes.
inline bool strncasecmp_portable(const char* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; ++i) if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return false;
    return true;
}
// A page's visible text: scripts, styles and tags dropped, five entities
// unescaped, whitespace collapsed.
inline std::string TextOf(const std::string& html) {
    std::string o, lower = html;
    for (char& c : lower) c = (char)tolower((unsigned char)c);
    size_t i = 0;
    auto skipBlock = [&](const char* open, const char* close) {
        size_t n = strlen(open);
        if (html.size() - i >= n && strncasecmp_portable(html.c_str() + i, open, n)) {
            size_t e = lower.find(close, i);
            i = e == std::string::npos ? html.size() : e + strlen(close);
            return true;
        }
        return false;
    };
    while (i < html.size()) {
        if (html[i] == '<') {
            if (skipBlock("<script", "</script>") || skipBlock("<style", "</style>")) { o += ' '; continue; }
            size_t e = html.find('>', i);
            i = e == std::string::npos ? html.size() : e + 1;
            o += ' ';
            continue;
        }
        if (html[i] == '&') {
            static const char* ent[][2] = { {"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", "\""}, {"&#039;", "'"}, {"&nbsp;", " "} };
            bool hit = false;
            for (auto& en : ent) { size_t l = strlen(en[0]); if (!html.compare(i, l, en[0])) { o += en[1]; i += l; hit = true; break; } }
            if (hit) continue;
        }
        o += html[i++];
    }
    std::string c;
    for (char ch : o) {
        bool ws = ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t';
        if (ws) { if (!c.empty() && c.back() != ' ') c += ' '; }
        else c += ch;
    }
    while (!c.empty() && c.back() == ' ') c.pop_back();
    return c;
}

// What a profile page is.
enum class Page { Profile, Unavailable, Unknown };
inline Page ClassifyProfile(const std::string& html) {
    if (html.find("not currently available") != std::string::npos) return Page::Unavailable;
    // A profile links its own tabs; the "not available" page has none.
    if (html.find("/home/overview/?") != std::string::npos && html.find("/home/inventory/?") != std::string::npos) return Page::Profile;
    return Page::Unknown;
}
// 1 signed in, 0 not, -1 cannot tell. Anonymous pages link /auth/login, a
// signed-in page /auth/logout (seen on a browser's signed-in overview).
inline int SignedIn(const std::string& html) {
    if (html.find("/auth/logout") != std::string::npos) return 1;
    if (html.find("/auth/login") != std::string::npos) return 0;
    return -1;
}
// N7 HQ's own words when its code exchange failed, "" otherwise:
// "An error occurred trying to exchange an auth code. Error: invalid_request
// : code is not issued to this environment".
inline std::string ExchangeError(const std::string& html) {
    std::string t = TextOf(html);
    size_t p = t.find("error occurred trying to exchange");
    if (p == std::string::npos) return "";
    size_t e = t.find("Error:", p);
    std::string why = e == std::string::npos ? "unknown" : t.substr(e + 6, 120);
    while (!why.empty() && why[0] == ' ') why.erase(0, 1);
    size_t end = why.find(" \xC2\xA9");   // the footer's copyright sign
    if (end != std::string::npos) why.resize(end);
    return why;
}
// A name made safe for a file name.
inline std::string FilePart(const std::string& s) {
    std::string o;
    for (char c : s) o += ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') ? c : '_';
    return o;
}

// N7 HQ's session cookie, kept by hand. Wine's WinHTTP (the game runs under
// Proton on Linux) did not send back ME3N7HQSID, set with
// "domain=.n7hq.masseffect.com": every request after the sign-in was
// anonymous. So automatic cookies are off and the jar is ours: each
// Set-Cookie's name=value is kept (Max-Age=0 or an empty value drops it) and
// sent back on every request to N7 HQ. Values are credentials: never logged.
struct CookieJar {
    std::vector<std::pair<std::string, std::string>> c;
    void Take(const std::string& setCookie) {
        std::string pair = setCookie.substr(0, setCookie.find(';'));
        size_t eq = pair.find('=');
        if (eq == std::string::npos || eq == 0) return;
        auto trim = [](std::string v) {
            while (!v.empty() && (v[0] == ' ' || v[0] == '\t')) v.erase(0, 1);
            while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.pop_back();
            return v;
        };
        std::string name = trim(pair.substr(0, eq)), value = trim(pair.substr(eq + 1));
        std::string lower = setCookie;
        for (char& ch : lower) ch = (char)tolower((unsigned char)ch);
        bool drop = value.empty() || value == "deleted" || lower.find("max-age=0") != std::string::npos;
        for (size_t i = 0; i < c.size(); ++i)
            if (c[i].first == name) { if (drop) c.erase(c.begin() + i); else c[i].second = value; return; }
        if (!drop) c.push_back({name, value});
    }
    std::string Header() const {
        std::string h;
        for (auto& kv : c) h += (h.empty() ? "" : "; ") + kv.first + "=" + kv.second;
        return h;
    }
    std::string Names() const {
        std::string n;
        for (auto& kv : c) n += (n.empty() ? "" : ", ") + kv.first;
        return n.empty() ? "none" : n;
    }
};

// One of a profile's summary stats ("" if absent): the text of its
// <div class="playerstat <cls>">, e.g. "432H 32M 54S" for pstimeplayed. A
// signed-in session without the game-data scopes shows "0" for everyone.
inline std::string PlayerStat(const std::string& html, const std::string& cls) {
    size_t p = html.find("playerstat " + cls + "\"");
    if (p == std::string::npos) return "";
    p = html.find('>', p);
    size_t e = p == std::string::npos ? std::string::npos : html.find('<', p);
    if (e == std::string::npos) return "";
    std::string v = html.substr(p + 1, e - p - 1);
    while (!v.empty() && (v[0] == ' ' || v[0] == '\n' || v[0] == '\r' || v[0] == '\t')) v.erase(0, 1);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\n' || v.back() == '\r' || v.back() == '\t')) v.pop_back();
    return v;
}

// N7 HQ's search page for a name it does not know: "No profile was found on
// Xbox 360 with the name X." ("" otherwise). An anonymous search said this
// for a profile its owner could open signed in, so it is logged, not obeyed.
inline std::string SearchMiss(const std::string& html) {
    std::string t = TextOf(html);
    size_t p = t.find("No profile was found");
    if (p == std::string::npos) return "";
    size_t e = t.find('.', p);
    return t.substr(p, e == std::string::npos ? 120 : e - p + 1);
}
inline std::string Lower(std::string s) { for (char& ch : s) ch = (char)tolower((unsigned char)ch); return s; }

// The profile's tabs, in the order they are read and saved.
static const char* const kTabs[] = { "overview", "inventory", "characters", "challenges", "achievements" };
static const int kTabCount = 5;

// ---- the result, and what the player is told -------------------------------

// A failure is two lines for the menu's box (each under 60 characters: what
// happened, then what to do) and a fuller line for the log.
struct Outcome {
    bool ok = false;
    std::string line1, line2;   // the box
    std::string detail;         // the log only; never a credential
    std::string name;           // the profile's name as N7 HQ spells it
    int pages = 0;              // saved
};
inline bool Fail(Outcome& o, const std::string& l1, const std::string& l2, const std::string& detail) {
    o.ok = false; o.line1 = l1; o.line2 = l2; o.detail = detail;
    return false;
}

// The two LSX requests this needs beyond GetAuthToken (ea_lsx.h's client).
// Both return false only when the EA app did not answer (the client is then
// closed); a refusal returns true with the value empty and `reply` naming
// the element the EA app sent instead (never a value).
inline std::string ReplyElement(const std::string& r) {
    size_t e = r.find("<Response");
    size_t s = e == std::string::npos ? std::string::npos : r.find('<', r.find('>', e));
    if (s == std::string::npos) return "(nothing)";
    size_t n = s + 1;
    while (n < r.size() && r[n] != ' ' && r[n] != '>' && r[n] != '/') ++n;
    return "<" + r.substr(s + 1, n - s - 1) + ">";
}
inline bool LsxUserId(lsx::Client& c, std::string& uid, std::string& reply) {
    std::string r;
    uid.clear(); reply.clear();
    if (!c.Request("<GetProfile index=\"0\"/>", r)) return false;
    size_t p = r.find("<GetProfileResponse");
    if (p == std::string::npos || !lsx::Attr(r.substr(p), "UserId", uid) || uid.empty() || uid == "0") {
        uid.clear(); reply = ReplyElement(r);
    }
    return true;
}
inline bool LsxAuthCode(lsx::Client& c, const std::string& uid, std::string& code, std::string& reply,
                        const std::string& scope = kScope, bool appendAuthSource = false,
                        const std::string& redirectUri = "") {
    std::string r;
    code.clear(); reply.clear();
    // RedirectUri is a real GetAuthCode attribute (the EA app's LSX schema:
    // UserId, ClientId, Scope, AppendAuthSource, RedirectUri,
    // ReleaseTypeOverride). N7 HQ exchanges a code against its own
    // redirect_uri, so a code minted here against the same one may be the
    // one it takes; empty omits it, as before.
    std::string req = "<GetAuthCode UserId=\"" + lsx::Escape(uid) + "\" ClientId=\"" + kClientId + "\" Scope=\"" +
                      lsx::Escape(scope) + "\" AppendAuthSource=\"" + (appendAuthSource ? "true" : "false") + "\"";
    if (!redirectUri.empty()) req += " RedirectUri=\"" + lsx::Escape(redirectUri) + "\"";
    req += "/>";
    if (!c.Request(req, r)) return false;
    size_t p = r.find("<AuthCode");
    if (p == std::string::npos || !lsx::Attr(r.substr(p), "value", code) || code.empty() || code == "invalid") {
        reply = p == std::string::npos ? ReplyElement(r) : code.empty() ? "<AuthCode> with no value" : "<AuthCode> 'invalid'";
        code.clear();
    }
    return true;
}

// Research only: ask the EA app's LSX GetAccessToken for a token, with a
// chosen Scope/TokenFormat (empty omitted). Its attributes are not in the EA
// app's strings; if one is wrong the EA app answers with some element, which
// `reply` reports (ReplyElement), so the real shape is learned, not invented.
// Returns false only when the connection dropped. The token is a credential:
// returned to the caller, never logged.
inline bool LsxAccessToken(lsx::Client& c, const std::string& scope, const std::string& tokenFormat,
                           std::string& token, std::string& reply) {
    std::string r;
    token.clear(); reply.clear();
    std::string req = "<GetAccessToken";
    if (!scope.empty()) req += " Scope=\"" + lsx::Escape(scope) + "\"";
    if (!tokenFormat.empty()) req += " TokenFormat=\"" + lsx::Escape(tokenFormat) + "\"";
    req += "/>";
    if (!c.Request(req, r)) return false;
    // The EA app answers GetAccessToken with an <AuthToken value=..> element
    // (the same element GetAuthToken uses) [V]; <AccessToken> is
    // accepted too in case a build differs.
    for (const char* el : {"<AuthToken", "<AccessToken"}) {
        size_t p = r.find(el);
        if (p != std::string::npos && lsx::Attr(r.substr(p), "value", token) && !token.empty()) return true;
    }
    token.clear();
    reply = ReplyElement(r);
    return true;
}

// ---- the ways to a code, tried in turn --------------------------------------

// Every code the EA app gave was taken by N7 HQ (/auth/success 302), and every
// session made from one answered an empty 500 on every page, while a session
// from a browser's EA sign-in reads the same pages with nothing but its
// ME3N7HQSID cookie. So the code itself differs. Not known how: each way
// below changes one thing, gets its own code and its own N7 HQ session, and
// the read goes on with the first session whose / is signed in.
struct Try {
    const char* id;     // for the log: "B1", "A2", ...
    const char* what;
    bool fromToken;     // B: connect/auth with the EA app's token; A: LSX GetAuthCode
    bool scope;         // N7 HQ's scope (its /auth/login asks for it), or none
    bool redirect;      // B: redirect_uri sent (else the client's default)
    bool appExtras;     // B: nonce, locale, sbiod_enabled, as Maxima's EA app sends them
    bool append;        // A: AppendAuthSource="true"
    bool aRedirect;     // A: GetAuthCode with RedirectUri = N7 HQ's callback
    bool scopedTok;     // B: use the GetAccessToken scoped token, not the launch token
};
static const Try kTries[] = {
    {"B1", "connect/auth, N7 HQ's scope and redirect_uri", true, true, true, false, false, false, false},
    {"B2", "connect/auth as the EA app sends it", true, true, false, true, false, false, false},
    {"B3", "connect/auth, no scope", true, false, true, false, false, false, false},
    {"A1", "GetAuthCode", false, true, false, false, false, false, false},
    {"A2", "GetAuthCode, AppendAuthSource", false, true, false, false, true, false, false},
    {"A3", "GetAuthCode, no scope", false, false, false, false, false, false, false},
    {"A4", "GetAuthCode, RedirectUri to N7 HQ", false, true, false, false, false, true, false},
    {"B4", "connect/auth with the GetAccessToken scoped token", true, true, true, false, false, false, true},
};
static const int kTryCount = (int)(sizeof kTries / sizeof kTries[0]);

// connect/auth's path and query for a B way. `responseType` "code" for a
// sign-in, "token" to see (tokeninfo) what N7 HQ's client would be given.
inline std::string AuthPath(const Try& t, const std::string& token, const char* responseType, const std::string& nonce = "") {
    std::string p = std::string("/connect/auth?client_id=") + kClientId + "&response_type=" + responseType;
    if (t.redirect) p += std::string("&redirect_uri=") + UrlEncode(kRedirect);
    if (t.scope) p += std::string("&scope=") + UrlEncode(kScope);
    if (t.appExtras) p += "&sbiod_enabled=false&locale=en_US&nonce=" + nonce;
    return p + "&access_token=" + UrlEncode(token);
}

// The access_token out of a response_type=token redirect to N7 HQ's callback
// (in the fragment or the query). Anywhere else does not count.
inline bool TokenFromRedirect(const std::string& location, std::string& token) {
    token.clear();
    std::string base = kRedirect;
    if (location.compare(0, base.size(), base) != 0 || location.size() == base.size()) return false;
    char sep = location[base.size()];
    if (sep != '?' && sep != '#') return false;
    std::string q = "?" + location.substr(base.size() + 1);
    for (char& c : q) if (c == '#') c = '&';
    token = QueryParam(q, "access_token");
    return !token.empty();
}

// A flat JSON object's field, as text ("" when absent or null): "k":"v" or "k":123.
inline std::string JsonField(const std::string& json, const std::string& key) {
    std::string k = "\"" + key + "\"";
    size_t p = json.find(k);
    if (p == std::string::npos) return "";
    p = json.find(':', p + k.size());
    if (p == std::string::npos) return "";
    while (++p < json.size() && (json[p] == ' ' || json[p] == '\t')) {}
    if (p >= json.size()) return "";
    if (json[p] == '"') {
        std::string v;
        for (++p; p < json.size() && json[p] != '"'; ++p) {
            if (json[p] == '\\' && p + 1 < json.size()) ++p;
            v += json[p];
        }
        return v;
    }
    size_t e = json.find_first_of(",}", p);
    std::string v = json.substr(p, e == std::string::npos ? std::string::npos : e - p);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\n' || v.back() == '\r')) v.pop_back();
    return v == "null" ? "" : v;
}
// The personas EA's identity service lists for the account
// (/proxy/identity/pids/me/personas), for the log: "<namespace> '<name>'"
// each. The namespace says where a persona lives (cem_ea_id for EA/Origin,
// xbox, ps3, ...). An error answer is reduced to its error fields.
inline std::string DescribePersonas(int status, const std::string& json) {
    if (status != 200) {
        std::string o = "HTTP " + std::to_string(status);
        for (const char* f : {"error", "error_description", "code", "message"}) {
            std::string v = JsonField(json, f);
            if (!v.empty()) o += std::string(", ") + f + " " + v;
        }
        return o;
    }
    std::string o;
    int n = 0;
    for (size_t at = 0; (at = json.find("\"namespaceName\"", at)) != std::string::npos; at += 15) {
        size_t b = json.rfind('{', at), e = json.find('}', at);
        std::string obj = json.substr(b == std::string::npos ? 0 : b, e == std::string::npos ? std::string::npos : e - (b == std::string::npos ? 0 : b) + 1);
        o += std::string(o.empty() ? "" : ", ") + JsonField(obj, "namespaceName") + " '" + JsonField(obj, "displayName") + "'";
        ++n;
    }
    return std::to_string(n) + " persona(s)" + (o.empty() ? "" : ": " + o);
}

// What tokeninfo says of a token, for the log: its client, scope, kind and
// lifetime. The account's ids only as present or not. An error answer is
// reduced to its error fields.
inline std::string DescribeTokenInfo(int status, const std::string& json) {
    if (status != 200) {
        std::string e = JsonField(json, "error"), d = JsonField(json, "error_description"), c = JsonField(json, "code");
        return "HTTP " + std::to_string(status) + (e.empty() ? "" : " " + e) + (d.empty() ? "" : ": " + d) + (c.empty() ? "" : " (" + c + ")");
    }
    std::string o = "client " + JsonField(json, "client_id") + ", scope '" + JsonField(json, "scope") + "'";
    for (const char* f : {"pid_type", "expires_in", "console_env", "is_underage"}) {
        std::string v = JsonField(json, f);
        if (!v.empty()) o += std::string(", ") + f + " " + v;
    }
    std::string ids;
    for (const char* f : {"pid_id", "user_id", "persona_id"})
        if (!JsonField(json, f).empty()) ids += std::string(ids.empty() ? "" : "/") + f;
    return o + ", " + (ids.empty() ? "no account ids" : ids + " present");
}


}  // namespace n7hq
}  // namespace ea

#ifdef _WIN32
#include <winhttp.h>

namespace ea {
namespace n7hq {

// One WinHTTP session: it keeps N7 HQ's cookie between requests. Redirects
// are not followed, so every Location is checked before anything goes to it.
class Web {
public:
    DWORD lastError = 0;
    CookieJar jar;
    std::wstring extraHeaders;   // sent with every request, "Name: value\r\n" each
    Web() {
        s_ = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (s_) WinHttpSetTimeouts(s_, 10000, 10000, 15000, 20000);
    }
    ~Web() { if (s_) WinHttpCloseHandle(s_); extraHeaders.assign(extraHeaders.size(), L'\0'); }
    bool Ok() const { return s_ != nullptr; }

    // false: no answer at all (lastError says why). `status` 0 then.
    // A transient TLS or connection failure (common on Proton's schannel) is
    // retried once; a real HTTP status (incl. 5xx) is not an error here and
    // comes back on the first try.
    bool Request(const wchar_t* method, const char* host, const std::string& path, const std::string& form,
                 int& status, std::string& location, std::string& body) {
        for (int attempt = 0; attempt < 2; ++attempt) {
            if (RequestOnce(method, host, path, form, status, location, body)) return true;
            if (lastError != ERROR_WINHTTP_SECURE_CHANNEL_ERROR && lastError != ERROR_WINHTTP_CONNECTION_ERROR &&
                lastError != ERROR_WINHTTP_TIMEOUT && lastError != ERROR_WINHTTP_CANNOT_CONNECT)
                return false;
        }
        return false;
    }
    bool RequestOnce(const wchar_t* method, const char* host, const std::string& path, const std::string& form,
                     int& status, std::string& location, std::string& body) {
        status = 0; location.clear(); body.clear(); lastError = 0;
        if (!s_) { lastError = ERROR_INVALID_HANDLE; return false; }
        HINTERNET c = WinHttpConnect(s_, Wide(host).c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!c) { lastError = GetLastError(); return false; }
        HINTERNET r = WinHttpOpenRequest(c, method, Wide(path).c_str(), nullptr, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        bool ok = false;
        if (r) {
            DWORD pol = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            WinHttpSetOption(r, WINHTTP_OPTION_REDIRECT_POLICY, &pol, sizeof pol);
            DWORD feat = WINHTTP_DISABLE_COOKIES;   // the jar sends them (CookieJar)
            WinHttpSetOption(r, WINHTTP_OPTION_DISABLE_FEATURE, &feat, sizeof feat);
            // A browser's Accept and Accept-Language: without them the signed-in
            // home page answered 500 in the first runs.
            std::wstring hdr = L"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                               L"Accept-Language: en-US,en;q=0.9\r\n";
            if (!form.empty()) hdr += L"Content-Type: application/x-www-form-urlencoded\r\n";
            hdr += extraHeaders;
            if (!jar.c.empty()) hdr += L"Cookie: " + Wide(jar.Header()) + L"\r\n";
            if (WinHttpSendRequest(r, hdr.c_str(), (DWORD)-1L,
                                   form.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)form.data(), (DWORD)form.size(), (DWORD)form.size(), 0)
                && WinHttpReceiveResponse(r, nullptr)) {
                DWORD code = 0, len = sizeof code;
                WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                                    &code, &len, WINHTTP_NO_HEADER_INDEX);
                status = (int)code;
                for (DWORD idx = 0;;) {
                    wchar_t sc[4096]; DWORD sl = sizeof sc;
                    DWORD before = idx;
                    if (!WinHttpQueryHeaders(r, WINHTTP_QUERY_SET_COOKIE, WINHTTP_HEADER_NAME_BY_INDEX, sc, &sl, &idx)) break;
                    std::string line;
                    for (DWORD i = 0; i < sl / sizeof(wchar_t); ++i) line += (char)(sc[i] < 128 ? sc[i] : '?');
                    jar.Take(line);
                    if (idx == before) break;   // an index that does not move would loop
                }
                wchar_t loc[2048]; DWORD ll = sizeof loc;
                if (WinHttpQueryHeaders(r, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX, loc, &ll, WINHTTP_NO_HEADER_INDEX))
                    for (DWORD i = 0; i < ll / sizeof(wchar_t); ++i) location += (char)(loc[i] < 128 ? loc[i] : '?');
                ok = true;
                for (;;) {
                    DWORD avail = 0;
                    if (!WinHttpQueryDataAvailable(r, &avail)) { ok = false; break; }
                    if (avail == 0) break;
                    if (body.size() + avail > (8u << 20)) { ok = false; lastError = ERROR_BUFFER_OVERFLOW; break; }
                    size_t at = body.size(); body.resize(at + avail);
                    DWORD got = 0;
                    if (!WinHttpReadData(r, &body[at], avail, &got)) { ok = false; break; }
                    body.resize(at + got);
                }
            }
            if (!ok && !lastError) lastError = GetLastError();
            WinHttpCloseHandle(r);
        } else lastError = GetLastError();
        WinHttpCloseHandle(c);
        return ok;
    }

private:
    HINTERNET s_ = nullptr;
    static std::wstring Wide(const std::string& s) { return std::wstring(s.begin(), s.end()); }
};

// Step callback: step 1-4, and in step 4 the page being read (1-5).
using Progress = std::function<void(int step, int page)>;
using LogFn = std::function<void(const std::string&)>;

// The whole read: sign-in, search, the five tabs saved under `dir` as
// <platform>-<name>-<tab>.html. Never touches the local save.
// `session`, when given, is a pasted N7 HQ session cookie (ME3N7HQSID): the
// read uses it directly and the whole EA-app sign-in is skipped. A browser's
// own session carries N7 HQ's full scopes, which the EA app's token does not,
// so this is the one way the console read works. The value is the player's
// own credential: used only against n7hq.masseffect.com, never logged.
inline bool ReadProfile(const std::string& platform, const std::string& name, const std::wstring& dir,
                        Outcome& o, const Progress& step, const LogFn& log, const std::string& session = "") {
    o = Outcome();
    const Platform* plat = FindPlatform(platform);
    if (!plat) return Fail(o, "That platform is not one N7 HQ lists.", "Pick Xbox 360, PlayStation 3, Wii U or PC.", "platform '" + platform + "'");
    if (!ValidName(name)) return Fail(o, "That name cannot be a console name.", "Use letters, digits, space, - _ . (up to 16).", "name refused");
    std::string label = plat->label;
    std::string scopedToken;   // from GetAccessToken with N7 HQ's scope, for route B4
    std::unique_ptr<Web> cur;  // the signed-in N7 HQ session (from the EA sign-in, or the pasted cookie)
    int st = 0; std::string loc, body;
    int signedIn = 1;
    bool ownPages500 = false;  // signed in, but the account's own pages answer 500
    std::string route;
    bool afterSignIn = false;   // set once N7 HQ has taken the code
    auto unreachable = [&](const char* what) {
        DWORD le = cur ? cur->lastError : 0;
        if (st == 0) return Fail(o, "N7 HQ did not answer (n7hq.masseffect.com).", "The site may be down, try again later.",
                                 std::string(what) + ": WinHTTP error " + std::to_string(le));
        // Every page answered 500 for the signed-in session while the site
        // answered signed out: a failure of this sign-in, not an outage.
        if (st >= 500 && afterSignIn)
            return Fail(o, "N7 HQ had a server error after the sign-in.", "Send mp_save.log, nothing was changed.",
                        std::string(what) + ": HTTP " + std::to_string(st) + (route.empty() ? "" : " (code from " + route + ")"));
        if (st == 429) return Fail(o, "N7 HQ is busy (too many requests).", "Wait a minute and try again.", std::string(what) + ": 429");
        return Fail(o, "N7 HQ did not answer (n7hq.masseffect.com).", "The site may be down, try again later.",
                    std::string(what) + ": HTTP " + std::to_string(st));
    };
    // A server error's page is kept as LEMP\n7hq\error-<n>.html and its words
    // logged: what N7 HQ said is the only clue to why.
    int errors = 0;
    auto keepError = [&](const std::string& what) {
        std::wstring f = dir + L"\\error-" + std::to_wstring(++errors) + L".html";
        FILE* fh = _wfopen(f.c_str(), L"wb");
        if (fh) { fwrite(body.data(), 1, body.size(), fh); fclose(fh); }
        std::string words = TextOf(body).substr(0, 240);
        log("n7hq: " + what + ": HTTP " + std::to_string(st) + ", " + std::to_string(body.size()) + " bytes" +
            (fh ? ", saved as error-" + std::to_string(errors) + ".html" : "") + (words.empty() ? "" : ": " + words));
    };

    // A pasted session cookie skips the whole EA-app sign-in (steps 1-2).
    if (!session.empty()) {
        step(2, 0);
        CreateDirectoryW(dir.c_str(), nullptr);
        log("n7hq: using a pasted N7 HQ session (ME3N7HQSID " + std::to_string(session.size()) + " chars), EA sign-in skipped");
        // N7 HQ answered some fresh connections with the signed-out page (its
        // /auth/login link) for a session that the next connection, a few
        // seconds later, read every page with. Every request of one connection
        // got the same answer, so a signed-out first answer starts over on a
        // new connection, a few times, before the session counts as refused.
        const int kSessionTries = 5;
        for (int tryNo = 1;; ++tryNo) {
            cur.reset(new Web);
            cur->jar.Take("ME3N7HQSID=" + session);
            if (!cur->Request(L"GET", kHost, kTabRoot, "", st, loc, body) || st >= 300 || SignedIn(body) != 0) break;
            log("n7hq: step 2: connection " + std::to_string(tryNo) + " answered signed out" +
                (tryNo < kSessionTries ? ", trying a new connection" : ""));
            if (tryNo == kSessionTries)
                return Fail(o, "N7 HQ did not accept the session token.", "Sign in to N7 HQ again, copy a new token and retry.",
                            "the signed-out page on " + std::to_string(kSessionTries) + " connections");
            Sleep(1500);
        }
    } else {

    // 1. The EA app: its token (the B ways, and what tokeninfo says of it) and
    // the account's user id (the A ways).
    step(1, 0);
    lsx::Client app;
    if (!app.Connect()) {
        if (app.err.find("not running") != std::string::npos)
            return Fail(o, "The EA app did not answer. Is it running?", "Start ME LE from the EA app and try again.", "EA app: " + app.err);
        return Fail(o, "The EA app refused LEMP's connection.", "Restart the EA app, details in mp_save.log.", "EA app: " + app.err);
    }
    std::string token, uid, why;
    if (app.GetAuthToken(token)) {
        log("n7hq: step 1: EA app token, " + std::to_string(token.size()) + " chars");
    } else {
        why = "no token: " + app.err;
        log("n7hq: step 1: EA app gave no token: " + app.err);
        if (!app.Connect())   // the client closes on a failure
            return Fail(o, "The EA app refused LEMP's connection.", "Restart the EA app, details in mp_save.log.", "EA app: " + app.err);
    }
    {
        std::string reply;
        if (!LsxUserId(app, uid, reply)) {
            log("n7hq: step 1: the EA app dropped the connection at GetProfile: " + app.err);
            if (!app.Connect() || !LsxUserId(app, uid, reply)) uid.clear();
        }
        if (uid.empty()) log("n7hq: step 1: EA app GetProfile gave no user id: " + (reply.empty() ? app.err : reply));
    }
    auto wipe = [](std::string& s) { s.assign(s.size(), '\0'); };
    if (token.empty() && uid.empty())
        return Fail(o, "The EA app gave no sign-in. Are you signed in?", "Sign in to the EA app (not offline mode).", why + ", and no user id");
    // N7 HQ makes its session from the token its code is exchanged for, so
    // what such a token holds is the first thing to know: tokeninfo on the EA
    // app's token, and on one minted from it for N7 HQ's client.
    Web ea;
    auto describe = [&](const std::string& t, const char* what) {
        int s = 0; std::string l, b;
        bool sent = ea.Request(L"GET", kEaHost, "/connect/tokeninfo?access_token=" + UrlEncode(t), "", s, l, b);
        log(std::string("n7hq: step 1: tokeninfo, ") + what + ": " + (sent ? DescribeTokenInfo(s, b) : "WinHTTP error " + std::to_string(ea.lastError)));
        wipe(b);
    };
    if (!token.empty()) {
        describe(token, "the EA app's token");
        int s = 0; std::string l, b, minted;
        std::string path = AuthPath(kTries[0], token, "token");
        bool sent = ea.Request(L"GET", kEaHost, path, "", s, l, b);
        wipe(path);
        if (sent && TokenFromRedirect(l, minted)) describe(minted, "minted for N7 HQ's client");
        else log("n7hq: step 1: response_type=token for N7 HQ's client: " +
                 (sent ? std::to_string(s) + (l.empty() ? ": " + JsonField(b, "error_description") : " -> " + HostOf(l)) : "WinHTTP error " + std::to_string(ea.lastError)));
        wipe(minted); wipe(l); wipe(b);
        // Can the EA app mint a token carrying N7 HQ's data scopes? If so, a
        // code from it would not 500. GetAccessToken is tried on its OWN LSX
        // connection, so a wrong attribute cannot poison `app` (route A).
        // tokeninfo on any token shows the scope EA actually granted.
        lsx::Client probe;
        if (probe.Connect()) {
            struct AT { const char* what; const char* scope; const char* fmt; bool keep; };
            for (const AT& a : { AT{"GetAccessToken, no attributes", "", "", false},
                                 AT{"GetAccessToken, N7 HQ's scope", kScope, "", true},
                                 AT{"GetAccessToken, N7 HQ's scope, JWS", kScope, "JWS", false} }) {
                std::string at, reply;
                if (!LsxAccessToken(probe, a.scope, a.fmt, at, reply)) {
                    log(std::string("n7hq: step 1: ") + a.what + ": the EA app dropped the connection: " + probe.err);
                    break;
                }
                if (at.empty()) { log(std::string("n7hq: step 1: ") + a.what + ": " + reply); continue; }
                log(std::string("n7hq: step 1: ") + a.what + ": a token, " + std::to_string(at.size()) + " chars");
                describe(at, a.what);
                // Keep the scoped (non-JWS, opaque, as the EA import uses)
                // token for route B4: a code from a token that carries N7
                // HQ's data scopes is the one that may not 500.
                if (a.keep && scopedToken.empty()) scopedToken = at;
                at.assign(at.size(), '\0');
            }
            probe.Close();
        }
    }
    // EA's ME3 servers for the consoles (console_probe.h): does one take the
    // EA app's token, and what does it hold for the account? Then EA's
    // identity service: the personas linked to the account, by namespace
    // (a console's gamertag or PSN name, if one is linked). Both only read.
    if (!token.empty()) {
        console::ProbeAll(token, [&](const std::string& l) { log("n7hq: step 1: " + l); });
        Web id;
        id.extraHeaders = L"Authorization: Bearer " + std::wstring(token.begin(), token.end()) + L"\r\nX-Expand-Results: true\r\n";
        int s = 0; std::string l, b;
        bool sent = id.Request(L"GET", "gateway.ea.com", "/proxy/identity/pids/me/personas", "", s, l, b);
        log("n7hq: step 1: identity personas: " + (sent ? DescribePersonas(s, b) : "WinHTTP error " + std::to_string(id.lastError)));
        wipe(b);
    }

    // 2. N7 HQ: each way's code in a session of its own (kTries), until one
    // is signed in.
    step(2, 0);
    CreateDirectoryW(dir.c_str(), nullptr);
    std::string tried;          // each way's end, for the failure's log line
    bool good = false, any500 = false;
    bool anyConn = false;       // a way failed on a connection/TLS error, not a status
    std::string lastConn;
    for (int i = 0; i < kTryCount && !good; ++i) {
        const Try& t = kTries[i];
        std::string head = std::string("n7hq: step 2: ") + t.id + " (" + t.what + "): ";
        auto skip = [&](const std::string& end) { log(head + end); tried += std::string(tried.empty() ? "" : ", ") + t.id + " " + end; };
        std::string code, got;
        if (t.fromToken) {
            const std::string& useToken = t.scopedTok ? scopedToken : token;
            if (useToken.empty()) { skip(t.scopedTok ? "no scoped token" : "no token"); continue; }
            int s = 0; std::string l, b;
            std::string path = AuthPath(t, useToken, "code", std::to_string(GetTickCount()));
            bool sent = ea.Request(L"GET", kEaHost, path, "", s, l, b);
            wipe(path);
            if (!sent) got = "accounts.ea.com: WinHTTP error " + std::to_string(ea.lastError);
            else if (!CodeFromRedirect(l, code))
                got = "connect/auth " + std::to_string(s) + (l.empty() ? ": " + JsonField(b, "error_description") : " -> " + HostOf(l));
            wipe(l);
        } else {
            if (uid.empty()) { skip("no user id"); continue; }
            std::string reply;
            if (!LsxAuthCode(app, uid, code, reply, t.scope ? kScope : "", t.append, t.aRedirect ? std::string(kRedirect) : "")) {
                got = "the EA app dropped the connection: " + app.err;
                app.Connect();   // for the next way
            } else if (code.empty()) got = "GetAuthCode " + reply;
        }
        if (code.empty()) { skip("no code, " + got); continue; }
        size_t codeLen = code.size();
        cur.reset(new Web);
        route = t.id;
        afterSignIn = false;
        // The first visit picks the desktop layout, as the site's own link
        // does (/?ver=default sets ME3N7HQTemplate_type=default), then
        // /auth/login, as a browser's sign-in starts. Neither is known to be
        // needed: a browser's session read every page with ME3N7HQSID alone.
        // A connection error on a single way (a flaky TLS handshake over
        // Proton's schannel is common after many fresh sessions) skips that
        // way, so the later ways still run; only if every way fails does the
        // read give up (the !good block). `connFail` records it for that.
        bool wayConnFailed = false;
        auto connFail = [&](const char* what) {
            anyConn = true;
            wayConnFailed = true;
            lastConn = std::string(what) + ": WinHTTP error " + std::to_string(cur->lastError);
            skip(lastConn);
        };
        if (!cur->Request(L"GET", kHost, "/?ver=default", "", st, loc, body)) { wipe(code); connFail("GET /?ver=default"); continue; }
        if (st >= 400) { wipe(code); skip("GET /?ver=default: HTTP " + std::to_string(st)); continue; }
        if (!cur->Request(L"GET", kHost, "/auth/login", "", st, loc, body)) { wipe(code); connFail("/auth/login"); continue; }
        if (st >= 400) { wipe(code); skip("/auth/login: HTTP " + std::to_string(st)); continue; }
        bool sent = cur->Request(L"GET", kHost, "/auth/success?code=" + UrlEncode(code), "", st, loc, body);
        wipe(code);
        if (!sent) { connFail("/auth/success"); continue; }
        std::string trail = "code " + std::to_string(codeLen) + " chars, /auth/success " + std::to_string(st);
        std::string err = ExchangeError(body);
        if (!err.empty()) { skip(trail + ", refused: " + err); continue; }
        if (st >= 400) { skip(trail); continue; }
        afterSignIn = true;
        std::string last = "/auth/success";
        for (int hop = 0; hop < 3 && st >= 300 && st < 400; ++hop) {
            std::string p = N7Path(loc);
            if (p.empty()) { trail += " -> " + HostOf(loc); break; }
            trail += " -> " + p;
            last = p;
            if (!cur->Request(L"GET", kHost, p, "", st, loc, body)) { connFail(p.c_str()); break; }
            trail += " " + std::to_string(st);
        }
        if (wayConnFailed) continue;   // a hop's connection failed: next way
        if (st >= 500) {
            any500 = true;
            keepError("step 2: " + std::string(t.id) + ", " + last);
            // The pages that 500ed (/, the account page, the search) are the
            // ones about the signed-in account itself. A profile by name may
            // still open on the session: tried, and if it holds a profile the
            // read goes on with this session.
            std::string direct = std::string(kTabRoot) + kTabs[0] + "/?name=" + UrlEncode(Lower(name)) + "&platform=" + platform;
            if (!cur->Request(L"GET", kHost, direct, "", st, loc, body)) { connFail(direct.c_str()); continue; }
            Page k = st < 300 ? ClassifyProfile(body) : Page::Unknown;
            std::string played = PlayerStat(body, "pstimeplayed");
            trail += ", then " + direct + " " + std::to_string(st) + " " + std::to_string(body.size()) + " bytes" +
                     (k == Page::Profile ? ", a profile, time played '" + played + "'" : k == Page::Unavailable ? ", not available" : "") +
                     (st < 300 ? (SignedIn(body) == 1 ? ", signed in" : SignedIn(body) == 0 ? ", signed out" : "") : "");
            if (st >= 500) keepError("step 2: " + std::string(t.id) + ", " + direct);
            if (k == Page::Profile && SignedIn(body) == 1) {
                log(head + trail + ": goes on with this session");
                good = true;
                ownPages500 = true;
                continue;
            }
            skip(trail);
            continue;
        }
        int si = st < 300 ? SignedIn(body) : -1;
        if (si == 1) { log(head + trail + ": signed in"); good = true; }
        else skip(trail + (si == 0 ? ": not signed in" : ": cannot tell"));
    }
    wipe(token);
    wipe(scopedToken);
    app.Close();
    if (!good) {
        if (any500)
            return Fail(o, "N7 HQ had a server error after the sign-in.", "Send mp_save.log, nothing was changed.", "every way: " + tried);
        if (anyConn)
            return Fail(o, "N7 HQ did not answer (n7hq.masseffect.com).", "The site may be down, try again later.", "every way: " + tried + " (last: " + lastConn + ")");
        return Fail(o, "N7 HQ did not keep the sign-in.", "Try again, and if it repeats, send mp_save.log.", "every way: " + tried);
    }
    log("n7hq: step 2: signed in with " + route + ", cookies held: " + cur->jar.Names());
    }  // end of the EA sign-in path

    Web& n7 = *cur;
    // The account's own page (kTabRoot): site_scripts.js opens kTabRoot +
    // "?pid=<persona>" from a #personas_list's entries (data-persona), so a
    // signed-in kTabRoot may list
    // the personas linked to the EA account, consoles included. Saved for a
    // later build to offer them; it never stops the read.
    if (ownPages500) {
        log("n7hq: step 2: account page skipped (the account's own pages answer 500 on this session)");
    } else if (n7.Request(L"GET", kHost, kTabRoot, "", st, loc, body) && st < 300) {
        if (signedIn != 1) signedIn = SignedIn(body) == 1 ? 1 : signedIn;
        size_t personas = 0;
        for (size_t at = 0; (at = body.find("data-persona=", at)) != std::string::npos; at += 13) personas++;
        FILE* f = _wfopen((dir + L"\\account-home.html").c_str(), L"wb");
        if (f) { fwrite(body.data(), 1, body.size(), f); fclose(f); }
        log("n7hq: step 2: account page " + std::to_string(st) + ", " + std::to_string(body.size()) + " bytes, " +
            std::to_string(personas) + " linked persona(s) listed" + (body.find("personas_list") == std::string::npos ? " (no personas_list)" : "") +
            (f ? ", saved" : ", not saved"));
    } else if (st >= 500) {
        keepError("step 2: account page");
    } else {
        log("n7hq: step 2: account page: " + (st ? "HTTP " + std::to_string(st) : "WinHTTP error " + std::to_string(n7.lastError)));
    }

    // 3. The search, as N7 HQ's own box sends it.
    step(3, 0);
    std::string profileName = name;
    if (!n7.Request(L"POST", kHost, "/search/", "player_name=" + UrlEncode(name, true) + "&platform=" + platform, st, loc, body))
        return unreachable("search");
    if (st >= 500 && afterSignIn) { keepError("step 3: search"); st = 200; loc.clear(); body.clear(); }
    else if (st >= 400) return unreachable("search");
    std::string p = N7Path(loc);
    std::string found = QueryParam(p, "name");
    if (!found.empty()) profileName = found;
    std::string miss = p.empty() ? SearchMiss(body) : "";
    log("n7hq: step 3: search " + std::to_string(st) + (p.empty() ? " (no redirect)" : " -> " + p) + (miss.empty() ? "" : ": " + miss));

    // 4. The tabs, each saved as it comes. The overview decides the name: the
    // one typed first, then the search's spelling (the search lower-cases and
    // drops edge underscores, which an archived profile's own name kept).
    CreateDirectoryW(dir.c_str(), nullptr);
    // N7 HQ's addresses use the lower-cased name ("Shepard117" is
    // ?name=shepard117), so that is tried as well.
    std::vector<std::string> names{name};
    for (const std::string& n : {profileName, Lower(name)})
        if (std::find(names.begin(), names.end(), n) == names.end()) names.push_back(n);
    std::string sizes;
    for (int t = 0; t < kTabCount; ++t) {
        step(4, t + 1);
        std::string path;
        bool got = false;
        for (size_t i = 0; i < (t == 0 ? names.size() : 1); ++i) {
            if (t == 0) profileName = names[i];
            path = std::string(kTabRoot) + kTabs[t] + "/?name=" + UrlEncode(profileName) + "&platform=" + platform;
            got = n7.Request(L"GET", kHost, path, "", st, loc, body) && st < 400;
            if (!got || t != 0 || ClassifyProfile(body) != Page::Unavailable) break;
            log("n7hq: step 4: " + path + ": not currently available");
        }
        if (!got) {
            if (st >= 500) keepError("step 4: " + path);
            if (t == 0) return unreachable(path.c_str());
            std::string tab = kTabs[t]; tab[0] = (char)toupper((unsigned char)tab[0]);
            return Fail(o, "N7 HQ stopped answering at the " + tab + " page.", "Try again later, the saved pages are kept.",
                        path + ": " + (st ? "HTTP " + std::to_string(st) : "WinHTTP error " + std::to_string(n7.lastError)));
        }
        if (t == 0) {
            o.name = profileName;
            Page k = ClassifyProfile(body);
            if (k == Page::Unavailable) {
                if (signedIn == 0)
                    return Fail(o, "N7 HQ did not keep the sign-in.", "Try again, and if it repeats, send mp_save.log.",
                                "the profile page is the signed-out 'not currently available' page");
                return Fail(o, "N7 HQ: no public " + label + " profile '" + name + "'.",
                            "Check the name and console, or make it public there.", "not currently available under any spelling tried");
            }
            if (k == Page::Unknown)
                return Fail(o, "N7 HQ's pages look different from what LEMP knows.", "Send mp_save.log and the LEMP\\n7hq folder.",
                            path + ": no profile tabs and no 'not available' text (" + std::to_string(body.size()) + " bytes)");
        }
        std::wstring file = dir + L"\\" + std::wstring(platform.begin(), platform.end()) + L"-";
        std::string fp = FilePart(profileName);
        file += std::wstring(fp.begin(), fp.end()) + L"-" + std::wstring(kTabs[t], kTabs[t] + strlen(kTabs[t])) + L".html";
        FILE* f = _wfopen(file.c_str(), L"wb");
        bool wrote = f && fwrite(body.data(), 1, body.size(), f) == body.size();
        if (f) fclose(f);
        if (!wrote)
            return Fail(o, "Could not save the pages to LEMP\\n7hq.", "Check that Documents is writable (antivirus?).",
                        "cannot write a page (Windows error " + std::to_string(GetLastError()) + ")");
        o.pages++;
        char kb[32]; snprintf(kb, sizeof kb, "%.1f KB", body.size() / 1024.0);
        sizes += std::string(sizes.empty() ? "" : ", ") + kTabs[t] + " " + std::to_string(st) + " " + kb;
    }
    log("n7hq: step 4: " + sizes);
    o.ok = true;
    return true;
}

}  // namespace n7hq
}  // namespace ea
#endif
