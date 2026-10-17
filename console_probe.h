// console_probe.h — do EA's ME3 servers for the consoles (PS3, Xbox 360)
// take the EA app's sign-in, and what do they hold for the account?
//
// The PC import (ea_import.h) signs in to the PC instance with ORIGIN_LOGIN
// and reads the account's settings. The redirector still names an instance
// for "masseffect-3-ps3" and for "masseffect-3-xbl2" (Blaze's Xbox 360
// platform name), each with a port of its own, while a made-up name is
// answered with an error. Whether those instances take an EA (PC) token,
// and serve an EA account's linked console persona, is what this asks:
//   1. the redirector, with the service's name (the rest of the request as
//      the PC client sends it);
//   2. the instance, only if its certificate is signed by EA's OTG3
//      authority (ea_blaze.h), as for the PC import;
//   3. ORIGIN_LOGIN with the token; then authentication listPersonas
//      (0x64, Pocket Relay's and ME3PSE's component tables) and util
//      USER_SETTINGS_LOAD_ALL.
// Logged: the server's error codes, the persona names, which tags came
// back, how many settings and their names. Never the token, never an id's
// value. Nothing is written anywhere: this only reads.
#pragma once
#include "ea_blaze.h"
#include <functional>
#include <set>

namespace ea {
namespace console {

using LogFn = std::function<void(const std::string&)>;

struct Service { const char* name; const char* label; };
static const Service kServices[] = {
    {"masseffect-3-pc", "PC"},   // the control: the PC import signs in here
    {"masseffect-3-ps3", "PS3"},
    {"masseffect-3-xbl2", "Xbox 360"},
};
enum : uint16_t { kListPersonas = 0x64 };

// A reply's shape for the log: every tag, groups and lists with their
// members in braces. Strings are shown only for name tags, numbers only for
// kinds and counts; anything else (ids, tokens, keys) as its tag alone.
inline std::string Shape(const tdf::Value& v, int depth = 0) {
    static const std::set<std::string> names{"DSNM", "NAME", "PNAM", "XNAM"};
    static const std::set<std::string> kinds{"XTYP", "PLAT", "STAS", "NTYP", "ATYP", "TYPE", "CNT", "STAT"};
    std::string o;
    for (const tdf::Value& k : v.kids) {
        if (!o.empty()) o += ' ';
        o += k.tag.empty() ? "-" : k.tag;
        if (!k.str.empty() && names.count(k.tag)) o += "='" + k.str + "'";
        else if (k.kids.empty() && k.str.empty() && kinds.count(k.tag)) o += "=" + std::to_string(k.num);
        if (!k.kids.empty() && depth < 4) o += "{" + Shape(k, depth + 1) + "}";
        if (o.size() > 600) return o.substr(0, 600) + "…";
    }
    return o;
}

// One service: what its instance says to the token. An empty token only
// checks that the instance answers with EA's certificate (no sign-in).
inline void ProbeService(const Service& svc, const std::string& token, const LogFn& log) {
    std::string head = std::string("console: ") + svc.label + " (" + svc.name + "): ";
    Blaze redir;
    redir.ssl.ca = &Otg3();
    tdf::Value inst;
    if (!redir.Connect(kRedirectorHost, kRedirectorPort) ||
        !redir.Request(kRedirectorComponent, kGetServerInstance, InstanceRequest(svc.name), inst)) {
        log(head + "redirector: " + redir.err);
        return;
    }
    std::string host; uint16_t port = 0;
    if (!InstanceAddress(inst, host, port)) { log(head + "the redirector named no server"); return; }
    Blaze s;
    s.ssl.ca = &Otg3();
    if (!s.Connect(host, port)) { log(head + host + ":" + std::to_string(port) + ": " + s.err + " (nothing sent)"); return; }
    if (token.empty()) { log(head + host + ":" + std::to_string(port) + " answers with EA's certificate (no sign-in tried)"); return; }
    tdf::Writer login;
    login.TagStr("AUTH", token);
    login.TagInt("TYPE", 1);
    tdf::Value lr;
    bool in = s.Request(kAuthComponent, kOriginLogin, login.b, lr);
    std::fill(login.b.begin(), login.b.end(), 0);
    if (!in) { log(head + host + ":" + std::to_string(port) + ": ORIGIN_LOGIN refused, " + s.err); return; }
    log(head + "ORIGIN_LOGIN accepted: " + Shape(lr));
    tdf::Value pr;
    if (s.Request(kAuthComponent, kListPersonas, Bytes(), pr)) log(head + "listPersonas: " + Shape(pr));
    else log(head + "listPersonas: " + s.err);
    tdf::Value sr;
    if (!s.Request(kUtilComponent, kUserSettingsLoadAll, Bytes(), sr)) { log(head + "settings: " + s.err); return; }
    const tdf::Value* smap = sr.Find("SMAP");
    if (!smap || smap->type != tdf::Map) { log(head + "settings: no SMAP (" + Shape(sr) + ")"); return; }
    std::string keys;
    size_t n = 0;
    for (size_t i = 0; i + 1 < smap->kids.size(); i += 2, ++n)
        if (keys.size() < 300) keys += (keys.empty() ? "" : ", ") + smap->kids[i].str;
    log(head + "settings: " + std::to_string(n) + (n ? " (" + keys + ")" : ""));
}

inline void ProbeAll(const std::string& token, const LogFn& log) {
    for (const Service& svc : kServices) ProbeService(svc, token, log);
}

}  // namespace console
}  // namespace ea
