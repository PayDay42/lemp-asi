// ea_import.h — import the player's ME3 (2012) multiplayer profile from EA's
// own ME3 server into LEMP's save.
//
// The flow is Pocket Relay's retriever (its src/services/retriever/:
// mod.rs, origin.rs), the one that already copies EA profiles today:
//   1. the account's token from the EA app (ea_lsx.h: Origin SDK GetAuthToken,
//      what 2012's ME3 itself logged in with);
//   2. EA's redirector (gosredirector.ea.com:42127) -> the ME3 instance;
//   3. authentication ORIGIN_LOGIN (AUTH = token, TYPE = 1) -> the persona's
//      display name (PDTL.DSNM);
//   4. util USER_SETTINGS_LOAD_ALL -> SMAP, the settings 2012 stored: the
//      very strings LEMP's save holds.
// Both servers must present certificates signed by EA's OTG3 authority
// (ea_blaze.h) before the token is sent.
//
// Runs only when the player has asked for the import and agreed;
// nothing here runs at startup. Blocking: mp_save.asi calls it on a thread.
#pragma once
#include "ea_lsx.h"
#include "mp_save_format.h"
#include <map>

namespace ea {

// UTF-8 (the server's strings) -> UTF-16 (the save's), as mpsave reads
// files; an invalid sequence fails the whole import rather than garbling a record.
inline bool Utf8To16(const std::string& s, std::u16string& out) {
    out.clear();
    for (size_t i = 0; i < s.size();) {
        unsigned char b = (unsigned char)s[i];
        char32_t c; int n;
        if (b < 0x80) { c = b; n = 0; }
        else if ((b & 0xE0) == 0xC0) { c = b & 0x1F; n = 1; }
        else if ((b & 0xF0) == 0xE0) { c = b & 0x0F; n = 2; }
        else if ((b & 0xF8) == 0xF0) { c = b & 0x07; n = 3; }
        else return false;
        for (int k = 1; k <= n; ++k) {
            if (i + k >= s.size()) return false;
            unsigned char t = (unsigned char)s[i + k];
            if ((t & 0xC0) != 0x80) return false;
            c = (c << 6) | (t & 0x3F);
        }
        mpsave::AppendUtf16(out, c);
        i += 1 + n;
    }
    return true;
}

// The records' layout version: 2012's serializer writes "20;..." and
// LoadToSaveManager refuses anything newer (ShowDataTooNewError disables
// saving), so a newer record is refused here, before anything is written.
static const int kMaxRecordVersion = 20;

// The settings 2012's MP stored on EA's server, by name (LE3's
// SFXOnlinePlayerStorage ids 87..95), into LEMP's
// save. `summary` says what was found, for the log and the player.
inline bool MapSettings(const std::map<std::string, std::string>& s, MPSaveData& d, std::string& why, std::string& summary) {
    d = MPSaveData();
    auto get = [&](const char* k, std::u16string& out) -> bool {
        auto it = s.find(k);
        if (it == s.end()) return false;
        if (!Utf8To16(it->second, out)) { why = std::string("setting ") + k + " is not UTF-8"; return false; }
        return true;
    };
    auto versionOk = [&](const char* k, const std::u16string& v) -> bool {
        int ver = 0; size_t i = 0;
        while (i < v.size() && v[i] >= u'0' && v[i] <= u'9' && i < 6) ver = ver * 10 + (v[i++] - u'0');
        if (i == 0 || ver > kMaxRecordVersion) {
            why = std::string("setting ") + k + " has layout version " + (i ? std::to_string(ver) : std::string("(none)")) +
                  ", newer than this LEMP reads (" + std::to_string(kMaxRecordVersion) + ")";
            return false;
        }
        return true;
    };
    if (!get("Base", d.base)) {
        if (why.empty()) why = "this EA account has no ME3 multiplayer profile (no Base setting)";
        return false;
    }
    if (!versionOk("Base", d.base)) return false;
    if (get("NewItem", d.reinforcements) && !versionOk("NewItem", d.reinforcements)) return false;
    if (!why.empty()) return false;
    if (get("FaceCodes", d.facecodes) && !versionOk("FaceCodes", d.facecodes)) return false;
    if (!why.empty()) return false;
    // `selected=` has no Blaze key (2012 kept it in the profile): the imported
    // player lands in kit select, as a new one does.
    for (int i = 1; i <= 6; ++i) {
        std::string k = "class" + std::to_string(i); std::u16string v;
        if (get(k.c_str(), v)) { if (!versionOk(k.c_str(), v)) return false; d.classes.push_back(v); }
        else if (!why.empty()) return false;
    }
    // char0..charN, in numeric order (a map sorts "char10" before "char2").
    std::map<int, std::string> chars;
    for (auto& kv : s) {
        const std::string& k = kv.first;
        if (k.size() > 4 && k.compare(0, 4, "char") == 0 && k.find_first_not_of("0123456789", 4) == std::string::npos && k.size() < 10)
            chars[atoi(k.c_str() + 4)] = k;
    }
    for (auto& c : chars) {
        std::u16string v;
        if (!get(c.second.c_str(), v)) return false;
        if (!versionOk(c.second.c_str(), v)) return false;
        d.characters.push_back(v);
    }
    // The challenges: our layout version "1", then ids 89..95 in order, as
    // SFXSaveManagerMP_Local.ChallengeSnapshot writes them (csreward is an int).
    static const char* kChallengeKeys[] = { "Completion", "Progress", "cscompletion", "csreward", "cstimestamps", "cstimestamps2", "cstimestamps3" };
    bool anyChallenge = false;
    for (auto k : kChallengeKeys) anyChallenge |= s.count(k) > 0;
    if (anyChallenge) {
        d.challenges.push_back(u"1");
        for (auto k : kChallengeKeys) {
            std::u16string v;
            if (!get(k, v)) { if (!why.empty()) return false; if (!strcmp(k, "csreward")) v = u"0"; }
            d.challenges.push_back(v);
        }
    }
    summary = std::to_string(d.classes.size()) + (d.classes.size() == 1 ? " class, " : " classes, ")
              + std::to_string(d.characters.size()) + (d.characters.size() == 1 ? " character" : " characters") +
              (anyChallenge ? ", challenges" : ", no challenges");
    return true;
}

struct ImportResult {
    std::string displayName;   // the EA persona (ORIGIN_LOGIN's PDTL.DSNM)
    MPSaveData data;
    std::string summary;
    size_t settings = 0;       // how many settings EA returned
};

// Steps, for the screen to show while it waits.
enum Stage { kStageEaApp = 1, kStageConnecting = 2, kStageSigningIn = 3, kStageDownloading = 4 };

// The whole import. `stage` is told each step (from this thread). The token
// lives only inside this call.
template <class OnStage>
inline bool FetchMe3Profile(ImportResult& r, std::string& err, OnStage stage) {
    stage(kStageEaApp);
    std::string token;
    {
        lsx::Client app;
        if (!app.Connect() || !app.GetAuthToken(token)) { err = "EA app: " + app.err; return false; }
    }

    stage(kStageConnecting);
    std::string host; uint16_t port = 0;
    {
        Blaze redir;
        redir.ssl.ca = &Otg3();
        tdf::Value inst;
        if (!redir.Connect(kRedirectorHost, kRedirectorPort) ||
            !redir.Request(kRedirectorComponent, kGetServerInstance, InstanceRequest(), inst)) {
            err = "EA's ME3 redirector: " + redir.err;
            if (redir.err.find("not signed by") != std::string::npos)
                err += " (a hosts-file entry for gosredirector.ea.com, e.g. an old Pocket Relay setup, would do this)";
            return false;
        }
        if (!InstanceAddress(inst, host, port)) { err = "EA's ME3 redirector named no server"; return false; }
    }

    Blaze me3;
    me3.ssl.ca = &Otg3();
    if (!me3.Connect(host, port)) { err = "EA's ME3 server " + host + ": " + me3.err; return false; }

    stage(kStageSigningIn);
    tdf::Writer login;
    login.TagStr("AUTH", token);
    login.TagInt("TYPE", 1);
    token.assign(token.size(), '\0'); token.clear();
    tdf::Value lr;
    if (!me3.Request(kAuthComponent, kOriginLogin, login.b, lr)) {
        err = "EA did not accept the EA app's sign-in (" + me3.err + ")";
        return false;
    }
    std::fill(login.b.begin(), login.b.end(), 0);
    if (const tdf::Value* p = lr.Find("PDTL")) if (const tdf::Value* n = p->Find("DSNM")) r.displayName = n->str;
    if (r.displayName.empty()) if (const tdf::Value* n = lr.Find("DSNM")) r.displayName = n->str;

    stage(kStageDownloading);
    tdf::Value sr;
    if (!me3.Request(kUtilComponent, kUserSettingsLoadAll, Bytes(), sr)) { err = "EA's ME3 server: " + me3.err; return false; }
    const tdf::Value* smap = sr.Find("SMAP");
    if (!smap || smap->type != tdf::Map) { err = "EA's ME3 server sent no settings"; return false; }
    std::map<std::string, std::string> settings;
    for (size_t i = 0; i + 1 < smap->kids.size(); i += 2) settings[smap->kids[i].str] = smap->kids[i + 1].str;
    r.settings = settings.size();
    std::string why;
    if (!MapSettings(settings, r.data, why, r.summary)) { err = why; return false; }
    return true;
}

}  // namespace ea
