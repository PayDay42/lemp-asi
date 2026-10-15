// mp_save_format.h — the on-disk format of mp_save.asi's MP save file.
//
// Pure C++ (no Windows headers), so it can be tested natively on Linux:
//     g++ -std=c++17 -o test_mp_save_format test_mp_save_format.cpp && ./test_mp_save_format
//
// The file holds the five strings 2012's MP serializer produces
// (SFXOnlineSaveGameMP's Server*String fields), one per
// line, UTF-8, with `\`, CR and LF escaped. The strings are `;`-delimited
// records and may carry player-typed character names, so nothing about their
// contents is assumed.
//
//     # comment lines
//     version=1
//     base=...
//     reinforcements=...
//     facecodes=...
//     selected=...     (the last selected kit: 2012 kept it in the profile)
//     class=...        (repeated, in order)
//     character=...    (repeated, in order)
//     challenge=...    (repeated, in order; optional: the MP
//                      challenges' state, SFXAccomplishmentStorage's player-
//                      storage settings 89..95)
//     gaw=...          (optional: the MP Galaxy at War zone
//                      ratings, which 2012 kept on EA's GaW service —
//                      SFXSaveManagerMP_Local.GAWSnapshot says what it holds)
#pragma once
#include <string>
#include <vector>

struct MPSaveData {
    std::u16string base, reinforcements, facecodes, selected;
    std::vector<std::u16string> classes, characters, challenges;
    // Empty when the save has none (one from an older save format).
    std::u16string gaw;

    // The flat order the script reads them in: base, reinforcements,
    // facecodes, selected, then the classes, then the characters, then the
    // challenge strings, then the gaw string if there is one.
    static const size_t kFixedSlots = 4;
    size_t NumGaw() const { return gaw.empty() ? 0 : 1; }
    size_t SlotCount() const { return kFixedSlots + classes.size() + characters.size() + challenges.size() + NumGaw(); }
    const std::u16string* Slot(size_t i) const {
        if (i == 0) return &base;
        if (i == 1) return &reinforcements;
        if (i == 2) return &facecodes;
        if (i == 3) return &selected;
        i -= kFixedSlots;
        if (i < classes.size()) return &classes[i];
        i -= classes.size();
        if (i < characters.size()) return &characters[i];
        i -= characters.size();
        if (i < challenges.size()) return &challenges[i];
        i -= challenges.size();
        if (i < NumGaw()) return &gaw;
        return nullptr;
    }
};

namespace mpsave {

inline void AppendUtf8(std::string& out, char32_t c) {
    if (c < 0x80) out += (char)c;
    else if (c < 0x800) { out += (char)(0xC0 | (c >> 6)); out += (char)(0x80 | (c & 0x3F)); }
    else if (c < 0x10000) {
        out += (char)(0xE0 | (c >> 12)); out += (char)(0x80 | ((c >> 6) & 0x3F));
        out += (char)(0x80 | (c & 0x3F));
    } else {
        out += (char)(0xF0 | (c >> 18)); out += (char)(0x80 | ((c >> 12) & 0x3F));
        out += (char)(0x80 | ((c >> 6) & 0x3F)); out += (char)(0x80 | (c & 0x3F));
    }
}

// UTF-16 -> escaped UTF-8. An unpaired surrogate is kept as its own code
// point (WTF-8 style) rather than dropped, so a value always round-trips.
inline std::string Escape(const std::u16string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        char32_t c = s[i];
        if (c == u'\\') { out += "\\\\"; continue; }
        if (c == u'\n') { out += "\\n"; continue; }
        if (c == u'\r') { out += "\\r"; continue; }
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < s.size() && s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) {
            c = 0x10000 + ((c - 0xD800) << 10) + (s[i + 1] - 0xDC00);
            ++i;
        }
        AppendUtf8(out, c);
    }
    return out;
}

inline void AppendUtf16(std::u16string& out, char32_t c) {
    if (c >= 0x10000) {
        c -= 0x10000;
        out += (char16_t)(0xD800 + (c >> 10));
        out += (char16_t)(0xDC00 + (c & 0x3FF));
    } else {
        out += (char16_t)c;
    }
}

// Escaped UTF-8 -> UTF-16. false on a malformed escape or UTF-8 sequence.
inline bool Unescape(const std::string& s, std::u16string& out) {
    out.clear();
    for (size_t i = 0; i < s.size();) {
        unsigned char b = (unsigned char)s[i];
        if (b == '\\') {
            if (i + 1 >= s.size()) return false;
            char e = s[i + 1];
            if (e == '\\') out += u'\\';
            else if (e == 'n') out += u'\n';
            else if (e == 'r') out += u'\r';
            else return false;
            i += 2;
            continue;
        }
        char32_t c; int n;
        if (b < 0x80) { c = b; n = 0; }
        else if ((b & 0xE0) == 0xC0) { c = b & 0x1F; n = 1; }
        else if ((b & 0xF0) == 0xE0) { c = b & 0x0F; n = 2; }
        else if ((b & 0xF8) == 0xF0) { c = b & 0x07; n = 3; }
        else return false;
        if (i + n >= s.size()) return false;   // truncated sequence
        for (int k = 1; k <= n; ++k) {
            unsigned char t = (unsigned char)s[i + k];
            if ((t & 0xC0) != 0x80) return false;
            c = (c << 6) | (t & 0x3F);
        }
        AppendUtf16(out, c);
        i += 1 + n;
    }
    return true;
}

inline std::string Serialize(const MPSaveData& d) {
    std::string out =
        "# LEMP multiplayer save, written by mp_save.asi.\n"
        "# 2012's MP records (SFXOnlineSaveGameMP), one value per line.\n"
        "version=1\n";
    out += "base=" + Escape(d.base) + "\n";
    out += "reinforcements=" + Escape(d.reinforcements) + "\n";
    out += "facecodes=" + Escape(d.facecodes) + "\n";
    out += "selected=" + Escape(d.selected) + "\n";
    for (auto& c : d.classes) out += "class=" + Escape(c) + "\n";
    for (auto& c : d.characters) out += "character=" + Escape(c) + "\n";
    for (auto& c : d.challenges) out += "challenge=" + Escape(c) + "\n";
    if (!d.gaw.empty()) out += "gaw=" + Escape(d.gaw) + "\n";
    return out;
}

// false (with a reason) on anything unexpected: a file this cannot read in
// full is not loaded at all, rather than loaded in part.
inline bool Parse(const std::string& text, MPSaveData& d, std::string& why) {
    d = MPSaveData();
    bool version = false, base = false;
    size_t pos = 0;
    int lineNo = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = (nl == std::string::npos) ? text.size() : nl + 1;
        ++lineNo;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) { why = "line " + std::to_string(lineNo) + ": no '='"; return false; }
        std::string key = line.substr(0, eq);
        std::u16string val;
        if (!Unescape(line.substr(eq + 1), val)) { why = "line " + std::to_string(lineNo) + ": bad escape or UTF-8"; return false; }
        if (key == "version") {
            if (line.substr(eq + 1) != "1") { why = "unknown version " + line.substr(eq + 1); return false; }
            version = true;
        }
        else if (key == "base") { d.base = val; base = true; }
        else if (key == "reinforcements") d.reinforcements = val;
        else if (key == "facecodes") d.facecodes = val;
        else if (key == "selected") d.selected = val;
        else if (key == "class") d.classes.push_back(val);
        else if (key == "character") d.characters.push_back(val);
        else if (key == "challenge") d.challenges.push_back(val);
        else if (key == "gaw") d.gaw = val;
        else { why = "line " + std::to_string(lineNo) + ": unknown key '" + key + "'"; return false; }
    }
    if (!version) { why = "no version line"; return false; }
    if (!base) { why = "no base line"; return false; }
    return true;
}

// mpname.txt / mpaddress.txt: the MP player name and the last address joined,
// for the main-menu session's Multiplayer screen (MPMainMenu.SFXMPProfileName).
// Their own files, because that screen runs at the main menu, before the MP
// records exist. One escaped `key=` line each.
inline std::string SerializeValue(const char* key, const char* what, const std::u16string& value) {
    return std::string("# LEMP ") + what + ", written by mp_save.asi.\n" + key + "=" + Escape(value) + "\n";
}
inline bool ParseValue(const std::string& text, const char* key, std::u16string& value, std::string& why) {
    std::string prefix = std::string(key) + "=";
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = (nl == std::string::npos) ? text.size() : nl + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        if (line.compare(0, prefix.size(), prefix) != 0) { why = "not a " + prefix + " line"; return false; }
        if (!Unescape(line.substr(prefix.size()), value)) { why = "bad escape or UTF-8"; return false; }
        return true;
    }
    why = "no " + prefix + " line";
    return false;
}
inline std::string SerializeName(const std::u16string& name) { return SerializeValue("name", "player name", name); }
inline bool ParseName(const std::string& text, std::u16string& name, std::string& why) { return ParseValue(text, "name", name, why); }
inline std::string SerializeAddress(const std::u16string& a) { return SerializeValue("address", "last address joined", a); }
inline bool ParseAddress(const std::string& text, std::u16string& a, std::string& why) { return ParseValue(text, "address", a, why); }

}  // namespace mpsave
