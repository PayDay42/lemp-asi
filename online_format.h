// online_format.h — the text formats of mp_save.asi's matchmaking ops, with no
// Windows in them, so test_online_format.cpp runs them natively.
//
//  - JSON to and from the master server. Only what it
//    sends: one flat object of strings, integers, booleans and null. Nested
//    values are skipped, not parsed.
//  - The option strings script and ASI pass in AsiBuf: "?key=value?key=value",
//    the URL-option form, so script reads them with GameInfo.ParseOption and
//    builds them with $. A value never holds '?' or '=' (Opt() replaces them),
//    or ParseOption would split it.
#pragma once
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>

namespace online {

// ---- JSON out ------------------------------------------------------------

inline std::string JsonString(const std::string& s) {
    std::string o = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += (char)c; }
        else if (c < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); o += b; }
        else o += (char)c;
    }
    return o + "\"";
}

// Builds {"k":v,...} in call order.
struct JsonObject {
    std::string body;
    JsonObject& Raw(const char* k, const std::string& v) {
        body += (body.empty() ? "{" : ",") + JsonString(k) + ":" + v;
        return *this;
    }
    JsonObject& Str(const char* k, const std::string& v) { return Raw(k, JsonString(v)); }
    JsonObject& Int(const char* k, long long v) { return Raw(k, std::to_string(v)); }
    JsonObject& Bool(const char* k, bool v) { return Raw(k, v ? "true" : "false"); }
    std::string Done() const { return body.empty() ? "{}" : body + "}"; }
};

// ---- JSON in -------------------------------------------------------------

// A flat object's scalar members. Strings are kept as UTF-8; numbers as their
// text; true/false as "true"/"false"; null is left out. Nested objects and
// arrays are skipped. False on anything that is not an object.
struct JsonFields {
    std::map<std::string, std::string> v;
    bool Has(const char* k) const { return v.count(k) != 0; }
    std::string Str(const char* k, const std::string& d = "") const {
        auto it = v.find(k);
        return it == v.end() ? d : it->second;
    }
    long long Int(const char* k, long long d = 0) const {
        auto it = v.find(k);
        if (it == v.end() || it->second.empty()) return d;
        char* end = nullptr;
        long long n = strtoll(it->second.c_str(), &end, 10);
        return (end && *end == 0) ? n : d;
    }
    bool Bool(const char* k, bool d = false) const {
        auto it = v.find(k);
        return it == v.end() ? d : it->second == "true";
    }
};

namespace detail {
struct Reader {
    const std::string& s;
    size_t i = 0;
    void Ws() { while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++; }
    bool Eat(char c) { Ws(); if (i < s.size() && s[i] == c) { i++; return true; } return false; }
    static void Utf8(std::string& o, uint32_t cp) {
        if (cp < 0x80) o += (char)cp;
        else if (cp < 0x800) { o += (char)(0xC0 | (cp >> 6)); o += (char)(0x80 | (cp & 0x3F)); }
        else { o += (char)(0xE0 | (cp >> 12)); o += (char)(0x80 | ((cp >> 6) & 0x3F)); o += (char)(0x80 | (cp & 0x3F)); }
    }
    bool String(std::string& o) {
        Ws();
        if (i >= s.size() || s[i] != '"') return false;
        i++;
        while (i < s.size() && s[i] != '"') {
            char c = s[i++];
            if (c != '\\') { o += c; continue; }
            if (i >= s.size()) return false;
            char e = s[i++];
            switch (e) {
            case '"': case '\\': case '/': o += e; break;
            case 'n': o += '\n'; break;
            case 't': o += '\t'; break;
            case 'r': o += '\r'; break;
            case 'b': o += '\b'; break;
            case 'f': o += '\f'; break;
            case 'u': {
                if (i + 4 > s.size()) return false;
                uint32_t cp = 0;
                for (int k = 0; k < 4; k++) {
                    char h = s[i++];
                    cp <<= 4;
                    if (h >= '0' && h <= '9') cp |= h - '0';
                    else if (h >= 'a' && h <= 'f') cp |= h - 'a' + 10;
                    else if (h >= 'A' && h <= 'F') cp |= h - 'A' + 10;
                    else return false;
                }
                Utf8(o, cp);   // a surrogate half comes out as itself; nothing here sends one
                break;
            }
            default: return false;
            }
        }
        if (i >= s.size()) return false;
        i++;
        return true;
    }
    // Skips any value; for scalars, `out` gets its text (strings unescaped).
    bool Value(std::string& out, bool& isNull, int depth = 0) {
        Ws();
        isNull = false;
        if (i >= s.size() || depth > 16) return false;
        char c = s[i];
        if (c == '"') return String(out);
        if (c == '{' || c == '[') {
            char close = c == '{' ? '}' : ']';
            i++;
            if (Eat(close)) { isNull = true; return true; }
            for (;;) {
                std::string k, v; bool n;
                if (c == '{') { if (!String(k) || !Eat(':')) return false; }
                if (!Value(v, n, depth + 1)) return false;
                if (Eat(',')) continue;
                if (Eat(close)) { isNull = true; return true; }
                return false;
            }
        }
        size_t start = i;
        while (i < s.size() && (isalnum((unsigned char)s[i]) || s[i] == '-' || s[i] == '+' || s[i] == '.')) i++;
        out = s.substr(start, i - start);
        if (out == "null") { isNull = true; out.clear(); }
        return !out.empty() || isNull;
    }
};
}  // namespace detail

inline bool ParseJsonObject(const std::string& text, JsonFields& f) {
    f.v.clear();
    detail::Reader r{text};
    if (!r.Eat('{')) return false;
    if (r.Eat('}')) return true;
    for (;;) {
        std::string k, v; bool isNull = false;
        if (!r.String(k) || !r.Eat(':') || !r.Value(v, isNull)) return false;
        if (!isNull) f.v[k] = v;
        if (r.Eat(',')) continue;
        return r.Eat('}');
    }
}

// ---- option strings --------------------------------------------------------

// One "?key=value", with the value made safe for ParseOption.
inline std::string Opt(const char* key, const std::string& value) {
    std::string v;
    for (char c : value) v += (c == '?' || c == '=' || c == '\n' || c == '\r') ? ' ' : c;
    return std::string("?") + key + "=" + v;
}
inline std::string Opt(const char* key, long long value) { return Opt(key, std::to_string(value)); }

// "?a=1?b=x" -> {a:1, b:x}; keys lower-cased, as ParseOption compares them
// without case. A part with no '=' is a key with an empty value.
inline std::map<std::string, std::string> ParseOptions(const std::string& s) {
    std::map<std::string, std::string> m;
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] == '?') { i++; continue; }
        size_t end = s.find('?', i);
        if (end == std::string::npos) end = s.size();
        std::string part = s.substr(i, end - i);
        size_t eq = part.find('=');
        std::string k = part.substr(0, eq), v = eq == std::string::npos ? "" : part.substr(eq + 1);
        for (char& c : k) c = (char)tolower((unsigned char)c);
        if (!k.empty()) m[k] = v;
        i = end;
    }
    return m;
}
inline long long OptInt(const std::map<std::string, std::string>& m, const char* k, long long d) {
    auto it = m.find(k);
    if (it == m.end() || it->second.empty()) return d;
    char* end = nullptr;
    long long n = strtoll(it->second.c_str(), &end, 10);
    return (end && *end == 0) ? n : d;
}

// ---- text for script ---------------------------------------------------------

// UTF-8 (the server's names) to UTF-16 (the game's TCHAR). Malformed bytes
// come out as '?'; code points past the BMP too (the game's fonts have none).
inline std::u16string Utf8To16(const std::string& s) {
    std::u16string o;
    for (size_t i = 0; i < s.size();) {
        unsigned char c = (unsigned char)s[i];
        uint32_t cp; int n;
        if (c < 0x80) { cp = c; n = 1; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; n = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; n = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; n = 4; }
        else { o += u'?'; i++; continue; }
        if (i + n > s.size()) { o += u'?'; break; }
        bool ok = true;
        for (int k = 1; k < n; k++) {
            unsigned char d = (unsigned char)s[i + k];
            if ((d & 0xC0) != 0x80) { ok = false; break; }
            cp = (cp << 6) | (d & 0x3F);
        }
        if (!ok) { o += u'?'; i++; continue; }
        o += (cp > 0xFFFF || (cp >= 0xD800 && cp <= 0xDFFF)) ? u'?' : (char16_t)cp;
        i += n;
    }
    return o;
}

// ---- the server URL ---------------------------------------------------------

// "http[s]://host[:port][/base]" -> parts. The base path has no trailing '/'.
struct ServerUrl { bool https = false; std::string host; int port = 0; std::string base; };
inline bool ParseServerUrl(std::string u, ServerUrl& out) {
    while (!u.empty() && (u.back() == '/' || u.back() == ' ' || u.back() == '\r' || u.back() == '\n')) u.pop_back();
    while (!u.empty() && u.front() == ' ') u.erase(0, 1);
    size_t p;
    if (u.rfind("https://", 0) == 0) { out.https = true; p = 8; }
    else if (u.rfind("http://", 0) == 0) { out.https = false; p = 7; }
    else return false;
    size_t slash = u.find('/', p);
    std::string hostport = u.substr(p, slash == std::string::npos ? std::string::npos : slash - p);
    out.base = slash == std::string::npos ? "" : u.substr(slash);
    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos && hostport.find(']') == std::string::npos) {
        out.host = hostport.substr(0, colon);
        out.port = atoi(hostport.c_str() + colon + 1);
        if (out.port < 1 || out.port > 65535) return false;
    } else {
        out.host = hostport;
        out.port = out.https ? 443 : 80;
    }
    return !out.host.empty();
}

}  // namespace online
