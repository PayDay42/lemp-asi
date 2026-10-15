// ea_lsx.h — the EA app's local "LSX" service, from which 2012's ME3 got the
// token it logged in to Blaze with (Origin SDK GetAuthToken, no client id:
// LSXRequest<GetAuthTokenT, AuthTokenT> in 2012's exe). LE3's own script path
// to it never answers, so mp_save.asi asks the EA app
// itself, as an Origin SDK client would.
//
// A port of origin-sdk 0.2.0's client (github.com/ploxxxy/origin-sdk:
// src/sdk.rs, src/crypto.rs, src/random.rs), checked against Maxima's server
// side (github.com/ArmchairDevelopers/Maxima, maxima-lib/src/lsx/) [R]:
//   - TCP 127.0.0.1:3216 [V: the EA app's command line, -gameSdkPort=3216];
//     each message is XML ending in one NUL byte.
//   - The app opens with <Event sender="EALS"><Challenge key=K .../>. The
//     reply, to recipient "EALS", carries response = hex(AES-128-ECB(K)) under
//     the key 00..0F, and key = K. Both sides then switch to a session key:
//     seed = (hex[0] << 8) | hex[1] (the response's first two hex
//     characters), MSVC rand() seeded with 7 is stepped once, reseeded with
//     its output + seed, and gives the 16 key bytes.
//   - <ChallengeAccepted/> still arrives in the clear; from then on every
//     message both ways is hex(AES-128-ECB(xml)) under the session key.
//   - <GetAuthToken/> to recipient "EbisuSDK" -> <AuthToken value="..."/>.
//
// The token is a credential: it is returned to the caller only, never logged.
#pragma once
#include "ea_blaze.h"   // sockets, AES, hex
#include <chrono>

namespace ea {
namespace lsx {

static const uint16_t kPort = 3216;

// MSVC rand(), as origin-sdk's Random.
struct MsRand {
    uint32_t seed;
    uint32_t Next() { seed = seed * 214013u + 2531011u; return (seed >> 16) & 0x7FFF; }
};

// The session key for a seed (origin-sdk Crypto::set_key); seed 0 = 00..0F.
inline void MakeKey(uint32_t seed, uint8_t key[16]) {
    if (seed == 0) { for (int i = 0; i < 16; ++i) key[i] = (uint8_t)i; return; }
    MsRand r{7};
    r.seed = r.Next() + seed;
    for (int i = 0; i < 16; ++i) key[i] = (uint8_t)r.Next();
}

// An attribute's value out of an XML element, unescaping the five entities.
inline bool Attr(const std::string& xml, const std::string& name, std::string& out) {
    size_t p = 0;
    for (;;) {
        p = xml.find(name + "=\"", p);
        if (p == std::string::npos) return false;
        if (p == 0 || xml[p - 1] == ' ' || xml[p - 1] == '\t' || xml[p - 1] == '\n') break;
        p += name.size();
    }
    p += name.size() + 2;
    size_t e = xml.find('"', p);
    if (e == std::string::npos) return false;
    std::string v = xml.substr(p, e - p);
    out.clear();
    for (size_t i = 0; i < v.size(); ++i) {
        if (v[i] != '&') { out += v[i]; continue; }
        static const char* ent[][2] = { {"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", "\""}, {"&apos;", "'"} };
        bool hit = false;
        for (auto& en : ent) { size_t l = strlen(en[0]); if (!v.compare(i, l, en[0])) { out += en[1]; i += l - 1; hit = true; break; } }
        if (!hit) out += '&';
    }
    return true;
}
inline std::string Escape(const std::string& s) {
    std::string o;
    for (char c : s) { if (c == '&') o += "&amp;"; else if (c == '<') o += "&lt;"; else if (c == '>') o += "&gt;"; else if (c == '"') o += "&quot;"; else o += c; }
    return o;
}

class Client {
public:
    std::string err;
    std::string contentId = "Origin.OFR.50.0004049";   // Mass Effect Legendary Edition [V, EA app log]
    std::string title, multiplayerId, language;        // origin-sdk's simple example leaves these empty
    std::string sdkVersion = "10.6.1.8";               // origin-sdk's default
    int timeoutMs = 10000;
    uint16_t port = kPort;

    ~Client() { Close(); }
    void Close() { if (s_ != EA_BADSOCK) { ea_closesock(s_); s_ = EA_BADSOCK; } }

    bool Connect() {
        Close();
        s_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s_ == EA_BADSOCK) return Fail("no socket");
#ifdef _WIN32
        DWORD t = (DWORD)timeoutMs;
        setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof t);
        setsockopt(s_, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof t);
#else
        timeval t{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
        setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof t);
        setsockopt(s_, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof t);
#endif
        sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
        a.sin_addr.s_addr = htonl(0x7F000001);
        if (connect(s_, (sockaddr*)&a, sizeof a) != 0) return Fail("the EA app is not running (nothing on 127.0.0.1:" + std::to_string(port) + ")");

        // The challenge, in the clear.
        std::string m, key;
        for (;;) {
            if (!Recv(m)) return false;
            if (m.find("<Challenge") != std::string::npos && Attr(m.substr(m.find("<Challenge")), "key", key)) break;
        }
        uint8_t k0[16]; MakeKey(0, k0);
        Bytes enc = AesEcbEncrypt(k0, key);
        std::string response = Hex(enc.data(), enc.size());
        std::string reply =
            "<LSX><Request recipient=\"EALS\" id=\"0\"><ChallengeResponse response=\"" + response +
            "\" key=\"" + Escape(key) + "\" version=\"3\"><ContentId>" + Escape(contentId) +
            "</ContentId><Title>" + Escape(title) + "</Title><MultiplayerId>" + Escape(multiplayerId) +
            "</MultiplayerId><Language>" + Escape(language) + "</Language><Version>" + Escape(sdkVersion) +
            "</Version></ChallengeResponse></Request></LSX>";
        if (!Send(reply)) return false;
        for (auto until = Deadline();;) {
            if (Late(until)) return Fail("the EA app did not accept the handshake in time");
            if (!Recv(m)) return false;
            if (m.find("<ChallengeAccepted") != std::string::npos) break;
            if (m.find("<Response") != std::string::npos) return Fail("the EA app refused the handshake: " + Element(m));
        }
        MakeKey(((uint32_t)(uint8_t)response[0] << 8) | (uint8_t)response[1], key_);
        return true;
    }

    // An encrypted request to "EbisuSDK"; the reply's XML in `out`.
    bool Request(const std::string& body, std::string& out) {
        std::string id = std::to_string(++id_);
        std::string xml = "<LSX><Request recipient=\"EbisuSDK\" id=\"" + id + "\">" + body + "</Request></LSX>";
        Bytes enc = AesEcbEncrypt(key_, xml);
        if (!Send(Hex(enc.data(), enc.size()))) return false;
        for (auto until = Deadline();;) {
            if (Late(until)) return Fail("the EA app did not answer in time");
            std::string m, plain, rid;
            if (!Recv(m)) return false;
            Bytes ct;
            if (!FromHex(m, ct) || !AesEcbDecrypt(key_, ct, plain)) continue;   // not for us (or an event we cannot read)
            size_t r = plain.find("<Response");
            if (r == std::string::npos) continue;                              // an event
            if (Attr(plain.substr(r, plain.find('>', r) - r), "id", rid) && rid != id) continue;
            out = plain;
            return true;
        }
    }

    // The account's auth token (GetAuthToken), or false with `err` saying why.
    bool GetAuthToken(std::string& token) {
        std::string r;
        if (!Request("<GetAuthToken/>", r)) return false;
        size_t p = r.find("<AuthToken");
        if (p == std::string::npos || !Attr(r.substr(p), "value", token) || token.empty())
            return Fail("the EA app gave no token: " + Element(r));
        return true;
    }

private:
    // Each Recv is bounded by the socket timeout, but a listener that keeps
    // sending what we skip (events, or bytes that are not the EA app's) would
    // hold these loops forever: they also give up after 30 s in all.
    static std::chrono::steady_clock::time_point Deadline() { return std::chrono::steady_clock::now() + std::chrono::seconds(30); }
    static bool Late(std::chrono::steady_clock::time_point t) { return std::chrono::steady_clock::now() > t; }

    ea_sock s_ = EA_BADSOCK;
    uint8_t key_[16] = {};
    unsigned id_ = 0;
    std::string buf_;

    bool Fail(const std::string& why) { err = why; Close(); return false; }
    bool Send(const std::string& m) {
        std::string w = m; w.push_back('\0');
        const char* p = w.data(); size_t n = w.size();
        while (n) { int k = (int)send(s_, p, (int)n, 0); if (k <= 0) return Fail("send to the EA app failed"); p += k; n -= k; }
        return true;
    }
    bool Recv(std::string& m) {
        for (;;) {
            size_t z = buf_.find('\0');
            if (z != std::string::npos) { m = buf_.substr(0, z); buf_.erase(0, z + 1); return true; }
            if (buf_.size() > (1u << 22)) return Fail("the EA app sent an oversized message");
            char tmp[8192];
            int k = (int)recv(s_, tmp, sizeof tmp, 0);
            if (k <= 0) return Fail(k == 0 ? "the EA app closed the connection" : "the EA app did not answer in time");
            buf_.append(tmp, k);
        }
    }
    // The reply's first element inside <Response>, for an error message; an
    // AuthToken's value is never shown.
    static std::string Element(const std::string& xml) {
        size_t r = xml.find("<Response");
        size_t s = r == std::string::npos ? std::string::npos : xml.find('<', xml.find('>', r));
        if (s == std::string::npos) return "(nothing)";
        size_t e = xml.find('>', s);
        std::string el = xml.substr(s, e == std::string::npos ? std::string::npos : e - s + 1);
        if (el.find("value=") != std::string::npos && el.find("AuthToken") != std::string::npos) return "<AuthToken ...>";
        return el.size() > 200 ? el.substr(0, 200) + "..." : el;
    }
};

}  // namespace lsx
}  // namespace ea
