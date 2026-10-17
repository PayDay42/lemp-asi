// ea_blaze.h — a blocking client for EA's ME3 (2012) Blaze servers: SSLv3
// (RSA key exchange, RC4-128 with SHA-1 or MD5 MACs), Blaze's packet framing,
// and TDF, the tagged binary encoding its requests and replies use.
//
// A port of Pocket Relay's retriever (its server's src/services/retriever/)
// and the SSLv3 client it uses (blaze-ssl-async's src/handshake/client.rs,
// crypto/mod.rs), which reach EA's ME3 servers today. Packet framing: Pocket
// Relay's src/session/packet.rs (FireFrame). TDF: the `tdf`
// 0.4 crate Pocket Relay builds on.
//
// Blocking and single-connection on purpose: mp_save.asi runs it on its own
// thread, only after the player has asked for the import and agreed.
//
// Unlike blaze-ssl-async, which accepts any certificate, this checks the
// server's certificate the way 2012's ProtoSSL did: signed by EA's "OTG3
// Certificate Authority", whose key 2012's exe carries (kOtg3Modulus). The
// session carries the player's EA token, which must reach no one but EA.
//
// Builds natively too (POSIX sockets) for test_ea_blaze.cpp.
#pragma once
#include "ea_crypto.h"
#include <functional>
#include <map>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
typedef SOCKET ea_sock;
#define EA_BADSOCK INVALID_SOCKET
#define ea_closesock closesocket
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
typedef int ea_sock;
#define EA_BADSOCK (-1)
#define ea_closesock close
#endif

namespace ea {

inline void RandomBytes(uint8_t* p, size_t n) {
#ifdef _WIN32
    BCryptGenRandom(nullptr, p, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    FILE* f = fopen("/dev/urandom", "rb"); size_t r = f ? fread(p, 1, n, f) : 0; if (f) fclose(f);
    (void)r;
#endif
}

// ---- SSLv3 --------------------------------------------------------------------
class Ssl {
public:
    std::string err;            // why the last call failed
    std::string peerSubject, peerIssuer, peerPin;   // the server certificate's CN, issuer CN, SPKI SHA-1
    Bytes peerCert;                                 // the server certificate (DER)
    // The CA the server's certificate must be signed by (null: not required;
    // checkCa: checked and reported in peerSignedByCa only, for the test).
    // Not a pin on each server's own key: the redirector hands out more than
    // one instance (gsprodblapp-NN, ports vary between runs).
    const RsaKey* ca = nullptr;
    const RsaKey* checkCa = nullptr;
    bool peerSignedByCa = false;
    int timeoutMs = 15000;

    ~Ssl() { Close(); }
    void Close() { if (s_ != EA_BADSOCK) { ea_closesock(s_); s_ = EA_BADSOCK; } }

    bool Connect(const std::string& host, uint16_t port) {
        Close();
        addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) return Fail("cannot resolve " + host);
        for (addrinfo* a = res; a; a = a->ai_next) {
            ea_sock s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
            if (s == EA_BADSOCK) continue;
#ifdef _WIN32
            DWORD t = (DWORD)timeoutMs;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof t);
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof t);
#else
            timeval t{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof t);
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof t);
#endif
            if (connect(s, a->ai_addr, (int)a->ai_addrlen) == 0) { s_ = s; break; }
            ea_closesock(s);
        }
        freeaddrinfo(res);
        if (s_ == EA_BADSOCK) return Fail("cannot connect to " + host + ":" + std::to_string(port));
        return Handshake();
    }

    bool Write(const Bytes& data) {
        for (size_t o = 0; o < data.size(); o += 16384) {
            size_t n = data.size() - o < 16384 ? data.size() - o : 16384;
            if (!SendRecord(23, Bytes(data.begin() + o, data.begin() + o + n))) return false;
        }
        return true;
    }
    // At least `n` bytes of application data in `app` (appended), or false.
    bool ReadApp(Bytes& app, size_t n) {
        while (app.size() < n) {
            uint8_t type; Bytes p;
            if (!ReadRecord(type, p)) return false;
            if (type == 21) return Alert(p);
            if (type != 23) return Fail("unexpected record type " + std::to_string(type));
            app.insert(app.end(), p.begin(), p.end());
        }
        return true;
    }

private:
    ea_sock s_ = EA_BADSOCK;
    bool sha_ = true, encOn_ = false, decOn_ = false;
    Rc4 enc_, dec_;
    uint8_t macOut_[20], macIn_[20];
    uint64_t seqOut_ = 0, seqIn_ = 0;
    Bytes transcript_;

    bool Fail(const std::string& why) { err = why; Close(); return false; }
    bool Alert(const Bytes& p) {
        return Fail("server alert " + std::to_string(p.size() > 0 ? p[0] : 0) + "/" + std::to_string(p.size() > 1 ? p[1] : 0));
    }

    bool RawSend(const uint8_t* p, size_t n) {
        while (n) { int k = (int)send(s_, (const char*)p, (int)n, 0); if (k <= 0) return Fail("send failed"); p += k; n -= k; }
        return true;
    }
    bool RawRecv(uint8_t* p, size_t n) {
        while (n) { int k = (int)recv(s_, (char*)p, (int)n, 0); if (k <= 0) return Fail(k == 0 ? "connection closed" : "receive failed or timed out"); p += k; n -= k; }
        return true;
    }

    // SSLv3 MAC (RFC 6101 §5.2.3.1): hash(secret + pad2 + hash(secret + pad1 + seq + type + length + data)).
    void Mac(const uint8_t* secret, uint64_t seq, uint8_t type, const Bytes& data, uint8_t* out) {
        uint8_t hdr[11];
        for (int i = 0; i < 8; ++i) hdr[i] = (uint8_t)(seq >> (56 - 8 * i));
        hdr[8] = type; hdr[9] = (uint8_t)(data.size() >> 8); hdr[10] = (uint8_t)data.size();
        uint8_t pad1[48], pad2[48]; memset(pad1, 0x36, 48); memset(pad2, 0x5c, 48);
        if (sha_) {
            Sha1 h; uint8_t in[20];
            h.Update(secret, 20); h.Update(pad1, 40); h.Update(hdr, 11); h.Update(data); h.Final(in);
            h.Update(secret, 20); h.Update(pad2, 40); h.Update(in, 20); h.Final(out);
        } else {
            Md5 h; uint8_t in[16];
            h.Update(secret, 16); h.Update(pad1, 48); h.Update(hdr, 11); h.Update(data); h.Final(in);
            h.Update(secret, 16); h.Update(pad2, 48); h.Update(in, 16); h.Final(out);
        }
    }
    size_t MacLen() const { return sha_ ? 20 : 16; }

    bool SendRecord(uint8_t type, Bytes p) {
        if (encOn_) {
            uint8_t m[20]; Mac(macOut_, seqOut_++, type, p, m);
            p.insert(p.end(), m, m + MacLen());
            enc_.Apply(p.data(), p.size());
        }
        uint8_t h[5] = { type, 3, 0, (uint8_t)(p.size() >> 8), (uint8_t)p.size() };
        return RawSend(h, 5) && RawSend(p.data(), p.size());
    }
    bool ReadRecord(uint8_t& type, Bytes& p) {
        uint8_t h[5];
        if (!RawRecv(h, 5)) return false;
        size_t n = (h[3] << 8) | h[4];
        if (h[1] != 3 || n > 18432) return Fail("not an SSLv3 record");
        type = h[0]; p.resize(n);
        if (n && !RawRecv(p.data(), n)) return false;
        if (decOn_) {
            dec_.Apply(p.data(), p.size());
            if (p.size() < MacLen()) return Fail("record shorter than its MAC");
            Bytes body(p.begin(), p.end() - MacLen());
            uint8_t m[20]; Mac(macIn_, seqIn_++, type, body, m);
            if (memcmp(m, p.data() + body.size(), MacLen()) != 0) return Fail("bad record MAC");
            p.swap(body);
        }
        return true;
    }

    bool SendHandshake(uint8_t ht, const Bytes& body) {
        Bytes m = { ht, (uint8_t)(body.size() >> 16), (uint8_t)(body.size() >> 8), (uint8_t)body.size() };
        m.insert(m.end(), body.begin(), body.end());
        transcript_.insert(transcript_.end(), m.begin(), m.end());
        return SendRecord(22, m);
    }
    // The next whole handshake message (several may share a record, one may span records).
    Bytes hsBuf_;
    bool ReadHandshake(uint8_t& ht, Bytes& body, bool wantCcs = false) {
        for (;;) {
            if (hsBuf_.size() >= 4) {
                size_t n = (hsBuf_[1] << 16) | (hsBuf_[2] << 8) | hsBuf_[3];
                if (hsBuf_.size() >= 4 + n) {
                    ht = hsBuf_[0]; body.assign(hsBuf_.begin() + 4, hsBuf_.begin() + 4 + n);
                    if (ht != 20) transcript_.insert(transcript_.end(), hsBuf_.begin(), hsBuf_.begin() + 4 + n);
                    hsBuf_.erase(hsBuf_.begin(), hsBuf_.begin() + 4 + n);
                    return true;
                }
            }
            uint8_t type; Bytes p;
            if (!ReadRecord(type, p)) return false;
            if (type == 21) return Alert(p);
            if (type == 20 && wantCcs) { ht = 0xFF; return true; }   // ChangeCipherSpec
            if (type != 22) return Fail("unexpected record type " + std::to_string(type) + " in handshake");
            hsBuf_.insert(hsBuf_.end(), p.begin(), p.end());
        }
    }

    // SSLv3 key derivation (blaze-ssl-async generate_key_block):
    // out[i] = MD5(key + SHA1('A'*(i+1) + key + r1 + r2)).
    static void KeyBlock(uint8_t* out, size_t n, const uint8_t* key, size_t keyLen, const uint8_t* r1, const uint8_t* r2) {
        for (size_t i = 0; i * 16 < n; ++i) {
            Sha1 s; uint8_t salt[16]; memset(salt, 'A' + (int)i, i + 1);
            s.Update(salt, i + 1); s.Update(key, keyLen); s.Update(r1, 32); s.Update(r2, 32);
            uint8_t inner[20]; s.Final(inner);
            Md5 m; m.Update(key, keyLen); m.Update(inner, 20);
            uint8_t o[16]; m.Final(o);
            memcpy(out + i * 16, o, n - i * 16 < 16 ? n - i * 16 : 16);
        }
    }
    // Finished (RFC 6101 §5.6.9): MD5 and SHA-1 of transcript + sender + master + pad1, then outer.
    static Bytes FinishedHash(const Bytes& transcript, bool client, const uint8_t* master) {
        uint8_t sender[4] = { 'S', 'R', 'V', 'R' };
        if (client) memcpy(sender, "CLNT", 4);
        uint8_t pad1[48], pad2[48]; memset(pad1, 0x36, 48); memset(pad2, 0x5c, 48);
        Md5 m; uint8_t mi[16], mo[16];
        m.Update(transcript); m.Update(sender, 4); m.Update(master, 48); m.Update(pad1, 48); m.Final(mi);
        m.Update(master, 48); m.Update(pad2, 48); m.Update(mi, 16); m.Final(mo);
        Sha1 s; uint8_t si[20], so[20];
        s.Update(transcript); s.Update(sender, 4); s.Update(master, 48); s.Update(pad1, 40); s.Final(si);
        s.Update(master, 48); s.Update(pad2, 40); s.Update(si, 20); s.Final(so);
        Bytes out(mo, mo + 16); out.insert(out.end(), so, so + 20);
        return out;
    }

    bool Handshake() {
        transcript_.clear(); hsBuf_.clear(); encOn_ = decOn_ = false; seqIn_ = seqOut_ = 0;
        uint8_t cr[32], sr[32];
        RandomBytes(cr, 32);
        // ClientHello: SSLv3, no session, RC4-SHA then RC4-MD5, null compression.
        Bytes hello = { 3, 0 };
        hello.insert(hello.end(), cr, cr + 32);
        hello.insert(hello.end(), { 0, 0, 4, 0x00, 0x05, 0x00, 0x04, 1, 0 });
        if (!SendHandshake(1, hello)) return false;

        uint8_t ht; Bytes b;
        if (!ReadHandshake(ht, b)) return false;
        if (ht != 2 || b.size() < 38) return Fail("expected ServerHello");
        memcpy(sr, &b[2], 32);
        size_t sid = b[34];
        if (b.size() < 35 + sid + 3) return Fail("short ServerHello");
        uint16_t suite = (uint16_t)((b[35 + sid] << 8) | b[36 + sid]);
        if (suite == 0x0005) sha_ = true; else if (suite == 0x0004) sha_ = false;
        else return Fail("server chose cipher suite " + std::to_string(suite));

        if (!ReadHandshake(ht, b)) return false;
        if (ht != 11 || b.size() < 6) return Fail("expected Certificate");
        size_t clen = (b[3] << 16) | (b[4] << 8) | b[5];   // first certificate of the chain
        if (b.size() < 6 + clen) return Fail("short Certificate");
        CertInfo ci;
        if (!ParseCert(Bytes(b.begin() + 6, b.begin() + 6 + clen), ci)) return Fail("cannot read the server certificate");
        peerCert.assign(b.begin() + 6, b.begin() + 6 + clen);
        peerSubject = ci.subject; peerIssuer = ci.issuer; peerPin = Sha1Hex(ci.spki);
        peerSignedByCa = (ca || checkCa) && VerifyCertSignature(ci, ca ? *ca : *checkCa);
        if (ca && !peerSignedByCa)
            return Fail("server certificate '" + peerSubject + "' is not signed by EA's OTG3 authority; nothing was sent");

        if (!ReadHandshake(ht, b)) return false;
        if (ht != 14) return Fail("expected ServerHelloDone");

        uint8_t pm[48]; pm[0] = 3; pm[1] = 0; RandomBytes(pm + 2, 46);
        Bytes enc;
        if (!RsaEncrypt(ci.key, Bytes(pm, pm + 48), enc, RandomBytes)) return Fail("server key too small");
        if (!SendHandshake(16, enc)) return false;   // SSLv3: no length prefix

        uint8_t master[48], kb[80];
        KeyBlock(master, 48, pm, 48, cr, sr);
        KeyBlock(kb, 80, master, 48, sr, cr);
        size_t ml = MacLen();
        memcpy(macOut_, kb, ml); memcpy(macIn_, kb + ml, ml);
        enc_.Init(kb + 2 * ml, 16); dec_.Init(kb + 2 * ml + 16, 16);

        if (!SendRecord(20, Bytes{1})) return false;
        encOn_ = true;
        if (!SendHandshake(20, FinishedHash(transcript_, true, master))) return false;

        if (!ReadHandshake(ht, b, true) || ht != 0xFF) return err.empty() ? Fail("expected ChangeCipherSpec") : false;
        decOn_ = true;
        Bytes expect = FinishedHash(transcript_, false, master);
        if (!ReadHandshake(ht, b)) return false;
        if (ht != 20 || b != expect) return Fail("bad server Finished");
        return true;
    }
};

// ---- TDF ----------------------------------------------------------------------
namespace tdf {
enum Type { VarInt = 0, String = 1, Blob = 2, Group = 3, List = 4, Map = 5, Union = 6, IntList = 7, ObjType = 8, ObjId = 9, Float = 10, Generic = 12 };

struct Writer {
    Bytes b;
    void Tag(const char* t, Type ty) {
        uint8_t o[4] = { 0, 0, 0, (uint8_t)ty }; size_t n = strlen(t);
        const uint8_t* g = (const uint8_t*)t;
        if (n > 0) o[0] |= ((g[0] & 0x40) << 1) | ((g[0] & 0x10) << 2) | ((g[0] & 0x0F) << 2);
        if (n > 1) { o[0] |= ((g[1] & 0x40) >> 5) | ((g[1] & 0x10) >> 4); o[1] |= (g[1] & 0x0F) << 4; }
        if (n > 2) { o[1] |= ((g[2] & 0x40) >> 3) | ((g[2] & 0x10) >> 2) | ((g[2] & 0x0C) >> 2); o[2] |= (g[2] & 0x03) << 6; }
        if (n > 3) o[2] |= ((g[3] & 0x40) >> 1) | (g[3] & 0x1F);
        b.insert(b.end(), o, o + 4);
    }
    void Int(uint64_t v) {
        if (v < 0x40) { b.push_back((uint8_t)v); return; }
        b.push_back((uint8_t)((v & 0x3F) | 0x80)); v >>= 6;
        while (v >= 0x80) { b.push_back((uint8_t)((v & 0x7F) | 0x80)); v >>= 7; }
        b.push_back((uint8_t)v);
    }
    void Str(const std::string& s) { Int(s.size() + 1); b.insert(b.end(), s.begin(), s.end()); b.push_back(0); }
    void TagInt(const char* t, uint64_t v) { Tag(t, VarInt); Int(v); }
    void TagStr(const char* t, const std::string& s) { Tag(t, String); Str(s); }
    void TagUnionUnset(const char* t) { Tag(t, Union); b.push_back(0x7F); }
};

// A decoded value. Groups, unions and lists keep their members in `kids`;
// maps their pairs in `kids` as key, value, key, value...
struct Value {
    std::string tag; int type = -1;
    uint64_t num = 0; std::string str;
    std::vector<Value> kids;
    const Value* Find(const char* t) const {     // depth-first, the first match
        for (auto& k : kids) { if (k.tag == t) return &k; if (const Value* f = k.Find(t)) return f; }
        return nullptr;
    }
};

struct Reader {
    const uint8_t* p; size_t n; bool bad = false;
    uint8_t Byte() { if (!n) { bad = true; return 0; } --n; return *p++; }
    uint64_t Int() {
        uint8_t c = Byte(); uint64_t r = c & 0x3F; int sh = 6;
        while ((c & 0x80) && !bad) { c = Byte(); if (sh < 64) r |= (uint64_t)(c & 0x7F) << sh; sh += 7; }
        return r;
    }
    std::string Tag(uint8_t& ty) {
        if (n < 4) { bad = true; return ""; }
        const uint8_t* i = p; p += 4; n -= 4; ty = i[3];
        auto dec = [](uint8_t m, uint8_t c) -> char { return (char)((m | c) == 0 ? 0 : (m & 0x40) == 0 ? (0x30 | c) : (m | c)); };
        char o[5] = { dec((i[0] & 0x80) >> 1, (i[0] & 0x7C) >> 2),
                      dec((i[0] & 2) << 5, ((i[0] & 1) << 4) | ((i[1] & 0xF0) >> 4)),
                      dec((i[1] & 8) << 3, ((i[1] & 7) << 2) | ((i[2] & 0xC0) >> 6)),
                      dec((i[2] & 0x20) << 1, i[2] & 0x1F), 0 };
        return std::string(o);
    }
    bool Body(Value& v, int ty, int depth = 0) {
        v.type = ty;
        if (depth > 32) { bad = true; return false; }
        switch (ty) {
        case VarInt: v.num = Int(); break;
        case String: case Blob: {
            uint64_t l = Int(); if (l > n) { bad = true; break; }
            v.str.assign((const char*)p, (size_t)l); p += l; n -= (size_t)l;
            if (ty == String && !v.str.empty() && v.str.back() == 0) v.str.pop_back();
            break;
        }
        case Group: Members(v, depth); break;
        case List: {
            int et = Byte(); uint64_t c = Int();
            for (uint64_t k = 0; k < c && !bad; ++k) { v.kids.emplace_back(); Body(v.kids.back(), et, depth + 1); }
            break;
        }
        case Map: {
            int kt = Byte(), vt = Byte(); uint64_t c = Int();
            for (uint64_t k = 0; k < c && !bad; ++k) {
                v.kids.emplace_back(); Body(v.kids.back(), kt, depth + 1);
                v.kids.emplace_back(); Body(v.kids.back(), vt, depth + 1);
            }
            break;
        }
        case Union: {
            v.num = Byte();
            if (v.num != 0x7F && !bad) { uint8_t t; Value k; k.tag = Tag(t); Body(k, t, depth + 1); v.kids.push_back(k); }
            break;
        }
        case IntList: { uint64_t c = Int(); for (uint64_t k = 0; k < c && !bad; ++k) Int(); break; }
        case ObjType: Int(); Int(); break;
        case ObjId: Int(); Int(); Int(); break;
        case Float: if (n < 4) bad = true; else { p += 4; n -= 4; } break;
        case Generic: {
            if (Byte() == 1) { Int(); int t = Byte(); Value k; Body(k, t, depth + 1); v.kids.push_back(k); Byte(); }
            break;
        }
        default: bad = true;
        }
        return !bad;
    }
    // Tagged members up to a group's 0 terminator (or the end, at top level).
    void Members(Value& v, int depth) {
        while (!bad) {
            if (!n) { if (depth > 0) bad = true; return; }
            if (*p == 0) { ++p; --n; return; }
            uint8_t t = 0; Value k; k.tag = Tag(t);
            if (bad) return;
            Body(k, t, depth + 1);
            v.kids.push_back(k);
        }
    }
};

inline bool Parse(const Bytes& b, Value& out) {
    Reader r{b.data(), b.size()}; out = Value(); out.type = Group;
    r.Members(out, 0);
    return !r.bad;
}
}  // namespace tdf

// ---- Blaze ----------------------------------------------------------------------
class Blaze {
public:
    Ssl ssl;
    std::string err;
    uint16_t lastError = 0;   // the server's error code, when it answered with one

    bool Connect(const std::string& host, uint16_t port) {
        if (!ssl.Connect(host, port)) { err = ssl.err; return false; }
        return true;
    }

    // Sends a request and waits for its response (notifications are skipped).
    bool Request(uint16_t component, uint16_t command, const Bytes& body, Bytes& reply) {
        lastError = 0;
        Bytes pkt;
        size_t len = body.size();
        uint8_t opts = len > 0xFFFF ? 1 : 0;
        uint8_t h[12] = { (uint8_t)(len >> 8), (uint8_t)len, (uint8_t)(component >> 8), (uint8_t)component,
                          (uint8_t)(command >> 8), (uint8_t)command, 0, 0, 0, (uint8_t)(opts << 4),
                          (uint8_t)(seq_ >> 8), (uint8_t)seq_ };
        pkt.insert(pkt.end(), h, h + 12);
        if (opts) { pkt.push_back((uint8_t)(len >> 24)); pkt.push_back((uint8_t)(len >> 16)); }
        pkt.insert(pkt.end(), body.begin(), body.end());
        ++seq_;
        if (!ssl.Write(pkt)) { err = ssl.err; return false; }
        for (;;) {
            if (!ssl.ReadApp(buf_, 12)) { err = ssl.err; return false; }
            size_t plen = (buf_[0] << 8) | buf_[1];
            uint16_t comp = (uint16_t)((buf_[2] << 8) | buf_[3]), cmd = (uint16_t)((buf_[4] << 8) | buf_[5]);
            uint16_t error = (uint16_t)((buf_[6] << 8) | buf_[7]);
            int type = buf_[8] >> 4, popts = buf_[9] >> 4;
            size_t hl = 12;
            if (popts & 1) {
                if (!ssl.ReadApp(buf_, 14)) { err = ssl.err; return false; }
                plen |= (size_t)((buf_[12] << 8) | buf_[13]) << 16; hl = 14;
            }
            if (plen > (16u << 20)) { err = "Blaze packet too large"; ssl.Close(); return false; }
            if (!ssl.ReadApp(buf_, hl + plen)) { err = ssl.err; return false; }
            Bytes content(buf_.begin() + hl, buf_.begin() + hl + plen);
            buf_.erase(buf_.begin(), buf_.begin() + hl + plen);
            if (comp != component || cmd != command) continue;   // a notification or someone else's
            if (type == 3) { lastError = error; err = "server error " + std::to_string(error); return false; }
            if (type == 1) { reply.swap(content); return true; }
        }
    }
    bool Request(uint16_t component, uint16_t command, const Bytes& body, tdf::Value& reply) {
        Bytes r;
        if (!Request(component, command, body, r)) return false;
        if (!tdf::Parse(r, reply)) { err = "cannot decode the reply"; return false; }
        return true;
    }

private:
    uint16_t seq_ = 0;
    Bytes buf_;
};

// ---- EA's ME3 server --------------------------------------------------------------
// Component and command ids: Pocket Relay's src/utils/components.rs.
enum : uint16_t {
    kAuthComponent = 0x1, kOriginLogin = 0x98,
    kRedirectorComponent = 0x5, kGetServerInstance = 0x1,
    kUtilComponent = 0x9, kUserSettingsLoadAll = 0xC,
};
// EA's "OTG3 Certificate Authority" (OU=Online Technology Group, O=Electronic
// Arts, Inc.), the CA 2012's ProtoSSL trusted for its servers: the modulus
// from 2012's MassEffect3.exe CA table (file offset 0x119ebb8, pointed to by
// the entry named at 0x14f93b0, whose next field is the exponent, 3).
// [V] gosredirector's certificate (MD5, issued 2015) verifies with it; with
// 65537, the first guess, it does not.
static const uint8_t kOtg3Modulus[128] = {
    0x92,0x75,0xa1,0x5b,0x08,0x02,0x40,0xb8,0x9b,0x40,0x2f,0xd5,0x9c,0x71,0xc4,0x51,
    0x58,0x71,0xd8,0xf0,0x2d,0x93,0x7f,0xd3,0x0c,0x8b,0x1c,0x7d,0xf9,0x2a,0x04,0x86,
    0xf1,0x90,0xd1,0x31,0x0a,0xcb,0xd8,0xd4,0x14,0x12,0x90,0x3b,0x35,0x6a,0x06,0x51,
    0x49,0x4c,0xc5,0x75,0xee,0x0a,0x46,0x29,0x80,0xf0,0xd5,0x3a,0x51,0xba,0x5d,0x6a,
    0x19,0x37,0x33,0x43,0x68,0x25,0x2d,0xfe,0xdf,0x95,0x26,0x36,0x7c,0x43,0x64,0xf1,
    0x56,0x17,0x0e,0xf1,0x67,0xd5,0x69,0x54,0x20,0xfb,0x3a,0x55,0x93,0x5d,0xd4,0x97,
    0xbc,0x3a,0xd5,0x8f,0xd2,0x44,0xc5,0x9a,0xff,0xcd,0x0c,0x31,0xdb,0x9d,0x94,0x7c,
    0xa6,0x66,0x66,0xfb,0x4b,0xa7,0x5e,0xf8,0x64,0x4e,0x28,0xb1,0xa6,0xb8,0x73,0x95 };
inline const RsaKey& Otg3() {
    static const RsaKey k{ Bytes(kOtg3Modulus, kOtg3Modulus + 128), Bytes{ 0x03 } };
    return k;
}

static const char* kRedirectorHost = "gosredirector.ea.com";
static const uint16_t kRedirectorPort = 42127;

// Redirector GetServerInstance, as 2012's client sent it
// (Pocket Relay's src/services/retriever/models.rs InstanceRequest); `service` is
// the instance asked for: the PC client's own, or a console's (console_probe.h).
inline Bytes InstanceRequest(const char* service = "masseffect-3-pc") {
    tdf::Writer w;
    w.TagStr("BSDK", "3.15.6.0");
    w.TagStr("BTIM", "Dec 21 2012 12:47:10");
    w.TagStr("CLNT", "MassEffect3-pc");
    w.TagInt("CLTP", 0);
    w.TagStr("CSKU", "134845");
    w.TagStr("CVER", "05427.124");
    w.TagStr("DSDK", "8.14.7.1");
    w.TagStr("ENV", "prod");
    w.TagUnionUnset("FPID");
    w.TagInt("LOC", 0x656e4e5a);   // "enNZ", Pocket Relay's LOCALE_NZ
    w.TagStr("NAME", service);
    w.TagStr("PLAT", "Windows");
    w.TagStr("PROF", "standardSecure_v3");
    return w.b;
}

// The instance's address out of the redirector's reply: ADDR (union) ->
// VALU (group) -> HOST, PORT (InstanceDetails / InstanceAddress).
inline bool InstanceAddress(const tdf::Value& r, std::string& host, uint16_t& port) {
    const tdf::Value* addr = r.Find("ADDR");
    if (!addr) return false;
    const tdf::Value* h = addr->Find("HOST");
    const tdf::Value* p = addr->Find("PORT");
    if (!h || !p || h->str.empty()) return false;
    host = h->str; port = (uint16_t)p->num;
    return true;
}

}  // namespace ea
