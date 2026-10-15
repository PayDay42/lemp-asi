// ea_crypto.h — the primitives EA's ME3 (2012) Blaze connection needs: MD5,
// SHA-1, RC4, RSA public-key encryption (PKCS#1 v1.5) and just enough DER to
// take an RSA key out of an X.509 certificate.
//
// Ported from vendor/blaze-ssl-async (crypto/), Pocket Relay's SSLv3 client,
// which reaches EA's servers today; EA's ME3 servers speak only SSLv3 with
// TLS_RSA_WITH_RC4_128_{SHA,MD5} (2012's ProtoSSL). Nothing in Windows or
// Wine still offers SSLv3, so it is done by hand, as Pocket Relay does.
//
// Pure C++ (no Windows headers): test_ea_crypto.cpp checks it natively.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace ea {

typedef std::vector<uint8_t> Bytes;

// ---- MD5 (RFC 1321) ---------------------------------------------------------
struct Md5 {
    uint32_t h[4]; uint64_t len; uint8_t buf[64]; size_t n;
    Md5() { Reset(); }
    void Reset() { h[0] = 0x67452301; h[1] = 0xefcdab89; h[2] = 0x98badcfe; h[3] = 0x10325476; len = 0; n = 0; }
    static uint32_t Rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }
    void Block(const uint8_t* p) {
        static const uint32_t K[64] = {
            0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
            0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
            0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
            0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
            0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
            0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
            0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
            0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
        static const int R[64] = { 7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22, 5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
                                   4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23, 6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
        uint32_t m[16];
        for (int i = 0; i < 16; ++i) m[i] = p[i*4] | (p[i*4+1] << 8) | (p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        for (int i = 0; i < 64; ++i) {
            uint32_t f; int g;
            if (i < 16) { f = (b & c) | (~b & d); g = i; }
            else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) & 15; }
            else if (i < 48) { f = b ^ c ^ d; g = (3*i + 5) & 15; }
            else { f = c ^ (b | ~d); g = (7*i) & 15; }
            uint32_t t = d; d = c; c = b;
            b = b + Rol(a + f + K[i] + m[g], R[i]);
            a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    }
    void Update(const void* data, size_t sz) {
        const uint8_t* p = (const uint8_t*)data; len += sz;
        while (sz) { size_t k = 64 - n < sz ? 64 - n : sz; memcpy(buf + n, p, k); n += k; p += k; sz -= k; if (n == 64) { Block(buf); n = 0; } }
    }
    void Update(const Bytes& b) { Update(b.data(), b.size()); }
    void Final(uint8_t out[16]) {
        uint64_t bits = len * 8; uint8_t pad = 0x80; Update(&pad, 1);
        uint8_t z = 0; while (n != 56) Update(&z, 1);
        uint8_t l[8]; for (int i = 0; i < 8; ++i) l[i] = (uint8_t)(bits >> (8*i)); Update(l, 8);
        for (int i = 0; i < 4; ++i) for (int k = 0; k < 4; ++k) out[i*4+k] = (uint8_t)(h[i] >> (8*k));
        Reset();
    }
};

// ---- SHA-1 (FIPS 180-1) -----------------------------------------------------
struct Sha1 {
    uint32_t h[5]; uint64_t len; uint8_t buf[64]; size_t n;
    Sha1() { Reset(); }
    void Reset() { h[0] = 0x67452301; h[1] = 0xEFCDAB89; h[2] = 0x98BADCFE; h[3] = 0x10325476; h[4] = 0xC3D2E1F0; len = 0; n = 0; }
    static uint32_t Rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }
    void Block(const uint8_t* p) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) w[i] = ((uint32_t)p[i*4] << 24) | (p[i*4+1] << 16) | (p[i*4+2] << 8) | p[i*4+3];
        for (int i = 16; i < 80; ++i) w[i] = Rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t t = Rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = Rol(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    void Update(const void* data, size_t sz) {
        const uint8_t* p = (const uint8_t*)data; len += sz;
        while (sz) { size_t k = 64 - n < sz ? 64 - n : sz; memcpy(buf + n, p, k); n += k; p += k; sz -= k; if (n == 64) { Block(buf); n = 0; } }
    }
    void Update(const Bytes& b) { Update(b.data(), b.size()); }
    void Final(uint8_t out[20]) {
        uint64_t bits = len * 8; uint8_t pad = 0x80; Update(&pad, 1);
        uint8_t z = 0; while (n != 56) Update(&z, 1);
        uint8_t l[8]; for (int i = 0; i < 8; ++i) l[i] = (uint8_t)(bits >> (56 - 8*i)); Update(l, 8);
        for (int i = 0; i < 5; ++i) for (int k = 0; k < 4; ++k) out[i*4+k] = (uint8_t)(h[i] >> (24 - 8*k));
        Reset();
    }
};

inline std::string Hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; } return s;
}
inline std::string Sha1Hex(const Bytes& b) { Sha1 s; s.Update(b); uint8_t o[20]; s.Final(o); return Hex(o, 20); }

// ---- RC4 --------------------------------------------------------------------
struct Rc4 {
    uint8_t S[256]; uint8_t i = 0, j = 0;
    void Init(const uint8_t* key, size_t n) {
        for (int k = 0; k < 256; ++k) S[k] = (uint8_t)k;
        uint8_t jj = 0;
        for (int k = 0; k < 256; ++k) { jj = (uint8_t)(jj + S[k] + key[k % n]); uint8_t t = S[k]; S[k] = S[jj]; S[jj] = t; }
        i = j = 0;
    }
    void Apply(uint8_t* p, size_t n) {
        for (size_t k = 0; k < n; ++k) {
            i = (uint8_t)(i + 1); j = (uint8_t)(j + S[i]);
            uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
            p[k] ^= S[(uint8_t)(S[i] + S[j])];
        }
    }
};

// ---- AES-128 (FIPS-197), one block at a time ---------------------------------
// For the EA app's local LSX service (ea_lsx.h), which encrypts with
// AES-128-ECB.
struct Aes128 {
    uint8_t rk[176];
    static const uint8_t* Sbox() {
        static const uint8_t s[256] = {
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };
        return s;
    }
    static const uint8_t* InvSbox() {
        static uint8_t inv[256]; static bool done = false;
        if (!done) { for (int i = 0; i < 256; ++i) inv[Sbox()[i]] = (uint8_t)i; done = true; }
        return inv;
    }
    static uint8_t Xt(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }
    static uint8_t Mul(uint8_t a, uint8_t b) { uint8_t r = 0; while (b) { if (b & 1) r ^= a; a = Xt(a); b >>= 1; } return r; }
    explicit Aes128(const uint8_t key[16]) {
        const uint8_t* s = Sbox(); InvSbox();
        memcpy(rk, key, 16);
        uint8_t rcon = 1;
        for (int i = 16; i < 176; i += 4) {
            uint8_t t[4] = { rk[i-4], rk[i-3], rk[i-2], rk[i-1] };
            if (i % 16 == 0) {
                uint8_t u = t[0]; t[0] = (uint8_t)(s[t[1]] ^ rcon); t[1] = s[t[2]]; t[2] = s[t[3]]; t[3] = s[u];
                rcon = Xt(rcon);
            }
            for (int k = 0; k < 4; ++k) rk[i+k] = rk[i-16+k] ^ t[k];
        }
    }
    void Encrypt(uint8_t b[16]) const {
        const uint8_t* s = Sbox();
        for (int k = 0; k < 16; ++k) b[k] ^= rk[k];
        for (int r = 1; r <= 10; ++r) {
            uint8_t t[16];
            for (int k = 0; k < 16; ++k) t[k] = s[b[(k + 4 * (k % 4)) % 16]];   // SubBytes + ShiftRows
            for (int c = 0; c < 4 && r < 10; ++c) {                            // MixColumns
                uint8_t* m = t + 4 * c; uint8_t a0 = m[0], a1 = m[1], a2 = m[2], a3 = m[3];
                m[0] = Xt(a0) ^ Xt(a1) ^ a1 ^ a2 ^ a3; m[1] = a0 ^ Xt(a1) ^ Xt(a2) ^ a2 ^ a3;
                m[2] = a0 ^ a1 ^ Xt(a2) ^ Xt(a3) ^ a3; m[3] = Xt(a0) ^ a0 ^ a1 ^ a2 ^ Xt(a3);
            }
            for (int k = 0; k < 16; ++k) b[k] = t[k] ^ rk[16 * r + k];
        }
    }
    void Decrypt(uint8_t b[16]) const {
        const uint8_t* is = InvSbox();
        for (int k = 0; k < 16; ++k) b[k] ^= rk[160 + k];
        for (int r = 9; r >= 0; --r) {
            uint8_t t[16];
            for (int k = 0; k < 16; ++k) t[(k + 4 * (k % 4)) % 16] = is[b[k]];  // InvShiftRows + InvSubBytes
            for (int k = 0; k < 16; ++k) t[k] ^= rk[16 * r + k];
            for (int c = 0; c < 4 && r > 0; ++c) {                             // InvMixColumns
                uint8_t* m = t + 4 * c; uint8_t a0 = m[0], a1 = m[1], a2 = m[2], a3 = m[3];
                m[0] = Mul(a0,14) ^ Mul(a1,11) ^ Mul(a2,13) ^ Mul(a3,9);
                m[1] = Mul(a0,9) ^ Mul(a1,14) ^ Mul(a2,11) ^ Mul(a3,13);
                m[2] = Mul(a0,13) ^ Mul(a1,9) ^ Mul(a2,14) ^ Mul(a3,11);
                m[3] = Mul(a0,11) ^ Mul(a1,13) ^ Mul(a2,9) ^ Mul(a3,14);
            }
            memcpy(b, t, 16);
        }
    }
};

// AES-128-ECB with PKCS#7 padding.
inline Bytes AesEcbEncrypt(const uint8_t key[16], const std::string& plain) {
    Aes128 a(key);
    size_t pad = 16 - plain.size() % 16;
    Bytes b(plain.begin(), plain.end()); b.insert(b.end(), pad, (uint8_t)pad);
    for (size_t o = 0; o < b.size(); o += 16) a.Encrypt(&b[o]);
    return b;
}
inline bool AesEcbDecrypt(const uint8_t key[16], Bytes b, std::string& plain) {
    if (b.empty() || b.size() % 16) return false;
    Aes128 a(key);
    for (size_t o = 0; o < b.size(); o += 16) a.Decrypt(&b[o]);
    uint8_t pad = b.back();
    if (pad < 1 || pad > 16) return false;
    for (size_t i = 0; i < pad; ++i) if (b[b.size() - 1 - i] != pad) return false;
    plain.assign(b.begin(), b.end() - pad);
    return true;
}
inline bool FromHex(const std::string& h, Bytes& out) {
    auto v = [](char c) -> int { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; };
    if (h.size() % 2) return false;
    out.clear();
    for (size_t i = 0; i < h.size(); i += 2) { int a = v(h[i]), b = v(h[i+1]); if (a < 0 || b < 0) return false; out.push_back((uint8_t)(a * 16 + b)); }
    return true;
}

// ---- RSA public operation ---------------------------------------------------
// Unsigned big integers as little-endian 32-bit limbs. Only m^e mod n with a
// public exponent is needed, a handful of times per connection, so plain
// schoolbook multiplication and shift-subtract reduction are fast enough.
namespace bn {
typedef std::vector<uint32_t> Num;
inline void Trim(Num& a) { while (!a.empty() && a.back() == 0) a.pop_back(); }
inline Num FromBytes(const uint8_t* p, size_t n) {   // big-endian bytes
    Num r((n + 3) / 4, 0);
    for (size_t k = 0; k < n; ++k) r[k / 4] |= (uint32_t)p[n - 1 - k] << (8 * (k % 4));
    Trim(r); return r;
}
inline Bytes ToBytes(const Num& a, size_t n) {       // big-endian, left-padded to n
    Bytes r(n, 0);
    for (size_t k = 0; k < n && k / 4 < a.size(); ++k) r[n - 1 - k] = (uint8_t)(a[k / 4] >> (8 * (k % 4)));
    return r;
}
inline size_t Bits(const Num& a) {
    if (a.empty()) return 0;
    size_t b = (a.size() - 1) * 32; uint32_t t = a.back(); while (t) { ++b; t >>= 1; } return b;
}
inline bool Bit(const Num& a, size_t i) { return i / 32 < a.size() && ((a[i / 32] >> (i % 32)) & 1); }
inline int Cmp(const Num& a, const Num& b) {
    if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
    for (size_t k = a.size(); k-- > 0;) if (a[k] != b[k]) return a[k] < b[k] ? -1 : 1;
    return 0;
}
inline void Sub(Num& a, const Num& b) {               // a -= b, a >= b
    uint64_t borrow = 0;
    for (size_t k = 0; k < a.size(); ++k) {
        uint64_t s = (uint64_t)a[k] - (k < b.size() ? b[k] : 0) - borrow;
        a[k] = (uint32_t)s; borrow = (s >> 63) & 1;
    }
    Trim(a);
}
inline Num Mul(const Num& a, const Num& b) {
    Num r(a.size() + b.size(), 0);
    for (size_t i = 0; i < a.size(); ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b.size(); ++j) {
            uint64_t t = (uint64_t)a[i] * b[j] + r[i + j] + carry;
            r[i + j] = (uint32_t)t; carry = t >> 32;
        }
        r[i + b.size()] += (uint32_t)carry;
    }
    Trim(r); return r;
}
inline Num Mod(const Num& a, const Num& m) {
    Num r;
    for (size_t i = Bits(a); i-- > 0;) {
        // r = r*2 + bit
        uint32_t carry = Bit(a, i) ? 1 : 0;
        for (size_t k = 0; k < r.size(); ++k) { uint32_t nc = r[k] >> 31; r[k] = (r[k] << 1) | carry; carry = nc; }
        if (carry) r.push_back(carry);
        if (Cmp(r, m) >= 0) Sub(r, m);
    }
    return r;
}
inline Num PowMod(const Num& b, const Num& e, const Num& m) {
    Num r(1, 1), x = Mod(b, m);
    for (size_t i = Bits(e); i-- > 0;) {
        r = Mod(Mul(r, r), m);
        if (Bit(e, i)) r = Mod(Mul(r, x), m);
    }
    return r;
}
}  // namespace bn

struct RsaKey { Bytes n, e; };   // big-endian, as in the certificate

// PKCS#1 v1.5 type 2 (encryption). `rnd` fills nonzero padding bytes.
template <class Rand>
inline bool RsaEncrypt(const RsaKey& key, const Bytes& msg, Bytes& out, Rand rnd) {
    size_t i = 0; while (i < key.n.size() && key.n[i] == 0) ++i;
    size_t k = key.n.size() - i;
    if (k < msg.size() + 11) return false;
    Bytes em(k, 0); em[1] = 2;
    size_t ps = k - 3 - msg.size();
    for (size_t p = 0; p < ps; ++p) { uint8_t b = 0; while (b == 0) rnd(&b, 1); em[2 + p] = b; }
    memcpy(&em[3 + ps], msg.data(), msg.size());
    bn::Num m = bn::FromBytes(em.data(), em.size());
    bn::Num c = bn::PowMod(m, bn::FromBytes(key.e.data(), key.e.size()), bn::FromBytes(key.n.data() + i, k));
    out = bn::ToBytes(c, k);
    return true;
}

// ---- DER, just enough for an X.509 certificate's RSA key ---------------------
struct Der {
    const uint8_t* p; size_t n;
    // Reads one TLV; false at the end or on malformed input.
    bool Next(uint8_t& tag, const uint8_t*& v, size_t& len) {
        if (n < 2) return false;
        tag = p[0]; size_t l = p[1], h = 2;
        if (l & 0x80) {
            int c = l & 0x7F; if (c < 1 || c > 4 || n < 2 + (size_t)c) return false;
            l = 0; for (int i = 0; i < c; ++i) l = (l << 8) | p[2 + i];
            h += c;
        }
        if (n - h < l) return false;
        v = p + h; len = l; p += h + l; n -= h + l;
        return true;
    }
};

struct CertInfo { RsaKey key; Bytes spki, tbs, sigAlg, sig; std::string subject, issuer; };

// The subject's CN (2.5.4.3) out of a Name, for the log.
inline std::string NameCN(const uint8_t* p, size_t n) {
    Der name{p, n}; uint8_t t; const uint8_t* v; size_t l; std::string out;
    while (name.Next(t, v, l)) {                       // SET
        Der set{v, l}; uint8_t t2; const uint8_t* v2; size_t l2;
        while (set.Next(t2, v2, l2)) {                 // SEQUENCE { OID, value }
            Der atv{v2, l2}; uint8_t to, tv; const uint8_t *vo, *vv; size_t lo, lv;
            if (!atv.Next(to, vo, lo) || !atv.Next(tv, vv, lv)) continue;
            static const uint8_t kCN[] = { 0x55, 0x04, 0x03 };
            if (to == 0x06 && lo == 3 && !memcmp(vo, kCN, 3)) out = std::string((const char*)vv, lv);
        }
    }
    return out;
}

inline bool ParseCert(const Bytes& der, CertInfo& ci) {
    Der top{der.data(), der.size()}; uint8_t t; const uint8_t* v; size_t l;
    if (!top.Next(t, v, l) || t != 0x30) return false;            // Certificate
    Der cert{v, l};
    const uint8_t* tbsStart = cert.p;
    if (!cert.Next(t, v, l) || t != 0x30) return false;           // tbsCertificate
    ci.tbs.assign(tbsStart, cert.p);
    Der tbs{v, l};
    {   // signatureAlgorithm { OID, ... } and the signature BIT STRING
        Der rest = cert; uint8_t t2; const uint8_t* v2; size_t l2;
        if (!rest.Next(t2, v2, l2) || t2 != 0x30) return false;
        Der alg{v2, l2}; uint8_t t3; const uint8_t* v3; size_t l3;
        if (!alg.Next(t3, v3, l3) || t3 != 0x06) return false;
        ci.sigAlg.assign(v3, v3 + l3);
        if (!rest.Next(t2, v2, l2) || t2 != 0x03 || l2 < 1 || v2[0] != 0) return false;
        ci.sig.assign(v2 + 1, v2 + l2);
    }
    if (!tbs.Next(t, v, l)) return false;
    if (t == 0xA0 && !tbs.Next(t, v, l)) return false;            // [0] version, then serial
    if (!tbs.Next(t, v, l) || t != 0x30) return false;            // signature algorithm
    if (!tbs.Next(t, v, l) || t != 0x30) return false;            // issuer
    ci.issuer = NameCN(v, l);
    if (!tbs.Next(t, v, l) || t != 0x30) return false;            // validity
    if (!tbs.Next(t, v, l) || t != 0x30) return false;            // subject
    ci.subject = NameCN(v, l);
    const uint8_t* spkiStart = tbs.p;
    if (!tbs.Next(t, v, l) || t != 0x30) return false;            // subjectPublicKeyInfo
    ci.spki.assign(spkiStart, tbs.p);
    Der spki{v, l};
    if (!spki.Next(t, v, l) || t != 0x30) return false;           // algorithm
    if (!spki.Next(t, v, l) || t != 0x03 || l < 1 || v[0] != 0) return false;  // BIT STRING
    Der bits{v + 1, l - 1};
    if (!bits.Next(t, v, l) || t != 0x30) return false;           // RSAPublicKey
    Der rsa{v, l};
    if (!rsa.Next(t, v, l) || t != 0x02) return false;
    ci.key.n.assign(v, v + l);
    if (!rsa.Next(t, v, l) || t != 0x02) return false;
    ci.key.e.assign(v, v + l);
    return true;
}

// True when `ci` carries a valid PKCS#1 v1.5 signature by `ca` over its
// tbsCertificate, with md5WithRSAEncryption or sha1WithRSAEncryption (what
// 2012's ProtoSSL checked; OTG3 signs with MD5).
inline bool VerifyCertSignature(const CertInfo& ci, const RsaKey& ca) {
    static const uint8_t kMd5Rsa[] = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x04 };
    static const uint8_t kSha1Rsa[] = { 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x05 };
    static const uint8_t kMd5Info[] = { 0x30,0x20,0x30,0x0C,0x06,0x08,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x05,0x05,0x00,0x04,0x10 };
    static const uint8_t kSha1Info[] = { 0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14 };
    Bytes info;
    if (ci.sigAlg == Bytes(kMd5Rsa, kMd5Rsa + 9)) {
        Md5 h; h.Update(ci.tbs); uint8_t d[16]; h.Final(d);
        info.assign(kMd5Info, kMd5Info + sizeof kMd5Info); info.insert(info.end(), d, d + 16);
    } else if (ci.sigAlg == Bytes(kSha1Rsa, kSha1Rsa + 9)) {
        Sha1 h; h.Update(ci.tbs); uint8_t d[20]; h.Final(d);
        info.assign(kSha1Info, kSha1Info + sizeof kSha1Info); info.insert(info.end(), d, d + 20);
    } else return false;
    size_t i = 0; while (i < ca.n.size() && ca.n[i] == 0) ++i;
    size_t k = ca.n.size() - i;
    if (ci.sig.size() > k || k < info.size() + 11) return false;
    bn::Num m = bn::PowMod(bn::FromBytes(ci.sig.data(), ci.sig.size()), bn::FromBytes(ca.e.data(), ca.e.size()),
                           bn::FromBytes(ca.n.data() + i, k));
    Bytes em = bn::ToBytes(m, k);
    // 00 01 FF..FF 00 DigestInfo
    if (em[0] != 0 || em[1] != 1) return false;
    size_t ps = k - 3 - info.size();
    for (size_t p = 0; p < ps; ++p) if (em[2 + p] != 0xFF) return false;
    if (em[2 + ps] != 0) return false;
    return memcmp(&em[3 + ps], info.data(), info.size()) == 0;
}

}  // namespace ea
