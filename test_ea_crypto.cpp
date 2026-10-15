// Known answers for ea_crypto.h, natively:
//   g++ -std=c++17 -O2 -o test_ea_crypto test_ea_crypto.cpp && ./test_ea_crypto
// With a certificate, also an RSA round trip through openssl:
//   openssl genrsa -traditional 1024 > k.pem
//   openssl req -new -x509 -key k.pem -subj /CN=test.example -days 1 -outform DER -out c.der
//   ./test_ea_crypto c.der ct.bin && openssl pkeyutl -decrypt -inkey k.pem -in ct.bin
//   (prints "LEMP premaster secret test")
#include "ea_crypto.h"
#include <cstdio>
#include <cstdlib>
using namespace ea;

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } else printf("ok   %s\n", #c); } while (0)

static std::string Md5Of(const std::string& s) { Md5 m; m.Update(s.data(), s.size()); uint8_t o[16]; m.Final(o); return Hex(o, 16); }
static std::string Sha1Of(const std::string& s) { Sha1 m; m.Update(s.data(), s.size()); uint8_t o[20]; m.Final(o); return Hex(o, 20); }
static void Rand(uint8_t* p, size_t n) { for (size_t i = 0; i < n; ++i) p[i] = (uint8_t)rand(); }

int main(int argc, char** argv) {
    CHECK(Md5Of("") == "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(Md5Of("abc") == "900150983cd24fb0d6963f7d28e17f72");
    CHECK(Md5Of(std::string(1000, 'a')) == "cabe45dcc9ae5b66ba86600cca6b8ba8");
    CHECK(Sha1Of("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d");
    CHECK(Sha1Of(std::string(1000000, 'a')) == "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    {
        Rc4 r; r.Init((const uint8_t*)"Key", 3);
        uint8_t p[] = "Plaintext"; r.Apply(p, 9);
        CHECK(Hex(p, 9) == "bbf316e8d940af0ad3");
    }
    {
        bn::Num c = bn::PowMod(bn::Num{65}, bn::Num{17}, bn::Num{3233});   // textbook RSA
        CHECK(c.size() == 1 && c[0] == 2790);
        bn::Num m = bn::PowMod(c, bn::Num{2753}, bn::Num{3233});
        CHECK(m.size() == 1 && m[0] == 65);
    }
    if (argc >= 3) {
        FILE* f = fopen(argv[1], "rb");
        Bytes der; int ch; while (f && (ch = fgetc(f)) != EOF) der.push_back((uint8_t)ch);
        if (f) fclose(f);
        CertInfo ci;
        CHECK(ParseCert(der, ci));
        printf("     subject=%s issuer=%s n=%zu bytes e=%s spki-sha1=%s\n", ci.subject.c_str(), ci.issuer.c_str(),
               ci.key.n.size(), Hex(ci.key.e.data(), ci.key.e.size()).c_str(), Sha1Hex(ci.spki).c_str());
        CHECK(ci.subject == "test.example");
        std::string msg = "LEMP premaster secret test";
        Bytes ct;
        CHECK(RsaEncrypt(ci.key, Bytes(msg.begin(), msg.end()), ct, Rand));
        FILE* o = fopen(argv[2], "wb"); fwrite(ct.data(), 1, ct.size(), o); fclose(o);
    }
    printf("%s (%d failure(s))\n", fails ? "FAILED" : "all passed", fails);
    return fails ? 1 : 0;
}
