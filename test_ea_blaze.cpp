// ea_blaze.h against EA's live redirector, natively (no token, no account
// data: the GetServerInstance request every 2012 ME3 client sends first):
//   g++ -std=c++17 -O2 -o test_ea_blaze test_ea_blaze.cpp && ./test_ea_blaze
// and as the ASI builds it, under Wine:
//   x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -o test_ea_blaze.exe test_ea_blaze.cpp -lws2_32 -lbcrypt
//   wine test_ea_blaze.exe
// Prints both servers' certificates (subject, issuer, SPKI SHA-1) and checks
// both are signed by EA's OTG3 CA (ea_blaze.h kOtg3Modulus). Then completes the SSLv3 handshake with the
// ME3 instance, pinned, and disconnects without a request.
// Offline, the TDF codec checks still run: ./test_ea_blaze offline
#include "ea_blaze.h"
#include <cstdio>
using namespace ea;

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } else printf("ok   %s\n", #c); } while (0)

int main(int argc, char** argv) {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    {   // TDF round trip: tags, varints, strings, unset union, map
        tdf::Writer w;
        w.TagStr("AUTH", "abc"); w.TagInt("TYPE", 1); w.TagInt("BIG", 1234567); w.TagUnionUnset("FPID");
        w.Tag("SMAP", tdf::Map); w.b.push_back(tdf::String); w.b.push_back(tdf::String); w.Int(2);
        w.Str("Base"); w.Str("20;4;x"); w.Str("class1"); w.Str("20;4;Adept;1;0;0");
        tdf::Value v;
        CHECK(tdf::Parse(w.b, v));
        CHECK(v.kids.size() == 5);
        CHECK(v.Find("AUTH") && v.Find("AUTH")->str == "abc");
        CHECK(v.Find("TYPE") && v.Find("TYPE")->num == 1);
        CHECK(v.Find("BIG") && v.Find("BIG")->num == 1234567);
        CHECK(v.Find("FPID") && v.Find("FPID")->num == 0x7F);
        const tdf::Value* m = v.Find("SMAP");
        CHECK(m && m->kids.size() == 4 && m->kids[0].str == "Base" && m->kids[3].str == "20;4;Adept;1;0;0");
        // Tag bytes as the tdf crate writes them (its test_tag_serialize: "TEST" -> D2 5C F4)
        tdf::Writer t; t.Tag("TEST", tdf::VarInt);
        CHECK(t.b.size() == 4 && t.b[0] == 0xD2 && t.b[1] == 0x5C && t.b[2] == 0xF4);
    }
    if (argc > 1 && std::string(argv[1]) == "offline") { printf("%s (%d)\n", fails ? "FAILED" : "all passed", fails); return fails != 0; }

    Blaze redir;
    redir.ssl.checkCa = &Otg3();
    bool ok = redir.Connect(kRedirectorHost, kRedirectorPort);
    printf("     redirector: %s cert subject='%s' issuer='%s' pin=%s\n", ok ? "connected" : redir.err.c_str(),
           redir.ssl.peerSubject.c_str(), redir.ssl.peerIssuer.c_str(), redir.ssl.peerPin.c_str());
    CHECK(ok);
    CHECK(redir.ssl.peerSignedByCa);
    if (argc > 1) {   // ./test_ea_blaze <file>: keep the redirector's certificate
        FILE* f = fopen(argv[1], "wb");
        if (f) { fwrite(redir.ssl.peerCert.data(), 1, redir.ssl.peerCert.size(), f); fclose(f); }
    }
    tdf::Value inst; std::string host; uint16_t port = 0;
    ok = ok && redir.Request(kRedirectorComponent, kGetServerInstance, InstanceRequest(), inst);
    if (!ok) printf("     request: %s\n", redir.err.c_str());
    CHECK(ok);
    CHECK(ok && InstanceAddress(inst, host, port));
    printf("     instance: %s:%u\n", host.c_str(), port);
    redir.ssl.Close();

    if (!host.empty()) {
        Ssl s; s.ca = &Otg3();   // required, as the import requires it
        ok = s.Connect(host, port);
        printf("     instance: %s cert subject='%s' issuer='%s' pin=%s\n", ok ? "handshake done" : s.err.c_str(),
               s.peerSubject.c_str(), s.peerIssuer.c_str(), s.peerPin.c_str());
        CHECK(ok);
        CHECK(s.peerSignedByCa);
        // A certificate the CA did not sign must stop before the key exchange
        // (here: a CA key that did not sign the server's).
        RsaKey other = Otg3(); other.n[127] ^= 2;
        Ssl bad2; bad2.ca = &other;
        CHECK(!bad2.Connect(host, port) && bad2.err.find("not signed by") != std::string::npos);
    }
    printf("%s (%d failure(s))\n", fails ? "FAILED" : "all passed", fails);
    return fails ? 1 : 0;
}
