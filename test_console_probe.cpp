// console_probe.h against EA's live redirector and instances, natively, with
// no token and no account: each service's instance is found and answers with
// EA's certificate (the sign-in itself is only tried in game).
//   g++ -std=c++17 -O2 -o test_console_probe test_console_probe.cpp && ./test_console_probe
// Also: the reply shapes, offline.
#include "console_probe.h"
#include <cstdio>
using namespace ea;

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } else printf("ok   %s\n", #c); } while (0)

int main(int argc, char** argv) {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    {   // the shape shows names and kinds, never other values
        tdf::Writer w;
        w.TagStr("DSNM", "Someone"); w.TagInt("XTYP", 2); w.TagInt("PID", 1000123456789ull); w.TagStr("XREF", "2533274800000000");
        w.TagStr("AUTH", "secret-token");
        tdf::Value v;
        CHECK(tdf::Parse(w.b, v));
        std::string s = console::Shape(v);
        CHECK(s == "DSNM='Someone' XTYP=2 PID XREF AUTH");
        CHECK(s.find("1000123456789") == std::string::npos && s.find("secret") == std::string::npos);
    }
    {   // the request names the asked instance
        tdf::Value v;
        CHECK(tdf::Parse(InstanceRequest("masseffect-3-ps3"), v) && v.Find("NAME") && v.Find("NAME")->str == "masseffect-3-ps3");
        CHECK(tdf::Parse(InstanceRequest(), v) && v.Find("NAME")->str == "masseffect-3-pc");
    }
    if (argc > 1 && std::string(argv[1]) == "offline") { printf("%s (%d)\n", fails ? "FAILED" : "all passed", fails); return fails != 0; }
    int reached = 0;
    console::ProbeAll("", [&](const std::string& l) {
        printf("     %s\n", l.c_str());
        if (l.find("answers with EA's certificate") != std::string::npos) ++reached;
    });
    CHECK(reached == 3);
    printf("%s (%d)\n", fails ? "FAILED" : "all passed", fails);
    return fails != 0;
}
