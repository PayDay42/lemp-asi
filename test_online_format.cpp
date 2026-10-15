// Native tests for online_format.h:  g++ -std=c++17 -Wall test_online_format.cpp && ./a.out
#include "online_format.h"
#include <cstdio>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main() {
    using namespace online;

    // What the master server sends.
    JsonFields f;
    CHECK(ParseJsonObject(R"({"outcome":2,"ticket":"ab12","address":"203.0.113.5","port":3659,"lobby":"ff00"})", f));
    CHECK(f.Int("outcome") == 2 && f.Str("address") == "203.0.113.5" && f.Int("port") == 3659 && f.Str("lobby") == "ff00");
    CHECK(ParseJsonObject(R"( { "code" : "K3ZQ9A", "reachable" : false, "joinFailures":0, "x": null, "n": {"a":[1,2,{"b":"c"}]}, "after":"yes" } )", f));
    CHECK(f.Str("code") == "K3ZQ9A" && !f.Bool("reachable", true) && !f.Has("x") && f.Str("after") == "yes");
    CHECK(ParseJsonObject(R"({"message":"a \"q\" \\ é\n"})", f) && f.Str("message") == "a \"q\" \\ \xc3\xa9\n");
    CHECK(ParseJsonObject("{}", f) && f.v.empty());
    CHECK(!ParseJsonObject("", f));
    CHECK(!ParseJsonObject("[1]", f));
    CHECK(!ParseJsonObject(R"({"a":"unterminated)", f));
    CHECK(!ParseJsonObject(R"({"a":1,})", f));
    CHECK(f.Int("missing", 7) == 7);
    CHECK(ParseJsonObject(R"({"n":"12x"})", f) && f.Int("n", -1) == -1);

    // What the ASI sends.
    std::string body = JsonObject().Str("build", "LEMPBuild=ab?LEMPMods=none").Int("port", 3659).Bool("open", true)
                           .Raw("rules", JsonObject().Int("map", 0).Done()).Done();
    CHECK(body == R"({"build":"LEMPBuild=ab?LEMPMods=none","port":3659,"open":true,"rules":{"map":0}})");
    CHECK(JsonString("a\"b\\c\x01") == "\"a\\\"b\\\\c\\u0001\"");
    CHECK(ParseJsonObject(body, f) && f.Str("build") == "LEMPBuild=ab?LEMPMods=none" && f.Bool("open"));

    // Option strings, script <-> ASI.
    CHECK(Opt("address", "203.0.113.5:3659") == "?address=203.0.113.5:3659");
    CHECK(Opt("message", "why? a=b") == "?message=why  a b");
    auto m = ParseOptions("?create=1?Private=0?map=5?difficulty=-1?flag");
    CHECK(OptInt(m, "create", 0) == 1 && OptInt(m, "private", 1) == 0 && OptInt(m, "map", 0) == 5);
    CHECK(OptInt(m, "difficulty", 9) == -1 && m.count("flag") && OptInt(m, "none", 3) == 3);
    CHECK(ParseOptions("").empty());

    // The server URL.
    ServerUrl u;
    CHECK(ParseServerUrl("http://127.0.0.1:8787", u) && !u.https && u.host == "127.0.0.1" && u.port == 8787 && u.base.empty());
    CHECK(ParseServerUrl(" https://lemp.example.workers.dev/ \r\n", u) && u.https && u.host == "lemp.example.workers.dev" && u.port == 443);
    CHECK(ParseServerUrl("https://h.example/api", u) && u.base == "/api");
    CHECK(!ParseServerUrl("ftp://x", u));
    CHECK(!ParseServerUrl("http://h:99999", u));
    CHECK(!ParseServerUrl("", u));

    // Leaderboard names, UTF-8 from the server to the game's UTF-16.
    CHECK(Utf8To16("Ab 1") == u"Ab 1");
    CHECK(Utf8To16("\xc3\xa9t\xc3\xa9") == u"\u00e9t\u00e9");
    CHECK(Utf8To16("\xe2\x82\xac") == u"\u20ac");
    CHECK(Utf8To16("\xf0\x9f\x98\x80x") == u"?x");      // past the BMP
    CHECK(Utf8To16("a\xc3") == u"a?");                     // cut short
    CHECK(Utf8To16("\xff\xc3!") == u"?" "?!");             // not UTF-8

    printf(fails ? "%d FAILED\n" : "all passed\n", fails);
    return fails != 0;
}
