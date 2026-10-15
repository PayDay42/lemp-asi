// Native test of mp_save_format.h (not an ASI):
//     g++ -std=c++17 -Wall -o test_mp_save_format test_mp_save_format.cpp && ./test_mp_save_format
#include "mp_save_format.h"
#include <cstdio>

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++g_fail; } } while (0)

int main() {
    MPSaveData d;
    d.base = u"12;345;0;;7";
    d.reinforcements = u"";
    d.facecodes = u"a\\b\nc\rd";
    d.selected = u"AdeptHumanMale";
    d.classes = {u"Adept;5;12000", u"", u"Soldier;20;999999"};
    d.characters = {u"AdeptAsari;Liara é中;1", u"x\U0001F600y", u"lone\xD800surrogate"};

    std::string text = mpsave::Serialize(d);
    MPSaveData r; std::string why;
    CHECK(mpsave::Parse(text, r, why));
    CHECK(r.base == d.base);
    CHECK(r.reinforcements == d.reinforcements);
    CHECK(r.facecodes == d.facecodes);
    CHECK(r.selected == d.selected);
    CHECK(r.classes == d.classes);
    CHECK(r.characters == d.characters);
    CHECK(r.SlotCount() == 10);
    CHECK(*r.Slot(3) == u"AdeptHumanMale");
    CHECK(*r.Slot(4) == u"Adept;5;12000");
    CHECK(*r.Slot(9) == d.characters[2]);
    CHECK(r.Slot(10) == nullptr);
    // One value per line: escapes leave no raw CR/LF inside a value.
    int lines = 0; for (char c : text) lines += (c == '\n');
    CHECK(lines == 3 + 4 + 3 + 3);   // 2 comments + version, 4 fixed, 3 classes, 3 characters

    // CRLF line endings (a hand-edited file) still parse.
    std::string crlf;
    for (char c : text) { if (c == '\n') crlf += '\r'; crlf += c; }
    CHECK(mpsave::Parse(crlf, r, why) && r.characters == d.characters);

    // Refusals.
    CHECK(!mpsave::Parse("base=1\n", r, why));                    // no version
    CHECK(!mpsave::Parse("version=2\nbase=1\n", r, why));         // unknown version
    CHECK(!mpsave::Parse("version=1\n", r, why));                 // no base
    CHECK(!mpsave::Parse("version=1\nbase=a\\q\n", r, why));      // bad escape
    CHECK(!mpsave::Parse("version=1\nbase=a\\\n", r, why));       // trailing backslash
    CHECK(!mpsave::Parse("version=1\nbase=\xC3\n", r, why));      // truncated UTF-8
    CHECK(!mpsave::Parse("version=1\nbase=\xC3", r, why));        // truncated at EOF
    CHECK(!mpsave::Parse("version=1\nbase=1\nfoo=2\n", r, why));  // unknown key
    CHECK(mpsave::Parse("version=1\nbase=\n", r, why) && r.base.empty() && r.SlotCount() == 4);
    // Challenge strings: after the characters, in order; a file
    // from before them loads with none.
    {
        MPSaveData c = d;
        c.challenges = {u"22,0,5,17", u"22,3,0,0,40", u"", u"7"};
        MPSaveData rc;
        CHECK(mpsave::Parse(mpsave::Serialize(c), rc, why) && rc.challenges == c.challenges);
        CHECK(rc.SlotCount() == 14 && *rc.Slot(10) == u"22,0,5,17" && *rc.Slot(13) == u"7" && rc.Slot(14) == nullptr);
        CHECK(mpsave::Parse(text, rc, why) && rc.challenges.empty());
        // The Galaxy at War string: the last slot, after the
        // challenges; a file from before it loads with none, and an empty
        // one is not written.
        c.gaw = u"1,50,57,100,50,63";
        CHECK(mpsave::Parse(mpsave::Serialize(c), rc, why) && rc.gaw == c.gaw && rc.challenges == c.challenges);
        CHECK(rc.NumGaw() == 1 && rc.SlotCount() == 15 && *rc.Slot(14) == c.gaw && rc.Slot(15) == nullptr);
        CHECK(mpsave::Parse(text, rc, why) && rc.gaw.empty() && rc.NumGaw() == 0);
        CHECK(mpsave::Serialize(d).find("gaw=") == std::string::npos);
    }
    // A file from before 'selected' existed still loads, with no selection.
    CHECK(mpsave::Parse("version=1\nbase=b\nclass=c\n", r, why) && r.selected.empty() && *r.Slot(4) == u"c");

    // mpname.txt
    std::u16string nm;
    CHECK(mpsave::ParseName(mpsave::SerializeName(u"Commander é\\n"), nm, why) && nm == u"Commander é\\n");
    CHECK(mpsave::ParseName(mpsave::SerializeName(u""), nm, why) && nm.empty());
    CHECK(!mpsave::ParseName("# only a comment\n", nm, why));
    CHECK(!mpsave::ParseName("other=1\n", nm, why));
    // The name file's text is unchanged by the generalisation to keyed values.
    CHECK(mpsave::SerializeName(u"N") == "# LEMP player name, written by mp_save.asi.\nname=N\n");

    // mpaddress.txt
    std::u16string ad;
    CHECK(mpsave::ParseAddress(mpsave::SerializeAddress(u"rnabc-1-2-3-4.a.free.pinggy.link:41234"), ad, why) && ad == u"rnabc-1-2-3-4.a.free.pinggy.link:41234");
    CHECK(!mpsave::ParseAddress(mpsave::SerializeName(u"x"), ad, why));   // a name file is not an address
    CHECK(!mpsave::ParseName(mpsave::SerializeAddress(u"x"), nm, why));

    printf(g_fail ?"%d FAILED\n" : "all passed\n", g_fail);
    return g_fail ? 1 : 0;
}
