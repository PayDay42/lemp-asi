// Native test of balance_classify.h (not an ASI):
//     g++ -std=c++17 -Wall -o test_balance_classify test_balance_classify.cpp && ./test_balance_classify
//
// Every text here is quoted straight from one game session's log, except the "Nothing" and "Other" cases, which that run never produced (a
// quiet SETNOPEC-style success, and an engine message neither known form
// covers) and so are exercised only here.
#include "balance_classify.h"
#include <cstdio>

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++g_fail; } } while (0)

int main() {
    using balance::Classify;
    using balance::Outcome;

    CHECK(Classify(u"") == Outcome::Nothing);

    // That log's one row among 241 attempts
    // whose class WAS already loaded: a working set, not a failure.
    CHECK(Classify(u"Executing set command  gui_codex_images.Weapons.MOD_ammo-capacity_512x256") == Outcome::Success);
    CHECK(Classify(u"Executing set command") == Outcome::Success);   // the prefix alone

    // :385 (preceding), :403: a weapon class not loaded yet.
    CHECK(Classify(u"Unrecognized class or object sfxweapon_shotgun_crusader") == Outcome::ClassNotFound);
    CHECK(Classify(u"Unrecognized class or object sfxweaponmod_pistolultralight") == Outcome::ClassNotFound);

    // :401, :403 — the class loaded, the property name is simply wrong
    // (never resolves, however long the GRI runs).
    CHECK(Classify(u"Unrecognized property adhesionrot on class sfxweapon") == Outcome::PropertyNotFound);
    CHECK(Classify(u"Unrecognized property adhesionrot on class sfxweapon_sniperrifle_base") == Outcome::PropertyNotFound);

    // Never seen in this build's run, but must not be mistaken for a known
    // outcome: GET's own failure text is inferred, not yet directly logged
    // (balance_classify.h's header comment), and any future engine message
    // outside the two known forms must fall here, not silently pass as a
    // value or a success.
    CHECK(Classify(u"Some other engine message entirely") == Outcome::Other);
    CHECK(Classify(u"Unrecognized") == Outcome::Other);   // too short to match either prefix safely

    // A real value never starts with either failure prefix (float/vector/
    // object-path syntax), but the match is prefix-only: guard it is not
    // fooled by a value that merely CONTAINS the words later on.
    CHECK(Classify(u"(X=630.7,Y=788.4) Unrecognized class or object") == Outcome::Other);

    // GET (ClassifyGet). The texts are a build-7 run's, verbatim: GET says
    // "Unrecognized class <C>" (not SET's "... or object"), and a found
    // property prints its exported value with no prefix at all. Classify()
    // read both as Other, so no GET ever succeeded.
    using balance::ClassifyGet;
    CHECK(Classify(u"Unrecognized class sfxweapon_smg_bloodpack") == Outcome::Other);   // the old misreading
    CHECK(Classify(u"(Bonuses=,X=29.299999,Y=36.599998,MaxLevel=100,Level=0,Value=0.000000,StaticBonus=1.000000)") == Outcome::Other);
    CHECK(ClassifyGet(u"") == Outcome::Nothing);
    CHECK(ClassifyGet(u"Unrecognized class sfxweapon_smg_bloodpack") == Outcome::ClassNotFound);
    CHECK(ClassifyGet(u"Unrecognized class or object sfxweapon_shotgun_crusader") == Outcome::ClassNotFound);
    CHECK(ClassifyGet(u"Unrecognized property adhesionrot") == Outcome::PropertyNotFound);
    CHECK(ClassifyGet(u"Unrecognized property adhesionrot on class sfxweapon") == Outcome::PropertyNotFound);
    CHECK(ClassifyGet(u"(Bonuses=,X=29.299999,Y=36.599998,MaxLevel=100,Level=0,Value=0.000000,StaticBonus=1.000000)") == Outcome::Success);
    CHECK(ClassifyGet(u"GUI_Codex_Weapons_Images.Weapons.smg_shuriken_512x256") == Outcome::Success);
    CHECK(ClassifyGet(u"(X=0.000000,Y=0.500000)") == Outcome::Success);
    CHECK(ClassifyGet(u"(\"SFXGameContent.SFXWeaponMod_ShotgunStability\")") == Outcome::Success);
    CHECK(ClassifyGet(u"0.850000") == Outcome::Success);
    CHECK(ClassifyGet(u"Unrecognized") == Outcome::Success);   // neither full prefix: a value

    if (g_fail == 0) printf("OK\n"); else printf("%d FAILED\n", g_fail);
    return g_fail != 0;
}
