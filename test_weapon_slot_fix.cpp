// Native test of weapon_slot_fix.h (not an ASI):
//     g++ -std=c++17 -Wall -o test_weapon_slot_fix test_weapon_slot_fix.cpp && ./test_weapon_slot_fix
//
// A synthetic Mappings (not the real baked weapon_slot_defaults.h table)
// drives most cases, so each one pins down one rule in isolation. The last
// group uses the real baked table, as a smoke test that the generator's
// output still resolves the way these rules assume.
#include "weapon_slot_fix.h"
#include <cstdio>

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++g_fail; } } while (0)

using weaponslotfix::Mappings;
using weaponslotfix::FixCharacterRecord;
using weaponslotfix::Widen;

// A small, hand-built mapping: ids 100/101 are "mapped" (to some class name,
// the identity doesn't matter beyond being non-empty and consistent), id 999
// is never mapped. "testkit"'s defaults are 100 (slot 0) and 101 (slot 1).
static Mappings TestMappings() {
    Mappings m;
    m.idToClass.emplace(100, Widen("Weapon.Primary"));
    m.idToClass.emplace(101, Widen("Weapon.Secondary"));
    m.classToId.emplace(Widen("Weapon.Primary"), 100);
    m.classToId.emplace(Widen("Weapon.Secondary"), 101);
    m.kitWeapons.emplace(Widen("testkit"), std::make_pair(Widen("Weapon.Primary"), Widen("Weapon.Secondary")));
    return m;
}

// mp_save_format.h's comma format: a character= value's own fields are
// ';'-delimited (that file's header comment); the Weapons field inside one
// of them is ','-delimited ids (SFXOnlineSaveGameMP.SetWeapons/GetWeapons).
// A minimal but version-field-accurate record, version < 15 (16 fields before
// Weapons, so Weapons is field index 16 — this record has exactly that many
// leading fields): Version;DevelopmentVersion;KitName;CharacterName;Tint1;
// Tint2;Pattern;PatternColor;SkinTone;SecondsPlayed;Year;Month;Day;Seconds;
// Powers;HotKeys;Weapons;WeaponMods;Deployed
static std::u16string MakeRecord(const char* kit, const char* weapons) {
    std::u16string r = Widen("14;1;");
    r += Widen(kit);
    r += Widen(";Name;0;0;0;0;0;0;2026;1;1;0;;;");
    r += Widen(weapons);
    r += Widen(";;0");
    return r;
}

int main() {
    Mappings m = TestMappings();

    // All valid: byte-identical, nothing logged.
    {
        std::u16string rec = MakeRecord("testkit", "100,101");
        std::u16string before = rec;
        std::vector<std::string> log;
        int n = FixCharacterRecord(rec, m, log);
        CHECK(n == 0);
        CHECK(rec == before);
        CHECK(log.empty());
    }

    // Unmapped primary: slot 0 substituted with the kit's default, slot 1
    // (already valid) kept exactly as it was.
    {
        std::u16string rec = MakeRecord("testkit", "999,101");
        std::vector<std::string> log;
        int n = FixCharacterRecord(rec, m, log);
        CHECK(n == 1);
        CHECK(log.size() == 1);
        auto fields = weaponslotfix::Split(rec, u';');
        CHECK(fields[16] == Widen("100,101"));
    }

    // Unmapped secondary: slot 1 substituted, slot 0 kept.
    {
        std::u16string rec = MakeRecord("testkit", "100,999");
        std::vector<std::string> log;
        int n = FixCharacterRecord(rec, m, log);
        CHECK(n == 1);
        auto fields = weaponslotfix::Split(rec, u';');
        CHECK(fields[16] == Widen("100,101"));
    }

    // Both unmapped: both substituted independently with their own slot's default.
    {
        std::u16string rec = MakeRecord("testkit", "999,998");
        std::vector<std::string> log;
        int n = FixCharacterRecord(rec, m, log);
        CHECK(n == 2);
        CHECK(log.size() == 2);
        auto fields = weaponslotfix::Split(rec, u';');
        CHECK(fields[16] == Widen("100,101"));
    }

    // A single surviving weapon (already the compacted, post-drop shape):
    // only slot 0 exists, and it is valid — left alone, no slot 1 invented.
    {
        std::u16string rec = MakeRecord("testkit", "101");
        std::u16string before = rec;
        std::vector<std::string> log;
        int n = FixCharacterRecord(rec, m, log);
        CHECK(n == 0);
        CHECK(rec == before);
    }

    // A single surviving weapon that is itself unmapped: substituted in slot
    // 0, no slot 1 invented (the token list stays length 1).
    {
        std::u16string rec = MakeRecord("testkit", "999");
        std::vector<std::string> log;
        int n = FixCharacterRecord(rec, m, log);
        CHECK(n == 1);
        auto fields = weaponslotfix::Split(rec, u';');
        CHECK(fields[16] == Widen("100"));
    }

    // Unmapped, but the kit is not in the table: left untouched (today's
    // behaviour — the engine will still drop it), not invented from nothing.
    {
        std::u16string rec = MakeRecord("nosuchkit", "999,101");
        std::u16string before = rec;
        std::vector<std::string> log;
        int n = FixCharacterRecord(rec, m, log);
        CHECK(n == 0);
        CHECK(rec == before);
        CHECK(log.empty());
    }

    // An empty Weapons field (both slots already gone): nothing to do.
    {
        std::u16string rec = MakeRecord("testkit", "");
        std::u16string before = rec;
        std::vector<std::string> log;
        int n = FixCharacterRecord(rec, m, log);
        CHECK(n == 0);
        CHECK(rec == before);
    }

    // Version >= 15 shifts the Weapons field two positions later
    // (PhongID/EmissiveID): same record shape, two extra leading fields.
    {
        std::u16string rec = Widen("15;1;testkit;Name;0;0;0;0;0;0;0;0;2026;1;1;0;;;999,101;;0");
        std::vector<std::string> log;
        int n = FixCharacterRecord(rec, m, log);
        CHECK(n == 1);
        auto fields = weaponslotfix::Split(rec, u';');
        CHECK(fields[18] == Widen("100,101"));
    }

    // Too few fields to even reach a Weapons position: left untouched, not
    // an error (a record this cannot confidently read is passed through).
    {
        std::u16string rec = Widen("14;1;testkit");
        std::u16string before = rec;
        std::vector<std::string> log;
        int n = FixCharacterRecord(rec, m, log);
        CHECK(n == 0);
        CHECK(rec == before);
    }

    // The real, generated table (weapon_slot_defaults.h): a smoke test that
    // AdeptAsari's own baked defaults still resolve. Not tied to the exact
    // weapon classes (those can change if the install is rebuilt from a
    // different config) — only that an unmapped id in a real kit's record
    // resolves to SOME currently-mapped id in each slot, and a valid id is
    // never touched.
    {
        Mappings real = weaponslotfix::BuildMappings();
        auto it = real.kitWeapons.find(Widen("adeptasari"));   // lower-cased key
        CHECK(it != real.kitWeapons.end());
        if (it != real.kitWeapons.end()) {
            int id0 = real.classToId.at(it->second.first);
            int id1 = real.classToId.at(it->second.second);
            std::u16string rec = MakeRecord("AdeptAsari", "-1,-1");   // -1: never a real id
            std::vector<std::string> log;
            int n = FixCharacterRecord(rec, real, log);
            CHECK(n == 2);
            auto fields = weaponslotfix::Split(rec, u';');
            std::string wantAscii = std::to_string(id0) + ",";
            std::u16string want = Widen(wantAscii.c_str());
            CHECK(fields[16].substr(0, want.size()) == want);

            // The same kit's real valid ids pass through byte-identical.
            std::string idsAscii = std::to_string(id0) + "," + std::to_string(id1);
            std::u16string valid = MakeRecord("AdeptAsari", idsAscii.c_str());
            std::u16string before = valid;
            std::vector<std::string> log2;
            int n2 = FixCharacterRecord(valid, real, log2);
            CHECK(n2 == 0);
            CHECK(valid == before);
        }
    }

    if (g_fail == 0) printf("OK\n"); else printf("%d FAILED\n", g_fail);
    return g_fail != 0;
}
