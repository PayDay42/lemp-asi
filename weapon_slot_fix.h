// weapon_slot_fix.h — a saved weapon id the installed config no longer maps,
// replaced with the kit's own default for that same slot, in place, before
// the game ever sees the string.
//
// Pure C++ (no Windows headers), so it is testable natively on Linux, the way
// mp_save_format.h and balance_classify.h are:
//     g++ -std=c++17 -o test_weapon_slot_fix test_weapon_slot_fix.cpp && ./test_weapon_slot_fix
//
// WHERE THE SLOT IS LOST, AND WHY THIS IS THE ONLY PLACE LEFT TO FIX IT.
// A character record's Weapons field is a comma-separated list of ids
// (mp_save_format.h's "character=" line, one of its ';'-delimited fields —
// the exact field documented below). The engine's own deserializer (an
// always-loaded class this DLC does not define, so it cannot be recompiled
// to behave differently) walks that list in order and keeps only the ids
// that still resolve to a class; an id that no longer does is skipped, not
// replaced with a placeholder, so every id after it shifts one array
// position earlier. That same compiled function is what maps an id to a
// class in the first place, so by the time any DLC-owned script sees the
// weapon list, the position information the list started with is already
// gone — nothing downstream can recover which slot a surviving id came
// from. The one place that still has the original, unshifted list is this
// string, before that deserializer ever runs on it.
//
// THE SUBSTITUTE. 2012's own fallback for an empty loadout (both slots)
// is the character's class's own default loadout; this applies the same
// idea per slot instead of only when nothing survives at all, which is why
// it is a DIFFERENT behaviour from 2012's (DIFFERENCES-TO-ME3-MP.md), not a
// port. The default weapon ids come from a baked table
// (weapon_slot_defaults.h) read out of the installed build's own config —
// not invented, not guessed at runtime: the same (Kit, Weapon) rows the
// lobby itself already uses to seed a character with no saved record at all.
//
// WHAT THIS NEVER DOES. If a slot's id is already mapped, that token is
// left untouched, character by character — a loadout with nothing retired
// passes through byte-identical. If an id is unmapped AND no substitute can
// be resolved for it (kit not found in the baked table, index out of
// range), it is also left untouched: the engine then drops it exactly as it
// does today. This never makes a save worse than it already was; it only
// sometimes makes it better.
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdlib>
#include "weapon_slot_defaults.h"

namespace weaponslotfix {

// ASCII -> UTF-16, for the baked tables' plain-ASCII class/kit names.
inline std::u16string Widen(const char* s) {
    std::u16string out;
    for (; *s; ++s) out += (char16_t)(unsigned char)*s;
    return out;
}

inline std::u16string ToLower(std::u16string s) {
    for (auto& c : s) if (c >= u'A' && c <= u'Z') c += (u'a' - u'A');
    return s;
}

struct Mappings {
    std::unordered_map<int, std::u16string> idToClass;
    std::unordered_map<std::u16string, int> classToId;
    // Keyed by the lower-cased kit name (Name is case-insensitive in
    // UnrealScript): the two default weapon classes, in slot order.
    std::unordered_map<std::u16string, std::pair<std::u16string, std::u16string>> kitWeapons;
};

// Built once from the baked tables (weapon_slot_defaults.h). A duplicate id
// keeps its FIRST entry, matching SFXGameConfig.GetPurchasableItemClassName's
// own array.Find (first match) — the generator already applies this rule
// when baking the table, so here it is only ever exercised by a test's own
// synthetic, deliberately-duplicated table.
inline Mappings BuildMappings() {
    Mappings m;
    for (auto& row : weapondefaults::kIdToClass) {
        std::u16string cls = Widen(row.className);
        if (m.idToClass.find(row.id) == m.idToClass.end()) m.idToClass.emplace(row.id, cls);
        if (m.classToId.find(cls) == m.classToId.end()) m.classToId.emplace(cls, row.id);
    }
    for (auto& row : weapondefaults::kKitDefaults) {
        m.kitWeapons.emplace(ToLower(Widen(row.kit)),
                              std::make_pair(Widen(row.weapon0), Widen(row.weapon1)));
    }
    return m;
}

inline std::vector<std::u16string> Split(const std::u16string& s, char16_t sep) {
    std::vector<std::u16string> out;
    size_t pos = 0;
    while (true) {
        size_t n = s.find(sep, pos);
        out.push_back(s.substr(pos, n == std::u16string::npos ? std::u16string::npos : n - pos));
        if (n == std::u16string::npos) break;
        pos = n + 1;
    }
    return out;
}

inline std::u16string Join(const std::vector<std::u16string>& v, char16_t sep) {
    std::u16string out;
    for (size_t i = 0; i < v.size(); ++i) { if (i) out += sep; out += v[i]; }
    return out;
}

inline bool ParseInt(const std::u16string& s, int& v) {
    if (s.empty()) return false;
    std::string a(s.begin(), s.end());
    char* end = nullptr;
    long n = strtol(a.c_str(), &end, 10);
    if (end != a.c_str() + a.size()) return false;
    v = (int)n;
    return true;
}

// The Weapons field's position within a character record split on ';',
// mirroring SFXOnlineSaveGameMP.SetCharacter's own read order (LE3's
// SFXGame.pcc, byte-identical to 2012's bar one added log line): Version,
// DevelopmentVersion, KitName, CharacterName, Tint1ID, Tint2ID, PatternID,
// PatternColorID, [PhongID, EmissiveID if Version>=15], SkinToneID,
// SecondsPlayed, TimeStamp x4, Powers, HotKeys(unread), Weapons. 16 fields
// before Weapons normally, 18 from version 15 on.
inline size_t WeaponsFieldIndex(int version) { return version >= 15 ? 18 : 16; }

// Slot indices 0/1 only: SFXPawn_PlayerMP.LoadWeapons only ever reads
// GetWeapon(0, ...) and GetWeapon(1, ...) (MaxWeapons = 2, SFXCharacterClass's
// own default). Any token beyond index 1 is left exactly as found.
static const size_t kSlots = 2;

// Rewrites `record` (one "character=" value, mpsave::MPSaveData::characters[i])
// in place if, and only if, it substitutes at least one id; returns the
// number of substitutions (0 if the record is unchanged, including when it
// could not be read at all — version missing, too few fields, or a
// non-numeric Weapons token — which is treated the same as "nothing to do",
// not as an error: a record this cannot confidently parse is left exactly as
// it was handed in). `log` gets one line per substitution actually made.
inline int FixCharacterRecord(std::u16string& record, const Mappings& m, std::vector<std::string>& log) {
    std::vector<std::u16string> fields = Split(record, u';');
    if (fields.size() < 3) return 0;   // no KitName even
    int version;
    if (!ParseInt(fields[0], version)) return 0;
    size_t widx = WeaponsFieldIndex(version);
    if (widx >= fields.size()) return 0;
    std::u16string kit = ToLower(fields[2]);
    auto kitIt = m.kitWeapons.find(kit);

    std::vector<std::u16string> tokens = Split(fields[widx], u',');
    // An empty Weapons field splits to one empty token, not zero fields:
    // treat it as no weapons at all, same as 2012's empty record.
    if (tokens.size() == 1 && tokens[0].empty()) return 0;

    int changed = 0;
    for (size_t slot = 0; slot < kSlots && slot < tokens.size(); ++slot) {
        int id;
        if (!ParseInt(tokens[slot], id)) continue;   // not a plain integer: leave it
        if (m.idToClass.find(id) != m.idToClass.end()) continue;   // already mapped
        if (kitIt == m.kitWeapons.end()) continue;    // unknown kit: nothing to substitute with
        const std::u16string& defaultClass = slot == 0 ? kitIt->second.first : kitIt->second.second;
        auto idIt = m.classToId.find(defaultClass);
        if (idIt == m.classToId.end()) continue;      // the default itself isn't mapped (shouldn't happen)
        std::string oldAscii(tokens[slot].begin(), tokens[slot].end());
        std::string newAscii = std::to_string(idIt->second);
        tokens[slot] = std::u16string(newAscii.begin(), newAscii.end());
        std::string kitAscii(fields[2].begin(), fields[2].end());
        log.push_back("weapon slot fix: kit " + kitAscii + " slot " + std::to_string(slot) +
                       ": id " + oldAscii + " no longer maps, substituted the kit's default (id " + newAscii + ")");
        ++changed;
    }
    if (changed == 0) return 0;   // untouched: `record` is not rewritten at all
    fields[widx] = Join(tokens, u',');
    record = Join(fields, u';');
    return changed;
}

}  // namespace weaponslotfix
