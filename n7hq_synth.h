// n7hq_synth.h — the second half of the N7 HQ console-profile converter: turn
// the parsed Profile (n7hq_convert.h) into 2012's Server*String save records
// (mp_save_format.h's MPSaveData). Pure C++, testable natively.
//
// Record grammar (2012's SFXOnlineSaveGameMP, version 20;4):
//   base   = V;D;Credits;NextPack;NumCopies;TotalCreditsSpent;TotalPlatSpent;
//            TotalGamesPlayed;TotalTimePlayed;LastLevelUp;PlayerVariables
//   class  = V;D;className;Level;XPOffset;NumPromotions      (one per base class)
//   char   = V;D;KitName;CharName;Tint1;Tint2;Pattern;PatternColor;Phong;
//            Emissive;Skin;SecondsPlayed;Y;Mo;Da;Secs;Powers;"";Weapons;Mods;
//            Deployed;LeveledUp                              (one per unlocked kit)
//   a power = Name ClassId Rank Evo0..Evo5 WheelIndex UsesTalentPoints
// PlayerVariables is a fixed-width hex blob: 2 hex chars per
// mpplayervariablemappings id (0..kMaxVarId), amount clamped 255, no gaps.
//
// Ids come from weapon_slot_defaults.h (kIdToClass, kKitDefaults). Item ids:
// the N7 HQ asset tail equals the class-name tail. Kit unlock ids: the kit name
// is itself a class row. Consumable and power display names need their own
// tables (n7hq_names.h), built from the game's strings.
#pragma once
#include "n7hq_convert.h"
#include "n7hq_names.h"
#include "n7hq_challenges.h"
#include "mp_save_format.h"
#include "weapon_slot_defaults.h"
#include <algorithm>
#include <map>
#include <string>
#include <cstring>

namespace ea {
namespace n7conv {

static const int kVersion = 20, kDevVersion = 4;
static const int kMaxVarId = 670;   // weapon_slot_defaults.h's largest id

// The class-name tail of a kIdToClass entry: drop the package (before the last
// '.'), then a leading SFX<Type>_ prefix, leaving the asset-style tail
// (SFXGameContent.SFXWeapon_AssaultRifle_Avenger -> AssaultRifle_Avenger).
inline std::string ClassTail(const std::string& cls) {
    size_t dot = cls.rfind('.');
    std::string t = dot == std::string::npos ? cls : cls.substr(dot + 1);
    static const char* const pre[] = { "SFXWeaponMod_", "SFXWeapon_", "SFXGameEffect_",
                                       "SFXPowerCustomActionMP_", "SFXPowerCustomAction_", "SFXGameContent_" };
    for (const char* p : pre) {
        size_t n = strlen(p);
        if (t.compare(0, n, p) == 0) { t = t.substr(n); break; }
    }
    return t;
}

// id lookups, built once from kIdToClass.
struct IdMaps {
    std::map<std::string, int> byTail;   // asset/class tail -> id (first wins)
    std::map<std::string, int> byRaw;    // the raw name after the last '.' -> id
    IdMaps() {
        for (const auto& e : weapondefaults::kIdToClass) {
            std::string cls = e.className;
            std::string tail = ClassTail(cls);
            byTail.emplace(tail, e.id);
            // Gear equipment is classed MatchConsumable_Gear_<x>_0; N7 HQ's
            // asset is the middle (Gear_<x>). Add an alias that drops a leading
            // "MatchConsumable_" and a trailing "_<digit>" tier so it matches.
            std::string alias = tail;
            if (alias.compare(0, 16, "MatchConsumable_") == 0) alias = alias.substr(16);
            size_t u = alias.rfind('_');
            if (u != std::string::npos && u + 1 < alias.size()) {
                bool allDig = true;
                for (size_t i = u + 1; i < alias.size(); ++i) if (alias[i] < '0' || alias[i] > '9') allDig = false;
                if (allDig) alias = alias.substr(0, u);
            }
            if (alias != tail) byTail.emplace(alias, e.id);
            size_t dot = cls.rfind('.');
            byRaw.emplace(dot == std::string::npos ? cls : cls.substr(dot + 1), e.id);
        }
    }
    int ItemId(const std::string& assetTail) const {
        auto it = byTail.find(assetTail);
        return it == byTail.end() ? -1 : it->second;
    }
    int KitId(const std::string& kit) const {
        auto it = byRaw.find(kit);          // kit names are bare class rows
        if (it != byRaw.end()) return it->second;
        auto t = byTail.find(kit);
        return t == byTail.end() ? -1 : t->second;
    }
};
inline const IdMaps& Ids() { static IdMaps m; return m; }

// The six base classes, and which one a kit id belongs to (it contains the word).
// In the order a server-written save lists the class records.
static const char* const kBaseClasses[] = { "Adept", "Soldier", "Engineer", "Sentinel", "Infiltrator", "Vanguard" };
inline std::string BaseClassOf(const std::string& kitId) {
    for (const char* c : kBaseClasses)
        if (kitId.find(c) != std::string::npos) return c;
    return "";
}

// The verified consumable display name -> id table (n7hq_names.h).
inline const std::map<std::string, int>& ConsumableMap() {
    static std::map<std::string, int> m = [] {
        std::map<std::string, int> r;
        for (const NameId& e : kConsumableIds) r.emplace(e.name, e.id);
        return r;
    }();
    return m;
}

inline std::string Hex2(int v) {
    v = v < 0 ? 0 : (v > 255 ? 255 : v);
    static const char* h = "0123456789ABCDEF";
    std::string o; o += h[(v >> 4) & 0xF]; o += h[v & 0xF];
    return o;
}

// A report of what the synthesis covered, so nothing is written blind.
struct SynthReport {
    int itemsPlaced = 0, itemsUnmapped = 0;
    int kitsUnlocked = 0, kitsUnmapped = 0;
    int consumablesPlaced = 0, consumablesUnmapped = 0;
    std::vector<std::string> unmapped;   // the display/asset names with no id
};

// The PlayerVariables hex blob: one 2-hex slot per id 0..kMaxVarId. Items set
// their level, kits their unlock flag (1), consumables their count. `cons` maps
// a consumable display name to its id (n7hq_names.h); empty leaves consumables
// out (and the report flags them, so a caller can refuse to write).
// `existing`, when given, is the player's current PlayerVariables blob: the
// import is merged onto it rather than built from zeros. N7 HQ is authoritative
// for every slot it shows (each card owned or not, each consumable); slots it
// never shows keep the existing value: the account flags (starter, the promo
// and free-weapon "granted" flags, so nothing is granted twice) and the one
// consumable family N7 HQ does not list (Polonium ammo).
inline std::vector<int> DecodeBlob(const std::string& blob) {
    std::vector<int> a(kMaxVarId + 1, 0);
    for (int i = 0; i <= kMaxVarId && 2 * i + 1 < (int)blob.size(); ++i)
        a[i] = (int)strtol(blob.substr(2 * i, 2).c_str(), nullptr, 16);
    return a;
}
inline std::string PlayerVariables(const Profile& p, const std::map<std::string, int>& cons, SynthReport& r,
                                   const std::string* existing = nullptr) {
    std::vector<int> amount = (existing && existing->size() == (size_t)(kMaxVarId + 1) * 2)
                              ? DecodeBlob(*existing) : std::vector<int>(kMaxVarId + 1, 0);
    for (const Item& it : p.items) {
        if (it.group == "consumables") continue;   // counted from the consumables tab, not here
        int id = Ids().ItemId(it.asset);
        if (id < 0 || id > kMaxVarId) {
            if (it.owned) { r.itemsUnmapped++; r.unmapped.push_back("item:" + it.group + "/" + it.asset); }
            continue;
        }
        // N7 HQ wins for every card it shows, kits included: the import
        // overwrites the current progress. A kit card is capped at its display
        // maximum (a human kit shown 4-4 can hold more copies), so copies above
        // the cap are lost; the kit itself stays unlocked and extra copies have
        // no gameplay effect. (Taking the higher of the two kept stale counts
        // from an older save, tested.)
        amount[id] = it.owned ? (it.level > 0 ? it.level : 1) : 0;
        if (it.owned) r.itemsPlaced++;
    }
    // Kits: the inventory's kit cards already set each kit's count (its level
    // bar, e.g. 5-2 = 2 copies), which is what a real save holds. The
    // characters page only confirms the kit exists, so it fills a kit the
    // inventory did not list, and never lowers a count to 1.
    for (const Kit& k : p.kits) {
        int id = Ids().KitId(k.id);
        if (id < 0 || id > kMaxVarId) { r.kitsUnmapped++; r.unmapped.push_back("kit:" + k.id); continue; }
        if (amount[id] == 0) amount[id] = 1;
        r.kitsUnlocked++;
    }
    for (const Consumable& c : p.consumables) {
        auto it = cons.find(c.name);
        if (it == cons.end() || it->second < 0 || it->second > kMaxVarId) { r.consumablesUnmapped++; r.unmapped.push_back("consumable:" + c.name); continue; }
        amount[it->second] = c.count;
        r.consumablesPlaced++;
    }
    std::string blob;
    for (int i = 0; i <= kMaxVarId; ++i) blob += Hex2(amount[i]);
    return blob;
}

inline std::string Join(std::initializer_list<std::string> parts, char sep = ';') {
    std::string o; bool first = true;
    for (const std::string& s : parts) { if (!first) o += sep; o += s; first = false; }
    return o;
}

// base record (without the version prefix helper, built explicitly).
inline std::string BuildBase(const Profile& p, const std::map<std::string, int>& cons, SynthReport& r) {
    std::string pv = PlayerVariables(p, cons, r);
    long long credits = p.credits < 0 ? 0 : p.credits;
    return Join({ std::to_string(kVersion), std::to_string(kDevVersion), std::to_string(credits),
                  "-1", "0", "0", "0", std::to_string(p.gamesPlayed < 0 ? 0 : p.gamesPlayed),
                  std::to_string(p.secondsPlayed < 0 ? 0 : p.secondsPlayed), "0", pv });
}

// one class record per base class present, from any kit of that class.
inline std::vector<std::string> BuildClasses(const Profile& p) {
    std::map<std::string, const Kit*> byClass;   // base class -> a kit of it
    for (const Kit& k : p.kits) {
        std::string bc = BaseClassOf(k.id);
        if (bc.empty()) continue;
        if (k.level > 0 && !byClass.count(bc)) byClass[bc] = &k;
    }
    std::vector<std::string> out;
    for (const char* c : kBaseClasses) {
        auto it = byClass.find(c);
        if (it == byClass.end()) continue;
        const Kit* k = it->second;
        out.push_back(Join({ std::to_string(kVersion), std::to_string(kDevVersion), c,
                             std::to_string(k->level), std::to_string(k->xp > 0 ? k->xp : 0) + ".0000",
                             std::to_string(k->promotions) }));
    }
    return out;
}

// ---- challenges ----------------------------------------------------------------
//
// The save's eight challenge strings (SFXSaveManagerMP_Local.ChallengeSnapshot):
// "1", then profile settings 89..95 as SFXAccomplishmentStorage writes them:
//   89 Completion  "22,<points>,<count per accomplishment Index>"
//   90 Progress    "22,<value per progress counter Index>"
//   91 RewardLevel "22,<level per RewardID>"
//   92 the selected banner
//   93..95 completion times, Unix seconds per accomplishment Index, 250 a string.
// Indices 0..99 are LE3's single-player achievements and stay as they are; the
// multiplayer rows are kChallenges (n7hq_challenges.h).
struct ChallengeReport {
    int golds = 0, silvers = 0, completed = 0, counters = 0, unmapped = 0, skipped = 0;
    long long points = 0;
};

inline std::vector<long long> CsvNumbers(const std::string& s) {
    std::vector<long long> v;
    size_t i = 0;
    while (i <= s.size()) {
        size_t c = s.find(',', i);
        if (c == std::string::npos) c = s.size();
        v.push_back(atoll(s.substr(i, c - i).c_str()));
        i = c + 1;
    }
    return v;
}
inline std::string CsvJoin(const std::vector<long long>& v, size_t from = 0, size_t to = std::string::npos) {
    std::string o;
    for (size_t i = from; i < v.size() && i < to; ++i) { if (i > from) o += ","; o += std::to_string(v[i]); }
    return o;
}

// `existing` is the current save's challenge strings (empty for none). `now` is
// the time a newly imported completion gets. Returns the eight strings, or an
// empty vector when the profile has no challenges tab (the save keeps its own).
inline std::vector<std::string> BuildChallenges(const Profile& p, const std::vector<std::string>& existing, long long now,
                                                ChallengeReport& r) {
    if (!p.challengesRead) return {};
    // the table: Index -> row, and each group's silvers in ascending Index
    std::map<int, const ChallengeRow*> byIndex;
    std::map<std::string, std::vector<int>> silversOf;
    int maxIndex = 0, maxProgress = 0, maxReward = 0;
    for (const ChallengeRow& c : kChallenges) {
        byIndex[c.index] = &c;
        if (strcmp(c.name, c.group) != 0) silversOf[c.group].push_back(c.index);
        maxIndex = std::max(maxIndex, c.index);
        maxProgress = std::max(maxProgress, c.progress);
        maxReward = std::max(maxReward, c.reward);
    }
    // the current strings, or the empty form a fresh profile writes
    bool have = existing.size() == 8 && existing[0] == "1" && existing[1].rfind("22,", 0) == 0 &&
                existing[2].rfind("22,", 0) == 0 && existing[3].rfind("22,", 0) == 0;
    std::vector<long long> comp, prog, reward, times;
    long long banner = 0;
    if (have) {
        std::vector<long long> c = CsvNumbers(existing[1]);
        comp.assign(c.begin() + 2, c.end());
        std::vector<long long> g = CsvNumbers(existing[2]);
        prog.assign(g.begin() + 1, g.end());
        std::vector<long long> w = CsvNumbers(existing[3]);
        reward.assign(w.begin() + 1, w.end());
        banner = atoll(existing[4].c_str());
        for (int t = 5; t < 8; ++t)
            if (!existing[t].empty()) { std::vector<long long> x = CsvNumbers(existing[t]); times.insert(times.end(), x.begin(), x.end()); }
    }
    if (comp.size() < (size_t)maxIndex + 1) comp.resize(maxIndex + 1, 0);
    if (times.size() < comp.size()) times.resize(comp.size(), 0);
    if (prog.size() < (size_t)maxProgress + 1) prog.resize(maxProgress + 1, 0);
    if (reward.size() < (size_t)maxReward + 1) reward.resize(maxReward + 1, 0);
    // Completions. A gold's row is its own Index; a silver is its block's
    // place-th silver by ascending Index (N7 HQ's order). The Mass Effect gold's
    // block lists the other golds again and has no silvers of its own: skipped.
    std::vector<bool> covered(comp.size(), false);
    // progress per counter: the largest value below its goal (exact), else the
    // largest at its goal (N7 HQ caps a finished counter there).
    std::map<int, long long> exact, capped;
    for (const Challenge& c : p.challenges) {
        int index = -1;
        if (c.pos < 0) {
            auto it = byIndex.find(c.group);
            if (it == byIndex.end() || strcmp(it->second->name, it->second->group) != 0) { r.unmapped++; continue; }
            index = c.group; r.golds++;
        } else {
            auto g = byIndex.find(c.group);
            if (g == byIndex.end()) { r.unmapped++; continue; }
            auto s = silversOf.find(g->second->name);
            if (s == silversOf.end()) { r.skipped++; continue; }
            if ((size_t)c.pos >= s->second.size()) { r.unmapped++; continue; }
            index = s->second[c.pos]; r.silvers++;
        }
        covered[index] = true;
        comp[index] = c.times;
        if (c.times > 0) r.completed++;
        const ChallengeRow* row = byIndex[index];
        if (row->progress >= 0 && c.progress >= 0) {
            bool atGoal = c.goal >= 0 && c.progress >= c.goal;
            std::map<int, long long>& m = atGoal ? capped : exact;
            auto e = m.find(row->progress);
            if (e == m.end() || e->second < c.progress) m[row->progress] = c.progress;
        }
    }
    for (auto& e : exact) { prog[e.first] = e.second; r.counters++; }
    for (auto& e : capped)
        if (!exact.count(e.first)) { prog[e.first] = std::max(prog[e.first], e.second); r.counters++; }
    // Each covered row: its reward level and completion time follow it. A
    // completed multiplayer row needs a time: the lobby re-marks completions from
    // their times after LE3's achievement sync zeroes them, and re-marks any
    // row that still has one, so an incomplete row's time is cleared.
    for (size_t i = 0; i < covered.size(); ++i) {
        if (!covered[i]) continue;
        const ChallengeRow* row = byIndex[(int)i];
        if (comp[i] > 0) { if (times[i] <= 0) times[i] = now; }
        else times[i] = 0;
        if (row->reward > 0) reward[row->reward] = comp[i] > 0 ? std::max(reward[row->reward], 1LL) : 0;
    }
    // Challenge points: UnlockReward adds a row's PointValue on every completion.
    long long points = 0;
    for (const ChallengeRow& c : kChallenges)
        if ((size_t)c.index < comp.size()) points += (long long)c.points * comp[c.index];
    r.points = points;
    std::vector<std::string> out;
    out.push_back("1");
    out.push_back("22," + std::to_string(points) + "," + CsvJoin(comp));
    out.push_back("22," + CsvJoin(prog));
    out.push_back("22," + CsvJoin(reward));
    out.push_back(std::to_string(banner));
    for (size_t t = 0; t < 3; ++t) out.push_back(CsvJoin(times, t * 250, (t + 1) * 250));
    return out;
}

// ---- the whole save -----------------------------------------------------------

inline std::u16string U16(const std::string& s) { return std::u16string(s.begin(), s.end()); }
inline std::string U8(const std::u16string& s) {
    std::string o; for (char16_t c : s) o += c < 128 ? (char)c : '?'; return o;
}
inline std::vector<std::string> SplitSemi(const std::string& s) {
    std::vector<std::string> o; size_t a = 0;
    while (true) { size_t b = s.find(';', a); o.push_back(s.substr(a, b == std::string::npos ? std::string::npos : b - a)); if (b == std::string::npos) break; a = b + 1; }
    return o;
}

// A kit's PowersString from N7 HQ: the kit's powers in its own class order,
// each "<Name> <ClassId> <Rank> <Evo0..Evo5> 0 True", then the four consumable
// powers every MP kit carries (as the game writes them). `kitClasses` is the
// kit's power classes (tail, id) in PowerCustomActionClasses order; each N7 HQ
// power is matched to one by its display name (`displayOf`). Loading is by
// class (SFXPowerManager.LoadPowers, GetPowerByClass) and the class list is
// checked against the kit's (VerifySavedPawnPowers), so a class must be the
// kit's own; the name is only the de-duplication key and the game rewrites it
// from the pawn on its next save. Returns "" (the kit keeps its default
// powers, re-spent from the class's points) if any N7 HQ power has no class.
struct KitClass { std::string tail; int id; std::string display; };
inline std::string BuildPowers(const Kit& k, const std::vector<KitClass>& kitClasses, std::string& why) {
    std::vector<const Power*> used(kitClasses.size(), nullptr);
    std::vector<const Power*> left;
    for (const Power& pw : k.powers) {
        bool placed = false;
        for (size_t c = 0; c < kitClasses.size(); ++c) {
            if (used[c] || kitClasses[c].display.empty() || kitClasses[c].display != pw.name) continue;
            used[c] = &pw; placed = true; break;
        }
        if (!placed) left.push_back(&pw);
    }
    // One shown power and one class left (N7 HQ shows no name for a few
    // powers): they are each other.
    if (left.size() == 1) {
        int free = -1, n = 0;
        for (size_t c = 0; c < kitClasses.size(); ++c) if (!used[c]) { free = (int)c; ++n; }
        if (n == 1) { used[free] = left[0]; left.clear(); }
    }
    if (!left.empty()) { why = "no class of " + k.id + " is shown as '" + left[0]->name + "'"; return ""; }
    std::string out;
    auto add = [&](const std::string& s) { out += (out.empty() ? "" : ",") + s; };
    char rank[16];
    for (size_t c = 0; c < kitClasses.size(); ++c) {
        const Power* pw = used[c];
        snprintf(rank, sizeof rank, "%d.0000", pw ? pw->rank : 0);
        std::string e;
        for (int i = 0; i < 6; ++i) e += " " + std::to_string(pw ? pw->evo[i] : 0);
        add(kitClasses[c].tail + " " + std::to_string(kitClasses[c].id) + " " + rank + e + " 0 True");
    }
    // the consumable powers, as a real record holds them
    add("Consumable_Rocket 88 1.0000 0 0 0 0 0 0 0 False");
    add("Consumable_Revive 87 1.0000 0 0 0 0 0 0 4 False");
    add("Consumable_Shield 89 1.0000 0 0 0 0 0 0 5 False");
    add("Consumable_Ammo 86 1.0000 0 0 0 0 0 0 6 False");
    return out;
}

// A new kit's character record (none in the current save): the game's own
// empty-record form (appearance 0, no powers, no loadout, not deployed).
inline std::string NewCharacter(const std::string& kit, const std::string& powers, bool deployed = false) {
    return Join({ std::to_string(kVersion), std::to_string(kDevVersion), kit, kit,
                  "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                  powers, "", "", "", deployed ? "True" : "False", "True" });
}

struct SaveReport {
    SynthReport vars;
    int classes = 0, charsKept = 0, charsNew = 0, powersSet = 0, powersDefault = 0;
    ChallengeReport challenges;
    bool challengesSet = false;
    std::vector<std::string> notes;
};

// The import's save: the current one (`cur`, empty for none) with N7 HQ's data
// written over it. From N7 HQ: credits, games played and time played,
// PlayerVariables (merged, see above), the class records (level, XP,
// promotions), each kit's powers and deployed state, and the challenges
// (BuildChallenges; `now` dates a newly imported completion). Kept, as N7 HQ
// does not show them: face codes, GaW, the selected kit and banner, the base
// record's other counters (credits spent, next pack), each character record's
// name, appearance, loadout and leveled-up flag, the N7 Operation (weekly)
// challenge groups and the single-player achievements.
// kKitPowers (n7hq_names.h) as kit -> its power classes, in order.
inline const std::map<std::string, std::vector<KitClass>>& KitClasses() {
    static std::map<std::string, std::vector<KitClass>> m = [] {
        std::map<std::string, std::vector<KitClass>> r;
        for (const KitPower& e : kKitPowers) r[e.kit].push_back({ e.tail, e.id, e.display });
        return r;
    }();
    return m;
}

inline MPSaveData BuildSave(const Profile& p, const MPSaveData* cur, SaveReport& rep,
                            const std::map<std::string, std::vector<KitClass>>& kitClasses = KitClasses(),
                            long long now = 0) {
    MPSaveData d = cur ? *cur : MPSaveData();
    // base
    std::vector<std::string> b = cur && !cur->base.empty() ? SplitSemi(U8(cur->base)) : std::vector<std::string>();
    if (b.size() != 11) b = { std::to_string(kVersion), std::to_string(kDevVersion), "0", "-1", "0", "0", "0", "0", "0", "0", "" };
    std::string existing = b[10];
    b[0] = std::to_string(kVersion); b[1] = std::to_string(kDevVersion);
    if (p.credits >= 0) b[2] = std::to_string(p.credits);
    if (p.gamesPlayed >= 0) b[7] = std::to_string(p.gamesPlayed);
    if (p.secondsPlayed >= 0) b[8] = std::to_string(p.secondsPlayed);
    b[10] = PlayerVariables(p, ConsumableMap(), rep.vars, existing.empty() ? nullptr : &existing);
    std::string base;
    for (size_t i = 0; i < b.size(); ++i) base += (i ? ";" : "") + b[i];
    d.base = U16(base);
    // classes
    d.classes.clear();
    for (const std::string& c : BuildClasses(p)) { d.classes.push_back(U16(c)); rep.classes++; }
    // characters
    std::map<std::string, size_t> byKit;
    for (size_t i = 0; i < d.characters.size(); ++i) {
        std::vector<std::string> f = SplitSemi(U8(d.characters[i]));
        if (f.size() > 2) byKit[f[2]] = i;
    }
    for (const Kit& k : p.kits) {
        std::string powers, why;
        auto kc = kitClasses.find(k.id);
        if (kc != kitClasses.end()) powers = BuildPowers(k, kc->second, why);
        else why = "no class list for " + k.id;
        if (powers.empty()) { rep.powersDefault++; rep.notes.push_back(why); } else rep.powersSet++;
        auto at = byKit.find(k.id);
        if (at == byKit.end()) { d.characters.push_back(U16(NewCharacter(k.id, powers, k.deployed == 1))); rep.charsNew++; continue; }
        std::vector<std::string> f = SplitSemi(U8(d.characters[at->second]));
        if (f.size() == 22) {
            f[16] = powers;   // the PowersString field
            if (k.deployed >= 0) f[20] = k.deployed ? "True" : "False";
        }
        std::string rec;
        for (size_t i = 0; i < f.size(); ++i) rec += (i ? ";" : "") + f[i];
        d.characters[at->second] = U16(rec);
        rep.charsKept++;
    }
    // challenges
    std::vector<std::string> ex;
    for (const std::u16string& c : d.challenges) ex.push_back(U8(c));
    std::vector<std::string> ch = BuildChallenges(p, ex, now, rep.challenges);
    if (!ch.empty()) {
        d.challenges.clear();
        for (const std::string& c : ch) d.challenges.push_back(U16(c));
        rep.challengesSet = true;
    }
    return d;
}

}  // namespace n7conv
}  // namespace ea
