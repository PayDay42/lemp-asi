// n7hq_convert.h — parse a saved N7 HQ profile's HTML tabs into structured
// data, the first half of converting an N7 HQ console profile into LEMP's
// save. This header only READS the HTML (no Windows headers, testable
// natively); turning the parsed data into 2012's Server*String records is the
// second half (see the record grammar once it is settled).
//
// The pages are what mp_save.asi saves under LEMP\n7hq\<platform>-<name>-<tab>
// .html (n7hq_import.h): overview (credits), inventory (items and
// consumables), characters (per-kit level, promotions, XP, power ranks). The
// markup matches N7 HQ's public profile pages:
//   - inventory item: <div class="card"> (owned) or "card off" (not), an
//     <img src=".../multiplayer/<group>/<asset>.png">, a <span>Display Name</span>,
//     and a level bar <img src=".../levels/<n>-10.png"> (n = the item's level).
//   - consumable: <span>Name - count</span>.
//   - character: id="characterStats_<KitId>", "Level <n>", "<k> Promotions
//     awarded", "XP: <n>", and per power a <div class="powerbar"> of six
//     <img src=".../lk2.png"> (rank taken) / lk1.png (not), so the rank is the
//     count of lk2.
#pragma once
#include <map>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>

namespace ea {
namespace n7conv {

struct Item {
    std::string group;    // the asset folder: guns, AssaultRifleMods, Gear, ...
    std::string asset;    // the asset base name, e.g. AssaultRifle_Avenger
    std::string display;  // the shown name, e.g. "M-8 Avenger X"
    int level = 0;        // the level bar (0 when none/not owned)
    bool owned = false;
};
struct Consumable { std::string name; int count = 0; };
// A power: its rank 0..6 (the count of lk2 icons) and its six evolution slots,
// the save's EvolvedChoices[0..5] = rank 4 A/B, rank 5 A/B, rank 6 A/B. A slot
// holds the pick's order (1 at rank 4, 2 at rank 5, 3 at rank 6) or 0, which is
// how the game stores them (EvolvePower sets NumEvolved+1).
struct Power {
    std::string name;
    int rank = 0;
    int evo[6] = {0, 0, 0, 0, 0, 0};
    bool evoKnown = false;   // a statstree was found for it
};
struct Kit {
    std::string id;       // characterStats_<id>, e.g. AdeptN7
    int level = 0, promotions = 0;
    long long xp = 0;
    int deployed = -1;    // the kit grid: 1 deployed, 0 "mpDisable", -1 not in the grid
    std::vector<Power> powers;
};
// One row of the challenges tab. A gold is <div class="goldchallengeitem
// [challengecomplete]" onclick="onChallengesGroupClick(this, 'g<Index>')">,
// its Index the accomplishment's own; its silvers are the rows of <div
// class="silverblockchallenge" id="g<Index>">, in the order shown (`pos`).
struct Challenge {
    int group = -1;          // the gold's Index
    int pos = -1;            // -1 the gold itself, else the silver's place in its block
    bool complete = false;   // challengecomplete / silvercomplete
    int times = 0;           // a gold's "x<N>", a silver's "Times Completed: <N>"
    long long progress = -1, goal = -1;   // "Current progress: <a>/<b>" (-1 if absent)
};
struct Profile {
    std::string name, platform;
    long long credits = -1;   // -1 when the overview was not parsed
    long long gamesPlayed = -1, secondsPlayed = -1;   // the overview's totals, -1 if absent
    std::vector<Item> items;
    std::vector<Consumable> consumables;
    std::vector<Kit> kits;
    std::vector<Challenge> challenges;
    bool challengesRead = false;   // the challenges tab was given and held its table
};

// ---- small HTML helpers (no regex: the pages are large) --------------------

// The first integer in `s` at or after `from` ("," and spaces skipped), or -1.
inline long long IntAfter(const std::string& s, size_t from) {
    size_t i = from;
    while (i < s.size() && !(s[i] >= '0' && s[i] <= '9')) {
        if (s[i] == '<') return -1;   // ran into the next tag: no number here
        ++i;
    }
    if (i >= s.size()) return -1;
    long long v = 0; bool any = false;
    for (; i < s.size(); ++i) {
        if (s[i] >= '0' && s[i] <= '9') { v = v * 10 + (s[i] - '0'); any = true; }
        else if (s[i] == ',') continue;
        else break;
    }
    return any ? v : -1;
}
// The text of the first <span>...</span> at or after `from`, &amp; unescaped;
// `end` receives the index past </span>.
inline std::string SpanText(const std::string& s, size_t from, size_t& end) {
    size_t a = s.find("<span>", from);
    if (a == std::string::npos) { end = std::string::npos; return ""; }
    a += 6;
    size_t b = s.find("</span>", a);
    if (b == std::string::npos) { end = std::string::npos; return ""; }
    end = b + 7;
    std::string t = s.substr(a, b - a), o;
    for (size_t i = 0; i < t.size();) {
        if (!t.compare(i, 5, "&amp;")) { o += '&'; i += 5; }
        else o += t[i++];
    }
    return o;
}

// ---- the tabs --------------------------------------------------------------

// Overview: the player's current credits (-1 if not found).
inline long long ParseCredits(const std::string& html) {
    // "Current Credits:" then, past some tags, <div class="playerstat
    // pscredits">556</div>.
    size_t p = html.find("Current Credits:");
    if (p == std::string::npos) return -1;
    size_t c = html.find("pscredits", p);
    if (c == std::string::npos) return -1;
    size_t gt = html.find('>', c);
    return gt == std::string::npos ? -1 : IntAfter(html, gt + 1);
}

// Overview: a playerstat's text, e.g. <div class="playerstat psgameplayed">1200
// </div> ("" if absent).
inline std::string OverviewStat(const std::string& html, const char* cls) {
    size_t c = html.find(std::string("playerstat ") + cls + "\"");
    if (c == std::string::npos) return "";
    size_t gt = html.find('>', c), lt = gt == std::string::npos ? gt : html.find('<', gt);
    return lt == std::string::npos ? "" : html.substr(gt + 1, lt - gt - 1);
}
// "432H 32M 54S" in seconds (-1 if it is not that form).
inline long long ParsePlayTime(const std::string& t) {
    long long total = 0, n = -1; bool any = false;
    for (char ch : t) {
        if (ch >= '0' && ch <= '9') n = (n < 0 ? 0 : n * 10) + (ch - '0');
        else if (ch == 'H' || ch == 'M' || ch == 'S') {
            if (n < 0) return -1;
            total += n * (ch == 'H' ? 3600 : ch == 'M' ? 60 : 1); n = -1; any = true;
        } else if (ch != ' ' && ch != ',') return -1;
    }
    return any && n < 0 ? total : -1;
}

// Inventory: every item card (owned or not) and every consumable. The card's
// group+asset come from its icon path .../multiplayer/<group>/<asset>.png; the
// level from a levels/<n>-10.png bar; the name from the <span>. Consumables are
// "<span>Name - count</span>" (a '-' then a number), told apart from item
// cards (which have no " - <n>" in the span) by that trailing count.
inline void ParseInventory(const std::string& html, Profile& p) {
    size_t i = 0;
    while (true) {
        size_t c = html.find("class=\"card", i);
        if (c == std::string::npos) break;
        size_t spanEnd;
        // `class="card"` (owned) vs `class="card off"`: the char past "card"
        // is '"' for owned, ' ' (then "off") for not owned.
        bool off = html.compare(c + 11, 4, " off") == 0;
        // the card's bounds: up to the next card or a clear section end
        size_t next = html.find("class=\"card", c + 5);
        size_t limit = next == std::string::npos ? html.size() : next;
        Item it;
        it.owned = !off;
        // The card's own icon, not its rarity-background (cards/<rarity>-on.png)
        // or its level bar (levels/<n>-10.png): the first /multiplayer/<group>/
        // whose group is neither "cards" nor "levels".
        size_t scan = c;
        while (true) {
            size_t icon = html.find("/multiplayer/", scan);
            if (icon == std::string::npos || icon >= limit) break;
            size_t g = icon + 13;
            size_t slash = html.find('/', g), dot = html.find(".png", g);
            scan = icon + 13;
            if (slash == std::string::npos || dot == std::string::npos || slash >= dot) continue;
            std::string group = html.substr(g, slash - g);
            if (group == "cards" || group == "levels") continue;
            // "consumables/*" cards duplicate the Consumables tab's counts
            // (handled from its <span>Name - N</span>); skip them as items.
            if (group == "consumables") { it.group = group; break; }
            it.group = group;
            it.asset = html.substr(slash + 1, dot - slash - 1);
            break;
        }
        it.display = SpanText(html, c, spanEnd);
        // The level bar is levels/<max>-<current>.png (an unowned card shows
        // <max>-0): the level is the SECOND number. Checked against an exact
        // EA-app import of the same account (Collector "10-4" = level 4).
        size_t lv = html.find("/levels/", c);
        if (lv != std::string::npos && lv < limit) {
            size_t dash = html.find('-', lv + 8);
            size_t png = html.find(".png", lv + 8);
            if (dash != std::string::npos && png != std::string::npos && dash < png)
                it.level = (int)IntAfter(html, dash + 1);
        }
        p.items.push_back(it);
        i = c + 5;
    }
    // Consumables: spans with a trailing " - <count>".
    size_t j = 0;
    while (true) {
        size_t e;
        std::string sp = SpanText(html, j, e);
        if (e == std::string::npos) break;
        j = e;
        size_t dash = sp.rfind(" - ");
        if (dash != std::string::npos) {
            std::string tail = sp.substr(dash + 3);
            bool num = !tail.empty();
            for (char ch : tail) if (ch < '0' || ch > '9') num = false;
            if (num) { Consumable cn; cn.name = sp.substr(0, dash); cn.count = atoi(tail.c_str()); p.consumables.push_back(cn); }
        }
    }
}

// Characters: each id="characterStats_<id>" block, its level, promotions, XP,
// and each power's rank (the count of lk2.png in its powerbar). A power row is
// <div class="powername">Name</div> ... <div class="powerbar"> six imgs.
// The kit grid: <div class="mpCharacter characteritem[ mpDisable ...]"
// id="<kit>">. A kit without "mpDisable" is one the save records as deployed.
inline std::map<std::string, int> ParseDeployed(const std::string& html) {
    std::map<std::string, int> out;
    const std::string key = "class=\"mpCharacter characteritem";
    for (size_t i = 0; (i = html.find(key, i)) != std::string::npos; i += key.size()) {
        size_t clsEnd = html.find('"', i + 7);
        size_t idA = html.find("id=\"", i);
        if (clsEnd == std::string::npos || idA == std::string::npos || idA > html.find('>', i)) continue;
        idA += 4;
        size_t idB = html.find('"', idA);
        if (idB == std::string::npos) break;
        out[html.substr(idA, idB - idA)] = html.substr(i, clsEnd - i).find("mpDisable") == std::string::npos ? 1 : 0;
    }
    return out;
}

inline void ParseCharacters(const std::string& html, Profile& p) {
    const std::map<std::string, int> deployed = ParseDeployed(html);
    const std::string key = "id=\"characterStats_";
    size_t i = 0;
    while (true) {
        size_t s = html.find(key, i);
        if (s == std::string::npos) break;
        size_t idA = s + key.size(), idB = html.find('"', idA);
        if (idB == std::string::npos) break;
        size_t next = html.find(key, idA);
        size_t limit = next == std::string::npos ? html.size() : next;
        Kit k;
        k.id = html.substr(idA, idB - idA);
        auto dep = deployed.find(k.id);
        if (dep != deployed.end()) k.deployed = dep->second;
        size_t lp = html.find("Level", idB);
        if (lp != std::string::npos && lp < limit) k.level = (int)IntAfter(html, lp + 5);
        size_t pp = html.find("Promotions awarded", idB);
        // "<k> Promotions awarded": the number is just before the word.
        if (pp != std::string::npos && pp < limit) {
            size_t b = pp; while (b > idB && (html[b - 1] == ' ' || (html[b - 1] >= '0' && html[b - 1] <= '9'))) --b;
            k.promotions = (int)IntAfter(html, b);
        }
        size_t xp = html.find("XP:", idB);
        if (xp != std::string::npos && xp < limit) k.xp = IntAfter(html, xp + 3);
        // powers
        size_t q = idB;
        while (true) {
            size_t pn = html.find("class=\"powername\"", q);
            if (pn == std::string::npos || pn >= limit) break;
            size_t e;
            std::string name;
            size_t gt = html.find('>', pn);
            size_t lt = gt == std::string::npos ? std::string::npos : html.find('<', gt);
            if (gt != std::string::npos && lt != std::string::npos) name = html.substr(gt + 1, lt - gt - 1);
            size_t bar = html.find("class=\"powerbar\"", pn);
            size_t barNext = html.find("class=\"powername\"", pn + 1);
            size_t barLimit = (barNext == std::string::npos || barNext > limit) ? limit : barNext;
            int rank = 0;
            if (bar != std::string::npos && bar < barLimit) {
                size_t t = bar;
                while (true) {
                    size_t img = html.find("lk2.png", t);
                    if (img == std::string::npos || img >= barLimit) break;
                    ++rank; t = img + 7;
                }
            }
            Power pw; pw.name = name; pw.rank = rank;
            k.powers.push_back(pw);
            (void)e;
            q = pn + 1;
        }
        // Evolutions: each power's <div class="statstree"> names it in a
        // treeinfo <p>, then holds 9 poweritem divs: ranks 1-3, then the six
        // choices 4A 4B 5A 5B 6A 6B; "poweractive" marks the ones taken.
        size_t s2 = idB;
        while (true) {
            size_t st = html.find("class=\"statstree\"", s2);
            if (st == std::string::npos || st >= limit) break;
            size_t stNext = html.find("class=\"statstree\"", st + 1);
            size_t stLimit = (stNext == std::string::npos || stNext > limit) ? limit : stNext;
            std::string tree;
            size_t ti = html.find("treeinfo", st);
            if (ti != std::string::npos && ti < stLimit) {
                size_t pa = html.find("<p>", ti), pb = pa == std::string::npos ? pa : html.find("</p>", pa);
                if (pa != std::string::npos && pb != std::string::npos && pb < stLimit) tree = html.substr(pa + 3, pb - pa - 3);
            }
            std::vector<bool> active;
            size_t it = st;
            while (true) {
                size_t pi = html.find("class=\"poweritem", it);
                if (pi == std::string::npos || pi >= stLimit) break;
                size_t q2 = html.find('"', pi + 7);
                std::string cls = q2 == std::string::npos ? "" : html.substr(pi + 7, q2 - pi - 7);
                active.push_back(cls.find("poweractive") != std::string::npos);
                it = pi + 1;
            }
            for (Power& pw : k.powers) {
                if (pw.name != tree || pw.evoKnown) continue;
                if (active.size() >= 9)
                    for (int e2 = 0; e2 < 6; ++e2) pw.evo[e2] = active[3 + e2] ? (e2 / 2 + 1) : 0;
                pw.evoKnown = true;
                break;
            }
            s2 = st + 1;
        }
        p.kits.push_back(k);
        i = idA;
    }
}

// "Current progress: 5/8" inside [from, to): a and b, or -1.
inline void ProgressIn(const std::string& html, size_t from, size_t to, long long& a, long long& b) {
    a = b = -1;
    size_t c = html.find("Current progress:", from);
    if (c == std::string::npos || c >= to) return;
    a = IntAfter(html, c + 17);
    size_t slash = html.find('/', c);
    if (slash != std::string::npos && slash < to) b = IntAfter(html, slash + 1);
}
// The number after `label` inside [from, to), or -1.
inline long long NumberIn(const std::string& html, size_t from, size_t to, const char* label) {
    size_t c = html.find(label, from);
    return c == std::string::npos || c >= to ? -1 : IntAfter(html, c + strlen(label));
}

// Challenges: every gold, then every silver block's rows.
inline void ParseChallenges(const std::string& html, Profile& p) {
    const std::string goldKey = "class=\"goldchallengeitem", groupKey = "onChallengesGroupClick(this, 'g";
    for (size_t i = 0; (i = html.find(goldKey, i)) != std::string::npos; i += goldKey.size()) {
        size_t clsEnd = html.find('"', i + 7);
        size_t g = html.find(groupKey, i);
        size_t end = html.find("<!-- ./goldchallengeitem", i);
        if (clsEnd == std::string::npos || g == std::string::npos || end == std::string::npos || g > end) continue;
        Challenge c;
        c.group = (int)IntAfter(html, g + groupKey.size());
        c.complete = html.substr(i, clsEnd - i).find("challengecomplete") != std::string::npos;
        size_t h4 = html.find("<h4>", i), h4e = html.find("</h4>", i);
        if (h4 != std::string::npos && h4e != std::string::npos && h4e < end) {
            size_t x = html.find("<span>x", h4);
            if (x != std::string::npos && x < h4e) c.times = (int)IntAfter(html, x + 7);
        }
        if (c.complete && c.times < 1) c.times = 1;
        ProgressIn(html, i, end, c.progress, c.goal);
        if (c.group >= 0) p.challenges.push_back(c);
    }
    const std::string blockKey = "class=\"silverblockchallenge\"", rowKey = "class=\"silverchallenge";
    for (size_t b = 0; (b = html.find(blockKey, b)) != std::string::npos; b += blockKey.size()) {
        size_t tagEnd = html.find('>', b), id = html.find("id=\"g", b);
        if (tagEnd == std::string::npos || id == std::string::npos || id > tagEnd) continue;
        int group = (int)IntAfter(html, id + 5);
        size_t next = html.find(blockKey, tagEnd);
        size_t limit = next == std::string::npos ? html.size() : next;
        int pos = 0;
        for (size_t r = html.find(rowKey, tagEnd); r != std::string::npos && r < limit; r = html.find(rowKey, r + rowKey.size())) {
            size_t clsEnd = html.find('"', r + 7);
            size_t rowEnd = html.find("<!-- ./silverchallenge", r);
            if (clsEnd == std::string::npos || rowEnd == std::string::npos) break;
            Challenge c;
            c.group = group; c.pos = pos++;
            c.complete = html.substr(r, clsEnd - r).find("silvercomplete") != std::string::npos;
            long long t = NumberIn(html, r, rowEnd, "Times Completed:");
            c.times = t < 0 ? 0 : (int)t;
            if (c.complete && c.times < 1) c.times = 1;
            ProgressIn(html, r, rowEnd, c.progress, c.goal);
            p.challenges.push_back(c);
        }
    }
    p.challengesRead = !p.challenges.empty();
}

inline Profile Parse(const std::string& overview, const std::string& inventory, const std::string& characters,
                     const std::string& challenges = "") {
    Profile p;
    p.credits = ParseCredits(overview);
    std::string games = OverviewStat(overview, "psgameplayed");
    if (!games.empty() && games.find_first_not_of("0123456789,") == std::string::npos) p.gamesPlayed = IntAfter(games, 0);
    p.secondsPlayed = ParsePlayTime(OverviewStat(overview, "pstimeplayed"));
    ParseInventory(inventory, p);
    ParseCharacters(characters, p);
    if (!challenges.empty()) ParseChallenges(challenges, p);
    return p;
}

}  // namespace n7conv
}  // namespace ea
