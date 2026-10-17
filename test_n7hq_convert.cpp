// n7hq_convert.h, natively:
//   g++ -std=c++17 -O2 -o test_n7hq_convert test_n7hq_convert.cpp && ./test_n7hq_convert [<saved pages dir> <profile>]
// With no directory it runs the inline-HTML checks only. With one, it parses
// a real saved profile's tabs from that folder (<profile>-overview.html,
// -inventory.html, -characters.html, -challenges.html); the counts checked
// are that profile's.
#include "n7hq_convert.h"
#include "n7hq_synth.h"
#include <cstdio>
#include <fstream>
#include <sstream>
#include <algorithm>
using namespace ea::n7conv;

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } else printf("ok   %s\n", #c); } while (0)

static std::string slurp(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::stringstream ss; ss << f.rdbuf(); return ss.str();
}

int main(int argc, char** argv) {
    {   // inline markup
        CHECK(ParseCredits("Current Credits:</td><td><div class=\"playerstat pscredits\">20,573</div>") == 20573);
        CHECK(ParseCredits("<div>no credits here</div>") == -1);
        Profile p;
        std::string inv =
            "<div class=\"card\" style=\"background: url('x/common-on.png')\">"
            "<img src=\"//c/multiplayer/guns/AssaultRifle_Avenger.png\" /><span>M-8 Avenger X</span>"
            "<img src=\"//c/multiplayer/levels/10-10.png\" /></div>"
            "<div class=\"card off\"><img src=\"//c/multiplayer/Gear/Gear_BatarianGauntlet.png\" /><span>Batarian Gauntlet</span></div>"
            "<span>Thermal Clip Pack - 255</span><span>Medi-Gel - 11</span>";
        ParseInventory(inv, p);
        CHECK(p.items.size() == 2);
        CHECK(p.items[0].owned && p.items[0].group == "guns" && p.items[0].asset == "AssaultRifle_Avenger"
              && p.items[0].display == "M-8 Avenger X" && p.items[0].level == 10);
        CHECK(!p.items[1].owned && p.items[1].group == "Gear" && p.items[1].asset == "Gear_BatarianGauntlet" && p.items[1].level == 0);
        CHECK(p.consumables.size() == 2 && p.consumables[0].name == "Thermal Clip Pack" && p.consumables[0].count == 255
              && p.consumables[1].name == "Medi-Gel" && p.consumables[1].count == 11);
        Profile k;
        std::string ch =
            "<div id=\"characterStats_AdeptN7\">Level 20 N7 Fury 18 Promotions awarded XP: 5,333,080"
            "<div class=\"powername\">Annihilation Field</div><div class=\"powerbar\">"
            "<img src=\"lk2.png\"/><img src=\"lk2.png\"/><img src=\"lk2.png\"/><img src=\"lk2.png\"/><img src=\"lk1.png\"/><img src=\"lk1.png\"/></div>"
            "<div class=\"powername\">Fitness</div><div class=\"powerbar\"><img src=\"lk2.png\"/></div></div>";
        ParseCharacters(ch, k);
        CHECK(k.kits.size() == 1 && k.kits[0].id == "AdeptN7" && k.kits[0].level == 20 && k.kits[0].promotions == 18 && k.kits[0].xp == 5333080);
        CHECK(k.kits[0].powers.size() == 2 && k.kits[0].powers[0].name == "Annihilation Field" && k.kits[0].powers[0].rank == 4
              && k.kits[0].powers[1].rank == 1);
    }
    if (argc > 2) {   // the real fixtures
        std::string dir = argv[1] + std::string("/") + argv[2];
        Profile p = Parse(slurp(dir + "-overview.html"),
                          slurp(dir + "-inventory.html"),
                          slurp(dir + "-characters.html"));
        printf("     credits=%lld items=%zu (owned=%d) consumables=%zu kits=%zu\n",
               p.credits, p.items.size(),
               (int)std::count_if(p.items.begin(), p.items.end(), [](const Item& i){ return i.owned; }),
               p.consumables.size(), p.kits.size());
        CHECK(p.credits == 556);
        CHECK(p.items.size() > 200);
        CHECK(p.consumables.size() >= 8);
        CHECK(p.kits.size() == 65);
        // a known kit has data
        const Kit* adept = nullptr;
        for (auto& k : p.kits) if (k.id == "AdeptN7") adept = &k;
        CHECK(adept && adept->level > 0 && adept->powers.size() >= 4);
        if (adept) printf("     AdeptN7 level=%d promotions=%d xp=%lld powers=%zu first-rank=%d\n",
                          adept->level, adept->promotions, adept->xp, adept->powers.size(), adept->powers.empty()?-1:adept->powers[0].rank);
        // Evolutions: every power's picks = max(0, rank-3), at most one per
        // rank pair, pick order 1/2/3 by pair.
        int powersAll = 0, evoKnown = 0, consistent = 0;
        for (auto& k : p.kits) for (auto& pw : k.powers) {
            ++powersAll;
            if (!pw.evoKnown) continue;
            ++evoKnown;
            int picks = 0; bool ok = true;
            for (int pr = 0; pr < 3; ++pr) {
                int a = pw.evo[2 * pr], b = pw.evo[2 * pr + 1];
                if (a && b) ok = false;
                if (a || b) { ++picks; if ((a ? a : b) != pr + 1) ok = false; }
            }
            if (picks != (pw.rank > 3 ? pw.rank - 3 : 0)) ok = false;
            if (ok) ++consistent;
        }
        printf("     powers=%d with evolutions parsed=%d consistent=%d\n", powersAll, evoKnown, consistent);
        CHECK(evoKnown == powersAll && consistent == powersAll);
        if (adept) {
            printf("     AdeptN7 evolutions:");
            for (auto& pw : adept->powers) printf(" [%s r%d %d%d%d%d%d%d]", pw.name.c_str(), pw.rank, pw.evo[0], pw.evo[1], pw.evo[2], pw.evo[3], pw.evo[4], pw.evo[5]);
            printf("\n");
        }
        // Synthesis: Base (with the verified consumable table) + class records.
        SynthReport r;
        std::string base = BuildBase(p, ConsumableMap(), r);
        std::vector<std::string> classes = BuildClasses(p);
        printf("     base len=%zu (blob %d hex = %d ids); items placed=%d unmapped=%d; kits=%d unmapped=%d; consumables placed=%d unmapped=%d\n",
               base.size(), (kMaxVarId + 1) * 2, kMaxVarId + 1, r.itemsPlaced, r.itemsUnmapped, r.kitsUnlocked, r.kitsUnmapped, r.consumablesPlaced, r.consumablesUnmapped);
        printf("     credits field: %s\n", base.substr(0, base.find(';', base.find(';', base.find(';') + 1) + 1)).c_str());
        CHECK(base.rfind(";", base.size()) != std::string::npos);
        // the blob is exactly (kMaxVarId+1)*2 hex chars
        size_t lastSemi = base.rfind(';');
        CHECK(base.size() - lastSemi - 1 == (size_t)(kMaxVarId + 1) * 2);
        CHECK(r.itemsPlaced > 100 && r.itemsUnmapped == 0);
        CHECK(r.kitsUnlocked == 65 && r.kitsUnmapped == 0);
        CHECK(r.consumablesPlaced == 79 && r.consumablesUnmapped == 0);
        // the profile's Thermal Clip Pack (id 86) is 255 -> "FF" at hex slot 86
        size_t blobAt = base.rfind(';') + 1;
        CHECK(base.substr(blobAt + 86 * 2, 2) == "FF");
        CHECK(ConsumableMap().size() == 79);
        printf("     classes (%zu):\n", classes.size());
        for (auto& c : classes) printf("       %s\n", c.c_str());
        CHECK(classes.size() >= 5);
        // Adept class record carries the profile's level 20 / 18 promotions
        bool adeptClass = false;
        // and its XP (N7 HQ's kit XP is the class record's XP field).
        for (auto& c : classes) if (c.find(";Adept;20;5333080.0000;18") != std::string::npos) adeptClass = true;
        CHECK(adeptClass);
        // The overview's totals: 1200 games, 432H 32M 54S.
        CHECK(p.gamesPlayed == 1200 && p.secondsPlayed == 432LL * 3600 + 32 * 60 + 54);
        // The kit grid: every kit's deployed state is read (46 deployed, 19 mpDisable).
        {
            int dep = 0, notDep = 0, unknown = 0;
            for (const Kit& k : p.kits) (k.deployed == 1 ? dep : k.deployed == 0 ? notDep : unknown)++;
            printf("     deployed %d, not %d, unknown %d\n", dep, notDep, unknown);
            CHECK(dep == 46 && notDep == 19 && unknown == 0);
        }
        CHECK(ParsePlayTime("76H 25M 26S") == 275126 && ParsePlayTime("") == -1 && ParsePlayTime("12") == -1);
        // The whole save, from nothing: every kit gets a record with its powers.
        SaveReport sr;
        MPSaveData d = BuildSave(p, nullptr, sr);
        // No challenges tab given: the challenge strings are left alone.
        CHECK(!sr.challengesSet && d.challenges.empty());
        // The challenges tab: 35 golds (11 complete), 410 silvers, 0 unmapped;
        // the Mass Effect gold's block (25 rows, the golds again) skipped. The
        // points equal the page's own: every gold's and silver's "Challenge
        // points" times its completions, outside that block, is 7965 (summed
        // from the page separately; the converter takes the config's PointValue).
        {
            std::string chal = slurp(dir + "-challenges.html");
            Profile pc = Parse(slurp(dir + "-overview.html"), slurp(dir + "-inventory.html"), slurp(dir + "-characters.html"), chal);
            int goldsDone = 0;
            for (const Challenge& c : pc.challenges) if (c.pos < 0 && c.complete) goldsDone++;
            SaveReport cr;
            MPSaveData dc = BuildSave(pc, nullptr, cr, KitClasses(), 1700000000LL);
            const ChallengeReport& x = cr.challenges;
            printf("     challenges: golds %d (%d done) silvers %d unmapped %d skipped %d completed %d counters %d points %lld\n",
                   x.golds, goldsDone, x.silvers, x.unmapped, x.skipped, x.completed, x.counters, x.points);
            CHECK(cr.challengesSet && dc.challenges.size() == 8 && U8(dc.challenges[0]) == "1");
            CHECK(x.golds == 35 && goldsDone == 11 && x.silvers == 410 && x.unmapped == 0 && x.skipped == 25);
            CHECK(x.points == 7965);
            // every completed row has a time, every other covered row none
            std::vector<long long> comp = CsvNumbers(U8(dc.challenges[1]));
            std::vector<long long> times = CsvNumbers(U8(dc.challenges[5]) + "," + U8(dc.challenges[6]) + "," + U8(dc.challenges[7]));
            int timed = 0, done = 0;
            for (size_t i = 100; i + 2 < comp.size() && i < times.size(); ++i) { if (comp[i + 2] > 0) done++; if (times[i] > 0) timed++; }
            CHECK(done == x.completed && timed == done && comp.size() == 745 + 2 && times.size() == 745);
            // and it survives the save format
            std::string text = mpsave::Serialize(dc);
            MPSaveData back; std::string why;
            CHECK(mpsave::Parse(text, back, why) && back.challenges == dc.challenges);
        }
        {
            std::vector<std::string> bf = SplitSemi(U8(d.base));
            CHECK(bf.size() == 11 && bf[2] == "556" && bf[7] == "1200" && bf[8] == "1557174");
        }
        printf("     save: classes=%d chars new=%d kept=%d powers set=%d default=%d\n",
               sr.classes, sr.charsNew, sr.charsKept, sr.powersSet, sr.powersDefault);
        for (auto& n : sr.notes) printf("       note: %s\n", n.c_str());
        CHECK(sr.powersSet == 65 && sr.powersDefault == 0 && sr.charsNew == 65);
        for (auto& c : d.characters) {
            std::string s(c.begin(), c.end());
            if (s.find(";AdeptN7;") != std::string::npos) printf("     AdeptN7 record: %s\n", s.c_str());
        }
        // round trip through the file format
        std::string text = mpsave::Serialize(d), why;
        MPSaveData back;
        CHECK(mpsave::Parse(text, back, why) && back.characters.size() == d.characters.size() && back.base == d.base);
        if (!r.unmapped.empty()) {
            printf("     first unmapped (%zu total):", r.unmapped.size());
            for (size_t i = 0; i < r.unmapped.size() && i < 8; ++i) printf(" %s", r.unmapped[i].c_str());
            printf("\n");
        }
    }
    printf("%s (%d failure(s))\n", fails ? "FAILED" : "all passed", fails);
    return fails ? 1 : 0;
}
