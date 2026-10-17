// install_check.h: the TOC parser and the report, on made-up folders and,
// given a path, on a real DLC folder (its own TOC must list it exactly).
//
//   g++ -O2 -std=c++17 -o test_install_check test_install_check.cpp && ./test_install_check [<DLC folder>]
//
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include "install_check.h"

using namespace installcheck;
namespace sfs = std::filesystem;

// A TOC in the layout LegendaryExplorerCore writes: one bucket per entry here
// (the bucket count does not matter to the reader), the last entry's size 0.
static std::vector<uint8_t> MakeToc(const std::vector<TocEntry>& es) {
    std::vector<uint8_t> b;
    auto w32 = [&](uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back((uint8_t)(v >> (8 * i))); };
    w32(0x3AB70C13); w32(0); w32((uint32_t)es.size());
    size_t table = b.size();
    b.resize(table + es.size() * 8);
    for (size_t i = 0; i < es.size(); ++i) {
        size_t start = b.size();
        size_t esize = (28 + es[i].path.size() + 1 + 3) & ~(size_t)3;
        bool last = i + 1 == es.size();
        b.push_back(last ? 0 : (uint8_t)esize); b.push_back(last ? 0 : (uint8_t)(esize >> 8));
        b.push_back(0); b.push_back(0);
        w32((uint32_t)es[i].size);
        b.insert(b.end(), 20, 0);
        b.insert(b.end(), es[i].path.begin(), es[i].path.end());
        b.resize(start + esize);
        int32_t off = (int32_t)(start - (table + i * 8));
        for (int k = 0; k < 4; ++k) b[table + i * 8 + k] = (uint8_t)(off >> (8 * k));
        for (int k = 0; k < 4; ++k) b[table + i * 8 + 4 + k] = (uint8_t)(1 >> (8 * k));
    }
    return b;
}

struct FakeDir {
    bool exists = true;
    bool hasToc = true;
    std::map<std::string, int64_t> files;   // relative, '\'
    std::vector<TocEntry> toc;
    Fs fs() {
        Fs f;
        f.isDir = [this](const std::string& d) { return d.empty() && exists; };
        f.size = [this](const std::string& p) {
            auto it = files.find(p);
            return it == files.end() ? (int64_t)-1 : it->second;
        };
        f.listCooked = [this] {
            std::vector<std::string> v;
            for (auto& kv : files)
                if (kv.first.rfind("CookedPCConsole\\", 0) == 0 && kv.first.find('\\', 16) == std::string::npos)
                    v.push_back(kv.first.substr(16));
            return v;
        };
        f.readToc = [this](std::vector<uint8_t>& out) {
            if (!hasToc) return false;
            out = MakeToc(toc);
            return true;
        };
        return f;
    }
};

static FakeDir Good() {
    FakeDir d;
    d.toc = {{"CookedPCConsole\\Mount.dlc", 108}, {"CookedPCConsole\\Default_DLC_MOD_LEMultiplayer.bin", 1134248},
             {"CookedPCConsole\\BioP_MPMoon.pcc", 3009982}};
    for (auto& e : d.toc) d.files[e.path] = e.size;
    return d;
}

int main(int argc, char** argv) {
    int fails = 0;
    auto check = [&](const char* what, bool ok) { printf("%-60s %s\n", what, ok ? "ok" : "FAIL"); fails += !ok; };

    {   // an AutoTOC at launch lists the TOC with its size from before the rewrite
        FakeDir d = Good();
        d.toc.push_back({"PCConsoleTOC.bin", 72868});
        d.files["PCConsoleTOC.bin"] = 72916;
        Report r = Check(d.fs());
        check("TOC's own entry with a stale size: Ok", r.Ok());
        check("TOC's own entry: no administrator line", Message(r, "X").find("administrator") == std::string::npos);
    }

    {
        FakeDir d = Good();
        std::vector<TocEntry> es;
        auto b = MakeToc(d.toc);
        check("parse: three entries back", ParseToc(b.data(), b.size(), es) && es.size() == 3 &&
                                             es[2].path == "CookedPCConsole\\BioP_MPMoon.pcc" && es[2].size == 3009982);
        check("parse: truncated TOC refused", !ParseToc(b.data(), b.size() - 20, es));
        b[0] ^= 1;
        check("parse: bad magic refused", !ParseToc(b.data(), b.size(), es));
    }
    {
        FakeDir d = Good();
        Report r = Check(d.fs());
        check("clean folder: Ok, no message", r.Ok() && r.listed == 3 && Message(r, "X").empty());
    }
    {
        FakeDir d = Good();
        d.files.erase("CookedPCConsole\\Default_DLC_MOD_LEMultiplayer.bin");
        Report r = Check(d.fs());
        std::string m = Message(r, "X");
        check("missing file: named", r.missing.size() == 1 && m.find("1 file is missing") != std::string::npos &&
                                         m.find("Default_DLC_MOD_LEMultiplayer.bin") != std::string::npos &&
                                         m.find("corrupt") != std::string::npos);
    }
    {
        FakeDir d = Good();
        d.files["CookedPCConsole\\BioP_MPMoon.pcc"] = 3000000;
        d.files["CookedPCConsole\\Old_Removed.pcc"] = 5;
        Report r = Check(d.fs());
        check("mixed versions: different size and not listed", r.wrongSize.size() == 1 && r.extra.size() == 1 &&
                                                                 r.missing.empty());
    }
    {
        FakeDir d = Good();
        d.files["CookedPCConsole\\Old_Removed.pcc"] = 5;
        std::string m = Message(Check(d.fs()), "X");
        check("leftovers only: the build-key wording", m.find("change your build") != std::string::npos &&
                                                          m.find("corrupt") == std::string::npos);
    }
    {
        FakeDir d = Good();
        d.files["CookedPCConsole\\MOUNT.DLC"] = d.files["CookedPCConsole\\Mount.dlc"];
        d.files.erase("CookedPCConsole\\Mount.dlc");
        Report r = Check(d.fs());
        check("listing compared without case", r.extra.empty() && r.missing.size() == 1);
    }
    {
        FakeDir d = Good();
        std::map<std::string, int64_t> moved;
        for (auto& kv : d.files) moved["DLC_MOD_LEMultiplayer\\" + kv.first] = kv.second;
        d.files = moved;
        d.hasToc = false;
        Report r = Check(d.fs());
        std::string m = Message(r, "X");
        check("nested copy: found, says one folder too deep", r.nestedAt == "DLC_MOD_LEMultiplayer" &&
                                                                m.find("one folder too deep") != std::string::npos);
    }
    {
        FakeDir d = Good();
        std::map<std::string, int64_t> moved;
        for (auto& kv : d.files) moved["BioGame\\DLC\\DLC_MOD_LEMultiplayer\\" + kv.first] = kv.second;
        d.files = moved;
        check("zip's BioGame dropped in: found", Check(d.fs()).nestedAt == "BioGame\\DLC\\DLC_MOD_LEMultiplayer");
    }
    {
        FakeDir d = Good();
        d.hasToc = false;
        Report r = Check(d.fs());
        check("no TOC: said", r.noToc && Message(r, "X").find("PCConsoleTOC.bin, the list") != std::string::npos);
    }
    {
        FakeDir d;
        d.exists = false;
        Report r = Check(d.fs());
        check("no folder: nothing shown", r.noFolder && Message(r, "X").empty());
    }

    if (argc > 1) {
        // A real folder: the release's own TOC must list it exactly. Also
        // shows the check can see a presence: the same folder with one
        // file's size changed in the TOC must report it.
        sfs::path dir = argv[1];
        auto rel = [&](const std::string& p) {
            std::string s = p;
            for (char& c : s) if (c == '\\') c = '/';
            return dir / s;
        };
        Fs f;
        f.isDir = [&](const std::string& d) { return sfs::is_directory(d.empty() ? dir : rel(d)); };
        f.size = [&](const std::string& p) {
            std::error_code ec;
            auto n = sfs::file_size(rel(p), ec);
            return ec ? (int64_t)-1 : (int64_t)n;
        };
        f.listCooked = [&] {
            std::vector<std::string> v;
            for (auto& e : sfs::directory_iterator(dir / "CookedPCConsole"))
                if (e.is_regular_file()) v.push_back(e.path().filename().string());
            return v;
        };
        f.readToc = [&](std::vector<uint8_t>& out) {
            std::ifstream in(dir / "PCConsoleTOC.bin", std::ios::binary);
            if (!in) return false;
            out.assign(std::istreambuf_iterator<char>(in), {});
            return true;
        };
        Report r = Check(f);
        printf("real folder: %s\n", Summary(r).c_str());
        check("real folder: Ok", r.Ok());
        Fs g = f;
        std::string victim;
        g.size = [&](const std::string& p) {
            int64_t n = f.size(p);
            if (victim.empty() && n > 0) victim = p;
            return p == victim ? n + 1 : n;
        };
        Report r2 = Check(g);
        check("real folder, one size changed: reported", r2.wrongSize.size() == 1 && r2.wrongSize[0] == victim);
    }
    printf("%s\n", fails ? "FAILED" : "all ok");
    return fails != 0;
}
