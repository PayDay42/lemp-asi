// install_check.h - does the DLC folder hold what its PCConsoleTOC.bin lists?
//
// LE3 shows "The following downloadable content is corrupt and cannot be
// used" (string 333458) for a DLC folder whose CookedPCConsole\Mount.dlc
// does not open or parse, or whose Default_<DLC>.bin the file manager cannot
// find by name or open (MassEffect3.exe +0xafd410 and +0xafd280; both stamp
// 333458). The dialog says no more than that. A copy by hand can leave the
// folder short of files (a skipped "administrator permission" prompt under
// Program Files, a copy stopped part way), one level too deep, or mixed with
// an older version's files. The TOC the release ships lists every file and
// its size, so comparing the folder against it names the problem.
//
// Portable: the caller supplies the file system (sizes, the CookedPCConsole
// listing), so the logic is tested natively (test_install_check.cpp).
#pragma once
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace installcheck {

struct TocEntry {
    std::string path;   // as the TOC spells it: "CookedPCConsole\Mount.dlc"
    int64_t size;
};

// The LE TOC: magic 0x3AB70C13, a media count, a hash-bucket count, then one
// (offset from the bucket's own position, entry count) pair per bucket; each
// entry is int16 entry size, int16 flags, int32 file size, 20 bytes of SHA-1,
// the name null-terminated. LegendaryExplorerCore's TOCBinFile reads it the
// same way. False on anything out of bounds.
inline bool ParseToc(const uint8_t* b, size_t n, std::vector<TocEntry>& out) {
    out.clear();
    auto u32 = [&](size_t at, uint32_t& v) {
        if (at + 4 > n) return false;
        v = (uint32_t)b[at] | (uint32_t)b[at + 1] << 8 | (uint32_t)b[at + 2] << 16 | (uint32_t)b[at + 3] << 24;
        return true;
    };
    uint32_t magic, media, buckets;
    if (!u32(0, magic) || magic != 0x3AB70C13u || !u32(4, media) || !u32(8, buckets)) return false;
    if (buckets > (n - 12) / 8) return false;
    for (uint32_t i = 0; i < buckets; ++i) {
        size_t pos = 12 + (size_t)i * 8;
        uint32_t off, count;
        if (!u32(pos, off) || !u32(pos + 4, count)) return false;
        size_t p = pos + (size_t)(int32_t)off;
        for (uint32_t j = 0; j < count; ++j) {
            if (p + 28 >= n) return false;
            int16_t esize = (int16_t)(b[p] | b[p + 1] << 8);
            uint32_t fsize = 0;
            u32(p + 4, fsize);
            const char* name = (const char*)b + p + 28;
            size_t len = strnlen(name, n - (p + 28));
            if (p + 28 + len >= n) return false;
            out.push_back({std::string(name, len), (int64_t)(int32_t)fsize});
            if (j + 1 < count) {   // the last entry of the file writes 0 here
                if (esize <= 28) return false;
                p += (size_t)esize;
            }
        }
    }
    return !out.empty();
}

inline std::string Lower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

struct Report {
    bool noFolder = false;     // no DLC folder at all
    bool noToc = false;        // PCConsoleTOC.bin missing or unreadable
    std::string nestedAt;      // a complete-looking copy one level down, relative to the DLC folder
    size_t listed = 0;         // TOC entries
    std::vector<std::string> missing, wrongSize, extra;
    bool Ok() const { return !noFolder && !noToc && nestedAt.empty() && missing.empty() && wrongSize.empty() && extra.empty(); }
};

struct Fs {
    // The size of a file relative to the DLC folder ('\' separators), -1 if absent.
    std::function<int64_t(const std::string&)> size;
    // The files (not folders) directly in the DLC folder's CookedPCConsole.
    std::function<std::vector<std::string>()> listCooked;
    // Whether a directory relative to the DLC folder exists ("" = the folder itself).
    std::function<bool(const std::string&)> isDir;
    // The TOC's bytes; false if it cannot be read.
    std::function<bool(std::vector<uint8_t>&)> readToc;
};

// The two places a copy by hand puts the folder one level too deep: the
// DLC folder dropped into itself, and the zip's BioGame dropped into it.
static const char* const kNested[] = {"DLC_MOD_LEMultiplayer", "BioGame\\DLC\\DLC_MOD_LEMultiplayer"};

inline Report Check(const Fs& fs) {
    Report r;
    if (!fs.isDir("")) { r.noFolder = true; return r; }
    if (fs.size("CookedPCConsole\\Mount.dlc") < 0)
        for (const char* n : kNested)
            if (fs.size(std::string(n) + "\\CookedPCConsole\\Mount.dlc") >= 0) { r.nestedAt = n; break; }
    std::vector<uint8_t> toc;
    std::vector<TocEntry> entries;
    if (!fs.readToc(toc) || !ParseToc(toc.data(), toc.size(), entries)) { r.noToc = true; return r; }
    r.listed = entries.size();
    std::vector<std::string> known;
    for (const TocEntry& e : entries) {
        known.push_back(Lower(e.path));
        // The TOC's entry for itself cannot be trusted: a tool that rewrites
        // the TOC (an AutoTOC at launch) records the file's size from before
        // its own write. The game does not need it either.
        if (Lower(e.path) == "pcconsoletoc.bin") continue;
        int64_t have = fs.size(e.path);
        if (have < 0) r.missing.push_back(e.path);
        else if (have != e.size) r.wrongSize.push_back(e.path);
    }
    for (const std::string& f : fs.listCooked()) {
        std::string rel = "CookedPCConsole\\" + f;
        bool found = false;
        for (const std::string& k : known) if (k == Lower(rel)) { found = true; break; }
        if (!found) r.extra.push_back(rel);
    }
    return r;
}

// One line for the log.
inline std::string Summary(const Report& r) {
    if (r.noFolder) return "no DLC folder";
    std::string s = r.noToc ? "PCConsoleTOC.bin missing or unreadable" : std::to_string(r.listed) + " listed";
    if (!r.nestedAt.empty()) s += ", a copy one level down in " + r.nestedAt;
    if (!r.noToc)
        s += ", " + std::to_string(r.missing.size()) + " missing, " + std::to_string(r.wrongSize.size()) +
             " different size, " + std::to_string(r.extra.size()) + " not listed";
    auto first = [&](const char* what, const std::vector<std::string>& v) {
        if (!v.empty()) s += std::string("; first ") + what + ": " + v[0];
    };
    first("missing", r.missing);
    first("different", r.wrongSize);
    first("not listed", r.extra);
    return s;
}

// What the player is shown. Empty when there is nothing to say: no folder
// (LEMP is not installed, or was taken out and the ASI left) or all well.
inline std::string Message(const Report& r, const std::string& dlcDir) {
    if (r.Ok() || r.noFolder) return "";
    std::string m = "LEMP's files are not complete in\n" + dlcDir + "\n\n";
    if (!r.nestedAt.empty())
        m += "They are one folder too deep, in " + r.nestedAt +
             ". Move the folders inside it (CookedPCConsole and the files next to it) up into "
             "DLC_MOD_LEMultiplayer, or delete DLC_MOD_LEMultiplayer and copy it again.\n\n";
    else if (r.noToc)
        m += "PCConsoleTOC.bin, the list of LEMP's files, is missing or damaged.\n\n";
    auto list = [&](const std::vector<std::string>& v, const char* one, const char* many) {
        if (v.empty()) return;
        m += std::to_string(v.size()) + (v.size() == 1 ? one : many) + "\n";
        for (size_t i = 0; i < v.size() && i < 3; ++i) m += "    " + v[i] + "\n";
        if (v.size() > 3) m += "    ...\n";
        m += "\n";
    };
    if (r.nestedAt.empty()) {
        list(r.missing, " file is missing:", " files are missing:");
        list(r.wrongSize, " file has a different size (from another LEMP version?):",
             " files have a different size (from another LEMP version?):");
        list(r.extra, " file is not part of this version:", " files are not part of this version:");
    }
    if (!r.missing.empty() || !r.wrongSize.empty() || r.noToc || !r.nestedAt.empty())
        m += "The game may report the folder as corrupt, and LEMP won't work as it should.\n\n";
    else
        m += "Left over from an older version, they change your build, and you can't join players "
             "with a clean install.\n\n";
    m += "To fix it: close the game, delete the DLC_MOD_LEMultiplayer folder, and copy it again from "
         "the zip (or apply LEMP again in ME3Tweaks Mod Manager).";
    return m;
}

}  // namespace installcheck
