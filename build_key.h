// build_key.h - the LEMP build key: which DLC build this install holds.
//
// NOT 2012's mechanism. 2012 kept mismatched peers apart through Blaze's
// GameProtocolVersion; a direct-address
// join has no Blaze, and join_patch.asi switches off UE3's own package-GUID
// check (LE3 builds some packages in memory with a new GUID per process). So
// the client sends this key in its join URL (?LEMPBuild=) and the host's
// SFXGameInfoMP.PreLogin refuses a different one. The exe version, the ASIs,
// LE3's script packages and other mods travel beside it (LEMPGame, LEMPAsi,
// LEMPBase, LEMPMods: see JoinOptions below).
//
// The key: SHA-256 over one line per file under the DLC's CookedPCConsole,
//     <path relative to the DLC folder, lower case, '/'> \t <size> \t <sha256 of content> \n
// sorted by path, byte order. PCConsoleTOC.bin and _metacmm.txt are outside
// CookedPCConsole on purpose: the TOC is derived (and AutoTOC may rewrite it at
// launch), _metacmm.txt is mod-manager metadata. The short key, what players
// see and the URL carries, is the first 12 hex digits.
// The release tooling computes the same key in Python; test_build_key.cpp
// checks the two agree.
//
// Hashing 1.6 GB takes seconds, so per-file results are cached by
// (path, size, mtime) in a file of the caller's choosing (HashCache).
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace buildkey {

// FIPS 180-4 SHA-256.
struct Sha256 {
    uint32_t h[8];
    uint64_t len = 0;
    uint8_t buf[64];
    size_t fill = 0;

    Sha256() {
        static const uint32_t init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
        memcpy(h, init, sizeof h);
    }
    static uint32_t R(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    void Block(const uint8_t* p) {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = R(w[i - 15], 7) ^ R(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = R(w[i - 2], 17) ^ R(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = hh + (R(e, 6) ^ R(e, 11) ^ R(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
            uint32_t t2 = (R(a, 2) ^ R(a, 13) ^ R(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    void Update(const void* data, size_t n) {
        const uint8_t* p = (const uint8_t*)data;
        len += n;
        if (fill) {
            size_t take = std::min(n, 64 - fill);
            memcpy(buf + fill, p, take);
            fill += take; p += take; n -= take;
            if (fill < 64) return;
            Block(buf);
            fill = 0;
        }
        for (; n >= 64; p += 64, n -= 64) Block(p);
        memcpy(buf, p, n);
        fill = n;
    }
    std::string HexDigest() {
        uint64_t bits = len * 8;
        uint8_t pad = 0x80;
        Update(&pad, 1);
        uint8_t zero = 0;
        while (fill != 56) Update(&zero, 1);
        uint8_t l[8];
        for (int i = 0; i < 8; ++i) l[i] = (uint8_t)(bits >> (56 - 8 * i));
        Update(l, 8);
        static const char* hx = "0123456789abcdef";
        std::string out;
        for (uint32_t v : h)
            for (int s = 28; s >= 0; s -= 4) out += hx[(v >> s) & 15];
        return out;
    }
};

inline std::string Sha256Hex(const std::string& s) { Sha256 c; c.Update(s.data(), s.size()); return c.HexDigest(); }

struct Entry {
    std::string rel;    // lower case, '/', relative to the DLC folder
    uint64_t size = 0;
    std::string sha;    // hex
};

// The full key (64 hex digits) from the per-file entries.
inline std::string KeyFromEntries(std::vector<Entry> e) {
    std::sort(e.begin(), e.end(), [](const Entry& a, const Entry& b) { return a.rel < b.rel; });
    Sha256 c;
    for (const Entry& x : e) {
        std::string line = x.rel + "\t" + std::to_string((unsigned long long)x.size) + "\t" + x.sha + "\n";
        c.Update(line.data(), line.size());
    }
    return c.HexDigest();
}

inline std::string ShortKey(const std::string& full) { return full.substr(0, 12); }

// What else a peer must match, besides the DLC: other mods and game files.
// Each is its own join option, so the host can say
// which one differs:
//   LEMPGame  the exe's file version (VS_FIXEDFILEINFO, e.g. 2.0.0.48602).
//             Not a hash: the installed exe is already patched and differs
//             from MassEffect3_ORIG.exe while both are 2.0.0.48602 [V].
//   LEMPAsi   lemp.asi, which changes what the game does: join_patch and
//             online_api patch game code, mp_save and mp_menu serve the save,
//             the name and this key. One file (lemp.h), so its
//             diagnostics (repl_probe, crash_log, loadmap_hook) and
//             nofocuspause count too; up to 0.1.5 they were separate ASIs and
//             left out. AutoTOC is left out (third-party, rewrites the TOC only).
//   LEMPBase  LE3's script packages and Coalesced.bin. Our classes extend
//             SFXGame's and replication names objects by (package, NetIndex),
//             so a mod that edits SFXGame.pcc (a community patch) can desync
//             or crash a match. Left out: Startup.pcc and the official DLC
//             (assets, and what texture mods rewrite; not measured which of
//             their objects replication resolves).
//   LEMPMods  every other mounted DLC_MOD_* folder (one with
//             CookedPCConsole\Mount.dlc), names sorted, ',' between; "none".
//             Strict for now: no allow-list yet, and names only, not versions.
// Both hashes are the first 8 hex digits of SHA-256 over sorted lines
//     <path relative to Game\ME3, lower case, '/'> \t <size> \t <sha256> \n
// or <path> \t missing \n. All five go in one string, the value of ops 13/14:
//     LEMPBuild=<12>?LEMPGame=<ver>?LEMPAsi=<8>?LEMPBase=<8>?LEMPMods=<list>
// The release tooling's Python twin prints the same string.
inline const char* const kPlayAsis[] = {
    "binaries/win64/asi/lemp.asi",
};
inline const char* const kBaseFiles[] = {
    "biogame/cookedpcconsole/coalesced.bin",      "biogame/cookedpcconsole/core.pcc",
    "biogame/cookedpcconsole/engine.pcc",         "biogame/cookedpcconsole/gameframework.pcc",
    "biogame/cookedpcconsole/gfxui.pcc",          "biogame/cookedpcconsole/ipdrv.pcc",
    "biogame/cookedpcconsole/sfxautobots.pcc",    "biogame/cookedpcconsole/sfxgame.pcc",
    "biogame/cookedpcconsole/sfxgameeffects.pcc", "biogame/cookedpcconsole/sfxonlinefoundation.pcc",
    "biogame/cookedpcconsole/wwiseaudio.pcc",
};

// The hash of a list of files; a missing one (null) is a line of its own.
inline std::string ListHash(std::vector<std::pair<std::string, const Entry*>> files) {
    std::sort(files.begin(), files.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    Sha256 c;
    for (auto& f : files) {
        std::string line = f.second ? f.first + "\t" + std::to_string((unsigned long long)f.second->size) + "\t" +
                                          f.second->sha + "\n"
                                    : f.first + "\tmissing\n";
        c.Update(line.data(), line.size());
    }
    return c.HexDigest().substr(0, 8);
}

// "a.b.c.d" from a VS_VERSIONINFO block (or a whole exe file): the
// VS_FIXEDFILEINFO (signature FEEF04BD) after the first "VS_VERSION_INFO"
// key. "" if none.
inline std::string VersionFromBlock(const uint8_t* p, size_t n) {
    static const char key[] = "VS_VERSION_INFO";
    for (size_t i = 0; i + 30 + 16 + 16 <= n; ++i) {
        bool hit = true;
        for (size_t k = 0; k < 15 && hit; ++k) hit = p[i + 2 * k] == (uint8_t)key[k] && p[i + 2 * k + 1] == 0;
        if (!hit) continue;
        for (size_t j = i + 30; j < i + 30 + 16 && j + 16 <= n; ++j) {
            if (p[j] != 0xbd || p[j + 1] != 0x04 || p[j + 2] != 0xef || p[j + 3] != 0xfe) continue;
            auto u32 = [&](size_t o) {
                return (uint32_t)p[o] | (uint32_t)p[o + 1] << 8 | (uint32_t)p[o + 2] << 16 | (uint32_t)p[o + 3] << 24;
            };
            uint32_t ms = u32(j + 8), ls = u32(j + 12);
            return std::to_string(ms >> 16) + "." + std::to_string(ms & 0xffff) + "." + std::to_string(ls >> 16) +
                   "." + std::to_string(ls & 0xffff);
        }
        return "";
    }
    return "";
}

inline std::string JoinOptions(const std::string& shortKey, const std::string& game, const std::string& asi,
                               const std::string& base, const std::string& mods) {
    return "LEMPBuild=" + shortKey + "?LEMPGame=" + (game.empty() ? "unknown" : game) + "?LEMPAsi=" + asi +
           "?LEMPBase=" + base + "?LEMPMods=" + (mods.empty() ? "none" : mods);
}

#ifdef _WIN32
inline std::string Utf8Lower(const std::wstring& w) {
    std::string s;
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    s.resize(n);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    for (char& ch : s) if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
    return s;
}

// Per-file SHA-256, cached by (path, size, mtime) in one file. Save rewrites
// it with exactly the files looked up since Load, when any was hashed.
struct HashCache {
    struct Cached { uint64_t size, mtime; std::string sha; };
    std::vector<std::pair<std::string, Cached>> old, fresh;   // small: a linear scan is fine
    std::wstring path;
    int hashed = 0, cached = 0;
    std::vector<uint8_t> buf = std::vector<uint8_t>(1 << 20);

    void Load(const std::wstring& p) {
        path = p;
        if (FILE* f = _wfopen(p.c_str(), L"rb")) {
            char line[1024];
            while (fgets(line, sizeof line, f)) {
                char rel[768], sha[80];
                unsigned long long size, mtime;
                if (sscanf(line, "%767[^\t]\t%llu\t%llu\t%79s", rel, &size, &mtime, sha) == 4)
                    old.push_back({rel, {size, mtime, sha}});
            }
            fclose(f);
        }
    }
    // Fills e.size and e.sha for the file at full (e.rel is the cache key).
    // false, with why set, when it cannot be read.
    bool Hash(const std::wstring& full, Entry& e, std::string& why) {
        WIN32_FILE_ATTRIBUTE_DATA a;
        if (!GetFileAttributesExW(full.c_str(), GetFileExInfoStandard, &a)) { why = "cannot stat " + e.rel; return false; }
        e.size = (uint64_t)a.nFileSizeHigh << 32 | a.nFileSizeLow;
        uint64_t mtime = (uint64_t)a.ftLastWriteTime.dwHighDateTime << 32 | a.ftLastWriteTime.dwLowDateTime;
        const std::string* hit = nullptr;
        for (auto& c : old)
            if (c.first == e.rel && c.second.size == e.size && c.second.mtime == mtime) { hit = &c.second.sha; break; }
        if (hit) {
            e.sha = *hit;
            ++cached;
        } else {
            HANDLE h = CreateFileW(full.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                   FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (h == INVALID_HANDLE_VALUE) { why = "cannot open " + e.rel; return false; }
            Sha256 c;
            DWORD got = 0;
            uint64_t total = 0;
            while (ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr) && got > 0) { c.Update(buf.data(), got); total += got; }
            CloseHandle(h);
            if (total != e.size) { why = "short read of " + e.rel; return false; }
            e.sha = c.HexDigest();
            ++hashed;
        }
        fresh.push_back({e.rel, {e.size, mtime, e.sha}});
        return true;
    }
    void Save() {
        if (!hashed) return;
        std::wstring tmp = path + L".tmp";
        if (FILE* f = _wfopen(tmp.c_str(), L"wb")) {
            for (auto& x : fresh)
                fprintf(f, "%s\t%llu\t%llu\t%s\n", x.first.c_str(), (unsigned long long)x.second.size,
                        (unsigned long long)x.second.mtime, x.second.sha.c_str());
            fclose(f);
            MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING);
        }
    }
};

// Every file under <dlcDir>\CookedPCConsole, hashed or taken from the cache.
// Returns the full key, or "" with why set.
inline std::string ComputeKey(const std::wstring& dlcDir, HashCache& cache, std::string& why) {
    std::vector<Entry> entries;
    std::vector<std::wstring> dirs = {L"CookedPCConsole"};
    while (!dirs.empty()) {
        std::wstring sub = dirs.back();
        dirs.pop_back();
        WIN32_FIND_DATAW fd;
        HANDLE fh = FindFirstFileW((dlcDir + L"\\" + sub + L"\\*").c_str(), &fd);
        if (fh == INVALID_HANDLE_VALUE) {
            if (sub == L"CookedPCConsole") { why = "no CookedPCConsole folder"; return ""; }
            continue;
        }
        do {
            std::wstring name = fd.cFileName;
            if (name == L"." || name == L"..") continue;
            std::wstring relw = sub + L"\\" + name;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { dirs.push_back(relw); continue; }
            Entry e;
            e.rel = Utf8Lower(relw);
            std::replace(e.rel.begin(), e.rel.end(), '\\', '/');
            if (!cache.Hash(dlcDir + L"\\" + relw, e, why)) { FindClose(fh); return ""; }
            entries.push_back(e);
        } while (FindNextFileW(fh, &fd));
        FindClose(fh);
    }
    if (entries.empty()) { why = "CookedPCConsole is empty"; return ""; }
    return KeyFromEntries(entries);
}

// ListHash over files named relative to gameDir (Game\ME3). The cache keys
// are these names, which cannot collide with the DLC's ("cookedpcconsole/...").
inline std::string HashFileList(const std::wstring& gameDir, const char* const* rels, size_t n, HashCache& cache) {
    std::vector<Entry> got(n);
    std::vector<std::pair<std::string, const Entry*>> files;
    for (size_t i = 0; i < n; ++i) {
        std::wstring w(rels[i], rels[i] + strlen(rels[i]));
        std::replace(w.begin(), w.end(), L'/', L'\\');
        got[i].rel = rels[i];
        std::string why;
        files.push_back({rels[i], cache.Hash(gameDir + L"\\" + w, got[i], why) ? &got[i] : nullptr});
    }
    return ListHash(files);
}

// The running exe's file version, from its own version resource.
inline std::string RunningExeVersion() {
    HRSRC r = FindResourceW(nullptr, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(16));   // VS_VERSION_INFO, RT_VERSION
    if (!r) return "";
    HGLOBAL g = LoadResource(nullptr, r);
    const void* p = g ? LockResource(g) : nullptr;
    return p ? VersionFromBlock((const uint8_t*)p, SizeofResource(nullptr, r)) : "";
}

// Every other mounted DLC_MOD_* folder under <gameDir>\BioGame\DLC, sorted
// case-blind, ',' between. LE3 mounts a folder by its exact "DLC_" prefix.
inline std::string OtherMods(const std::wstring& gameDir, const std::wstring& ours) {
    std::vector<std::string> names;
    WIN32_FIND_DATAW fd;
    std::wstring dlc = gameDir + L"\\BioGame\\DLC\\";
    HANDLE fh = FindFirstFileW((dlc + L"DLC_MOD_*").c_str(), &fd);
    if (fh == INVALID_HANDLE_VALUE) return "";
    do {
        std::wstring name = fd.cFileName;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || name.compare(0, 8, L"DLC_MOD_") != 0 ||
            _wcsicmp(name.c_str(), ours.c_str()) == 0)
            continue;
        if (GetFileAttributesW((dlc + name + L"\\CookedPCConsole\\Mount.dlc").c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        std::string s;
        for (wchar_t ch : name) s += (ch > 32 && ch < 127 && ch != '?' && ch != ',') ? (char)ch : '_';
        names.push_back(s);
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
    std::sort(names.begin(), names.end(), [](const std::string& a, const std::string& b) {
        return _stricmp(a.c_str(), b.c_str()) < 0;
    });
    std::string out;
    for (auto& n : names) out += (out.empty() ? "" : ",") + n;
    return out;
}
#endif

}  // namespace buildkey
