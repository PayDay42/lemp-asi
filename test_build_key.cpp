// build_key.h: SHA-256 against FIPS vectors, and (Windows build) the key of a
// real DLC folder, cold and from the cache, to compare with the Python twin.
//
//   g++ -O2 -std=c++17 -o test_build_key test_build_key.cpp && ./test_build_key
//   x86_64-w64-mingw32-g++ -O2 -std=c++17 -static -municode -o test_build_key.exe test_build_key.cpp
//   WINEPREFIX=<scratch> "<Proton>/files/bin/wine" test_build_key.exe 'Z:\...\DLC_MOD_LEMultiplayer' <cache> ['Z:\...\Game\ME3']
//   (the Python twin, run on the same folder, must print the same key and options)
//
#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdio>
#include "build_key.h"

int wmain_or_main(int argc, wchar_t** wargv) {
    int fails = 0;
    auto check = [&](const char* what, bool ok) { printf("%-50s %s\n", what, ok ? "ok" : "FAIL"); fails += !ok; };
    using buildkey::Sha256Hex;
    check("sha256(\"\")", Sha256Hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check("sha256(\"abc\")", Sha256Hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check("sha256(448-bit message)",
          Sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    {
        buildkey::Sha256 c;
        std::string a(1000, 'a');
        for (int i = 0; i < 1000; ++i) c.Update(a.data(), a.size());
        check("sha256(10^6 x 'a'), fed in pieces",
              c.HexDigest() == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }
    // Order-independent input, sorted inside: same key either way.
    std::vector<buildkey::Entry> e = {{"cookedpcconsole/b.pcc", 2, "bb"}, {"cookedpcconsole/a.pcc", 1, "aa"}};
    std::vector<buildkey::Entry> r(e.rbegin(), e.rend());
    check("key independent of input order", buildkey::KeyFromEntries(e) == buildkey::KeyFromEntries(r));
    check("key = sha256 of the sorted lines",
          buildkey::KeyFromEntries(e) == Sha256Hex("cookedpcconsole/a.pcc\t1\taa\ncookedpcconsole/b.pcc\t2\tbb\n"));
    // The companion hashes: missing files are lines of their own, order-free.
    buildkey::Entry a{"x/a.asi", 3, "cc"};
    check("list hash: sorted lines, missing marked",
          buildkey::ListHash({{"x/b.asi", nullptr}, {"x/a.asi", &a}}) ==
              Sha256Hex("x/a.asi\t3\tcc\nx/b.asi\tmissing\n").substr(0, 8));
    {
        // A VS_VERSIONINFO header: lengths, "VS_VERSION_INFO\0" (UTF-16), pad, FEEF04BD ...
        std::vector<uint8_t> v(6, 0);
        for (const char* k = "VS_VERSION_INFO";; ++k) { v.push_back((uint8_t)*k); v.push_back(0); if (!*k) break; }
        while (v.size() % 4) v.push_back(0);
        uint32_t ffi[4] = {0xfeef04bd, 0x00010000, 2u << 16, 48602};
        for (uint32_t x : ffi)
            for (int i = 0; i < 4; ++i) v.push_back((uint8_t)(x >> (8 * i)));
        v.resize(v.size() + 64, 0);
        check("version from a VS_VERSIONINFO block", buildkey::VersionFromBlock(v.data(), v.size()) == "2.0.0.48602");
    }
    check("join options, none/unknown",
          buildkey::JoinOptions("abc", "", "11", "22", "") ==
              "LEMPBuild=abc?LEMPGame=unknown?LEMPAsi=11?LEMPBase=22?LEMPMods=none");
#ifdef _WIN32
    // argv: <DLC folder> <cache> [<Game\ME3 folder>: also the join options,
    // the exe version read from MassEffect3.exe's file as lemp_buildkey.py does]
    if (argc >= 3) {
        for (int pass = 1; pass <= 2; ++pass) {
            std::string why;
            DWORD t = GetTickCount();
            buildkey::HashCache cache;
            cache.Load(wargv[2]);
            std::string key = buildkey::ComputeKey(wargv[1], cache, why);
            std::string opts;
            if (argc >= 4 && !key.empty()) {
                std::wstring game = wargv[3];
                std::string ver;
                if (FILE* f = _wfopen((game + L"\\Binaries\\Win64\\MassEffect3.exe").c_str(), L"rb")) {
                    std::vector<uint8_t> exe;
                    static uint8_t b[1 << 16];
                    size_t n;
                    while ((n = fread(b, 1, sizeof b, f)) > 0) exe.insert(exe.end(), b, b + n);
                    fclose(f);
                    ver = buildkey::VersionFromBlock(exe.data(), exe.size());
                }
                opts = buildkey::JoinOptions(
                    buildkey::ShortKey(key), ver,
                    buildkey::HashFileList(game, buildkey::kPlayAsis, sizeof buildkey::kPlayAsis / sizeof *buildkey::kPlayAsis, cache),
                    buildkey::HashFileList(game, buildkey::kBaseFiles, sizeof buildkey::kBaseFiles / sizeof *buildkey::kBaseFiles, cache),
                    buildkey::OtherMods(game, L"DLC_MOD_LEMultiplayer"));
            }
            cache.Save();
            printf("pass %d: key %s  hashed %d cached %d  %lu ms  %s\n", pass, key.c_str(), cache.hashed, cache.cached,
                   (unsigned long)(GetTickCount() - t), why.c_str());
            if (!opts.empty()) printf("pass %d: options %s\n", pass, opts.c_str());
            check(pass == 1 ? "real folder: a key" : "real folder: second pass all from cache",
                  !key.empty() && (pass == 1 || cache.hashed == 0));
        }
    }
#endif
    printf(fails ? "%d FAILED\n" : "all ok\n", fails);
    return fails != 0;
}

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) { return wmain_or_main(argc, argv); }
#else
int main() { return wmain_or_main(0, nullptr); }
#endif
