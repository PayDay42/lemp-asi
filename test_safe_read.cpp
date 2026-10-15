// safe_read.h against kernel32's IsBadReadPtr on a PAGE_GUARD page.
//
//   x86_64-w64-mingw32-g++ -O2 -std=c++17 -static -o test_safe_read.exe test_safe_read.cpp
//   WINEPREFIX=<scratch> "<Proton>/files/bin/wine" test_safe_read.exe       # all checks
//   WINEPREFIX=<scratch> "<Proton>/files/bin/wine" test_safe_read.exe k32   # then kernel32's
//
// The `k32` run ends the process under Proton Experimental:
// "Unhandled exception 0x80000001 ... at kernel32+0x20cef", the address in the
// host's crash_logs. That is the bug safe_read.h exists for.
#include <windows.h>
#include <cstdio>
#include <cstring>
static BOOL (WINAPI* k32IsBadReadPtr)(const void*, UINT_PTR);
#include "safe_read.h"

static bool guarded(void* p) {
    MEMORY_BASIC_INFORMATION m; VirtualQuery(p, &m, sizeof m);
    return (m.Protect & PAGE_GUARD) != 0;
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    k32IsBadReadPtr = (BOOL (WINAPI*)(const void*, UINT_PTR))
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsBadReadPtr");
    int fails = 0;
    auto check = [&](const char* what, bool ok) { printf("%-58s %s\n", what, ok ? "ok" : "FAIL"); fails += !ok; };

    void* a = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE | PAGE_GUARD);
    check("new page is guarded", guarded(a));
    check("safe_read: guard page reported bad", IsBadReadPtr(a, 8) == TRUE);
    check("safe_read: guard still there afterwards", guarded(a));

    int local = 42;
    check("safe_read: readable stack var is good", IsBadReadPtr(&local, sizeof local) == FALSE);
    check("safe_read: NULL,8 is bad", IsBadReadPtr(nullptr, 8) == TRUE);
    check("safe_read: NULL,0 is good (Windows semantics)", IsBadReadPtr(nullptr, 0) == FALSE);
    void* r = VirtualAlloc(nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
    check("safe_read: reserved-not-committed is bad", IsBadReadPtr(r, 8) == TRUE);
    void* na = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    check("safe_read: PAGE_NOACCESS is bad", IsBadReadPtr(na, 8) == TRUE);
    void* ro = VirtualAlloc(nullptr, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READONLY);
    check("safe_read: PAGE_READONLY readable", IsBadReadPtr(ro, 8) == FALSE);
    check("safe_read: PAGE_READONLY not writable", IsBadWritePtr(ro, 8) == TRUE);
    DWORD old; VirtualProtect((char*)ro + 4096, 4096, PAGE_NOACCESS, &old);
    check("safe_read: range spanning into NOACCESS is bad", IsBadReadPtr((char*)ro + 4000, 200) == TRUE);
    check("safe_read: code is readable", IsBadReadPtr((void*)&main, 16) == FALSE);
    printf("%s\n", fails ? "SOME FAILED" : "ALL PASSED");
    if (argc > 1 && !strcmp(argv[1], "k32")) {
        printf("kernel32 IsBadReadPtr on the guard page (expected to end the process under Proton)...\n");
        BOOL k = k32IsBadReadPtr(a, 8);
        printf("kernel32 IsBadReadPtr returned %d; the process survived\n", k);
    }
    return fails;
}
