// safe_read.h — IsBadReadPtr / IsBadWritePtr that never touch the memory.
//
// Include right after <windows.h>. It redefines both names, so the 235 existing
// call sites need no edit.
//
// Why. kernel32's IsBadReadPtr probes by *reading* the range under an
// exception handler. Under Wine/Proton that handler catches only access
// violations. A range on a PAGE_GUARD page raises STATUS_GUARD_PAGE_VIOLATION
// (0x80000001), which it passes on; nothing else handles it, and Wine ends the
// process ("Unhandled exception 0x80000001"). Nothing reaches crash_log's
// fatal path and there is no DLL_PROCESS_DETACH.
// Measured [V] three times on the host as a client joined the lobby.
// Each crash_log shows
// `exc 0x80000001 at kernel32.dll+0x20cef`, which is inside IsBadReadPtr
// (Proton Experimental's kernel32: IsBadReadPtr at 0x20bc0, the next export
// at 0x20d40). The process is gone about 1 s later. Reproduced outside the
// game with `test_safe_read.cpp` under Proton's wine: the same address, then
// the unhandled-exception exit.
//
// Correction: this comment first blamed a *consumed* stack guard that let a
// thread overflow later. The +seh trace shows the exception is simply
// unhandled.
//
// This version asks VirtualQuery about every region the range spans and
// refuses uncommitted, PAGE_NOACCESS and PAGE_GUARD pages. It keeps the
// Windows semantics otherwise: a zero-length range is never bad, and NULL with
// a length is.
#pragma once
#include <windows.h>
#include <cstdint>

static inline bool asi_range_ok(const void* p, UINT_PTR n, DWORD want) {
    if (n == 0) return true;
    if (!p) return false;
    uintptr_t a = (uintptr_t)p, end = a + n;
    if (end < a) return false;
    while (a < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((void*)a, &mbi, sizeof mbi)) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
        if (!(mbi.Protect & want)) return false;
        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= a) return false;
        a = next;
    }
    return true;
}

static inline BOOL asi_IsBadReadPtr(const void* p, UINT_PTR n) {
    return !asi_range_ok(p, n, PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                               PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                               PAGE_EXECUTE_WRITECOPY);
}

static inline BOOL asi_IsBadWritePtr(void* p, UINT_PTR n) {
    return !asi_range_ok(p, n, PAGE_READWRITE | PAGE_WRITECOPY |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
}

#define IsBadReadPtr  asi_IsBadReadPtr
#define IsBadWritePtr asi_IsBadWritePtr
