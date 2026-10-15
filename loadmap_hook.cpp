// loadmap_hook — why does the client fail to travel after a clean handshake?
//
// WRITES TO GAME MEMORY: two vtable slots, in memory only, forwarded to the
// originals. Same instrument as tick_hook, pointed at a different question.
//
// ---------------------------------------------------------------------------
// The state this was built to explain
//
// With join_patch applied the client's pending level completes without an
// error — `NotifyReceivedText` processes all 197 packages the server
// advertises and raises nothing — and then the client sits at the main menu
// with no net driver and no pending level, while the host still shows the
// connection as live. No message box, nothing in any log.
//
// `UGameEngine::Tick`'s pending-level block (rva 0x5502c0) says where that
// decision is made:
//
//   550930  Tick(dt)                       ; vtable 0x2b0, what tick_hook hooks
//   550953  eax = Pending->Error.Num
//   55095c  if (eax == 0 || eax == 1) -> no error, carry on
//           else SetProgress(4, Localize(...), &Pending->Error) ; and give up
//   550a0f  if (!Pending->bSuccessfullyConnected) -> end
//   550a1d  if (Pending->bSentJoinRequest)        -> end
//   550a53  call [this+0x3e8]                     ; LoadMap(URL, Pending, Error)
//   550a59  if (result == 0)                      -> ?failed, back to the menu
//   550a74  if (Error != "")                      -> ?failed, back to the menu
//
// So the client reaches `LoadMap` and `LoadMap` refuses. Its `Error` out
// parameter is the reason, and it is discarded on the way to the menu — which
// is exactly why nothing is displayed.
//
// Slot 0x3e8 is hooked to read that string. Slot 0x2e0 (`SetProgress`) is
// hooked too, because it carries the title and message of any failure the
// engine *does* mean to show, and one of the two will be populated whichever
// path is taken.
//
// GEngine comes from the global at rva 0x18b31d0 — the same pointer the
// package-map code loads before calling slot 0x2d0 with "?failed".
// ---------------------------------------------------------------------------
#include <windows.h>
#include "lemp.h"
#include "safe_read.h"  // guard-page-safe IsBadReadPtr/IsBadWritePtr
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

static const uintptr_t RVA_GENGINE   = 0x18B31D0;  // -> UGameEngine*
static const size_t    SLOT_LOADMAP  = 0x3E8 / 8;  // 125
static const size_t    SLOT_PROGRESS = 0x2E0 / 8;  // 92
static const DWORD     START_DELAY_MS = 15000;

static uint8_t* g_base = nullptr;
static FILE*    g_log  = nullptr;

static void L(const char* fmt, ...) {
    SYSTEMTIME st; GetLocalTime(&st);
    va_list a; va_start(a, fmt);
    if (g_log) {
        fprintf(g_log, "%02d:%02d:%02d.%03d  ",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        vfprintf(g_log, fmt, a);
        fputc('\n', g_log);
        fflush(g_log);
    }
    va_end(a);
}

// UE3's FString is a TArray<TCHAR>: Data at +0, Num at +8. Confirmed twice —
// tick_hook reads the pending level's Error at +0xf4/+0xfc, the same 8-byte
// spacing, and Tick's own branch tests that Num against 0 and 1 (1 being the
// terminator of an empty string).
static void fstr(void* fs, char* out, size_t cap) {
    out[0] = 0;
    if (!fs || IsBadReadPtr(fs, 12)) { strncpy(out, "(unreadable)", cap - 1); return; }
    wchar_t* data = *(wchar_t**)fs;
    int num = *(int*)((uint8_t*)fs + 8);
    if (!data || num <= 1 || IsBadReadPtr(data, 2)) {
        _snprintf_s(out, cap, _TRUNCATE, "(empty, Num=%d)", num);
        return;
    }
    char buf[512] = {0};
    WideCharToMultiByte(CP_UTF8, 0, data, -1, buf, sizeof(buf) - 1, nullptr, nullptr);
    _snprintf_s(out, cap, _TRUNCATE, "Num=%d \"%s\"", num, buf);
}

typedef int  (*LoadMapFn)(void* self, void* url, void* pending, void* error);
typedef void (*ProgressFn)(void* self, int type, void* title, void* msg);
static LoadMapFn  g_origLoadMap  = nullptr;
static ProgressFn g_origProgress = nullptr;
static volatile LONG g_calls = 0;

static int HookedLoadMap(void* self, void* url, void* pending, void* error) {
    LONG n = InterlockedIncrement(&g_calls);
    L("LoadMap #%ld  pending=%p  ->  calling original", n, pending);
    int r = g_origLoadMap(self, url, pending, error);
    char e[600]; fstr(error, e, sizeof(e));
    L("LoadMap #%ld returned %d   Error %s", n, r, e);
    if (r == 0 || e[0] == 'N')  // non-empty Error prints as Num=...
        L("   ^ THIS is why the client goes back to the menu");
    return r;
}

static void HookedProgress(void* self, int type, void* title, void* msg) {
    char t[600], m[600];
    fstr(title, t, sizeof(t)); fstr(msg, m, sizeof(m));
    L("SetProgress type=%d  title %s  msg %s", type, t, m);
    if (g_origProgress) g_origProgress(self, type, title, msg);
}

static bool hook(void** vt, size_t slot, void* thunk, void** orig, const char* name) {
    if (IsBadReadPtr(vt + slot, 8)) { L("FAIL: %s slot unreadable", name); return false; }
    void* o = vt[slot];
    if (!o || (uint8_t*)o < g_base) { L("FAIL: %s slot looks wrong (%p)", name, o); return false; }
    DWORD old = 0;
    if (!VirtualProtect(vt + slot, 8, PAGE_READWRITE, &old)) {
        L("FAIL: %s VirtualProtect %lu", name, GetLastError()); return false;
    }
    *orig = o;
    vt[slot] = thunk;
    VirtualProtect(vt + slot, 8, old, &old);
    L("hooked %s: slot %zu was rva %llx", name, slot,
      (unsigned long long)((uint8_t*)o - g_base));
    return true;
}

static DWORD WINAPI Thread(LPVOID) {
    g_log = LempOpenDebugLog("loadmap_hook");

    g_base = (uint8_t*)GetModuleHandleA("MassEffect3.exe");
    if (!g_base) g_base = (uint8_t*)GetModuleHandleA(nullptr);
    L("== loadmap_hook ==  pid %lu  base %p", GetCurrentProcessId(), (void*)g_base);
    L("WRITES TO GAME MEMORY: two vtable slots, forwarded to the originals.");
    Sleep(START_DELAY_MS);

    void** pge = (void**)(g_base + RVA_GENGINE);
    if (IsBadReadPtr(pge, 8) || !*pge) { L("FAIL: GEngine not set yet at rva %llx",
                                          (unsigned long long)RVA_GENGINE); return 0; }
    void* ge = *pge;
    L("GEngine=%p", ge);
    if (IsBadReadPtr(ge, 8)) { L("FAIL: GEngine unreadable"); return 0; }
    void** vt = *(void***)ge;
    L("vtable=%p (rva %llx)", (void*)vt, (unsigned long long)((uint8_t*)vt - g_base));

    hook(vt, SLOT_LOADMAP,  (void*)&HookedLoadMap,  (void**)&g_origLoadMap,  "LoadMap");
    hook(vt, SLOT_PROGRESS, (void*)&HookedProgress, (void**)&g_origProgress, "SetProgress");
    L("Now join. Every LoadMap prints its result and its Error string.");

    for (int i = 0; i < 1080; ++i) { Sleep(10000); }
    return 0;
}

static DWORD WINAPI Gate(LPVOID) {
    if (!LempDebug()) return 0;   // a diagnostic: debug mode only
    CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
    return 0;
}

void LoadMapHookStart() { CreateThread(nullptr, 0, Gate, nullptr, 0, nullptr); }
