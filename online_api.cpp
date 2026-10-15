// online_api — a stand-in for the ONLINE_API online component LE3 dropped.
//
// NOT A PROBE. THIS ASI WRITES TO GAME MEMORY, like join_patch: 12 bytes at
// the top of one accessor function in .text, in memory only. Nothing on disk.
//
// ---------------------------------------------------------------------------
// Why it exists
//
// Host crash, killing a Collector Trooper with the Incisor:
// ACCESS_VIOLATION reading 0 at MassEffect3.exe+0xaf8bea, stack
// SFXPawn.DistributeScore -> SFXAccomplishmentManager.UpdateKillChallenges ->
// native GetKillAccomplishments (rva af8b90). Its first act is
//
//   af8bcb  call  98bf00            ; GameEngine->OnlineSubsystem (+0xA04)
//   af8bd7  call  98b5c0            ; GetComponentAPI(subsystem, &pair)
//   af8bdc  cmp   [rax],0 / je -> xor ecx,ecx
//   af8bea  mov   rax,[rcx]         ; <- fault: the interface is null
//   af8bed  call  [rax+0x28]        ; ISFXOnlineComponentAPI::GetCurrentTime
//
// and the result is compared with each Challenge's EventStartTime/
// EventEndTime (+0x90/+0x94, when both > 0). 98b5c0 reads
// SFXOnlineSubsystem.OnlineComponentList[1] (+0x1B4 + 1*0x10) =
// SFXONLINE_COMPONENT_TYPE_ONLINE_API. In 2012 that was
// SFXOnlineComponentBlazeHub (implements ISFXOnlineComponentAPI: GetCurrentTime,
// Idle, ResetLocale), Blaze's server clock. LE3's ComponentClassList registers
// nothing of that type, so the slot is always empty — and the null check
// above only picks a null `this` to call through.
//
// All eight callers of 98b5c0 are the accomplishment manager's
// Get*Accomplishments natives (af7xxx-afbxxx), each with the same unguarded
// pattern and each calling only slot +0x28. They were unreachable until the
// challenges port turned GoBig on (Mount.dlc 0x2c, once installed):
// every Update*Challenges returns early without it. So kills, powers, waves
// and match ends would all have crashed; a kill was simply first.
//
// What this does: replaces 98b5c0 with an equivalent that, when the slot is
// empty, returns a stand-in object whose interface vtable slot 5 (+0x28)
// returns the current UTC time in epoch seconds — the unit 2012's live file
// uses (EventEndTime=1350907200 is 2012-10-22). Every other slot logs and
// returns 0. When the slot is filled, it does exactly what the original did.
//
// The stand-in's UObject half is never dereferenced: all eight callers only
// test pair.obj for null and then use pair.iface ([rax+8]) [V, objdump].
// ---------------------------------------------------------------------------
#include <windows.h>
#include "lemp.h"
#include "safe_read.h"  // guard-page-safe IsBadReadPtr/IsBadWritePtr
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>

// Verified against the installed LE3 MassEffect3.exe (the unpacked one, image
// base 0x7ff74a890000 in the file), as join_patch.
static const uintptr_t RVA_GET_COMPONENT_API = 0x98B5C0;
static const uintptr_t RVA_API_IFACE_CLASS   = 0x990D20;  // 98b5e2: call -> UClass*
static const uintptr_t RVA_GET_IFACE_ADDRESS = 0x126030;  // 98b5ed: call (obj, class)
static const size_t    OFF_ONLINE_API_SLOT   = 0x1C4;     // OnlineComponentList[1]

// The whole original function, so a different build refuses rather than
// having its code overwritten.
static const uint8_t EXPECT[] = {
    0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20,
    0x48, 0x8b, 0xb9, 0xc4, 0x01, 0x00, 0x00,                    // mov rdi,[rcx+0x1c4]
    0x33, 0xc0, 0x48, 0x89, 0x42, 0x08, 0x48, 0x8b, 0xda, 0x48, 0x89, 0x3a,
    0x48, 0x85, 0xff, 0x74, 0x22,
    0xe8, 0x39, 0x57, 0x00, 0x00,                                // call 990d20
    0x48, 0x8b, 0xd0, 0x48, 0x8b, 0xcf,
    0xe8, 0x3e, 0xaa, 0x79, 0xff,                                // call 126030
};

struct IfacePair { void* obj; void* iface; };   // FScriptInterface
typedef void* (*StaticClassFn)();
typedef void* (*GetIfaceAddrFn)(void* obj, void* ifaceClass);

static uint8_t*       g_base = nullptr;
static FILE*          g_log  = nullptr;
static StaticClassFn  g_ifaceClass = nullptr;
static GetIfaceAddrFn g_ifaceAddr  = nullptr;
static volatile LONG  g_standinUses = 0;

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

// --- the stand-in ----------------------------------------------------------

static int GetCurrentTimeStandin(void*) {
    return (int)time(nullptr);   // UTC epoch seconds, as Blaze's server clock
}

template <int N>
static uintptr_t UnexpectedSlot(void*) {
    L("stand-in: unexpected call to interface slot %d (+0x%x); returned 0",
      N, N * 8);
    return 0;
}

static void* g_vtbl[16] = {
    (void*)&UnexpectedSlot<0>,  (void*)&UnexpectedSlot<1>,
    (void*)&UnexpectedSlot<2>,  (void*)&UnexpectedSlot<3>,
    (void*)&UnexpectedSlot<4>,  (void*)&GetCurrentTimeStandin,
    (void*)&UnexpectedSlot<6>,  (void*)&UnexpectedSlot<7>,
    (void*)&UnexpectedSlot<8>,  (void*)&UnexpectedSlot<9>,
    (void*)&UnexpectedSlot<10>, (void*)&UnexpectedSlot<11>,
    (void*)&UnexpectedSlot<12>, (void*)&UnexpectedSlot<13>,
    (void*)&UnexpectedSlot<14>, (void*)&UnexpectedSlot<15>,
};
static struct { void** vtbl; } g_standinIface = { g_vtbl };
static uint8_t g_standinObj[0x100];   // non-null; never dereferenced by callers

// --- the replacement for 98b5c0 --------------------------------------------

static IfacePair* GetComponentAPI(uint8_t* subsystem, IfacePair* out) {
    void* obj = *(void**)(subsystem + OFF_ONLINE_API_SLOT);
    out->iface = nullptr;
    out->obj = obj;
    if (obj) {
        out->iface = g_ifaceAddr(obj, g_ifaceClass());
        return out;
    }
    out->obj = g_standinObj;
    out->iface = &g_standinIface;
    LONG n = InterlockedIncrement(&g_standinUses);
    if (n == 1 || (n & (n - 1)) == 0)   // 1, 2, 4, 8, ...
        L("stand-in served (use %ld): GetCurrentTime = %d", n, (int)time(nullptr));
    return out;
}

// --- install ---------------------------------------------------------------

static DWORD WINAPI Thread(LPVOID) {
    g_log = LempOpenDebugLog("online_api");

    g_base = (uint8_t*)GetModuleHandleA("MassEffect3.exe");
    if (!g_base) g_base = (uint8_t*)GetModuleHandleA(nullptr);

    L("== online_api ==  pid %lu  base %p", GetCurrentProcessId(), (void*)g_base);
    L("Stands in for the ONLINE_API component (2012: SFXOnlineComponentBlazeHub).");
    L("WRITES TO GAME MEMORY: 12 bytes at rva %llx, in memory only.",
      (unsigned long long)RVA_GET_COMPONENT_API);

    uint8_t* at = g_base + RVA_GET_COMPONENT_API;
    if (IsBadReadPtr(at, sizeof(EXPECT)) || memcmp(at, EXPECT, sizeof(EXPECT)) != 0) {
        L("FAIL: the accessor at rva %llx does not match this build. Nothing patched.",
          (unsigned long long)RVA_GET_COMPONENT_API);
        return 0;
    }
    g_ifaceClass = (StaticClassFn)(g_base + RVA_API_IFACE_CLASS);
    g_ifaceAddr  = (GetIfaceAddrFn)(g_base + RVA_GET_IFACE_ADDRESS);

    uint8_t jmp[12] = {0x48, 0xB8};                 // mov rax, imm64
    uint64_t target = (uint64_t)(uintptr_t)&GetComponentAPI;
    memcpy(jmp + 2, &target, 8);
    jmp[10] = 0xFF; jmp[11] = 0xE0;                 // jmp rax

    DWORD old = 0;
    if (!VirtualProtect(at, sizeof(jmp), PAGE_EXECUTE_READWRITE, &old)) {
        L("FAIL: VirtualProtect %lu", GetLastError());
        return 0;
    }
    memcpy(at, jmp, sizeof(jmp));
    VirtualProtect(at, sizeof(jmp), old, &old);
    FlushInstructionCache(GetCurrentProcess(), at, sizeof(jmp));
    L("PATCH GetComponentAPI -> %p. Challenge natives now read the time from here.",
      (void*)&GetComponentAPI);
    return 0;
}

void OnlineApiStart() {
    CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
}
