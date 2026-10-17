// nofocuspause — stop the host freezing its animations when the window loses
//                focus, by clearing UEngine::bPauseOnLossOfFocus.
//
// WRITES TO GAME MEMORY: one bit, GEngine+0x8A0 bit 0x01000000. Nothing else.
// It calls nothing and hooks nothing.
//
// ---------------------------------------------------------------------------
// The symptom
//
// Alt-tab away from the host and character animation stops dead, while the
// game keeps running at full framerate: particles keep emitting and physics-
// simulated meshes keep falling. Alt-tab back and everything resumes. The
// joined client never does this — only the host, and only ever the host.
//
// Why it is the host [V]
//
// `HUD.OnLostFocusPause`, decompiled from LE3's own Engine.pcc:
//
//     public event function OnLostFocusPause(bool enable)
//     {
//         if (LostFocusPaused == enable) { return; }
//         if (WorldInfo.NetMode != ENetMode.NM_Client)
//         {
//             LostFocusPaused = enable;
//             PlayerOwner.SetPause(enable);
//         }
//     }
//
// The pause is skipped for exactly one case, NM_Client. A listen server is
// NM_ListenServer and single-player is NM_Standalone, so both pause; the
// joining client is the sole exception. That is the whole asymmetry.
//
// And why animation stops but physics does not: `SetPause` sets
// `WorldInfo.Pauser`, which gates actor and AnimTree ticking. The renderer,
// the particle systems and the PhysX scene are not on that path, so they carry
// on — which is what makes it read as "animations are broken" rather than
// "the game is paused".
//
// The lever [R] — THIS IS THE UNVERIFIED PART
//
// In stock UE3 the native focus-loss handler only calls into
// `OnLostFocusPause` when `GEngine->bPauseOnLossOfFocus` is set. That flag is
// a CPF_Config bool on UEngine — LExSDK/LE3/SDK_HEADERS/Engine_classes.h:3358,
// offset 0x8A0, mask 0x01000000 — and `bpauseonlossoffocus` is present in
// LE3's Coalesced string pool, so the key really is in this game's config.
//
// That LE3's native code reads this particular flag is carried-forward desk
// research, not something verified here: the shipped exe has an encrypted
// .text, so the caller cannot be disassembled statically. This ASI is the
// experiment that settles it.
//
// Reading the result — and the trap this project keeps falling into
//
// Before concluding anything from a zero or an absence, check the
// measurement can show a presence. So this logs the whole 32-bit flags word at
// +0x8A0 before and after the write, not just the one bit:
//
//   - bit already CLEAR on a host that still freezes  -> the hypothesis is
//     WRONG. Something other than bPauseOnLossOfFocus is driving
//     OnLostFocusPause, and the next place to look is the caller, not here.
//   - word reads 0x00000000 or 0xFFFFFFFF -> the offset or the GEngine
//     pointer is wrong. Do not read that as "the flag was already off".
//   - bit SET, we clear it, host stops freezing -> confirmed, and the
//     permanent fix is bPauseOnLossOfFocus=False in [Engine.Engine] inside
//     Coalesced.bin.
//
// The vtable rva is checked for the same reason: it is how we know the pointer
// really is a UGameEngine before trusting an offset into it.
//
// Clearing the flag prevents future pauses; it does not undo one already in
// effect. If you alt-tab during the startup delay below, alt-tab back once.
// ---------------------------------------------------------------------------
#include <windows.h>
#include "lemp.h"
#include "safe_read.h"  // guard-page-safe IsBadReadPtr/IsBadWritePtr
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

// Same global loadmap_hook uses, and it resolves there in practice.
static const uintptr_t RVA_GENGINE  = 0x18B31D0;   // -> UGameEngine*
static const uintptr_t RVA_VT_GAMEENGINE = 0x13983A0;  // sanity check only

// UEngine::bPauseOnLossOfFocus — Engine_classes.h:3358.
static const uintptr_t OFF_FLAGS = 0x8A0;
static const uint32_t  BIT_PAUSE = 0x01000000;

static const DWORD START_DELAY_MS = 15000;  // let the engine finish init
static const DWORD POLL_MS        = 2000;

static uint8_t* g_base = nullptr;

static void L(const char* fmt, ...) {
    va_list a; va_start(a, fmt);
    LempLogV("nofocuspause", fmt, a);
    va_end(a);
}

// Neighbours of bPauseOnLossOfFocus in the same dword, so the logged word can
// be eyeballed as a plausible flags field rather than taken on faith.
static void describe(uint32_t w, char* out, size_t cap) {
    _snprintf_s(out, cap, _TRUNCATE,
                "kismetLog=%d matureLang=%d terrainOverlay=%d noPhysXHW=%d "
                "PAUSEONLOSSOFFOCUS=%d checkParticleSize=%d",
                (w & 0x00100000) ? 1 : 0, (w & 0x00200000) ? 1 : 0,
                (w & 0x00400000) ? 1 : 0, (w & 0x00800000) ? 1 : 0,
                (w & BIT_PAUSE)  ? 1 : 0, (w & 0x02000000) ? 1 : 0);
}

static DWORD WINAPI Thread(LPVOID) {
    g_base = (uint8_t*)GetModuleHandleA("MassEffect3.exe");
    if (!g_base) g_base = (uint8_t*)GetModuleHandleA(nullptr);
    L("== nofocuspause ==  pid %lu  base %p", GetCurrentProcessId(), (void*)g_base);
    L("WRITES TO GAME MEMORY: one bit, GEngine+0x%llx bit 0x%08x.",
      (unsigned long long)OFF_FLAGS, BIT_PAUSE);
    Sleep(START_DELAY_MS);

    void** pge = (void**)(g_base + RVA_GENGINE);
    if (IsBadReadPtr(pge, 8) || !*pge) {
        L("FAIL: GEngine not set at rva %llx — nothing written.",
          (unsigned long long)RVA_GENGINE);
        return 0;
    }
    void* ge = *pge;
    L("GEngine=%p", ge);
    if (IsBadReadPtr(ge, OFF_FLAGS + 4)) {
        L("FAIL: GEngine unreadable to +0x%llx — nothing written.",
          (unsigned long long)(OFF_FLAGS + 4));
        return 0;
    }

    // Is this really a UGameEngine? If the vtable is not the one we expect the
    // offset below means nothing, so say so loudly rather than write blind.
    void** vt = *(void***)ge;
    uintptr_t vtrva = (uintptr_t)((uint8_t*)vt - g_base);
    L("vtable=%p (rva %llx)%s", (void*)vt, (unsigned long long)vtrva,
      vtrva == RVA_VT_GAMEENGINE ? " — matches UGameEngine" : "  *** UNEXPECTED ***");
    if (vtrva != RVA_VT_GAMEENGINE) {
        L("Refusing to write: the offset is only meaningful for UGameEngine.");
        return 0;
    }

    volatile uint32_t* flags = (volatile uint32_t*)((uint8_t*)ge + OFF_FLAGS);
    char desc[256];

    uint32_t before = *flags;
    describe(before, desc, sizeof(desc));
    L("flags@+0x%llx = 0x%08x  [%s]", (unsigned long long)OFF_FLAGS, before, desc);

    if (before == 0x00000000 || before == 0xFFFFFFFF) {
        L("SUSPECT: an all-zero/all-one word is what a WRONG OFFSET looks like.");
        L("Do not read this as 'the flag was already off'. Verify the offset");
        L("against Engine_classes.h:3358 before concluding anything.");
    }
    if (!(before & BIT_PAUSE)) {
        L("NOTE: bPauseOnLossOfFocus was ALREADY CLEAR. If the host still");
        L("freezes on focus loss, this flag is NOT the gate and the");
        L("hypothesis in the header is wrong — look at the native caller.");
    }

    *flags = before & ~BIT_PAUSE;

    uint32_t after = *flags;
    describe(after, desc, sizeof(desc));
    L("flags@+0x%llx = 0x%08x  [%s]  <- after write",
      (unsigned long long)OFF_FLAGS, after, desc);
    if (after & BIT_PAUSE) {
        L("FAIL: the bit did not stay clear. Memory protection, or the page is");
        L("being rewritten. Nothing further to try from here.");
        return 0;
    }
    L("bPauseOnLossOfFocus cleared. Alt-tab away from the host: animation");
    L("should keep running. Re-asserting every %lu ms in case config reloads.",
      POLL_MS);

    // Cheap insurance: a config reload would set it again. Only log a change.
    for (int i = 0; i < 5400; ++i) {          // ~3 h, same budget as repl_probe
        Sleep(POLL_MS);
        if (lemp::Exiting()) { L("stopping: engine exiting"); return 0; }
        uint32_t w = *flags;
        if (w & BIT_PAUSE) {
            *flags = w & ~BIT_PAUSE;
            L("bit had been set again (0x%08x) — cleared. Config reload?", w);
        }
    }
    return 0;
}

void NoFocusPauseStart() {
    CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
}
