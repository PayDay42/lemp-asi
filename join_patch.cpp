// join_patch — stop the client refusing the join at UE3's package-map check.
//
// THIS ASI WRITES TO GAME MEMORY, like tick_hook and unlike every probe. It
// patches four bytes (optionally six) inside one function, in memory only.
// Nothing on disk is touched.
//
// ---------------------------------------------------------------------------
// What it patches and why
//
// The joining client was found to abort two frames in with
//
//     "You cannot join the match because the host has downloadable content
//      you do not."
//
// which is UE3's stock `NoDownload` — package-map validation, not a DLC
// entitlement check (it fires with zero DLC installed on either side). The
// handler is UNetPendingLevel::NotifyReceivedText, vtable slot 94, rva
// 0x65f880, and `NoDownload` is referenced exactly once inside it.
//
// The executable is NOT packed, so the branch can be read rather than
// inferred. The tail of the `USES` handler,
// which processes one package advertised by the server:
//
//   65fcf6  call  FindPackageFileEntry(cache, 0, name, 0, 0) -> rbx
//   65fd19  test  rbx,rbx
//   65fd1c  je    65fd3e                 ; no entry at all -> mismatch
//   65fd1e  ...   xor/or over [rbx+0x6c..0x78] vs [rbp-0x50..-0x44]
//   65fd3c  je    65fd5e                 ; GUIDs equal -> ACCEPT
//   65fd3e  inc   DWORD PTR [r13+0x20]   ; FilesNeeded++
//   65fd42  bts   ecx,0xf                ; flags |= PKG_Need (0x8000)
//   65fd4c  mov   rax,[r13+0x8]
//   65fd50  cmp   DWORD PTR [rax+0xc4],0x0
//   65fd57  je    65fda8                 ; downloads disabled   -> REFUSE
//   65fd59  test  cl,0x1
//   65fd5c  je    65fda8                 ; !PKG_AllowDownload   -> REFUSE
//   65fd5e  ACCEPT: PackageMap->AddPackageInfo(&Info), return
//   65fda8  REFUSE: ... Localize("Engine","NoDownload") at 65fde6, SetError,
//                   and close the connection
//
// Both refusals funnel through 0x65fda8, and nothing else reaches it, so
// neutering the two `je`s removes the refusal entirely. That matters because
// clearing the error string afterwards is not enough — the same handler also
// closes the connection (`State` 2 -> 1), which is where tick_hook's BYPASS
// ran out of road.
//
// P1 is the cleaner of the two interventions: it makes a GUID mismatch take
// the accept path directly, so FilesNeeded is never incremented and PKG_Need
// is never set — the client's state is exactly as if the package had matched.
// P2/P3 cover the other case, where the client has no cache entry for the
// package at all, and are what guarantee no `NoDownload` can be raised.
//
// What this is NOT: a fix for whatever the two ends disagree about. It is the
// deliberate decision to let a client that is running THE SAME INSTALL as the
// host proceed. If a package genuinely cannot be resolved, the failure now
// happens where that package is used, which names it — the current check names
// nothing.
//
// ---------------------------------------------------------------------------
// P4/P5, and the package the check was hiding
//
// With P1-P3 alone the client stops refusing and immediately says what the old
// message would not: [V]
//
//     "Downloading package 'PlotManagerAutoDLC_HEN_PR' failed:
//      Error opening file"
//
// `PlotManagerAutoDLC_HEN_PR` exists on **no** disk — not in DLC_HEN_PR, not in
// the base game, nowhere under BioGame. It is built in memory at runtime, per
// installed DLC. So the host advertises a package that no client can ever
// resolve to a file, and stock UE3 does the only thing it can: mark it needed
// and try to download it, from a game with no download channel.
//
// That is why the refusal never depended on anything: not the map, not the game
// mode, not which DLC were installed, and not our authored content. Two
// identical installs disagree here, because the thing they disagree about is not
// a file either of them has.
//
// P4 and P5 remove the two writes that put such a package into the download
// queue — `FilesNeeded++` and `PackageFlags |= PKG_Need` — so it is registered
// in the package map like any other and nothing tries to fetch it. Anything that
// genuinely needs its contents will still fail at the point of use, by name.
//
// ---------------------------------------------------------------------------
// P6: the same question is asked again after travelling
//
// With P1-P5 the client accepts the welcome and travels — a loading screen,
// which no run before this had ever reached. It then bounced back to the main
// menu, because a *second* package check runs once the level is live. That is
// the function at rva 0x8cb640, which references three localization keys:
// `FailedFindPackage`, `PackageVersion` and `NoDownload`.
//
//   8cb8f1  cmp   rcx,rdx              ; package name vs a known one
//   8cb8fb  je    8cba96               ; -> FailedFindPackage
//   8cb939  call  [rax+0x10]           ; GPackageFileCache->FindPackageFile
//   8cb93e  je    8cba69               ; not found -> falls into 8cba96
//   8cba96  FailedFindPackage: Localize("Engine","FailedFindPackage"), fail
//   ...
//   8cc732  SUCCESS TAIL: if (ServerConnection->State != 1)
//                             Connection->PackageMap->AddPackageInfo(&Info);
//   8cc75c  mov   eax,1                ; verified
//
// `PlotManagerAutoDLC_HEN_PR` has no file, so `FindPackageFile` fails here
// exactly as it did before travelling, and the client drops the connection.
//
// P6 routes the failure into that success tail rather than suppressing the
// error afterwards. The distinction matters: the tail still calls
// `AddPackageInfo`, so the client's package map keeps the same entries in the
// same order as the server's — and package indices are how net objects are
// addressed. Skipping the entry would desynchronise every later reference.
// r13 and r14 (`this` and `&Info`) are callee-saved and live across the whole
// function, and the epilogue restores from `rsp+0xb0` rather than the frame
// pointer, so entering it from here is safe. The cost is one leaked FString
// per unresolvable package.
//
// ---------------------------------------------------------------------------
// P7, and the actual cause — packages that exist only in memory
//
// With P1-P6 the client's handshake is completely clean: 197 package entries
// processed, no error anywhere, pending level satisfied. It then bounced to the
// menu in silence. `loadmap_hook` asked the function that decides, and got a
// sentence: [V]
//
//     LoadMap returned 0   Error:
//       "Package 'SFXGameContent' version mismatch
//        [package 87A590444503D76834479E9F3BA93480,
//         info    EB032FF541D9305EAA77CCA22491BC7F]"
//     SetProgress type=4  title "Connection Lost"
//
// **`SFXGameContent` exists as no file anywhere under BioGame** — like
// `PlotManagerAuto*`, LE3 builds it in memory. A package object built in memory
// gets a fresh GUID in each process, so the host's copy and the client's copy
// can never agree, on identical installs, with nothing installed, forever.
//
// That is the root cause of this whole chain. The three checks are the same
// question asked in three places, and every one of them compares a GUID that is
// generated per run:
//
//   65fd1e  pending level, before travelling   -> "NoDownload"
//   8cb939  live level, after travelling       -> "FailedFindPackage"
//   b95330  LoadMap, resolving the map itself  -> "version mismatch"  <- P7
//
//   b952ea  movups xmm1,[rbx+0x6c]     ; the package's own Guid
//   b952ee  mov   r9d,[rsi+0x14] ...   ; the advertised FPackageInfo's Guid
//   b95312  xor/or over all four dwords
//   b95330  jne   b956bf               ; any difference -> version mismatch
//   b95336  mov   [rsi+0x8],rbx        ; match: Info.Parent = the package
//
// P7 neuters that `jne`, so the local package is accepted as the right one —
// which, for two clients of the same install, it is.
//
// The honest framing: this is not a fix, it is a decision to stop enforcing an
// identity check whose inputs LE3 cannot make comparable. A real fix belongs on
// the host — do not advertise packages that have no file — and would need
// nothing on the client at all.
//
// ---------------------------------------------------------------------------
// P8/P9: the same comparison a fourth time, for a package that arrives mid-match
//
// BioP_MPJngl, Geth wave 1: the first Geth Bomber spawn
// (DLC_MOD_M's SFXPawn_GethBomber_Shared.pcc) made the host advertise the
// forced-export packages `SFXGameContentDLC_Shared` and `Char_Enemies_Shared`.
// The client dropped 13 s into the match: [V]
//
//     SetProgress type=4  title "Package 'sfxgamecontentdlc_shared' version mismatch"
//     LoadMap #2 (to the menu)  ...  "Connection Lost"
//
// Not P7: that SetProgress came before any LoadMap. `PackageVersion` has four
// references in the exe (127e94, 660eb0, 8cbe03, 8cc30c); the last two are in
// 8cb640, the live-level function P6 already patches, one per mode of it
// (the global at 0x17df750 selects):
//
//   A  8cb6a0  FindPackage(name) -> found:
//      8cbbfd  movups xmm1,[r9+0x6c]   ; the package's own Guid
//      8cbc17  xor/or vs [r14+0x10..0x1c]  ; the advertised Info.Guid
//      8cbc40  je    8cbf39            ; match -> record the local package
//              (fall through)          ; -> "PackageVersion" at 8cbe03
//   B  8cbfd2  FindPackageFile / FindPackage / CreatePackage / LoadPackage, then
//      8cc10a  the same compare vs [rbx] (= &Info.Guid)
//      8cc149  je    8cc3f8            ; -> "PackageVersion" at 8cc30c
//
// Both match targets set Info's generation from the package (+0x9c) and
// register its Guid (call 666310) and continue to the success tail, as P7's
// accepted branch does. P8/P9 make both `je`s unconditional (`90 e9 rel32`,
// same target), so the client's own copy is accepted.
//
// Why the two processes disagree is NOT established [R]. All seven of our
// `SFXPawn_*_Shared.pcc` carry the Armax Arena's identity for the package
// (5d74d261..., copied from DLC_EXP_Pack003_Base); stock LE3 has two more
// (5890c15e... in Citadel/Leviathan/Omega/EC, 5960a07c... in METR_Patch01).
// Both instances went menu -> lobby -> map with no single-player content, so
// a stock copy resident on one side does not obviously fit. Which mode fired,
// and the two Guids, were not measured.
//
// ---------------------------------------------------------------------------
// P10: P8 accepted a package with no generations, and the client crashed
//
// BioP_MPGeth, ~9 s into the match (host on the Collector
// Adept, as it meleed): the client died, ACCESS_VIOLATION reading -1 at
// cac20+0xac (crash_log; the stack holds 8cc75c, P6-P9's success tail right
// after AddPackageInfo). cac20 is UPackageMap::Compute; per FPackageInfo
// (stride 0x4c: +0x08 Parent, +0x20 ObjectBase, +0x24 ObjectCount,
// +0x28 LocalGeneration, +0x2c RemoteGeneration) it does
//
//   cacb7  eax = min(Local, Remote) - 1
//   cacb9  cmp eax, Parent->GenerationNetObjectCount.Num   ; [r8+0x9c]
//   cacbb  jge cad20                    ; signed: -1 < 0 falls through
//   caccc  mov r10d,[Data + r9*4 - 4]   ; Data null, r9 = 0 -> reads -4
//
// Measured in the client's crash_mem snapshot [V]: the Info the host sent
// for `sfxgamecontentdlc_shared` carries the Guid 5d74d261-... (our
// SFXPawn_*_Shared.pcc) with RemoteGeneration 1 and LocalGeneration 0; the
// client's own package object has an all-zero Guid and no generations — an
// in-memory stub, not a loaded file. Our startup package imports
// SFXGameContentDLC_Shared.SFXOutlineGlowActorMP_ThermalScope and
// ...SFXSkeletalMeshComponent_ThermalScope (classes LE3 has only in
// Citadel's level files), so every process holds that stub from launch. The
// host had loaded a _Shared enemy file, which fills it in; the client had
// not yet. Before P8 that mismatch dropped the client; after, P8
// records a LocalGeneration of 0, which stock never produces.
//
// P10 makes that compare unsigned (jge -> jae). For every value stock
// produces (min >= 1) it decides the same; for 0 it takes the existing
// "generation beyond the count" path and leaves ObjectCount as it was (0
// for a new entry). Objects in that package then do not resolve on this
// client — the enemy is missing for it — but the match goes on. Not a fix
// for the race itself: the client's LocalGeneration stays 0 even after its
// own wave loading reads the file.
// ---------------------------------------------------------------------------
#include <windows.h>
#include "lemp.h"
#include "safe_read.h"  // guard-page-safe IsBadReadPtr/IsBadWritePtr
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

struct Patch {
    const char*   name;
    uintptr_t     rva;
    const uint8_t expect[8];
    const uint8_t want[8];
    size_t        len;
    bool          enabled;
};

// Verified against the installed LE3 MassEffect3.exe 2.0.0.48602 — the
// UNPACKED exe on this machine (the Steam original sits beside it as the
// packed MassEffect3_ORIG.exe). An earlier
// version of this comment called it "the shipped Steam build"; it is not.
// Image base 0x7ff74a890000 in the file. Bytes are checked before writing, so
// a different build refuses rather than corrupting a random instruction.
static Patch g_patches[] = {
    {"P1 GUID mismatch -> accept", 0x65FD3C, {0x74, 0x20}, {0xEB, 0x20}, 2, true},
    {"P2 downloads-disabled refusal", 0x65FD57, {0x74, 0x4F}, {0x90, 0x90}, 2, true},
    {"P3 no-PKG_AllowDownload refusal", 0x65FD5C, {0x74, 0x4A}, {0x90, 0x90}, 2, true},
    {"P4 FilesNeeded++", 0x65FD3E, {0x41, 0xFF, 0x45, 0x20},
                                   {0x90, 0x90, 0x90, 0x90}, 4, true},
    {"P5 flags |= PKG_Need", 0x65FD45, {0x0F, 0xBA, 0xE9, 0x0F},
                                       {0x90, 0x90, 0x90, 0x90}, 4, true},
    // P6: the same decision, taken a second time after the client has
    // travelled. See the note below.
    {"P6 FailedFindPackage -> accept", 0x8CBA96,
        {0x48, 0x8B, 0x05, 0x33, 0x77, 0xFE, 0x00},
        {0xE9, 0x97, 0x0C, 0x00, 0x00, 0x90, 0x90}, 7, true},
    // P7: the same GUID comparison a third time, inside LoadMap itself. See
    // the note below — this is the one the client actually died on.
    {"P7 LoadMap GUID mismatch", 0xB95330,
        {0x0F, 0x85, 0x89, 0x03, 0x00, 0x00},
        {0x90, 0x90, 0x90, 0x90, 0x90, 0x90}, 6, true},
    // P8/P9: the same GUID comparison inside the live-level function 8cb640,
    // for a package advertised mid-match. See the note below.
    {"P8 live-level GUID mismatch (A)", 0x8CBC40,
        {0x0F, 0x84, 0xF3, 0x02, 0x00, 0x00},
        {0x90, 0xE9, 0xF3, 0x02, 0x00, 0x00}, 6, true},
    {"P9 live-level GUID mismatch (B)", 0x8CC149,
        {0x0F, 0x84, 0xA9, 0x02, 0x00, 0x00},
        {0x90, 0xE9, 0xA9, 0x02, 0x00, 0x00}, 6, true},
    // P10: what P8/P9 accept can be a package with no generations; Compute
    // must not index generation -1 for it. See the note below.
    {"P10 Compute: generation 0 unsigned", 0xCACBB,
        {0x7D, 0x63}, {0x73, 0x63}, 2, true},
};
static const size_t N_PATCHES = sizeof(g_patches) / sizeof(g_patches[0]);

// A landmark inside the same function: the `lea rdx,[rip+...]` that loads the
// "NoDownload" localization key. If this does not match, the addresses above
// belong to some other build and nothing is written.
static const uintptr_t RVA_LANDMARK = 0x65FDE6;
static const uint8_t   LANDMARK[]   = {0x48, 0x8D, 0x15, 0xE3, 0xF9, 0xBB, 0x00};

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

static void hexline(char* out, size_t cap, const uint8_t* p, size_t n) {
    size_t off = 0;
    for (size_t i = 0; i < n && off + 3 < cap; ++i)
        off += (size_t)_snprintf_s(out + off, cap - off, _TRUNCATE, "%02x ", p[i]);
}

static bool apply(Patch& p) {
    uint8_t* at = g_base + p.rva;
    char have[64] = {0}, want[64] = {0};
    hexline(have, sizeof(have), at, p.len);
    hexline(want, sizeof(want), p.want, p.len);

    if (memcmp(at, p.expect, p.len) != 0) {
        char exp[64] = {0};
        hexline(exp, sizeof(exp), p.expect, p.len);
        L("SKIP  %-34s rva %llx: have [%s] expected [%s]",
          p.name, (unsigned long long)p.rva, have, exp);
        return false;
    }
    DWORD old = 0;
    if (!VirtualProtect(at, p.len, PAGE_EXECUTE_READWRITE, &old)) {
        L("FAIL  %-34s rva %llx: VirtualProtect %lu",
          p.name, (unsigned long long)p.rva, GetLastError());
        return false;
    }
    memcpy(at, p.want, p.len);
    VirtualProtect(at, p.len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), at, p.len);
    L("PATCH %-34s rva %llx: [%s] -> [%s]",
      p.name, (unsigned long long)p.rva, have, want);
    return true;
}

static DWORD WINAPI Thread(LPVOID) {
    char path[MAX_PATH];
    GetModuleFileNameA(GetModuleHandleA(nullptr), path, MAX_PATH);
    char* slash = strrchr(path, '\\');
    if (slash) *slash = 0;
    g_log = LempOpenDebugLog("join_patch");

    g_base = (uint8_t*)GetModuleHandleA("MassEffect3.exe");
    if (!g_base) g_base = (uint8_t*)GetModuleHandleA(nullptr);

    L("== join_patch ==  pid %lu  base %p", GetCurrentProcessId(), (void*)g_base);
    L("Neutralises UE3's NoDownload refusal in UNetPendingLevel::NotifyReceivedText.");
    L("WRITES TO GAME MEMORY: up to 6 bytes in .text, in memory only.");

    // Diagnostic mode: drop a file called join_patch_diag.txt next to the exe
    // and only P1-P3 are applied. That is deliberately the set that stops the
    // refusal but leaves the download attempt in place — which is what made the
    // client NAME the package it could not resolve. The full set is silent by
    // design, so there has to be a way back to the noisy version without a
    // rebuild between runs.
    char diag[MAX_PATH];
    _snprintf_s(diag, sizeof(diag), _TRUNCATE, "%s\\join_patch_diag.txt", path);
    if (GetFileAttributesA(diag) != INVALID_FILE_ATTRIBUTES) {
        for (size_t i = 3; i < N_PATCHES; ++i) g_patches[i].enabled = false;
        L("DIAG MODE (join_patch_diag.txt present): P1-P3 only.");
        L("The client will refuse again, but it will name the package first.");
    }

    uint8_t* lm = g_base + RVA_LANDMARK;
    if (IsBadReadPtr(lm, sizeof(LANDMARK)) ||
        memcmp(lm, LANDMARK, sizeof(LANDMARK)) != 0) {
        char have[64] = {0};
        if (!IsBadReadPtr(lm, sizeof(LANDMARK)))
            hexline(have, sizeof(have), lm, sizeof(LANDMARK));
        L("FAIL: landmark at rva %llx does not match (have [%s]).",
          (unsigned long long)RVA_LANDMARK, have);
        L("This is not the build these offsets were read from. Nothing patched.");
        return 0;
    }
    L("landmark ok: the NoDownload key load is where it was read from.");

    int done = 0;
    for (size_t i = 0; i < N_PATCHES; ++i) {
        if (!g_patches[i].enabled) { L("off   %s", g_patches[i].name); continue; }
        if (apply(g_patches[i])) ++done;
    }
    L("%d/%zu patches applied. A joining client will no longer be refused here.",
      done, N_PATCHES);
    return 0;
}

void JoinPatchStart() {
    CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
}
