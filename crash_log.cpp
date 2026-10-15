// crash_log.asi — say WHERE the game died.
//
// WHY THIS EXISTS. This project has no log channel at all: `Launch.log` is in
// `.rdata` with no code referencing it, `LogInternal` and `ClientMessage` are
// silent, and the console prints nothing. So a
// crash has been, for four runs in a row, a single bit of information — "it
// crashed" — and every diagnosis has had to come from static reading plus a
// bisect that costs one game launch per hypothesis. Three of those runs were
// spent on hypotheses that reading could have ruled out and did not.
//
// This turns a crash into a faulting address, a module offset, and a trail of
// return addresses. Against a stripped, formerly-packed binary that is not a
// symbol name, but it IS an RVA, and the exe's `.pdata` maps RVAs to function
// bounds for all 78,374 functions of the unpacked exe, so an RVA is exactly
// the thing that can be looked up.
//
// READ-ONLY with one exception, the same one tick_hook already takes: it
// installs exception handlers. It reads the stack it is handed, the module
// header, and — at the moment of a crash only — the objects the registers
// point at, to name them. It writes nothing into the game.
//
// Part of lemp.asi, and the one module that always writes (lemp.h). In debug
// mode its file is opened at start, as it always was. Otherwise nothing is
// written until a crash is reported: the lines before it (the game's debug
// strings, non-fatal exceptions) are kept in memory, the last RING_LINES of
// them, and go into the file ahead of the report. A run that does not fault
// leaves no file.
//
// Build: ./build.sh   (lemp.asi)
#include <windows.h>
#include "lemp.h"
#include "safe_read.h"  // guard-page-safe IsBadReadPtr/IsBadWritePtr
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdarg>

static FILE*    g_log   = nullptr;
static uint8_t* g_base  = nullptr;
static uint8_t* g_end   = nullptr;
static int      g_fired = 0;
static int      g_other = 0;   // non-fatal first-chance lines written (capped)

// Where the files go, fixed at start so a crash computes nothing: the
// LEMP\logs folder and this process's crash_log_<pid>_<tick>.txt in it.
static wchar_t  g_logDir[MAX_PATH];
static wchar_t  g_logPath[MAX_PATH];

// Outside debug mode, the lines before a crash. Slots are claimed with an
// interlocked counter, not a lock: L() runs inside the exception handler, on
// whatever thread faulted.
static const int  RING_LINES = 200;
static char       g_ring[RING_LINES][256];
static volatile LONG g_ringNext = 0;

static void L(const char* fmt, ...)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    va_list ap;
    va_start(ap, fmt);
    if (g_log) {
        fprintf(g_log, "%02d:%02d:%02d.%03d  ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        vfprintf(g_log, fmt, ap);
        fputc('\n', g_log);
        fflush(g_log);   // flush EVERY line: the process is about to die
    } else {
        char* line = g_ring[(InterlockedIncrement(&g_ringNext) - 1) % RING_LINES];
        int n = snprintf(line, 256, "%02d:%02d:%02d.%03d  ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        vsnprintf(line + n, 256 - n, fmt, ap);
    }
    va_end(ap);
}

// The file, opened at the first crash report when it is not open already
// (debug mode opens it at start), with the remembered lines first.
static void OpenForCrash()
{
    if (g_log || !g_logPath[0]) return;
    g_log = _wfopen(g_logPath, L"w");
    if (!g_log) return;
    const LONG next = g_ringNext;
    const LONG first = next > RING_LINES ? next - RING_LINES : 0;
    fprintf(g_log, "== crash_log ==  pid %lu  (no debug mode: the %ld lines before the crash, then the report)\n",
            (unsigned long)GetCurrentProcessId(), (long)(next - first));
    for (LONG i = first; i < next; i++) fprintf(g_log, "%s\n", g_ring[i % RING_LINES]);
    fflush(g_log);
}

// Which module an address belongs to, and its offset within it.
//
// The interesting answer is almost always MassEffect3.exe + RVA, because that
// is what funcs.py can resolve. But a fault inside a Wwise or PhysX DLL is a
// completely different diagnosis, and printing the module name is what
// distinguishes them.
static void DescribeAddr(void* p, char* out, size_t cap)
{
    HMODULE mod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                           | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)p, &mod) && mod) {
        char name[MAX_PATH] = {0};
        GetModuleFileNameA(mod, name, sizeof(name) - 1);
        const char* base = strrchr(name, '\\');
        base = base ? base + 1 : name;
        snprintf(out, cap, "%s+0x%llx", base,
                 (unsigned long long)((uint8_t*)p - (uint8_t*)mod));
    } else {
        snprintf(out, cap, "0x%016llx <no module>", (unsigned long long)(uintptr_t)p);
    }
}

// ---------------------------------------------------------------------------
// Naming the objects in the registers.
//
// The join crash faults at
//
//     MassEffect3.exe+0x131f85  mov rax,[rbp+0x154]   ; UClass::ClassConstructor
//                   +0x131f8c  mov rcx,rbx            ; the object being built
//                   +0x131f8f  call rax               ; NULL -> rip=0
//
// inside UObject::StaticConstructObject. So at that fault rbp IS the class with
// no constructor and rbx the object it was building — and the only thing
// missing from four crash logs was their NAMES. Reading them is the difference
// between inferring which class it is and being told.
//
// Same layout and name-pool RVA as repl_probe.cpp. Every read is guarded; a
// register that does not hold an object prints as such.
// ---------------------------------------------------------------------------
static const uintptr_t RVA_NAME_POOLS = 0x17B33D0;
static const size_t    OFF_FIELD_SUPER = 0x60;     // UField::SuperField
static const size_t    OFF_CLASS_CTOR  = 0x154;    // UClass::ClassConstructor, per the fault

#pragma pack(push, 1)
struct PackedIndex { uint32_t Offset : 20, Length : 9, Bits : 3; };
struct FNameEntry { PackedIndex Index; FNameEntry* HashNext; char AnsiName[1]; };
struct FName      { uint32_t Offset : 29, Chunk : 3; int32_t Number; };
struct UObject {
    void*    VfTable;   int32_t InternalIndex; uint64_t ObjectFlags;
    void*    HashNext;  void*   HashOuterNext; void*    StateFrame;
    void*    Linker;    void*   LinkerIndex;   int32_t  NetIndex;
    UObject* Outer;     FName   Name;          UObject* Class;
    UObject* ObjectArchetype;
};
#pragma pack(pop)

static const char* NameOf(const FName& n)
{
    FNameEntry** pools = (FNameEntry**)(g_base + RVA_NAME_POOLS);
    if (IsBadReadPtr(pools, 8 * sizeof(void*)) || n.Chunk > 7) return "<bad>";
    FNameEntry* c = pools[n.Chunk];
    if (!c) return "<null>";
    auto* e = (FNameEntry*)((uint8_t*)c + n.Offset);
    return IsBadReadPtr(e, 16) ? "<unreadable>" : e->AnsiName;
}

static bool LooksLikeObject(const void* p)
{
    if (!p || (uintptr_t)p < 0x10000 || IsBadReadPtr(p, sizeof(UObject))) return false;
    const UObject* o = (const UObject*)p;
    // A UObject's first qword is a vtable inside the exe's image.
    return (uint8_t*)o->VfTable > g_base && (uint8_t*)o->VfTable < g_end;
}

static void PathOf(const UObject* o, char* out, size_t cap)
{
    const UObject* chain[12]; int n = 0;
    for (const UObject* p = o; p && n < 12 && LooksLikeObject(p); p = p->Outer) chain[n++] = p;
    out[0] = 0;
    for (int i = n - 1; i >= 0; i--) {
        size_t len = strlen(out);
        // FName.Number n > 0 is the "_<n-1>" instance suffix: without it every
        // SkeletalMeshActor_N printed as plain "SkeletalMeshActor".
        int num = chain[i]->Name.Number;
        if (num > 0) snprintf(out + len, cap - len, "%s%s_%d", len ? "." : "", NameOf(chain[i]->Name), num - 1);
        else         snprintf(out + len, cap - len, "%s%s", len ? "." : "", NameOf(chain[i]->Name));
    }
}

static void DescribeWwiseComponent(const UObject* o);

static void DescribeObject(const char* reg, const void* p)
{
    if (!LooksLikeObject(p)) { L("%s = %p  (not an object)", reg, p); return; }
    const UObject* o = (const UObject*)p;
    char path[512], cls[256] = "?";
    PathOf(o, path, sizeof(path));
    if (LooksLikeObject(o->Class)) snprintf(cls, sizeof(cls), "%s", NameOf(o->Class->Name));
    L("%s = %p  %s  class=%s  flags=%016llx", reg, p, path, cls,
      (unsigned long long)o->ObjectFlags);
    if (strcmp(cls, "WwiseAudioComponent") == 0) DescribeWwiseComponent(o);
    if (strcmp(cls, "Class") == 0) {
        const UObject* sup = *(UObject* const*)((const uint8_t*)o + OFF_FIELD_SUPER);
        void* ctor = IsBadReadPtr((const uint8_t*)o + OFF_CLASS_CTOR, 8)
                     ? nullptr : *(void* const*)((const uint8_t*)o + OFF_CLASS_CTOR);
        char spath[512] = "NULL";
        if (LooksLikeObject(sup)) PathOf(sup, spath, sizeof(spath));
        L("      SuperField=%s  ClassConstructor=%p%s", spath, ctor,
          ctor ? "" : "   <- NULL: this class can never be constructed");
    }
}

static const char* CodeName(DWORD c)
{
    switch (c) {
        case EXCEPTION_ACCESS_VIOLATION:      return "ACCESS_VIOLATION";
        case EXCEPTION_STACK_OVERFLOW:        return "STACK_OVERFLOW";
        case EXCEPTION_ILLEGAL_INSTRUCTION:   return "ILLEGAL_INSTRUCTION";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:    return "INT_DIVIDE_BY_ZERO";
        case EXCEPTION_PRIV_INSTRUCTION:      return "PRIV_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR:         return "IN_PAGE_ERROR";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "ARRAY_BOUNDS_EXCEEDED";
        case 0xE06D7363:                      return "C++ exception (throw)";
        default:                              return "?";
    }
}

// ---------------------------------------------------------------------------
// Values and objects, not just addresses.
//
// Firebase Jade crashes at MassEffect3.exe+0xcf7ef3, in Wwise's speaker panner
// (+0xcf7ea0): an unbounded search for the speaker sector holding a direction,
// which never ends when the direction is NaN.
// Two fixes chosen from reading the bank data changed nothing. So the log now
// captures what was on hand at the fault instead of what the data suggests:
//   - the XMM registers — the panner holds the direction in xmm6 (x) and
//     xmm7 (z), loaded from [r8] and [r8+8];
//   - the floats at r8 and at the speaker table (r12 = rcx at entry);
//   - every UObject reachable from the faulting thread's stack, directly or
//     one pointer away. UE3's Wwise integration uses the component pointer as
//     the AkGameObjectID, so the playing instance's game object — the emitter
//     — should be among them, named.
// Still read-only: every read goes through IsBadReadPtr.
// ---------------------------------------------------------------------------
static bool IsFinite(float f) { uint32_t u; memcpy(&u, &f, 4); return (u & 0x7f800000u) != 0x7f800000u; }

static void DumpFloats(const char* what, const void* p, int n)
{
    if (!p || IsBadReadPtr(p, n * 4)) { L("  %s @ %p: unreadable", what, p); return; }
    const float* f = (const float*)p;
    char line[512]; size_t len = 0;
    len += snprintf(line + len, sizeof(line) - len, "  %s @ %p:", what, p);
    for (int i = 0; i < n && len < sizeof(line) - 24; i++)
        len += snprintf(line + len, sizeof(line) - len, " %g%s", f[i], IsFinite(f[i]) ? "" : "!");
    L("%s", line);
}

static void ReportValues(const CONTEXT* cx)
{
    L("xmm registers (low 4 floats; '!' marks non-finite):");
    const M128A* x = &cx->Xmm0;
    for (int i = 0; i < 16; i++) {
        char name[8]; snprintf(name, sizeof(name), "xmm%d", i);
        DumpFloats(name, &x[i], 4);
    }
    L("memory at registers (as floats):");
    DumpFloats("[r8]  ", (const void*)cx->R8, 8);
    DumpFloats("[r12] ", (const void*)cx->R12, 16);
    DumpFloats("[rcx] ", (const void*)cx->Rcx, 8);
    DumpFloats("[rdi] ", (const void*)cx->Rdi, 16);
    DumpFloats("[rbx] ", (const void*)cx->Rbx, 16);
}

// A WwiseAudioComponent's own idea of where it is. A capture named
// BioD_MPJngl's SkeletalMeshActor.WwiseAudioComponent as the only real object
// on the audio thread's stack at the NaN-direction fault, and this component
// follows a bone of its owner's skeletal mesh (m_nAttachBoneIndex). Offsets
// from LExSDK/LE3 (WwiseAudio_classes.h, Engine_classes.h).
static const size_t OFF_AC_OWNER       = 0x78;    // UActorComponent::Owner
static const size_t OFF_ACTOR_LOCATION = 0x108;   // AActor::Location (FVector)
static const size_t OFF_ACTOR_ROTATION = 0x114;   // AActor::Rotation (3 x int)
static const size_t OFF_WAC_LOCATION   = 0xF0;    // location, Orientation, ComponentLocation,
                                                  // ComponentOrientation, CachedLastPosition,
                                                  // CachedLastOrientation: 6 FVectors to 0x138
static const size_t OFF_WAC_SKELCOMP   = 0x138;   // m_OwnerSkelMeshComponent
static const size_t OFF_WAC_BONE       = 0x148;   // m_nAttachBoneIndex
static const size_t OFF_WAC_FLAGS      = 0x188;   // bUseOwnerLocation = bit 0

static void DescribeWwiseComponent(const UObject* o)
{
    const uint8_t* b = (const uint8_t*)o;
    if (IsBadReadPtr(b, 0x190)) return;
    static const char* names[6] = { "location", "Orientation", "ComponentLocation",
                                    "ComponentOrientation", "CachedLastPosition", "CachedLastOrientation" };
    for (int k = 0; k < 6; k++) {
        const float* v = (const float*)(b + OFF_WAC_LOCATION + 12 * k);
        L("      %-22s %g %g %g%s", names[k], v[0], v[1], v[2],
          (IsFinite(v[0]) && IsFinite(v[1]) && IsFinite(v[2])) ? "" : "   <- NON-FINITE");
    }
    L("      m_nAttachBoneIndex=%d  bUseOwnerLocation=%u",
      *(const int32_t*)(b + OFF_WAC_BONE), *(const uint32_t*)(b + OFF_WAC_FLAGS) & 1u);
    const UObject* skel = *(UObject* const*)(b + OFF_WAC_SKELCOMP);
    char path[512] = "NULL";
    if (LooksLikeObject(skel)) PathOf(skel, path, sizeof(path));
    L("      m_OwnerSkelMeshComponent=%s", path);
    const UObject* owner = *(UObject* const*)(b + OFF_AC_OWNER);
    if (LooksLikeObject(owner) && !IsBadReadPtr((const uint8_t*)owner + OFF_ACTOR_ROTATION, 12)) {
        PathOf(owner, path, sizeof(path));
        const float*   loc = (const float*)((const uint8_t*)owner + OFF_ACTOR_LOCATION);
        const int32_t* rot = (const int32_t*)((const uint8_t*)owner + OFF_ACTOR_ROTATION);
        L("      Owner=%s  Location=%g %g %g%s  Rotation=%d %d %d", path, loc[0], loc[1], loc[2],
          (IsFinite(loc[0]) && IsFinite(loc[1]) && IsFinite(loc[2])) ? "" : "   <- NON-FINITE",
          rot[0], rot[1], rot[2]);
    } else {
        L("      Owner=%p (not an object)", (const void*)owner);
    }
}

static void ReportStackObjects(const CONTEXT* cx)
{
    L("objects reachable from the stack (direct, or one pointer away):");
    const void* seen[256]; int nseen = 0, lines = 0;
    auto once = [&](const void* o) {
        for (int k = 0; k < nseen; k++) if (seen[k] == o) return false;
        if (nseen < 256) seen[nseen++] = o;
        return true;
    };
    uint8_t** sp = (uint8_t**)cx->Rsp;
    for (int i = 0; i < 1024 && lines < 80; i++) {
        if (IsBadReadPtr(sp + i, sizeof(void*))) break;
        uint8_t* v = sp[i];
        if ((uintptr_t)v < 0x10000 || (v >= g_base && v < g_end)) continue;
        char tag[64];
        if (LooksLikeObject(v)) {
            if (!once(v)) continue;
            snprintf(tag, sizeof(tag), "[rsp+%04x]", (unsigned)(i * 8));
            DescribeObject(tag, v); lines++;
            continue;
        }
        // One hop: a readable heap block (a Wwise playback instance, a sound
        // params struct...) whose fields may hold the game object.
        if (IsBadReadPtr(v, 0x200)) continue;
        uint8_t** blk = (uint8_t**)v;
        for (int j = 0; j < 0x40 && lines < 80; j++) {
            uint8_t* w = blk[j];
            if (!LooksLikeObject(w) || !once(w)) continue;
            snprintf(tag, sizeof(tag), "[rsp+%04x]->+%03x", (unsigned)(i * 8), (unsigned)(j * 8));
            DescribeObject(tag, w); lines++;
        }
    }
    if (!lines) L("    (none)");
}

// A binary snapshot of the faulting thread's stack and of memory two pointer
// hops out, for offline search. The Jade NaN-direction crash
// defeated two rounds of naming objects: the emitter is a Wwise voice, and
// what identifies a voice is its sound's 32-bit Wwise ID, held by the playback
// instance a pointer or two from the stack. Every ID the DLC's banks define is
// known offline, so a search of this snapshot names the sound (and its bank)
// without knowing a single Wwise struct layout.
// Format: repeated records {u64 address, u32 length, bytes}. Read-only.
static void DumpMemorySnapshot(const CONTEXT* cx)
{
    // v2 (after the first try died mid-dump with a 0-byte file): every
    // read goes through ReadProcessMemory on our own process, which FAILS
    // instead of faulting when another thread frees the memory between check
    // and read; every record is written straight through with WriteFile, so a
    // process that dies mid-dump still leaves what was written.
    wchar_t path[MAX_PATH];
    _snwprintf(path, MAX_PATH, L"%ls\\crash_mem_%lu_%lu.bin", g_logDir,
               (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
    path[MAX_PATH - 1] = 0;
    HANDLE f = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (f == INVALID_HANDLE_VALUE) { L("memory snapshot: cannot open %ls", path); return; }
    L("memory snapshot: writing %ls", path);
    HANDLE self = GetCurrentProcess();

    static uintptr_t seen[16384];                 // open-addressing set of dumped blocks
    memset(seen, 0, sizeof(seen));
    auto add = [&](uintptr_t a) {
        size_t h = (a >> 4) * 0x9E3779B97F4A7C15ull >> 50;   // 14 bits
        for (size_t k = 0; k < 16384; k++) {
            size_t s = (h + k) & 16383;
            if (seen[s] == a) return false;
            if (!seen[s]) { seen[s] = a; return true; }
        }
        return false;
    };
    const uint32_t BLK = 0x100;
    static uint8_t buf[0x1000];
    static uintptr_t queue[12000]; int qn = 0, qi = 0, blocks = 0;
    auto rd = [&](uintptr_t a, uint32_t len) {
        SIZE_T got = 0;
        return ReadProcessMemory(self, (LPCVOID)a, buf, len, &got) && got == len;
    };
    auto rec = [&](uintptr_t a, uint32_t len) {       // buf holds the bytes
        uint8_t hdr[12]; uint64_t a64 = a; memcpy(hdr, &a64, 8); memcpy(hdr + 8, &len, 4);
        DWORD w; WriteFile(f, hdr, 12, &w, nullptr); WriteFile(f, buf, len, &w, nullptr);
    };
    auto consider = [&](uintptr_t v, int depth) {
        if (v < 0x10000 || (v & 7) || v > 0x00007fffffffffffull
            || ((uint8_t*)v >= g_base && (uint8_t*)v < g_end)) return;
        if (qn >= 12000 || !add(v)) return;
        queue[qn++] = (v << 2) | (uintptr_t)depth;    // depth packed in the low bits (v is 8-aligned)
    };

    // Level 0: the stack itself, generously.
    uintptr_t lo = cx->Rsp - 0x200, hi = cx->Rsp + 0x3000;
    for (uintptr_t a = lo; a < hi; a += 0x800) {
        if (!rd(a, 0x800)) continue;
        rec(a, 0x800);
        for (uint32_t o = 0; o < 0x800; o += 8) { uintptr_t v; memcpy(&v, buf + o, 8); consider(v, 1); }
    }
    const DWORD64 regs[] = { cx->Rax, cx->Rbx, cx->Rcx, cx->Rdx, cx->Rsi, cx->Rdi, cx->Rbp,
                             cx->R8, cx->R9, cx->R10, cx->R11, cx->R12, cx->R13, cx->R14, cx->R15 };
    for (DWORD64 r : regs) consider((uintptr_t)r, 1);

    // Levels 1 and 2.
    while (qi < qn && blocks < 10000) {
        uintptr_t v = queue[qi] >> 2; int depth = (int)(queue[qi] & 3); qi++;
        if (!rd(v, BLK)) continue;
        rec(v, BLK); blocks++;
        if (depth < 2)
            for (uint32_t o = 0; o < BLK; o += 8) { uintptr_t w; memcpy(&w, buf + o, 8); consider(w, depth + 1); }
    }
    CloseHandle(f);
    L("memory snapshot: done  (stack 0x%llx..0x%llx, %d heap blocks of 0x%x, 2 hops)",
      (unsigned long long)lo, (unsigned long long)hi, blocks, BLK);
}

static void Report(EXCEPTION_POINTERS* ep, const char* where)
{
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord) return;
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    CONTEXT*          cx = ep->ContextRecord;

    OpenForCrash();
    char buf[512];
    L("");
    L("################ CRASH (%s) ################", where);
    L("code    0x%08lx  %s", (unsigned long)er->ExceptionCode, CodeName(er->ExceptionCode));
    DescribeAddr(er->ExceptionAddress, buf, sizeof(buf));
    L("at      %s", buf);

    // For an access violation the record carries what it tried to touch and
    // whether it was a read or a write. A read of a small address is a null
    // dereference and names its own bug; a read of something like
    // 0xdddddddd is a use-after-free.
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2) {
        const ULONG_PTR op = er->ExceptionInformation[0];
        L("tried   %s 0x%016llx%s",
          op == 0 ? "READ" : (op == 1 ? "WRITE" : "EXECUTE"),
          (unsigned long long)er->ExceptionInformation[1],
          er->ExceptionInformation[1] < 0x10000 ? "   <- NULL DEREFERENCE" : "");
    }

    // Is the engine already tearing itself down? GCallbackEvent (rva 0x17d5648)
    // is set once by appInit and zeroed only by appPreExit (+0x11a650), whose
    // only callers are WinMain's exit and seven appErrorf sites in
    // UnSkeletalAnim.cpp — and those RETURN, so the game ticks on into a NULL
    // GCallbackEvent (the Rio wave-1 fault at +0x59ac67, both machines).
    // NULL here means the fault is fallout; the cause is the error text in the
    // "debug:" lines above.
    if (g_base && g_end - g_base > 0x17df7a4) {
        void* const* cbe = (void* const*)(g_base + 0x17d5648);
        // NOT a pre-exit flag, despite the label: appInit sets it to 1 as well
        // as appPreExit, so it reads 1 all run. Kept
        // for continuity with older logs; GCallbackEvent is the exit signal.
        const int* exiting = (const int*)(g_base + 0x17df7a0);
        if (!IsBadReadPtr(cbe, sizeof(*cbe)) && !IsBadReadPtr(exiting, sizeof(*exiting)))
            L("engine  GCallbackEvent=%p  preexit-flag=%d%s", *cbe, *exiting,
              *cbe ? "" : "   <- appPreExit HAS RUN: an appErrorf fired first (see debug: lines)");
    }

    L("rip=%016llx rsp=%016llx rbp=%016llx",
      (unsigned long long)cx->Rip, (unsigned long long)cx->Rsp, (unsigned long long)cx->Rbp);
    L("rcx=%016llx rdx=%016llx r8 =%016llx r9 =%016llx",
      (unsigned long long)cx->Rcx, (unsigned long long)cx->Rdx,
      (unsigned long long)cx->R8,  (unsigned long long)cx->R9);
    L("rax=%016llx rbx=%016llx rsi=%016llx rdi=%016llx",
      (unsigned long long)cx->Rax, (unsigned long long)cx->Rbx,
      (unsigned long long)cx->Rsi, (unsigned long long)cx->Rdi);

    // What the registers point at. rbp/rbx first: at the StaticConstructObject
    // fault they are the constructor-less class and the object it was building.
    L("objects in registers:");
    DescribeObject("rbp", (void*)cx->Rbp);
    DescribeObject("rbx", (void*)cx->Rbx);
    DescribeObject("rcx", (void*)cx->Rcx);
    DescribeObject("rsi", (void*)cx->Rsi);
    DescribeObject("rdi", (void*)cx->Rdi);
    DescribeObject("r12", (void*)cx->R12);
    DescribeObject("r13", (void*)cx->R13);
    DescribeObject("r14", (void*)cx->R14);
    DescribeObject("r15", (void*)cx->R15);

    // The call trail, by scanning the stack rather than by unwinding.
    //
    // RtlCaptureStackBackTrace unwinds from the CURRENT frame, not from the
    // faulting context, so it describes this handler. StackWalk64 needs
    // symbols the stripped exe does not have. What does work on any binary is
    // to walk the stack upward and print every qword that lands inside the
    // executable's code range: return addresses are exactly that, so the
    // result is the call trail plus some noise, and the noise is obvious
    // because it does not repeat between runs.
    //
    // These are RVAs into MassEffect3.exe. The exe's .pdata resolves an RVA to
    // its enclosing function and that function's callers.
    L("stack scan — return addresses into MassEffect3.exe, innermost first:");
    uint8_t** sp = (uint8_t**)cx->Rsp;
    int shown = 0;
    for (int i = 0; i < 2048 && shown < 40; i++) {
        if (IsBadReadPtr(sp + i, sizeof(void*))) break;
        uint8_t* v = sp[i];
        if (v > g_base && v < g_end) {
            L("    [rsp+%04x]  MassEffect3.exe+0x%llx",
              (unsigned)(i * sizeof(void*)),
              (unsigned long long)(v - g_base));
            shown++;
        }
    }
    if (!shown) L("    (none — stack may be corrupt, or the fault is in another module)");

    ReportValues(cx);
    DumpMemorySnapshot(cx);   // before the slow object listing: the most useful data first
    ReportStackObjects(cx);
    L("################ END CRASH ################");
}

static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* ep)
{
    // First-chance handlers see EVERYTHING, including the exceptions a program
    // throws and handles on purpose. ME3 ships DirtySDK, Wwise and a C++
    // runtime, all of which throw in normal operation, so logging every
    // first-chance exception would bury the fatal one in noise.
    //
    // Filter to the codes that are actually fatal, and cap the count: a crash
    // inside a crash handler can otherwise fill a disk.
    const DWORD c = ep->ExceptionRecord->ExceptionCode;
    const bool fatal = c == EXCEPTION_ACCESS_VIOLATION
                    || c == EXCEPTION_ILLEGAL_INSTRUCTION
                    || c == EXCEPTION_PRIV_INSTRUCTION
                    || c == EXCEPTION_STACK_OVERFLOW
                    || c == EXCEPTION_IN_PAGE_ERROR
                    || c == EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
    // Faults raised INSIDE kernel32 are IsBadReadPtr probing memory and
    // catching its own exception — repl_probe does that thousands of times.
    // Counting them used up the 8-report cap before a real crash (once,
    // eight reports, all kernel32+0x20cef, and the map-load crash unlogged).
    if (fatal) {
        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        HMODULE at = nullptr;
        if (k32 && GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                                      | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                      (LPCSTR)ep->ExceptionRecord->ExceptionAddress, &at)
            && at == k32) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    if (fatal && g_fired < 8) {
        g_fired++;
        Report(ep, "first-chance");
    }
    // Every OTHER first-chance exception, one line each, capped. Added after
    // the lobby's Powers screen ended the process with nothing
    // here — no access violation, so a C++ exception (0xE06D7363), a
    // breakpoint (0x80000003, an assert), a fail-fast (0xC0000409) or the
    // like, which the filter above drops and which the game's own handler then
    // turns into a silent exit. Written as it happens, not at exit: a
    // TerminateProcess runs no exit hook.
    // OutputDebugString arrives as one of these, with the text in the record:
    // [0] = length in characters (with the NUL), [1] = the string. Log the
    // text. The game has no log, and appErrorf's
    // message reaches us this way or not at all — a Rio crash had its
    // cause printed 1.7 s before the fault, and we kept only the code. W is
    // raised first; A follows with the same text when nobody took W.
    if ((c == 0x4001000a || c == 0x40010006) && ep->ExceptionRecord->NumberParameters >= 2) {
        static int s_debug = 0;
        static bool s_lastWide = false;
        const ULONG_PTR n = ep->ExceptionRecord->ExceptionInformation[0];
        const void* s = (const void*)ep->ExceptionRecord->ExceptionInformation[1];
        const bool wide = c == 0x4001000a;
        if (!wide && s_lastWide) { s_lastWide = false; return EXCEPTION_CONTINUE_SEARCH; }
        s_lastWide = wide;
        if (s_debug >= 2000) return EXCEPTION_CONTINUE_SEARCH;
        s_debug++;
        char text[512];
        size_t len = n ? (size_t)n - 1 : 0, k = 0;
        if (len > sizeof(text) - 1) len = sizeof(text) - 1;
        if (s && !IsBadReadPtr(s, len * (wide ? 2 : 1))) {
            for (; k < len; k++) {
                unsigned ch = wide ? ((const wchar_t*)s)[k] : ((const unsigned char*)s)[k];
                if (!ch) break;
                text[k] = ch == '\r' || ch == '\n' ? ' ' : (ch < 0x20 || ch > 0x7e ? '?' : (char)ch);
            }
        }
        text[k] = 0;
        L("debug: %s", text);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (!fatal && g_other < 300) {
        g_other++;
        char where[MAX_PATH + 32];
        DescribeAddr(ep->ExceptionRecord->ExceptionAddress, where, sizeof(where));
        L("exc 0x%08lx at %s  (non-fatal first-chance #%d)", (unsigned long)c, where, g_other);
    }
    return EXCEPTION_CONTINUE_SEARCH;   // never swallow it; let the game die as it would
}

static LONG WINAPI UnhandledHandler(EXCEPTION_POINTERS* ep)
{
    Report(ep, "unhandled");
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI Init(LPVOID)
{
    const std::wstring& dir = LempLogDir();
    _snwprintf(g_logDir, MAX_PATH, L"%ls", dir.c_str());
    g_logDir[MAX_PATH - 1] = 0;
    _snwprintf(g_logPath, MAX_PATH, L"%ls\\crash_log_%lu_%lu.txt", g_logDir,
               (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
    g_logPath[MAX_PATH - 1] = 0;
    if (LempDebug()) g_log = _wfopen(g_logPath, L"w");

    g_base = (uint8_t*)GetModuleHandleA("MassEffect3.exe");
    if (!g_base) g_base = (uint8_t*)GetModuleHandleA(nullptr);
    uint32_t peOff = *(uint32_t*)(g_base + 0x3C);
    g_end = g_base + *(uint32_t*)(g_base + peOff + 0x18 + 0x38);   // SizeOfImage

    L("== crash_log ==  pid %lu  base %p  end %p",
      (unsigned long)GetCurrentProcessId(), (void*)g_base, (void*)g_end);
    L("Installs exception handlers and writes nothing into the game.");
    L("Addresses print as MassEffect3.exe+RVA; resolve with phase0/funcs.py.");
    L("Silence here means the process exited WITHOUT faulting — which is");
    L("itself a finding: a clean exit is not a crash.");

    // Both, deliberately. The vectored handler runs before any SEH frame, so
    // it sees the fault even if the game catches it; the unhandled filter is
    // the backstop for anything that reaches the top. BugSentry may replace
    // the unhandled filter, which is exactly why the vectored one is there.
    AddVectoredExceptionHandler(1, VectoredHandler);
    SetUnhandledExceptionFilter(UnhandledHandler);
    return 0;
}

void CrashLogStart()
{
    CreateThread(nullptr, 0, Init, nullptr, 0, nullptr);
}

// A normal exit (ExitProcess) says so; a TerminateProcess leaves no line.
// Only into a file already open: a clean exit is no reason to start one.
void CrashLogExit(bool processExit)
{
    if (g_log) L("process exiting (DLL_PROCESS_DETACH, %s)", processExit ? "ExitProcess" : "FreeLibrary");
}
