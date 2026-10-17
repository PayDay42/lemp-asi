// shield_regen — shields and barriers regenerate at their stated rate at any
//                frame rate.
//
// WRITES TO GAME MEMORY: one UFunction's Script array, SFXShield_Base.Tick's
// (UStruct::Script: data pointer, count, capacity). The new bytecode lives in
// a buffer from the game's own allocator; the old buffer is left allocated.
// Nothing else is written, nothing is hooked, nothing is called but the
// game's TArray resize (to allocate). Control: LEMP\noshieldfix.txt.
//
// ---------------------------------------------------------------------------
// The bug [V, decompiled from SFXGame.pcc, LE3 and the 2012 original alike]
//
// SFXShield_Base.Tick, once the regen delay has run out:
//
//     SetCurrentShields(FMin(MaxVal, CurrentShields
//                            + GetShieldRegenRate() * MaxVal * DeltaSeconds));
//
// and SetCurrentShields (final) stores whole points:
//
//     CurrentShields = float(Max(int(NewCurrentShields), 0));
//
// so every frame keeps floor(rate * MaxShields * DeltaSeconds) points. When a
// frame's share is below one point, regen stops; above that, it runs at
// floor(share) * fps points a second, not rate * MaxShields. With 500 shields
// at the 2012 MP rates (0.33 / 0.286 / 0.25 of the maximum per second) regen
// stops above 165 / 143 / 125 fps. The original game ran capped near 60 fps,
// where most of a frame's share survived; this game does not cap.
//
// Only the authority's Tick writes (SetCurrentShields checks Role), so in
// multiplayer the host's frame rate decides it for every player and enemy.
// Every shield type inherits this Tick (player barriers and tech shields are
// empty subclasses of SFXShield_Player, which does not override it).
//
// The int() is kept: it is also on the damage path (ApplyDamageToShields),
// where it decides what a sub-point remnant after a hit does. Only regen
// changes.
//
// ---------------------------------------------------------------------------
// The fix: carry the fraction in ShieldRegenTimer
//
// ShieldRegenTimer counts the regen delay down; regen runs only while it is
// <= 0, and every hit sets it to the (positive) delay again
// (ResetShieldRegenTimer). So while regen runs it is free to hold the
// remainder as a value in (-1, 0], and a hit clears that remainder exactly
// when it should be cleared. Its only other reader (SFXDoor) reads it only
// when it is > 0. No new variable is needed, which a running game could not
// add. The regen statement becomes:
//
//     ShieldRegenTimer -= GetShieldRegenRate() * MaxVal * DeltaSeconds;
//     SetCurrentShields(FMin(MaxVal, CurrentShields - ShieldRegenTimer));
//     ShieldRegenTimer = ShieldRegenTimer % 1.0;
//
// CurrentShields is whole on the authority, so the points SetCurrentShields
// drops are exactly the fraction of -ShieldRegenTimer, which % keeps (fmod
// keeps the dividend's sign). On a client SetCurrentShields does nothing and
// % keeps the timer within (-1, 0]; the client's shields come from
// replication as before. Simulated against the original at 30-500 fps with
// frame-time jitter: 99-100% of the stated refill rate, where the original
// never refills a 500-point shield on the hardest rate at 240 fps.
//
// How it is written [V, bytecode dumped with Legendary Explorer's parser]:
// in memory Tick is 631 bytes (439 on disk: object references widen from 4 to
// 8 bytes) and the regen statement is bytes 335-400. A new 746-byte buffer
// gets the original, the statement replaced by EX_Jump to 631 and EX_Nothing
// padding, then the new statements at 631 and EX_Jump back to 401. No
// existing jump target moves. Object and name references in the new code are
// copied from the original's own (the same properties, the same function), so
// the function references nothing it did not already reference.
//
// The buffer pointer is swapped with one aligned 4-byte store of its lower
// half (the upper halves must match; see Patch); a Tick already running keeps
// reading the old buffer, which is never freed for that reason (631 bytes).
// The game frees the new one like any Script array. The collector does not
// read bytecode (UStruct keeps ScriptObjectReferences for that), and the new
// code references nothing the old did not.
//
// Refused, leaving everything as it is, unless all of this holds:
//   - Tick is 631 bytes and its bytecode, with the 53 reference slots zeroed,
//     hashes as LE3's; SetCurrentShields (found through Tick's own reference
//     to it) is 61 bytes and hashes as LE3's. Another mod that changed either
//     (a community fix for the same bug, say) is left alone: patching over it
//     could count the fraction twice.
//   - the reference slots the new code copies point at objects of the
//     expected names, and agree with the other slots naming the same object.
//   - the game's TArray resize has the expected prologue.
// It runs once, from its own thread, after the engine has started.
// ---------------------------------------------------------------------------
#include <windows.h>
#include "lemp.h"
#include "safe_read.h"  // guard-page-safe IsBadReadPtr/IsBadWritePtr
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

const uintptr_t RVA_NAME_POOLS = 0x17B33D0;    // as mp_menu / mp_save
const uintptr_t RVA_OBJOBJECTS = 0x1887E40;
const uintptr_t RVA_ARRAY_RESIZE = 0x73440;    // as lemp_voice
const uint8_t ARRAY_RESIZE_PROLOGUE[9] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9};
const size_t OFF_SCRIPT = 0x7C;                // UStruct::Script (LExSDK Core_classes.h)

const DWORD START_DELAY_MS = 10000;
const DWORD POLL_MS = 2000;
const int   POLLS = 150;                       // ~5 minutes

// SFXShield_Base.Tick in memory: size, the masked hash, the reference slots.
const int      TICK_SIZE = 631;
const uint64_t TICK_HASH = 0xa2044dd38128fcd3ull;
const int TICK_SLOTS[] = {1, 16, 25, 34, 49, 65, 75, 85, 102, 116, 125, 138, 152, 162, 175, 186,
                          204, 213, 221, 232, 244, 252, 263, 276, 285, 296, 306, 316, 325, 336,
                          346, 356, 367, 379, 389, 406, 415, 425, 443, 458, 468, 478, 493, 503,
                          513, 522, 542, 561, 578, 588, 598, 611, 620};
const int SET_SIZE = 61;
const uint64_t SET_HASH = 0xaea23ede06c4b022ull;
const int SET_SLOTS[] = {7, 22, 36, 47};

// The regen statement, and the slots the new code copies (memory offsets).
const int STMT_BEGIN = 335, STMT_END = 401;
const int SLOT_TIMER = 102, SLOT_TIMER2 = 116;               // ShieldRegenTimer
const int SLOT_DELTA = 389, SLOT_DELTA2 = 125;               // Tick.DeltaSeconds
const int SLOT_MAXVAL = 346, SLOT_MAXVAL2 = 379;             // Tick.MaxVal
const int SLOT_CURRENT = 356, SLOT_CURRENT2 = 406;           // CurrentShields
const int SLOT_SETFN = 336;                                  // SetCurrentShields
const int SLOT_RATENAME = 367;                               // EX_NamedFunction GetShieldRegenRate: FName + vtable index

// Tokens (UE3 / LE3 bytecode).
const uint8_t EX_Jump = 0x06, EX_Nothing = 0x0B, EX_Let = 0x0F, EX_FinalFunction = 0x1C,
              EX_FloatConst = 0x1E, EX_LocalFloatVariable = 0x5B,
              EX_InstanceFloatVariable = 0x5F, EX_NamedFunction = 0x65, EX_EndFunctionParms = 0x16;
const uint8_t NAT_MultiplyFF = 171, NAT_PercentFF = 173, NAT_SubtractFF = 175,
              NAT_SubtractEqualFF = 185, NAT_FMin = 244;

#pragma pack(push, 1)
struct PackedIndex { uint32_t Offset : 20, Length : 9, Bits : 3; };
struct FNameEntry { PackedIndex Index; FNameEntry* HashNext; char AnsiName[1]; };
struct FName      { uint32_t Offset : 29, Chunk : 3; int32_t Number; };
template <class T> struct TArray { T* Data; int32_t Count, Max; };
struct UObject {
    void*    VfTable;   int32_t InternalIndex; uint64_t ObjectFlags;
    void*    HashNext;  void*   HashOuterNext; void*    StateFrame;
    void*    Linker;    void*   LinkerIndex;   int32_t  NetIndex;
    UObject* Outer;     FName   Name;          UObject* Class;
    UObject* ObjectArchetype;
};
#pragma pack(pop)

typedef void (*ArrayResizeFn)(void* array, int prev, int n, int elemSize);

uint8_t*     g_base = nullptr;
uint8_t*     g_end = nullptr;
FNameEntry** g_pools = nullptr;
TArray<UObject*>* g_objs = nullptr;

void L(const char* fmt, ...) {
    va_list a; va_start(a, fmt);
    LempLogV("shield_regen", fmt, a);
    va_end(a);
}

const char* NameOf(const FName& n) {
    if (!g_pools || n.Chunk > 7) return "<bad>";
    FNameEntry* c = g_pools[n.Chunk];
    if (!c) return "<null>";
    auto* e = (FNameEntry*)((uint8_t*)c + n.Offset);
    return IsBadReadPtr(e, 16) ? "<unreadable>" : e->AnsiName;
}
bool Readable(const void* p, size_t n) { return p && !IsBadReadPtr(p, n); }
const char* ObjName(const UObject* o) { return Readable(o, sizeof(UObject)) ? NameOf(o->Name) : "<none>"; }
bool Is(const UObject* o, const char* cls, const char* name, const char* outer) {
    if (!Readable(o, sizeof(UObject)) || !Readable(o->Class, sizeof(UObject))) return false;
    if (_stricmp(NameOf(o->Class->Name), cls) != 0 || _stricmp(NameOf(o->Name), name) != 0) return false;
    return !outer || _stricmp(ObjName(o->Outer), outer) == 0;
}

uint64_t MaskedHash(const uint8_t* code, int size, const int* slots, size_t nslots) {
    uint64_t h = 0xcbf29ce484222325ull;
    size_t s = 0;
    for (int i = 0; i < size; ++i) {
        while (s < nslots && i >= slots[s] + 8) ++s;
        uint8_t b = (s < nslots && i >= slots[s]) ? 0 : code[i];
        h = (h ^ b) * 0x100000001b3ull;
    }
    return h;
}
// On a refusal: the bytes found, so the next log shows what differs.
void Dump(const char* what, const uint8_t* code, int size) {
    char line[16 * 3 + 1];
    for (int i = 0; i < size; i += 16) {
        int n = size - i < 16 ? size - i : 16;
        for (int j = 0; j < n; ++j) snprintf(line + j * 3, 4, "%02x ", code[i + j]);
        L("  %s %4d: %s", what, i, line);
    }
}
UObject* PtrAt(const uint8_t* code, int off) { UObject* p; memcpy(&p, code + off, 8); return p; }

// SFXShield_Base.Tick: a Function named Tick whose outer is the class SFXShield_Base.
UObject* FindTick() {
    if (!Readable(g_objs, sizeof(*g_objs))) return nullptr;
    int n = g_objs->Count;
    UObject** data = g_objs->Data;
    if (n <= 0 || !Readable(data, (size_t)n * sizeof(UObject*))) return nullptr;
    for (int i = 0; i < n; ++i) {
        if ((i & 0xFFFF) == 0 && lemp::Exiting()) return nullptr;
        UObject* o = data[i];
        if (!o || IsBadReadPtr(o, sizeof(UObject))) continue;
        if (_stricmp(NameOf(o->Name), "Tick") != 0) continue;   // cheap test first
        if (!Is(o, "Function", "Tick", "SFXShield_Base")) continue;
        if (Is(o->Outer, "Class", "SFXShield_Base", "SFXGame")) return o;
    }
    return nullptr;
}

bool CheckRef(const uint8_t* code, int slot, int twin, const char* cls, const char* name) {
    UObject* p = PtrAt(code, slot);
    if (twin >= 0 && PtrAt(code, twin) != p) {
        L("REFUSED: slots %d and %d name different objects (%p, %p)", slot, twin, (void*)p, (void*)PtrAt(code, twin));
        return false;
    }
    if (!Is(p, cls, name, nullptr)) {
        L("REFUSED: slot %d is %s '%s', not %s '%s'", slot,
          Readable(p, sizeof(UObject)) && Readable(p->Class, sizeof(UObject)) ? NameOf(p->Class->Name) : "?", ObjName(p), cls, name);
        return false;
    }
    return true;
}

struct Emit {
    uint8_t* out; int pos;
    void b(uint8_t v) { out[pos++] = v; }
    void copy(const uint8_t* src, int n) { memcpy(out + pos, src, n); pos += n; }
    void ref(uint8_t token, const uint8_t* code, int slot) { b(token); copy(code + slot, 8); }
    void jump(int target) { b(EX_Jump); b((uint8_t)(target & 0xFF)); b((uint8_t)(target >> 8)); }
};

void Patch() {
    UObject* tick = nullptr;
    for (int i = 0; i < POLLS && !tick; ++i) {
        if (lemp::Exiting()) { L("stopping: engine exiting"); return; }
        tick = FindTick();
        if (!tick) Sleep(POLL_MS);
    }
    if (!tick) { L("REFUSED: SFXShield_Base.Tick not found in GObjects"); return; }

    auto* script = (TArray<uint8_t>*)((uint8_t*)tick + OFF_SCRIPT);
    if (!Readable(script, sizeof(*script))) { L("REFUSED: Tick's Script unreadable"); return; }
    const uint8_t* code = script->Data;
    L("Tick %p: Script %p, %d bytes (max %d)", (void*)tick, (const void*)code, script->Count, script->Max);
    if (script->Count != TICK_SIZE || !Readable(code, TICK_SIZE)) {
        L("REFUSED: Tick is %d bytes, not %d (changed by another mod or a game patch)", script->Count, TICK_SIZE);
        return;
    }
    uint64_t h = MaskedHash(code, TICK_SIZE, TICK_SLOTS, sizeof(TICK_SLOTS) / sizeof(TICK_SLOTS[0]));
    if (h != TICK_HASH) {
        L("REFUSED: Tick's bytecode hashes %016llx, not %016llx (changed by another mod or a game patch)",
          (unsigned long long)h, (unsigned long long)TICK_HASH);
        Dump("Tick", code, TICK_SIZE);
        return;
    }
    if (!CheckRef(code, SLOT_TIMER, SLOT_TIMER2, "FloatProperty", "ShieldRegenTimer") ||
        !CheckRef(code, SLOT_DELTA, SLOT_DELTA2, "FloatProperty", "DeltaSeconds") ||
        !CheckRef(code, SLOT_MAXVAL, SLOT_MAXVAL2, "FloatProperty", "MaxVal") ||
        !CheckRef(code, SLOT_CURRENT, SLOT_CURRENT2, "FloatProperty", "CurrentShields") ||
        !CheckRef(code, SLOT_SETFN, -1, "Function", "SetCurrentShields"))
        return;
    if (_stricmp(NameOf(*(const FName*)(code + SLOT_RATENAME)), "GetShieldRegenRate") != 0) {
        L("REFUSED: the regen statement does not call GetShieldRegenRate");
        return;
    }

    // SetCurrentShields must still truncate: the carry assumes it does.
    UObject* setFn = PtrAt(code, SLOT_SETFN);
    auto* setScript = (TArray<uint8_t>*)((uint8_t*)setFn + OFF_SCRIPT);
    if (!Readable(setScript, sizeof(*setScript)) || setScript->Count != SET_SIZE || !Readable(setScript->Data, SET_SIZE)) {
        L("REFUSED: SetCurrentShields is %d bytes, not %d", Readable(setScript, sizeof(*setScript)) ? setScript->Count : -1, SET_SIZE);
        return;
    }
    h = MaskedHash(setScript->Data, SET_SIZE, SET_SLOTS, sizeof(SET_SLOTS) / sizeof(SET_SLOTS[0]));
    if (h != SET_HASH) {
        L("REFUSED: SetCurrentShields hashes %016llx, not %016llx", (unsigned long long)h, (unsigned long long)SET_HASH);
        Dump("SetCurrentShields", setScript->Data, SET_SIZE);
        return;
    }

    uint8_t* resize = g_base + RVA_ARRAY_RESIZE;
    if (!Readable(resize, sizeof(ARRAY_RESIZE_PROLOGUE)) ||
        memcmp(resize, ARRAY_RESIZE_PROLOGUE, sizeof(ARRAY_RESIZE_PROLOGUE)) != 0) {
        L("REFUSED: the TArray resize at rva 0x%llx is not the expected code", (unsigned long long)RVA_ARRAY_RESIZE);
        return;
    }

    // Build the new script in a local first, then copy it into the game's buffer.
    uint8_t buf[TICK_SIZE + 128];
    memcpy(buf, code, TICK_SIZE);
    Emit e{buf, STMT_BEGIN};
    e.jump(TICK_SIZE);
    while (e.pos < STMT_END) e.b(EX_Nothing);
    e.pos = TICK_SIZE;
    // ShieldRegenTimer -= GetShieldRegenRate() * MaxVal * DeltaSeconds;
    e.b(NAT_SubtractEqualFF);
    e.ref(EX_InstanceFloatVariable, code, SLOT_TIMER);
    e.b(NAT_MultiplyFF);
    e.b(NAT_MultiplyFF);
    e.b(EX_NamedFunction); e.copy(code + SLOT_RATENAME, 10); e.b(EX_EndFunctionParms);
    e.ref(EX_LocalFloatVariable, code, SLOT_MAXVAL);
    e.b(EX_EndFunctionParms);
    e.ref(EX_LocalFloatVariable, code, SLOT_DELTA);
    e.b(EX_EndFunctionParms);
    e.b(EX_EndFunctionParms);
    // SetCurrentShields(FMin(MaxVal, CurrentShields - ShieldRegenTimer));
    e.ref(EX_FinalFunction, code, SLOT_SETFN);
    e.b(NAT_FMin);
    e.ref(EX_LocalFloatVariable, code, SLOT_MAXVAL);
    e.b(NAT_SubtractFF);
    e.ref(EX_InstanceFloatVariable, code, SLOT_CURRENT);
    e.ref(EX_InstanceFloatVariable, code, SLOT_TIMER);
    e.b(EX_EndFunctionParms);
    e.b(EX_EndFunctionParms);
    e.b(EX_EndFunctionParms);
    // ShieldRegenTimer = ShieldRegenTimer % 1.0;
    e.b(EX_Let);
    e.ref(EX_InstanceFloatVariable, code, SLOT_TIMER);
    e.b(NAT_PercentFF);
    e.ref(EX_InstanceFloatVariable, code, SLOT_TIMER);
    e.b(EX_FloatConst); { float one = 1.0f; e.copy((const uint8_t*)&one, 4); }
    e.b(EX_EndFunctionParms);
    e.jump(STMT_END);
    const int newSize = e.pos;
    L("new Tick: %d bytes (regen statement %d-%d -> jump to %d, %d bytes appended)",
      newSize, STMT_BEGIN, STMT_END, TICK_SIZE, newSize - TICK_SIZE);

    // Script.Data sits at +0x7C: 4-byte aligned, not 8, so an 8-byte store can
    // straddle a cache line and the game thread's read of it could tear. Two
    // heap blocks almost always share the upper 32 bits; then only the lower
    // half changes, in one aligned 4-byte store, which cannot tear. If they do
    // not, try a few more allocations (the misses stay allocated, a few
    // hundred bytes), then refuse rather than risk it.
    const uint32_t oldHigh = (uint32_t)((uintptr_t)code >> 32);
    TArray<uint8_t> fresh{nullptr, 0, 0};
    for (int tries = 0; tries < 8; ++tries) {
        fresh = TArray<uint8_t>{nullptr, 0, 0};
        ((ArrayResizeFn)resize)(&fresh, 0, newSize, 1);
        if (!fresh.Data) { L("REFUSED: the game's allocator returned nothing"); return; }
        if ((uint32_t)((uintptr_t)fresh.Data >> 32) == oldHigh) break;
        L("allocation %p does not share the old buffer's upper half (%08x); again", (void*)fresh.Data, oldHigh);
    }
    if ((uint32_t)((uintptr_t)fresh.Data >> 32) != oldHigh) {
        L("REFUSED: no allocation shared the old buffer's upper 32 bits");
        return;
    }
    memcpy(fresh.Data, buf, newSize);

    if (lemp::Exiting()) { L("stopping: engine exiting"); return; }
    // Count and capacity first: nothing reads them while the function runs.
    // Then the data pointer's lower half, in one store; the old buffer stays
    // allocated for a Tick already running in it.
    script->Max = newSize;
    script->Count = newSize;
    MemoryBarrier();
    volatile uint32_t* dataLow = (volatile uint32_t*)((uint8_t*)tick + OFF_SCRIPT);   // little-endian: Data's lower half
    *dataLow = (uint32_t)(uintptr_t)fresh.Data;
    MemoryBarrier();
    L("PATCHED: SFXShield_Base.Tick's Script %p -> %p (old buffer kept)", (const void*)code, (void*)script->Data);
}

DWORD WINAPI Thread(LPVOID) {
    g_base = (uint8_t*)GetModuleHandleA("MassEffect3.exe");
    if (!g_base) g_base = (uint8_t*)GetModuleHandleA(nullptr);
    uint32_t peOff = *(uint32_t*)(g_base + 0x3C);
    g_end = g_base + *(uint32_t*)(g_base + peOff + 0x18 + 0x38);
    L("== shield_regen ==  pid %lu  base %p", GetCurrentProcessId(), (void*)g_base);
    L("WRITES TO GAME MEMORY: SFXShield_Base.Tick's Script array (once).");

    std::wstring off = LempDir() + L"\\noshieldfix.txt";
    if (GetFileAttributesW(off.c_str()) != INVALID_FILE_ATTRIBUTES) {
        L("LEMP\\noshieldfix.txt exists: nothing patched.");
        return 0;
    }
    Sleep(START_DELAY_MS);
    if (lemp::Exiting()) return 0;
    g_pools = (FNameEntry**)(g_base + RVA_NAME_POOLS);
    g_objs = (TArray<UObject*>*)(g_base + RVA_OBJOBJECTS);
    Patch();
    return 0;
}

}  // namespace

void ShieldRegenStart() {
    CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
}
