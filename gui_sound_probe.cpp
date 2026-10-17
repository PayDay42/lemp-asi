// gui_sound_probe — logs every SFXGUIInteraction.PlayGuiSound / StopGuiSound
// call: the sound's name, whether the native posted it, and the script
// function that called it. A diagnostic for the MP music, which is set
// through these two natives only (Play_mus_mp, Set_mus_gameplaymode_*,
// Set_mus_map_*); debug mode only.
//
// WRITES TO GAME MEMORY: two UFunction::Func pointers (PlayGuiSound's and
// StopGuiSound's), as mp_menu does for CallListFnc. Each wrapper calls the
// game's own native with the same arguments; it changes nothing the native
// sees.
//
// Reading the argument. A native called from script gets the CALLER's FFrame,
// its Code at the argument expression. The wrapper remembers Code, evaluates
// the expression with Stack.Step (GNatives[op], as the native itself does)
// into its own buffer, puts Code back where it was, and then calls the
// original, which evaluates it again. Only one-token reads are evaluated this
// way: a name literal, a local / instance / default variable. Anything else
// (a struct member, an array element, a call: any of which may contain a
// function call that must not run twice) is not touched, and the line says
// "<expr 0x..>" with the result. FFrame's
// layout (Node, Object, Code at consecutive qwords) is proven on the first
// call from script, as lemp_voice proves it: Code must point inside the
// calling function's own bytecode. A call that matches no layout (one from
// native code, with no script around it) is skipped, not counted against the
// proof; more than one matching layout turns argument reading off for good.
// Without a proven layout the wrapper reads nothing, calls the original and
// logs the result.
#include <windows.h>
#include "lemp.h"
#include "safe_read.h"
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

const uintptr_t RVA_NAME_POOLS    = 0x17B33D0;   // as mp_menu / repl_probe
const uintptr_t RVA_OBJOBJECTS    = 0x1887E40;
const size_t    OFF_FUNC_FUNC     = 0xD8;        // UFunction::Func
const size_t    OFF_STRUCT_SCRIPT = 0x7C;        // UStruct::Script (Data 8, Count 4, Max 4)

// UE3 opcodes the argument may start with for the wrapper to evaluate it.
const uint8_t EX_LocalVariable = 0x00, EX_InstanceVariable = 0x01, EX_DefaultVariable = 0x02,
              EX_NameConst = 0x21;

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

typedef void (*ExecFn)(UObject* self, uint8_t* stack, void* result);
typedef void (*NativeFn)(UObject* ctx, uint8_t* stack, void* result);

uint8_t*          g_base = nullptr;
uint8_t*          g_end  = nullptr;
FNameEntry**      g_pools = nullptr;
TArray<UObject*>* g_objs = nullptr;
void**            g_gnatives = nullptr;

struct Target {
    const char* name;
    UObject*    fn = nullptr;
    ExecFn      orig = nullptr;
    void*       hook = nullptr;
    int         rebinds = 0;
};
Target g_play{"PlayGuiSound"}, g_stop{"StopGuiSound"};

void L(const char* fmt, ...) {
    va_list a; va_start(a, fmt);
    LempLogV("gui_sound", fmt, a);
    va_end(a);
}
const char* NameOf(const FName& n) {
    if (!g_pools || n.Chunk > 7) return "<bad>";
    FNameEntry* c = g_pools[n.Chunk];
    if (!c) return "<null>";
    auto* e = (FNameEntry*)((uint8_t*)c + n.Offset);
    return IsBadReadPtr(e, 16) ? "<unreadable>" : e->AnsiName;
}
const char* ClassNameOf(UObject* o) {
    UObject* c = o ? o->Class : nullptr;
    return (c && !IsBadReadPtr(c, sizeof(UObject))) ? NameOf(c->Name) : "?";
}
bool InExe(void* p) { return (uint8_t*)p >= g_base && (uint8_t*)p < g_end; }

// --- the script stack (as lemp_voice) ---------------------------------------------------
size_t g_offCode = 0;                 // 0 = not proven yet
const size_t kUnproven = (size_t)-1;

bool CodeInsideNode(uint8_t* stack, size_t offCode) {
    if (IsBadReadPtr(stack + offCode - 16, 24)) return false;
    UObject* node = *(UObject**)(stack + offCode - 16);
    uint8_t* code = *(uint8_t**)(stack + offCode);
    if (!node || !code || IsBadReadPtr(node, OFF_STRUCT_SCRIPT + 16)) return false;
    const char* cn = ClassNameOf(node);
    if (_stricmp(cn, "Function") != 0 && _stricmp(cn, "State") != 0 && _stricmp(cn, "Class") != 0) return false;
    uint8_t* data; int32_t count;
    memcpy(&data, (uint8_t*)node + OFF_STRUCT_SCRIPT, 8);
    memcpy(&count, (uint8_t*)node + OFF_STRUCT_SCRIPT + 8, 4);
    return data && count > 0 && code >= data && code < data + count;
}
bool ProveFrame(uint8_t* stack) {
    if (g_offCode == kUnproven) return false;
    if (g_offCode) return CodeInsideNode(stack, g_offCode);
    static const size_t kTry[] = {0x28, 0x20, 0x30, 0x38};
    int hits = 0; size_t hit = 0;
    for (size_t off : kTry) if (CodeInsideNode(stack, off)) { ++hits; hit = off; }
    if (hits == 1) { g_offCode = hit; L("FFRAME: Code at +0x%zx, proven", hit); return true; }
    if (hits == 0) return false;   // not a call from script; try the next one
    g_offCode = kUnproven;
    L("FFRAME: %d candidate layouts: arguments will not be read", hits);
    return false;
}
uint8_t*& Code(uint8_t* stack) { return *(uint8_t**)(stack + g_offCode); }
UObject* FrameNode(uint8_t* stack) { return *(UObject**)(stack + g_offCode - 16); }
UObject* FrameObject(uint8_t* stack) { return *(UObject**)(stack + g_offCode - 8); }

int g_lines = 0;
const int kMaxLines = 4000;

void Wrap(Target& t, UObject* self, uint8_t* stack, void* result) {
    char arg[160] = "?";
    char from[160] = "?";
    if (g_gnatives && stack && ProveFrame(stack)) {
        UObject* node = FrameNode(stack);
        UObject* outer = node ? node->Outer : nullptr;
        snprintf(from, sizeof(from), "%s.%s", outer && !IsBadReadPtr(outer, sizeof(UObject)) ? NameOf(outer->Name) : "?", node ? NameOf(node->Name) : "?");
        uint8_t* saved = Code(stack);
        uint8_t op = saved ? *saved : 0xFF;
        if (op == EX_NameConst || op == EX_LocalVariable || op == EX_InstanceVariable || op == EX_DefaultVariable) {
            alignas(16) uint8_t v[32] = {0};
            ++Code(stack);
            ((NativeFn)g_gnatives[op])(FrameObject(stack), stack, v);
            Code(stack) = saved;   // the original reads the argument itself
            FName n; memcpy(&n, v, sizeof(n));
            snprintf(arg, sizeof(arg), "%s", NameOf(n));
        } else {
            snprintf(arg, sizeof(arg), "<expr 0x%02x>", op);
        }
    }
    t.orig(self, stack, result);
    if (g_lines < kMaxLines) {
        ++g_lines;
        L("%s %s -> %s  (from %s)%s", t.name, arg, result ? (*(uint32_t*)result ? "posted" : "NOT posted") : "?", from,
          g_lines == kMaxLines ? "  [line cap reached: no more lines]" : "");
    }
}
void HookPlay(UObject* self, uint8_t* stack, void* result) { Wrap(g_play, self, stack, result); }
void HookStop(UObject* self, uint8_t* stack, void* result) { Wrap(g_stop, self, stack, result); }

bool FindTargets() {
    for (int i = 0; i < g_objs->Count; ++i) {
        UObject* o = g_objs->Data[i];
        if (!o || IsBadReadPtr(o, 0xF0) || _stricmp(ClassNameOf(o), "Function") != 0) continue;
        UObject* outer = o->Outer;
        if (!outer || IsBadReadPtr(outer, sizeof(UObject)) || _stricmp(NameOf(outer->Name), "SFXGUIInteraction") != 0) continue;
        if (_stricmp(NameOf(o->Name), "PlayGuiSound") == 0) g_play.fn = o;
        if (_stricmp(NameOf(o->Name), "StopGuiSound") == 0) g_stop.fn = o;
    }
    return g_play.fn && g_stop.fn;
}

// The game binds a name-bound native's Func lazily, and again after a map
// change (as mp_menu sees for CallListFnc): whenever the slot holds something
// other than our wrapper, that is the game's thunk; keep it and hook again.
void Keep(Target& t) {
    void** slot = (void**)((uint8_t*)t.fn + OFF_FUNC_FUNC);
    if (IsBadReadPtr(slot, sizeof(void*))) return;
    void* cur = *slot;
    if (!cur || cur == t.hook) return;
    if (!InExe(cur)) { static int warned = 0; if (warned++ < 3) L("%s: Func %p is not in the exe: left alone", t.name, cur); return; }
    t.orig = (ExecFn)cur;
    *slot = t.hook;
    if (t.rebinds++ == 0) L("HOOKED: SFXGUIInteraction.%s (Func rva 0x%llx)", t.name, (unsigned long long)((uint8_t*)cur - g_base));
}

DWORD WINAPI Thread(LPVOID) {
    if (!LempDebug()) return 0;   // a diagnostic: debug mode only
    g_base = (uint8_t*)GetModuleHandleA("MassEffect3.exe");
    if (!g_base) g_base = (uint8_t*)GetModuleHandleA(nullptr);
    uint32_t peOff = *(uint32_t*)(g_base + 0x3C);
    g_end = g_base + *(uint32_t*)(g_base + peOff + 0x18 + 0x38);
    g_pools = (FNameEntry**)(g_base + RVA_NAME_POOLS);
    g_objs = (TArray<UObject*>*)(g_base + RVA_OBJOBJECTS);
    g_play.hook = (void*)&HookPlay;
    g_stop.hook = (void*)&HookStop;
    L("== gui_sound ==  pid %lu", (unsigned long)GetCurrentProcessId());
    for (int t = 0;; ++t) {
        Sleep(250);
        if (lemp::Exiting()) { L("stopping: engine exiting"); return 0; }
        if (IsBadReadPtr(g_objs, sizeof(*g_objs)) || !g_objs->Data || g_objs->Count < 1000) continue;
        if (FindTargets()) break;
        if (t > 2400) { L("ABORT: SFXGUIInteraction.PlayGuiSound / StopGuiSound never appeared"); return 0; }
    }
    for (;;) {
        if (lemp::Exiting()) { L("stopping: engine exiting"); return 0; }
        if (!g_gnatives) g_gnatives = LempGNatives();   // shared with mp_save; until then arguments are not read
        Keep(g_play);
        Keep(g_stop);
        Sleep(250);
    }
}

}  // namespace

void GuiSoundProbeStart() {
    CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
}
