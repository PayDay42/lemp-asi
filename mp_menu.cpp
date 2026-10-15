// mp_menu — loads the main menu's Multiplayer screen when its entry is pressed.
//
// NOT A PROBE. THIS ASI WRITES TO GAME MEMORY, like mp_save and join_patch:
// one UFunction::Func pointer, SFXGUI_MainMenu_RTT.CallListFnc's (native), and
// the Multiplayer entry's FncOnSelect text in the live menu's ListEntries
// (ShowDemoLoginPopup -> ShowGameManual, in place; RewriteSelect).
// In debug mode it writes one log of its own, mp_menu_<pid>_<tick>.txt in
// Documents\BioWare\Mass Effect Legendary Edition\LEMP\logs (lemp.h).
//
// ---------------------------------------------------------------------------
// Why it exists
//
// The Multiplayer entry (DLC config; ShowGameManual once RewriteSelect has
// renamed it) calls ShowGameManual, which opens movie
// tag 'Manual', which the DLC points at MPMainMenu.SFXGUI_MPMainMenuEntry
// (MPMainMenu.pcc). The native OpenMovie does NOT load a class that is not in
// memory [V], and on the main menu after a fresh boot nothing of the DLC is:
// the DLC mounts after the menu's HUD auto-load has run [V], and neither a
// startup-package line naming a separate file nor one naming a package inside
// the DLC's startup file loaded it there [V, probe MMpkg=0]. 2012 needed no MP
// code at the main menu: Blaze, native, did its part. This is ours.
//
// What it does, on the game thread, inside the call:
//   CallListFnc is entered (the menu evaluating or selecting an entry) -> if
//   the class SFXGUI_MPMainMenuEntry is not in GObjects, call (ProcessEvent)
//   SFXGUIInteraction.InitializeStartupGuiForPlayer(the local controller,
//   Class'Engine.DebugCameraHUD') -> the original. Throttled (3 s, 30 tries).
//   Once loaded: ProcessEvent SFXGUI_MPMainMenuEntry.CloseLoader() on each
//   live instance, closing the movie that routine also opened (CloseLoaders).
// ShowGameManual itself cannot be hooked: a script function's Func is NULL in
// LE3 [V, this ASI's first version].
// InitializeStartupGuiForPlayer is the startup GUI's own loader, the path that
// worked after a map load [V]: for every movielibrary entry whose
// HUDTypeToAutoLoadFor the HUD class is a child of, LoadSeekFreeObjectBlocking
// the MovieClass (through dynamicloadmapping), then OpenMovie. The DLC has ONE
// entry keyed on Engine.DebugCameraHUD, a leaf class no game HUD derives from
// and no LE3 entry names (tag MPMainMenuLoader, bAutoStart=false,
// bAutoVisible=false): so this loads our class and nothing else, and no map's
// own ClientSetHUD ever matches it. Two object parameters, no strings: nothing
// here allocates or frees game memory.
//
// If anything is not found, it logs and leaves the function alone.
#include <windows.h>
#include "lemp.h"
#include "safe_read.h"  // guard-page-safe IsBadReadPtr/IsBadWritePtr
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>

static const uintptr_t RVA_NAME_POOLS = 0x17B33D0;   // as repl_probe / mp_save
static const uintptr_t RVA_OBJOBJECTS = 0x1887E40;
static const size_t    OFF_FUNC_FUNC  = 0xD8;        // UFunction::Func (LExSDK; mp_save verifies it)
static const size_t    VT_PROCESSEVENT = 0x230;      // UObject::ProcessEvent (LExSDK Core_classes.h)

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

typedef void (*ExecFn)(UObject* self, void* stack, void* result);
typedef void (*ProcessEventFn)(UObject* self, UObject* func, void* parms, void* result);

static uint8_t*     g_base = nullptr;
static uint8_t*     g_end  = nullptr;
static FNameEntry** g_pools = nullptr;
static TArray<UObject*>* g_objs = nullptr;
static FILE*        g_log = nullptr;
static ExecFn       g_origCallListFnc = nullptr;
static UObject*     g_initGuiFn = nullptr;       // SFXGUIInteraction.InitializeStartupGuiForPlayer
static UObject*     g_loaderHud = nullptr;       // Class'Engine.DebugCameraHUD'
static UObject*     g_target = nullptr;          // SFXGUI_MainMenu_RTT.CallListFnc
static UObject*     g_validatePcFn = nullptr;    // SFXGUIInteraction.ValidatePlayerController

static void L(const char* fmt, ...) {
    if (!g_log) return;
    SYSTEMTIME st; GetLocalTime(&st);
    va_list a; va_start(a, fmt);
    fprintf(g_log, "%02d:%02d:%02d.%03d  ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    vfprintf(g_log, fmt, a);
    fputc('\n', g_log);
    fflush(g_log);
    va_end(a);
}
static const char* NameOf(const FName& n) {
    if (!g_pools || n.Chunk > 7) return "<bad>";
    FNameEntry* c = g_pools[n.Chunk];
    if (!c) return "<null>";
    auto* e = (FNameEntry*)((uint8_t*)c + n.Offset);
    return IsBadReadPtr(e, 16) ? "<unreadable>" : e->AnsiName;
}
static const char* ClassNameOf(UObject* o) {
    UObject* c = o->Class;
    return (c && !IsBadReadPtr(c, sizeof(UObject))) ? NameOf(c->Name) : "?";
}
static inline UObject* SlotAt(TArray<UObject*>* a, int i) {
    if (!a || IsBadReadPtr(a, sizeof(*a))) return nullptr;
    UObject** data = a->Data;
    if (!data || i < 0 || i >= a->Count || i >= a->Max) return nullptr;
    if (IsBadReadPtr(data + i, sizeof(UObject*))) return nullptr;
    return data[i];
}
static bool InExe(void* p) { return (uint8_t*)p >= g_base && (uint8_t*)p < g_end; }
static bool IsDefault(UObject* o) { return strncmp(NameOf(o->Name), "Default__", 9) == 0; }

// Our class, cached once found; still valid while GObjects[its index] is it.
static UObject* g_cls = nullptr;
static bool ClassStillThere() {
    if (!g_cls) return false;
    return SlotAt(g_objs, g_cls->InternalIndex) == g_cls && _stricmp(NameOf(g_cls->Name), "SFXGUI_MPMainMenuEntry") == 0;
}
// On the game thread GObjects is consistent: no IsBadReadPtr per object
// (which is slow), only null checks.
static void ScanForClass() {
    g_cls = nullptr;
    for (int i = 0; i < g_objs->Count; ++i) {
        UObject* o = g_objs->Data[i];
        if (!o || !o->Class) continue;
        if (_stricmp(NameOf(o->Class->Name), "Class") == 0 && _stricmp(NameOf(o->Name), "SFXGUI_MPMainMenuEntry") == 0) { g_cls = o; return; }
    }
}
static UObject* FindLive(const char* cls, const char* cls2) {
    for (int i = 0; i < g_objs->Count; ++i) {
        UObject* o = g_objs->Data[i];
        if (!o || !o->Class) continue;
        const char* cn = NameOf(o->Class->Name);
        if ((_stricmp(cn, cls) == 0 || (cls2 && _stricmp(cn, cls2) == 0)) && !IsDefault(o)) return o;
    }
    return nullptr;
}

// The local controller, as the GUI itself picks it: ValidatePlayerController(None)
// (native). Not a GObjects search by class, which can return the controller of
// the map just left, still in GObjects until the next garbage collection.
static UObject* LocalPC(UObject* gui, void* pe) {
    if (!g_validatePcFn) return nullptr;
    alignas(16) uint8_t parms[32] = {0};           // oPC = None, then the return value
    ((ProcessEventFn)pe)(gui, g_validatePcFn, parms, nullptr);
    return *(UObject**)(parms + 8);
}

// InitializeStartupGuiForPlayer does not only load the class: it then OPENS the
// entry's movie (tag MPMainMenuLoader, not started), and nothing closed it. It
// stayed open for the whole session with SFXGUI_Manual's m_bRequiresUIWorld,
// and the main menu reloaded after the lobby never started while it was there:
// no cursor. So, once the class is loaded, call
// SFXGUI_MPMainMenuEntry.CloseLoader() — a script event, no parameters — on
// every live instance; the script closes only the one tagged MPMainMenuLoader.
static void CloseLoaders() {
    UObject* fn = nullptr;
    for (int i = 0; i < g_objs->Count && !fn; ++i) {
        UObject* o = g_objs->Data[i];
        if (!o || !o->Class || o->Outer != g_cls) continue;
        if (_stricmp(NameOf(o->Class->Name), "Function") == 0 && _stricmp(NameOf(o->Name), "CloseLoader") == 0) fn = o;
    }
    if (!fn) { L("close: SFXGUI_MPMainMenuEntry.CloseLoader not found (an older MPMainMenu.pcc?): the loader stays open"); return; }
    int calls = 0;
    for (int i = 0; i < g_objs->Count; ++i) {
        UObject* o = g_objs->Data[i];
        if (!o || o->Class != g_cls || IsDefault(o)) continue;
        void** vt = *(void***)o;
        void* pe = vt ? vt[VT_PROCESSEVENT / 8] : nullptr;
        if (!pe || !InExe(pe)) continue;
        alignas(16) uint8_t parms[16] = {0};
        ((ProcessEventFn)pe)(o, fn, parms, nullptr);
        ++calls;
    }
    L("close: CloseLoader called on %d instance(s)", calls);
}

// The open loader was also the only thing keeping the class resident: once it
// was closed the class was collected, the hook reloaded it every 3 s, and a
// press between a close and a reload found no class — Multiplayer did nothing
// after a return from the lobby [V, main-menu session, mp_menu.log 15:15-15:16].
// So keep the class loaded without an open movie. RF_RootSet (0x4000, UE3's
// AddToRoot, which sets exactly this flag; LEC UnrealFlags) on the class and on
// its package, the outer chain. On the game thread, inside the hook.
static const uint64_t RF_RootSet = 0x4000;
static void RootClass() {
    for (UObject* o = g_cls; o; o = o->Outer) {
        uint64_t before = o->ObjectFlags;
        o->ObjectFlags |= RF_RootSet;
        L("root: %s flags 0x%llx -> 0x%llx", NameOf(o->Name), (unsigned long long)before, (unsigned long long)o->ObjectFlags);
    }
}

// The entry the DLC ships calls LE3's ShowDemoLoginPopup: a message box whose
// text the DLC sets to "Multiplayer needs lemp.asi ..." (string 935840), what a
// player without this ASI gets, since nothing of the DLC is loaded at the main
// menu then. With the ASI it must open the Multiplayer
// screen: so its FncOnSelect is rewritten to ShowGameManual (the path above) in
// the live menu's own ListEntries, before the original runs. In place: the old
// text is longer, so the new one and its terminator fit in its buffer and only
// the count changes (nothing allocated or freed). ShowList re-sends the entries
// to the movie on every list refresh, which picks the new name up [R: the list
// refreshes every ListUpdateInterval, 3 s; a list shown before the hook went in
// keeps the old name until then].
// ListEntries at 0x37C (LExSDK SFXGame_classes.h), an array of FMMListEntry
// (0x58: ListID, FncOnSelect, FncActiveConditional, ...; SFXGame_structs.h);
// checked by content, else left alone and logged once.
static const size_t OFF_RTT_LISTENTRIES = 0x37C;
static const size_t MMLISTENTRY_SIZE = 0x58, OFF_MM_LISTID = 0x00, OFF_MM_FNCONSELECT = 0x10, OFF_MM_FNCACTIVE = 0x20;
static const wchar_t kNoAsiSelect[] = L"ShowDemoLoginPopup";
static const wchar_t kAsiSelect[] = L"ShowGameManual";
static_assert(sizeof(kAsiSelect) <= sizeof(kNoAsiSelect), "the new name must fit the old one's buffer");
typedef TArray<wchar_t> FString;

static bool StrIs(const FString* s, const wchar_t* w) {
    if (IsBadReadPtr(s, sizeof(*s)) || !s->Data || s->Count != (int32_t)wcslen(w) + 1) return false;
    if (IsBadReadPtr(s->Data, s->Count * sizeof(wchar_t))) return false;
    return wcscmp(s->Data, w) == 0;
}

static UObject* g_lastMenu = nullptr;   // the menu instance last logged
static bool     g_badLayoutLogged = false;
static void RewriteSelect(UObject* menu) {
    auto* arr = (TArray<uint8_t>*)((uint8_t*)menu + OFF_RTT_LISTENTRIES);
    bool layoutOk = !IsBadReadPtr(arr, sizeof(*arr)) && arr->Data && arr->Count > 0 && arr->Count <= 256 && arr->Count <= arr->Max
                    && !IsBadReadPtr(arr->Data, arr->Count * MMLISTENTRY_SIZE)
                    && StrIs((FString*)(arr->Data + OFF_MM_LISTID), L"RootList");   // LE3's first entry, Resume
    if (!layoutOk) {
        if (!g_badLayoutLogged) L("select: ListEntries not where LExSDK puts it (0x%zx): the entry stays the no-ASI message", OFF_RTT_LISTENTRIES);
        g_badLayoutLogged = true;
        return;
    }
    int rewritten = 0, already = 0;
    for (int i = 0; i < arr->Count; ++i) {
        uint8_t* e = arr->Data + i * MMLISTENTRY_SIZE;
        auto* sel = (FString*)(e + OFF_MM_FNCONSELECT);
        if (!StrIs((FString*)(e + OFF_MM_LISTID), L"RootList") || !StrIs((FString*)(e + OFF_MM_FNCACTIVE), L"CanShowMultiplayer")) continue;
        if (StrIs(sel, kAsiSelect)) { ++already; continue; }
        if (!StrIs(sel, kNoAsiSelect) || IsBadWritePtr(sel->Data, sizeof(kNoAsiSelect))) continue;
        memcpy(sel->Data, kAsiSelect, sizeof(kAsiSelect));
        sel->Count = (int32_t)(sizeof(kAsiSelect) / sizeof(wchar_t));
        ++rewritten;
    }
    if (menu != g_lastMenu || rewritten) {
        L("select: menu %p: %d entry(ies) %ls -> %ls, %d already", (void*)menu, rewritten, kNoAsiSelect, kAsiSelect, already);
        g_lastMenu = menu;
    }
}

static DWORD g_lastTry = 0;
static int   g_tries = 0;

static void TryLoad() {
    UObject* gui = FindLive("SFXGUIInteraction", nullptr);
    void** vt = gui ? *(void***)gui : nullptr;
    void* pe = vt ? vt[VT_PROCESSEVENT / 8] : nullptr;
    UObject* pc = (gui && pe && InExe(pe)) ? LocalPC(gui, pe) : nullptr;
    if (!gui || !pc || !pe || !InExe(pe)) {
        L("load %d: cannot (gui=%p pc=%p ProcessEvent=%p)", g_tries, (void*)gui, (void*)pc, pe);
        return;
    }
    // InitializeStartupGuiForPlayer(PlayerController oPlayer, Class<HUD> newHUDType):
    // two object parameters; the rest of the frame (its local) is zeroed.
    alignas(16) uint8_t parms[64] = {0};
    *(UObject**)(parms + 0) = pc;
    *(UObject**)(parms + 8) = g_loaderHud;
    ((ProcessEventFn)pe)(gui, g_initGuiFn, parms, nullptr);
    ScanForClass();
    L("load %d: InitializeStartupGuiForPlayer(%s, DebugCameraHUD) -> SFXGUI_MPMainMenuEntry %s",
      g_tries, ClassNameOf(pc), g_cls ? "LOADED" : "still absent (DLC not mounted yet?)");
    if (g_cls) { RootClass(); CloseLoaders(); }
}

// SFXGUI_MainMenu_RTT.CallListFnc(Name): every list condition and every
// selection of the main menu goes through it, after the DLC has mounted (the
// list is shown once the menu's data checks are done). Before the original
// runs, make sure our class is loaded, so a press on Multiplayer
// (ShowGameManual -> tag Manual) finds it. Throttled: one try every 3 s, 30
// in all, until it is there.
static void HookCallListFnc(UObject* self, void* stack, void* result) {
    if (!ClassStillThere()) {
        DWORD now = GetTickCount();
        if (g_tries < 30 && (g_tries == 0 || now - g_lastTry >= 3000)) {
            g_lastTry = now;
            ++g_tries;
            ScanForClass();
            if (!g_cls) TryLoad();
            else { L("load %d: already loaded", g_tries); RootClass(); }
            if (g_cls) g_tries = 0;   // loaded: a later map change may unload it, then try again
        }
    }
    if (self) RewriteSelect(self);
    g_origCallListFnc(self, stack, result);
}

static bool Install() {
    UObject* target = nullptr;
    for (int i = 0; i < g_objs->Count; ++i) {
        UObject* o = SlotAt(g_objs, i);
        if (!o || IsBadReadPtr(o, 0xF0)) continue;
        const char* cn = ClassNameOf(o);
        const char* on = NameOf(o->Name);
        UObject* outer = o->Outer;
        const char* outerName = (outer && !IsBadReadPtr(outer, sizeof(UObject))) ? NameOf(outer->Name) : "";
        if (_stricmp(cn, "Function") == 0) {
            if (_stricmp(on, "CallListFnc") == 0 && _stricmp(outerName, "SFXGUI_MainMenu_RTT") == 0) target = o;
            if (_stricmp(on, "InitializeStartupGuiForPlayer") == 0 && _stricmp(outerName, "SFXGUIInteraction") == 0) g_initGuiFn = o;
            if (_stricmp(on, "ValidatePlayerController") == 0 && _stricmp(outerName, "SFXGUIInteraction") == 0) g_validatePcFn = o;
        } else if (_stricmp(cn, "Class") == 0 && _stricmp(on, "DebugCameraHUD") == 0) {
            g_loaderHud = o;
        }
    }
    if (!target || !g_initGuiFn || !g_loaderHud) return false;   // SFXGame not up yet; try again
    g_target = target;
    return true;
}

// A script function's Func is NULL in LE3 [V: ShowGameManual's],
// and so is a name-bound native's until the game first calls it [V:
// CallListFnc's read 0 ten seconds after launch; mp_save's SaveConfig,
// an INDEXED native, reads its thunk at the same offset from the start]. So
// wait for the first call (the main menu showing its list) to bind it, then
// hook: every later call — list refreshes, and the press — goes through us.
// Thread() does it, and hooks again whenever the game re-binds it.

static DWORD WINAPI Thread(LPVOID) {
    g_log = LempOpenDebugLog("mp_menu");
    g_base = (uint8_t*)GetModuleHandleA("MassEffect3.exe");
    if (!g_base) g_base = (uint8_t*)GetModuleHandleA(nullptr);
    uint32_t peOff = *(uint32_t*)(g_base + 0x3C);
    g_end = g_base + *(uint32_t*)(g_base + peOff + 0x18 + 0x38);
    g_pools = (FNameEntry**)(g_base + RVA_NAME_POOLS);
    g_objs = (TArray<UObject*>*)(g_base + RVA_OBJOBJECTS);
    L("== mp_menu ==  pid %lu", (unsigned long)GetCurrentProcessId());
    for (int t = 0; t < 600; ++t) {
        Sleep(250);
        if (lemp::Exiting()) { L("stopping: engine exiting"); return 0; }
        if (IsBadReadPtr(g_objs, sizeof(*g_objs)) || !g_objs->Data || g_objs->Count < 1000) continue;
        if (Install()) break;
    }
    if (!g_target) { L("ABORT: CallListFnc / InitializeStartupGuiForPlayer / DebugCameraHUD never appeared"); return 0; }
    L("found CallListFnc; waiting for the game to bind it (first main-menu list)");
    // For the whole session, not once: after a return from MP the hook never ran
    // again [V: no log line on the returned menu, which shows its
    // list through CallListFnc] — the game binds these natives lazily and, it
    // appears, binds CallListFnc again after a map change, over our pointer.
    // Whenever the slot holds something else, that is the game's thunk: keep it
    // as the original and put the hook back. Logged.
    void** funcSlot = (void**)((uint8_t*)g_target + OFF_FUNC_FUNC);
    int rebinds = 0;
    for (int t = 0;; ++t) {
        // This loop never ends on its own (it is the live hook's keepalive
        // for the whole session) — the one place a background thread kept
        // reading GObjects-owned memory for as long as the process ran,
        // including into the engine's own teardown. Exit crashes were seen
        // at lemp.asi+0x63e1, twice, both with the engine's
        // pre-exit flag already set — this read of funcSlot (a UFunction's
        // Func field) is the leading candidate: nothing guarded it before.
        if (lemp::Exiting()) { L("stopping: engine exiting (%d rebind(s) seen)", rebinds); return 0; }
        if (IsBadReadPtr(funcSlot, sizeof(void*))) { Sleep(250); continue; }
        void* cur = *funcSlot;
        if (cur && cur != (void*)&HookCallListFnc) {
            if (!InExe(cur)) { L("ABORT: CallListFnc's Func %p is not in the exe", cur); return 0; }
            g_origCallListFnc = (ExecFn)cur;
            *funcSlot = (void*)&HookCallListFnc;
            if (rebinds++ == 0) L("HOOKED: SFXGUI_MainMenu_RTT.CallListFnc (Func rva 0x%llx, bound by the game)", (unsigned long long)((uint8_t*)cur - g_base));
            else L("re-HOOKED: the game re-bound CallListFnc (rva 0x%llx), %d time(s) so far", (unsigned long long)((uint8_t*)cur - g_base), rebinds - 1);
        }
        if (!rebinds && t && t % 240 == 0) L("CallListFnc still unbound after %d s", t / 4);
        Sleep(250);
    }
    return 0;
}

void MpMenuStart() {
    CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
}
