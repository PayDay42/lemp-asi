// mp_save — the MP records' storage: a file in Documents, since LE3 has none.
//
// NOT A PROBE. THIS ASI WRITES TO GAME MEMORY, like join_patch and tick_hook:
// one GNatives slot and one UFunction::Func pointer (both SaveConfig's), plus
// the script properties of SFXMPLocalSave objects it is asked to serve, and,
// when script asks (ops 57-59, below), class defaults and live objects through
// the engine's own set command, as the console's `set` would.
// It writes one file of its own:
//     Documents\BioWare\Mass Effect Legendary Edition\Save\ME3\LEMP_mpsave.txt
//     (LEMP_mpsave.bak.txt = the previous save)
// and, for the Multiplayer screen, LEMP_mpname.txt and LEMP_mpaddress.txt
// beside it. They sit in Save\ME3 because that is what the EA app cloud-syncs
// (everything under Save\, plus TrilogyGamerProfile, and nothing else beside
// it; Steam Cloud syncs nothing for LE). Plain files, as Local_Profile is, not a
// folder: every folder in Save\ME3 is a career. What must not be synced stays in
// Documents\...\Mass Effect Legendary Edition\LEMP\: the .tmp files a write
// goes through, so a crash mid-write never leaves a partial file in the synced
// tree, and in debug mode this run's log (logs\mp_save_<pid>_<tick>.txt). It reads the Windows
// clipboard's text when that screen's Paste asks for it.
//
// ---------------------------------------------------------------------------
// Why it exists
//
// 2012 kept the MP records (credits, class levels, characters, inventory) in
// EA's player storage. Our SFXSaveManagerMP_Local keeps 2012's serializer and
// hands its five strings to SFXMPLocalSave. That class first stored them with
// SaveConfig, which writes nothing to disk in LE3. BioWare's own script never
// calls it, and the one setting they persist, console history, goes through a
// native of its own (SFXConsole.SaveHistory). So this ASI does the file I/O
// the script cannot.
//
// How script reaches it. SFXMPLocalSave sets AsiOp and calls SaveConfig()
// (Object.uc: native(536) final). This hooks that native: the original runs
// first (harmless: it writes nothing), then, only for an SFXMPLocalSave, the
// op is served on the game thread, synchronously, during the call.
//
//   AsiOp 1  save:   BaseString, NewReinforcementsString, FaceCodesString,
//                    SelectedKit, ClassStrings[], CharacterStrings[],
//                    ChallengeStrings[], GAWString (each if the class has
//                    it) -> the file
//   AsiOp 2  query:  read the file; NumClass, NumChar, NumChallenge, NumGAW
//                    = its counts. Each character's own weapon-id list is
//                    fixed up here too, before anything is handed out by
//                    ops 3/4 below (FixUnmappedWeapons; weapon_slot_fix.h)
//   AsiOp 3  length: AsiLen = the length of slot AsiIndex (order: base,
//                    reinforcements, facecodes, selected, classes...,
//                    characters..., challenges..., gaw if any)
//   AsiOp 4  fill:   copy slot AsiIndex into AsiBuf, which script has made
//                    exactly AsiLen characters long
//
// AsiResult: script sets -2 before each call, so -2 afterwards means no ASI
// answered and the game plays on as before, with nothing saved. 0 = done,
// -1 = no save file, >0 = an error (logged).
//
// The ASI never allocates a game string: every buffer it writes into was made
// by script (the game's allocator), and it only overwrites characters inside
// one that is already the right length. So nothing here can hand the engine
// memory it would later free from the wrong heap.
//
// ---------------------------------------------------------------------------
// Finding GNatives: it has no symbol, so it is found and then verified. Every
// UFunction with a native index (iNative, LExSDK: UFunction+0xE4) has its exec
// thunk in Func (+0xD8), and GNatives[iNative] holds the same thunk. The
// SaveConfig thunk's address is searched for in the exe's non-executable
// sections; a candidate is accepted only if the table it implies agrees with
// the indexed natives in GObjects. SaveConfig's own iNative must read 536,
// which also checks the two LExSDK offsets.
#include <winsock2.h>   // before windows.h: lemp_online.h uses it
#include <windows.h>
#include "lemp.h"
#include "safe_read.h"  // guard-page-safe IsBadReadPtr/IsBadWritePtr
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "mp_save_format.h"
#include "build_key.h"
#include "lemp_online.h"
#include "ea_import.h"
#include "n7hq_import.h"
#include "n7hq_synth.h"     // the N7 HQ pages -> the save (op 53)
#include "balance_classify.h"
#include "weapon_slot_fix.h"
#include <atomic>

static const uintptr_t RVA_NAME_POOLS = 0x17B33D0;   // as repl_probe
static const uintptr_t RVA_OBJOBJECTS = 0x1887E40;   // as repl_probe
static const size_t    OFF_PAWN_MESH  = 0x03F4;      // calibrates UProperty::Offset, as repl_probe
static const size_t    OFF_FIELD_SUPER     = 0x60;   // LExSDK
static const size_t    OFF_FIELD_NEXT      = 0x68;
static const size_t    OFF_STRUCT_CHILDREN = 0x70;
static const size_t    OFF_FUNC_FUNC       = 0xD8;   // UFunction::Func
static const size_t    OFF_FUNC_FLAGS      = 0xE0;   // UFunction::FunctionFlags
static const size_t    OFF_FUNC_INATIVE    = 0xE4;   // UFunction::iNative
static const uint32_t  FUNC_NATIVE         = 0x400;
static const int       SAVECONFIG_NATIVE   = 536;    // Object.uc: native(536) SaveConfig
static const int       MAX_NATIVES         = 4096;

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
struct FStringRaw { wchar_t* Data; int32_t Count, Max; };   // Count includes the NUL
static_assert(sizeof(FStringRaw) == 16, "FString is 16 bytes");
static_assert(sizeof(wchar_t) == sizeof(char16_t), "TCHAR is UTF-16");

typedef void (*ExecFn)(UObject* self, void* stack, void* result);

static uint8_t*     g_base = nullptr;
static uint8_t*     g_end  = nullptr;
static FNameEntry** g_pools = nullptr;
static TArray<UObject*>* g_objs = nullptr;   // GObjects (ServePackages)
static size_t       g_propOffsetAt = 0;
static ExecFn       g_origSaveConfig = nullptr;
static std::wstring g_dir;     // local: LempDir(), .tmp files
static std::wstring g_cloud;   // Save\ME3: the files the EA app syncs
static MPSaveData   g_loaded;
static bool         g_haveLoaded = false;

// Shared with lemp_voice.cpp (lemp.h: LempGNatives()) — see FindGNatives's
// comment above: voice chat's own independent GNatives search was the one
// that failed on one installation, so it now waits for and reuses this
// result instead of searching a second time.
static std::atomic<void**> g_sharedGNatives{nullptr};

static void L(const char* fmt, ...) {
    va_list a; va_start(a, fmt);
    LempLogV("mp_save", fmt, a);
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
// GObjects read from this thread while the game thread grows it: re-read the
// header on every access, as repl_probe found the hard way.
static inline UObject* SlotAt(TArray<UObject*>* a, int i) {
    if (!a || IsBadReadPtr(a, sizeof(*a))) return nullptr;
    UObject** data = a->Data;
    if (!data || i < 0 || i >= a->Count || i >= a->Max) return nullptr;
    if (IsBadReadPtr(data + i, sizeof(UObject*))) return nullptr;
    return data[i];
}
// Every name compare here is case-insensitive, as FNames are: the name table
// keeps the spelling of whoever registered a name first. The first in-game
// run found BaseString and NewReinforcementsString but reported
// FaceCodesString "not found" under a case-sensitive strcmp.
static UObject* FindFieldByName(UObject* cls, const char* want) {
    for (UObject* c = cls; c && !IsBadReadPtr(c, 0x80);
         c = *(UObject**)((uint8_t*)c + OFF_FIELD_SUPER)) {
        for (UObject* f = *(UObject**)((uint8_t*)c + OFF_STRUCT_CHILDREN);
             f && !IsBadReadPtr(f, 0x80);
             f = *(UObject**)((uint8_t*)f + OFF_FIELD_NEXT)) {
            if (_stricmp(NameOf(f->Name), want) == 0) return f;
        }
    }
    return nullptr;
}
static size_t PropertyOffset(UObject* obj, const char* name) {
    if (!g_propOffsetAt || !obj) return 0;
    UObject* f = FindFieldByName(obj->Class, name);
    if (!f || IsBadReadPtr((uint8_t*)f + g_propOffsetAt, 4)) return 0;
    return *(uint32_t*)((uint8_t*)f + g_propOffsetAt);
}

// repl_probe's calibration, verbatim in substance: Pawn.Mesh's UProperty must
// hold OFF_PAWN_MESH at exactly one position.
// 1 calibrated, 0 Pawn not loaded yet (retry), -1 refused.
static int CalibratePropertyOffset(TArray<UObject*>* objs) {
    UObject* pawnCls = nullptr;
    for (int i = 0; i < objs->Count && !pawnCls; ++i) {
        UObject* o = SlotAt(objs, i);
        if (!o || IsBadReadPtr(o, 0x60)) continue;
        if (_stricmp(ClassNameOf(o), "Class") == 0 && _stricmp(NameOf(o->Name), "Pawn") == 0)
            pawnCls = o;
    }
    if (!pawnCls) return 0;
    UObject* meshProp = FindFieldByName(pawnCls, "Mesh");
    if (!meshProp) return 0;
    size_t hit = 0; int hits = 0;
    for (size_t off = 0x70; off <= 0xB0; off += 4) {
        if (IsBadReadPtr((uint8_t*)meshProp + off, 4)) continue;
        if (*(uint32_t*)((uint8_t*)meshProp + off) == (uint32_t)OFF_PAWN_MESH) { hit = off; ++hits; }
    }
    if (hits != 1) { L("PROPCAL: %d candidates for UProperty::Offset, refusing to guess", hits); return -1; }
    g_propOffsetAt = hit;
    L("PROPCAL: UProperty::Offset at +0x%zx", hit);
    return 1;
}

// ---------------------------------------------------------------------------
// Script property access on the served object.

static int32_t* IntProp(UObject* o, const char* name) {
    size_t off = PropertyOffset(o, name);
    return off ? (int32_t*)((uint8_t*)o + off) : nullptr;
}
static FStringRaw* StrProp(UObject* o, const char* name) {
    size_t off = PropertyOffset(o, name);
    return off ? (FStringRaw*)((uint8_t*)o + off) : nullptr;
}
static TArray<FStringRaw>* StrArrayProp(UObject* o, const char* name) {
    size_t off = PropertyOffset(o, name);
    return off ? (TArray<FStringRaw>*)((uint8_t*)o + off) : nullptr;
}
// Each read says why it refused (in `why`), so a failed save names its field.
static bool ReadFString(const FStringRaw* s, std::u16string& out, std::string& why) {
    out.clear();
    char b[160];
    if (!s) { why = "property not found"; return false; }
    if (s->Count == 0) return true;                        // ""
    if (s->Count < 0 || s->Count > (1 << 24) || !s->Data) {
        snprintf(b, sizeof(b), "bad header Data=%p Count=%d Max=%d", (void*)s->Data, s->Count, s->Max);
        why = b; return false;
    }
    if (IsBadReadPtr(s->Data, (size_t)s->Count * 2)) {
        snprintf(b, sizeof(b), "unreadable Data=%p Count=%d", (void*)s->Data, s->Count);
        why = b; return false;
    }
    int n = s->Count - 1;                                  // drop the NUL
    out.assign((const char16_t*)s->Data, (size_t)(n < 0 ? 0 : n));
    return true;
}
static bool ReadFStringArray(const TArray<FStringRaw>* a, std::vector<std::u16string>& out, std::string& why) {
    out.clear();
    char b[160];
    if (!a) { why = "property not found"; return false; }
    if (a->Count < 0 || a->Count > 4096) {
        snprintf(b, sizeof(b), "bad array header Data=%p Count=%d Max=%d", (void*)a->Data, a->Count, a->Max);
        why = b; return false;
    }
    if (a->Count == 0) return true;
    if (!a->Data || IsBadReadPtr(a->Data, (size_t)a->Count * sizeof(FStringRaw))) {
        snprintf(b, sizeof(b), "unreadable array Data=%p Count=%d", (void*)a->Data, a->Count);
        why = b; return false;
    }
    for (int i = 0; i < a->Count; ++i) {
        std::u16string s;
        if (!ReadFString(&a->Data[i], s, why)) { why = "element " + std::to_string(i) + ": " + why; return false; }
        out.push_back(s);
    }
    return true;
}

// ---------------------------------------------------------------------------
// The file.

static std::wstring SavePath()   { return g_cloud + L"\\LEMP_mpsave.txt"; }
static std::wstring BackupPath() { return g_cloud + L"\\LEMP_mpsave.bak.txt"; }

static bool WriteSave(const MPSaveData& d) {
    std::string text = mpsave::Serialize(d);
    std::wstring tmp = g_dir + L"\\mpsave.tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { L("save: cannot create %ls (%lu)", tmp.c_str(), GetLastError()); return false; }
    DWORD wrote = 0;
    BOOL ok = WriteFile(h, text.data(), (DWORD)text.size(), &wrote, nullptr) && wrote == text.size();
    ok = ok && FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok) { L("save: write failed (%lu)", GetLastError()); DeleteFileW(tmp.c_str()); return false; }
    // Keep the previous save; then swap the new one in whole.
    if (GetFileAttributesW(SavePath().c_str()) != INVALID_FILE_ATTRIBUTES)
        CopyFileW(SavePath().c_str(), BackupPath().c_str(), FALSE);
    if (!MoveFileExW(tmp.c_str(), SavePath().c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH)) {
        L("save: cannot replace %ls (%lu)", SavePath().c_str(), GetLastError());
        return false;
    }
    L("save: %zu bytes, %zu class and %zu character record(s), %zu challenge string(s), gaw \"%ls\"", text.size(), d.classes.size(), d.characters.size(), d.challenges.size(), (const wchar_t*)d.gaw.c_str());
    return true;
}

// -1 no file, 0 loaded, 2 unreadable.
static int ReadSave(MPSaveData& d) {
    HANDLE h = CreateFileW(SavePath().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) { L("load: no save file (new records)"); return -1; }
        L("load: cannot open %ls (%lu)", SavePath().c_str(), e);
        return 2;
    }
    std::string text;
    char buf[65536];
    DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0) text.append(buf, got);
    CloseHandle(h);
    std::string why;
    if (!mpsave::Parse(text, d, why)) { L("load: %ls is unreadable: %s. Not loaded.", SavePath().c_str(), why.c_str()); return 2; }
    L("load: %zu bytes, %zu class and %zu character record(s), %zu challenge string(s), gaw \"%ls\"", text.size(), d.classes.size(), d.characters.size(), d.challenges.size(), (const wchar_t*)d.gaw.c_str());
    return 0;
}

// ---------------------------------------------------------------------------
// A weapon id a save holds that the installed config no longer maps shifts
// the other weapon into its slot (weapon_slot_fix.h has the mechanism and
// why it belongs here, in this file, rather than in script).
// Runs once, right after a successful load, on every character record —
// before anything is ever handed to script (op 3/4, below). A valid
// loadout is not re-serialized at all (FixCharacterRecord leaves the string
// untouched when it has nothing to substitute), so this never costs a
// byte-identical save its identity.
// Control: LEMP\noweaponslotfix.txt disables this (the control, like
// nofov.txt/nodebug.txt): every record is then handed through exactly as
// read, including one the engine will go on to compact.
static bool WeaponSlotFixOn() {
    return GetFileAttributesW((LempDir() + L"\\noweaponslotfix.txt").c_str()) == INVALID_FILE_ATTRIBUTES;
}
static void FixUnmappedWeapons(MPSaveData& d) {
    if (!WeaponSlotFixOn()) { L("weapon slot fix: noweaponslotfix.txt, skipped"); return; }
    static const weaponslotfix::Mappings* s_mappings = nullptr;
    if (!s_mappings) {
        static weaponslotfix::Mappings m = weaponslotfix::BuildMappings();
        s_mappings = &m;
        L("weapon slot fix: %zu mapped id(s), %zu kit(s) in the baked table",
          s_mappings->idToClass.size(), s_mappings->kitWeapons.size());
    }
    int total = 0;
    for (auto& c : d.characters) {
        std::vector<std::string> lines;
        total += weaponslotfix::FixCharacterRecord(c, *s_mappings, lines);
        for (auto& line : lines) L("%s", line.c_str());
    }
    if (total > 0) L("weapon slot fix: %d substitution(s) this load", total);
}

// ---------------------------------------------------------------------------
// The ops, on the game thread.

static void Serve(UObject* self) {
    int32_t* op = IntProp(self, "AsiOp");
    int32_t* result = IntProp(self, "AsiResult");
    if (!op || !result) { L("serve: SFXMPLocalSave has no AsiOp/AsiResult (old DLC build?)"); return; }

    switch (*op) {
    case 1: {   // save
        MPSaveData d;
        std::string why;
        const char* field = nullptr;
        if (!ReadFString(StrProp(self, "BaseString"), d.base, why)) field = "BaseString";
        else if (!ReadFString(StrProp(self, "NewReinforcementsString"), d.reinforcements, why)) field = "NewReinforcementsString";
        else if (!ReadFString(StrProp(self, "FaceCodesString"), d.facecodes, why)) field = "FaceCodesString";
        else if (!ReadFString(StrProp(self, "SelectedKit"), d.selected, why)) field = "SelectedKit";
        else if (!ReadFStringArray(StrArrayProp(self, "ClassStrings"), d.classes, why)) field = "ClassStrings";
        else if (!ReadFStringArray(StrArrayProp(self, "CharacterStrings"), d.characters, why)) field = "CharacterStrings";
        // Optional: a class package from before the challenges
        // has no ChallengeStrings, and its saves must still write.
        else if (StrArrayProp(self, "ChallengeStrings") &&
                 !ReadFStringArray(StrArrayProp(self, "ChallengeStrings"), d.challenges, why)) field = "ChallengeStrings";
        // Optional, as the challenges: the MP Galaxy at War
        // ratings (SFXMPLocalSave.GAWString).
        else if (StrProp(self, "GAWString") &&
                 !ReadFString(StrProp(self, "GAWString"), d.gaw, why)) field = "GAWString";
        if (field) {
            L("save: could not read %s (property offset 0x%zx): %s", field, PropertyOffset(self, field), why.c_str());
            *result = 1; return;
        }
        if (d.base.empty()) { L("save: refused, BaseString is empty"); *result = 1; return; }
        *result = WriteSave(d) ? 0 : 1;
        if (*result == 0) { g_loaded = d; g_haveLoaded = true; }
        return;
    }
    case 2: {   // query
        int32_t* nc = IntProp(self, "NumClass");
        int32_t* nch = IntProp(self, "NumChar");
        if (!nc || !nch) { *result = 5; return; }
        MPSaveData d;
        int r = ReadSave(d);
        if (r == 0) {
            FixUnmappedWeapons(d);
            g_loaded = d; g_haveLoaded = true; *nc = (int32_t)d.classes.size(); *nch = (int32_t)d.characters.size();
            if (int32_t* nchl = IntProp(self, "NumChallenge")) *nchl = (int32_t)d.challenges.size();
            if (int32_t* ngaw = IntProp(self, "NumGAW")) *ngaw = (int32_t)d.NumGaw();
        }
        *result = r;
        return;
    }
    case 3:     // length
    case 4: {   // fill
        int32_t* idx = IntProp(self, "AsiIndex");
        if (!idx || !g_haveLoaded) { *result = 3; return; }
        const std::u16string* s = g_loaded.Slot((size_t)*idx);
        if (!s || *idx < 0) { L("serve: slot %d out of range", idx ? *idx : -1); *result = 3; return; }
        if (*op == 3) {
            int32_t* len = IntProp(self, "AsiLen");
            if (!len) { *result = 5; return; }
            *len = (int32_t)s->size();
            *result = 0;
            return;
        }
        FStringRaw* buf = StrProp(self, "AsiBuf");
        if (!buf) { *result = 5; return; }
        int32_t have = buf->Count > 0 ? buf->Count - 1 : 0;
        if (have != (int32_t)s->size()) {
            L("fill: slot %d wants %zu chars, AsiBuf has %d. Nothing written.", *idx, s->size(), have);
            *result = 4; return;
        }
        if (have > 0) {
            if (!buf->Data || IsBadWritePtr(buf->Data, (size_t)have * 2)) { *result = 4; return; }
            memcpy(buf->Data, s->data(), (size_t)have * 2);
        }
        *result = 0;
        return;
    }
    default:
        L("serve: unknown AsiOp %d", *op);
        *result = 6;
    }
}

// The main-menu session's Multiplayer screen (MPMainMenu.SFXMPProfileName,
// the DLC's main-menu package). Same protocol fields as SFXMPLocalSave (AsiOp, AsiResult,
// AsiLen, AsiBuf), its own ops and files. Each value is a length op, a fill op
// (into AsiBuf, which script made AsiLen long) and, for the files, a save op:
//   AsiOp 5 / 6 / 7    the MP player name        <-> mpname.txt
//   AsiOp 8 / 9 / 10   the last address joined   <-> mpaddress.txt
//   AsiOp 11 / 12      the Windows clipboard's text (read only). 11 takes the
//                      snapshot that 12 fills from, so both see the same text.
//   AsiOp 80 / 81      the Multiplayer screen's notice for an install with other
//                      mods or changed base files (build_key.h ModsNotice),
//                      length / fill; "" (length 0) for a plain install.
//   AsiOp 13 / 14      this install's identity as join options (build_key.h
//                      JoinOptions): "LEMPBuild=<12 hex>?LEMPGame=...?LEMPAsi=
//                      ...?LEMPBase=...?LEMPMods=...". The joining client
//                      appends "?" and it, the host's SFXGameInfoMP.PreLogin
//                      compares each. Served to SFXMPLocalSave too, which is
//                      what the host asks through.
// A length of -1 means none (no file, or no text on the clipboard).
//
// Ops 20-30, to SFXMPLocalSave: matchmaking, the master server's client
// (lemp_online.h has the protocol). They
// stand in for 2012's Blaze calls in SFXGameInfoMP_Lobby. None blocks: the
// network is on the ASI's own threads, and script polls.
//   AsiOp 20        start a search; AsiBuf = "?map=?enemy=?difficulty=", or
//                   "?code=<6 hex>": the lobby with that code,
//                   ending as a search does, join or failed (1 = malformed)
//   AsiOp 21        AsiIndex = its outcome (2012's SFXOnlineQuickMatchOutcome:
//                   0 in progress, 1 create, 2 join, 3 timeout, 4 failed), -1 none
//   AsiOp 22 / 23   the outcome's text, length / fill: "?address=h:p?lobby=",
//                   "?map=?enemy=?difficulty=" or "?message="
//   AsiOp 24        cancel the search
//   AsiOp 25        the last join did not connect (reported to the server)
//   Ops 20-25 are served to the main menu's SFXMPProfileName too: its
//   "Join lobby by code" (it has AsiIndex for 21).
//   AsiOp 26        the hosted lobby: AsiBuf = "?create=1?private=?open=?map=
//                   ?enemy=?difficulty=?players=?max=?port="; without create=1
//                   an update, 7 = not hosting
//   AsiOp 27        renew the hosted lobby's lease (7 = not hosting)
//   AsiOp 28        stop hosting
//   AsiOp 29 / 30   the hosted lobby's status, length / fill: "?code=?reachable=";
//                   29 also sets AsiIndex = reachable (-1 unknown, 1, 0)
//   AsiOp 32 / 33   online statistics, length / fill: "?players=?lobbies=?games=
//                   ?searching=" or "?error=": cached, refreshed in the background
//                   (at most every 10 s); "" before the first answer. Served to
//                   the main menu's SFXMPProfileName too.
//   AsiOp 34        the statistics' filter: AsiBuf = "?map=?enemy=?difficulty="
//                   as a search sends them, or "" for none; with one, 32/33
//                   also carry "?mlobbies=?mplayers=" (what that search finds)
//   AsiOp 31        a line of script trace (AsiBuf) into mp_save.log: the
//                   matchmaking steps, which repl_probe's sampled MPDebug missed
//
// Ops 45-49, to SFXMPLocalSave: the level package map's digest (ServePackages).
// Host and client must list the same packages with the
// same object counts, or every object after the first difference is named
// wrongly; join_patch turned UE3's own check off.
//   AsiOp 45 / 46   this process's digest, length / fill: "<entries>:<hex>",
//                   four hex digits per entry (name and object count)
//   AsiOp 47        compare the host's digest from entry AsiIndex on (AsiBuf =
//                   its hex); AsiIndex 0 starts a new comparison. AsiIndex =
//                   the first entry that differs so far, -1 none; result 2 =
//                   no package map found here
//   AsiOp 48 / 49   that entry's package here, length / fill: "<name>:<count>"
//
// Ops 50-52, to the main menu's SFXMPProfileName: importing the player's ME3
// (2012) multiplayer profile from EA (ea_import.h).
// Nothing reaches the EA app or EA's servers until script sends op 50, which
// it does only after the player chose the import and agreed.
//   AsiOp 50        start the import on a thread of its own (1 = one is running)
//   AsiOp 51 / 52   its status, length / fill: "?state=idle|running|done|failed
//                   ?stage=1-4?name=?summary=?error=". On done the save file
//                   already holds the profile; the previous one was copied to
//                   LEMP_mpsave.preimport-<date>-<time>.txt beside it.
//   AsiOp 53        read a console profile from N7 HQ (n7hq_import.h), AsiBuf
//                   "?platform=xbox|ps3|wiiu?name=<console name>": 0 started,
//                   1 one is running, 2 a platform or name it refuses. Its
//                   status is 51/52's, with ?kind=n7hq, ?stage=1-4, ?page=1-5
//                   (stage 4), ?pages= and, on failure, ?error= and ?hint= (the
//                   box's two lines). It writes the pages under LEMP\n7hq and
//                   never the save.
// Ops 72/73, to SFXMPLocalSave: the field of view (ServeCamera, below).
//   AsiOp 72        AsiIndex = the saved FOV, 70-110 (70 without a file)
//   AsiOp 73        save AsiIndex, clamped to 70-110, to LEMP\camera.txt
//                   Both answer 3 while LEMP\nofov.txt exists (the control).
// Ops 74/75, to SFXMPLocalSave: the log (ServeLog, below).
//   AsiOp 74        AsiIndex = 1 while the log is written, else 0
//   AsiOp 75        log on (AsiIndex 1) or off (0) from now on, and saved
//                   (LEMP\nodebug.txt); AsiResult 1 if it could not be saved
struct TextFile {
    const wchar_t* file;
    const wchar_t* tmp;
    const char* tag;
    std::string (*serialize)(const std::u16string&);
    bool (*parse)(const std::string&, std::u16string&, std::string&);
};
// file is in g_cloud, tmp in g_dir.
static const TextFile kNameFile    = { L"\\LEMP_mpname.txt",    L"\\mpname.tmp",    "name",    mpsave::SerializeName,    mpsave::ParseName };
static const TextFile kAddressFile = { L"\\LEMP_mpaddress.txt", L"\\mpaddress.tmp", "address", mpsave::SerializeAddress, mpsave::ParseAddress };

static bool ReadTextFile(const TextFile& f, std::u16string& value, bool& exists) {
    exists = false;
    std::wstring path = g_cloud + f.file;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return true;
        L("%s: cannot open %ls (%lu)", f.tag, path.c_str(), e);
        return false;
    }
    std::string text; char buf[4096]; DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0) text.append(buf, got);
    CloseHandle(h);
    std::string why;
    if (!f.parse(text, value, why)) { L("%s: %ls is unreadable: %s", f.tag, path.c_str(), why.c_str()); return false; }
    exists = true;
    return true;
}

static bool WriteTextFile(const TextFile& f, const std::u16string& value) {
    std::string text = f.serialize(value);
    std::wstring path = g_cloud + f.file, tmp = g_dir + f.tmp;
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { L("%s: cannot create %ls (%lu)", f.tag, tmp.c_str(), GetLastError()); return false; }
    DWORD wrote = 0;
    BOOL ok = WriteFile(h, text.data(), (DWORD)text.size(), &wrote, nullptr) && wrote == text.size() && FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok || !MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH)) {
        L("%s: write failed (%lu)", f.tag, GetLastError()); DeleteFileW(tmp.c_str()); return false;
    }
    L("%s: saved (%zu chars)", f.tag, value.size());
    return true;
}

// The clipboard's text, one line, trimmed: whatever was copied around an
// address (a trailing newline from a terminal, surrounding spaces) is not part
// of it. Capped, since the screen's field is one line.
static const size_t kClipMax = 255;
static bool ReadClipboardText(std::u16string& out, bool& exists) {
    exists = false;
    out.clear();
    if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) return true;
    if (!OpenClipboard(nullptr)) { L("clipboard: cannot open (%lu)", GetLastError()); return false; }
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    const char16_t* p = h ? (const char16_t*)GlobalLock(h) : nullptr;
    if (p) {
        size_t n = 0;
        while (p[n] && p[n] != u'\r' && p[n] != u'\n' && n < 4096) n++;   // first line only
        out.assign(p, n);
        GlobalUnlock(h);
    }
    CloseClipboard();
    auto blank = [](char16_t c) { return c == u' ' || c == u'\t' || c < 0x20; };
    while (!out.empty() && blank(out.back())) out.pop_back();
    size_t lead = 0;
    while (lead < out.size() && blank(out[lead])) lead++;
    out.erase(0, lead);
    if (out.size() > kClipMax) out.resize(kClipMax);
    exists = !out.empty();
    return true;
}
static std::u16string g_clip;
static bool g_clipExists = false;

// The build identity, computed off the game thread at launch (seconds cold,
// ms from the cache in LEMP\buildkey.cache). The first op 13 waits for it; an
// MP join or lobby is far later than that in practice.
static HANDLE g_keyThread = nullptr;
static std::u16string g_buildKey;   // JoinOptions, or empty: none (no DLC key)
static std::u16string g_modsNotice; // build_key.h ModsNotice, or empty: a plain install

static std::wstring GameDir() {
    wchar_t exe[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);          // ...\Game\ME3\Binaries\Win64\MassEffect3.exe
    std::wstring p = exe;
    for (int up = 0; up < 3; ++up) p = p.substr(0, p.find_last_of(L'\\'));
    return p;
}

static DWORD WINAPI KeyThread(LPVOID) {
    std::wstring game = GameDir();
    std::wstring dlc = game + L"\\BioGame\\DLC\\DLC_MOD_LEMultiplayer";
    std::string why;
    DWORD t = GetTickCount();
    buildkey::HashCache cache;
    cache.Load(g_dir + L"\\buildkey.cache");
    std::string full = buildkey::ComputeKey(dlc, cache, why);
    if (full.empty()) { L("buildkey: none for %ls: %s", dlc.c_str(), why.c_str()); return 0; }
    std::vector<buildkey::Entry> base;
    std::string exe = buildkey::RunningExeVersion(), mods = buildkey::OtherMods(game, L"DLC_MOD_LEMultiplayer");
    std::string opts = buildkey::JoinOptions(
        buildkey::ShortKey(full), exe,
        buildkey::HashFileList(game, buildkey::kPlayAsis, sizeof buildkey::kPlayAsis / sizeof *buildkey::kPlayAsis, cache),
        buildkey::HashFileList(game, buildkey::kBaseFiles, sizeof buildkey::kBaseFiles / sizeof *buildkey::kBaseFiles, cache, &base),
        mods);
    cache.Save();
    g_buildKey.assign(opts.begin(), opts.end());
    // Base files are compared only on the exe version their plain hashes are
    // of: another version's own files would all read as changed.
    std::string changed = exe == buildkey::kBaseGameVersion ? buildkey::DifferentBaseFiles(base) : "";
    std::string notice = buildkey::ModsNotice(mods, changed);
    g_modsNotice.assign(notice.begin(), notice.end());
    if (!notice.empty()) L("buildkey: not a plain install: mods \"%s\", changed base files \"%s\"%s", mods.c_str(),
                           changed.c_str(), exe == buildkey::kBaseGameVersion ? "" : " (another exe version: not compared)");
    L("buildkey: %s (DLC %s; %d files hashed, %d cached, %lu ms)", opts.c_str(), full.c_str(), cache.hashed,
      cache.cached, (unsigned long)(GetTickCount() - t));
    return 0;
}

static bool FillBuf(FStringRaw* buf, const std::u16string& value, const char* tag) {
    int32_t have = buf->Count > 0 ? buf->Count - 1 : 0;
    if (have != (int32_t)value.size()) { L("%s: wants %zu chars, AsiBuf has %d. Nothing written.", tag, value.size(), have); return false; }
    if (have > 0) {
        if (!buf->Data || IsBadWritePtr(buf->Data, (size_t)have * 2)) return false;
        memcpy(buf->Data, value.data(), (size_t)have * 2);
    }
    return true;
}

static void ServeName(UObject* self) {
    int32_t* op = IntProp(self, "AsiOp");
    int32_t* result = IntProp(self, "AsiResult");
    if (!op || !result) { L("name: SFXMPProfileName has no AsiOp/AsiResult"); return; }
    FStringRaw* buf = StrProp(self, "AsiBuf");
    int32_t* len = IntProp(self, "AsiLen");
    if (!buf || !len) { L("name: SFXMPProfileName has no AsiBuf/AsiLen"); *result = 5; return; }
    std::u16string value; bool exists = false; std::string why;
    if (*op == 13 || *op == 14) {
        if (g_keyThread && WaitForSingleObject(g_keyThread, 60000) != WAIT_OBJECT_0) {
            L("buildkey: still computing after 60 s"); *result = 2; return;
        }
        if (*op == 13) { *len = g_buildKey.empty() ? -1 : (int32_t)g_buildKey.size(); *result = 0; }
        else *result = g_buildKey.empty() ? 2 : FillBuf(buf, g_buildKey, "buildkey") ? 0 : 4;
        return;
    }
    if (*op == 80 || *op == 81) {
        if (g_keyThread && WaitForSingleObject(g_keyThread, 60000) != WAIT_OBJECT_0) { *result = 2; return; }
        if (*op == 80) { *len = (int32_t)g_modsNotice.size(); *result = 0; }
        else *result = FillBuf(buf, g_modsNotice, "modsnotice") ? 0 : 4;
        return;
    }
    const TextFile* f = (*op >= 5 && *op <= 7) ? &kNameFile : (*op >= 8 && *op <= 10) ? &kAddressFile : nullptr;
    switch (*op) {
    case 5: case 8:
        if (!ReadTextFile(*f, value, exists)) { *result = 2; return; }
        *len = exists ? (int32_t)value.size() : -1;
        *result = 0;
        return;
    case 6: case 9:
        if (!ReadTextFile(*f, value, exists) || !exists) { *result = 2; return; }
        *result = FillBuf(buf, value, f->tag) ? 0 : 4;
        return;
    case 7: case 10:
        if (!ReadFString(buf, value, why)) { L("%s: could not read AsiBuf: %s", f->tag, why.c_str()); *result = 1; return; }
        *result = WriteTextFile(*f, value) ? 0 : 1;
        return;
    case 11:
        if (!ReadClipboardText(g_clip, g_clipExists)) { *result = 2; return; }
        *len = g_clipExists ? (int32_t)g_clip.size() : -1;
        *result = 0;
        return;
    case 12:
        if (!g_clipExists) { *result = 2; return; }
        *result = FillBuf(buf, g_clip, "clipboard") ? 0 : 4;
        return;
    default:
        L("name: unknown AsiOp %d", *op);
        *result = 6;
    }
}

// ---------------------------------------------------------------------------
// The EA profile import (ops 50-52). Its thread does the network and writes
// the save; the game thread only starts it and reads its state.

static CRITICAL_SECTION g_impCs;
static HANDLE g_impThread = nullptr;
static int g_impState = 0;   // 0 idle, 1 running, 2 done, 3 failed
static int g_impStage = 0;
static std::string g_impName, g_impSummary, g_impError;
static int g_impKind = 0;    // 0 the EA import, 1 N7 HQ (op 53)
static int g_impPage = 0, g_impPages = 0;
static std::string g_impHint;
static std::string g_n7Platform, g_n7Name;   // op 53's request, set before its thread starts
static std::string g_n7Session;               // a pasted N7 HQ session (ME3N7HQSID), from the clipboard

// One option value for "?k=v" text: GameInfo.ParseOption has no escaping.
static std::string OptionValue(std::string v) {
    for (char& c : v) if (c == '?' || c == '=' || c == '\r' || c == '\n') c = ' ';
    return v;
}

static DWORD WINAPI ImportThread(void*) {
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    ea::ImportResult r; std::string err;
    bool ok = ea::FetchMe3Profile(r, err, [](int stage) {
        EnterCriticalSection(&g_impCs); g_impStage = stage; LeaveCriticalSection(&g_impCs);
        L("import: stage %d", stage);
    });
    if (ok) {
        L("import: EA returned %zu settings for '%s': %s", r.settings, r.displayName.c_str(), r.summary.c_str());
        // The current save stays, under a name no later save overwrites
        // (WriteSave's .bak is replaced by the next save).
        if (GetFileAttributesW(SavePath().c_str()) != INVALID_FILE_ATTRIBUTES) {
            SYSTEMTIME st; GetLocalTime(&st);
            wchar_t stamp[40];
            swprintf(stamp, 40, L"%04d%02d%02d-%02d%02d%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            std::wstring keep = g_cloud + L"\\LEMP_mpsave.preimport-" + stamp + L".txt";
            if (!CopyFileW(SavePath().c_str(), keep.c_str(), TRUE)) {
                ok = false; err = "could not keep a copy of the current save, so nothing was replaced";
                L("import: cannot copy the save to %ls (%lu)", keep.c_str(), GetLastError());
            } else {
                L("import: the previous save is kept as %ls", keep.c_str());
            }
        }
        if (ok && !WriteSave(r.data)) { ok = false; err = "the profile could not be written (see the debug log)"; }
    }
    if (!ok) L("import: failed: %s", err.c_str());
    else L("import: done");
    EnterCriticalSection(&g_impCs);
    g_impState = ok ? 2 : 3;
    g_impName = r.displayName; g_impSummary = r.summary; g_impError = err;
    LeaveCriticalSection(&g_impCs);
    return 0;
}

// A saved N7 HQ tab, read back whole ("" if missing).
static std::string ReadWholeFile(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "";
    std::string text; char buf[65536]; DWORD got = 0;
    while (ReadFile(h, buf, sizeof buf, &got, nullptr) && got > 0) text.append(buf, got);
    CloseHandle(h);
    return text;
}

// The pages N7 HQ gave, converted into the save (n7hq_convert.h, n7hq_synth.h):
// merged onto the current save, which is kept first as
// LEMP_mpsave.preimport-<date>-<time>.txt, as the EA import does. `err` says
// why nothing was written.
static bool ConvertN7(const std::wstring& dir, const std::string& name, std::string& summary, std::string& err) {
    std::wstring stem = dir + L"\\" + std::wstring(g_n7Platform.begin(), g_n7Platform.end()) + L"-";
    std::string fp = ea::n7hq::FilePart(name);
    stem += std::wstring(fp.begin(), fp.end()) + L"-";
    std::string ov = ReadWholeFile(stem + L"overview.html"), inv = ReadWholeFile(stem + L"inventory.html"),
                ch = ReadWholeFile(stem + L"characters.html"), chal = ReadWholeFile(stem + L"challenges.html");
    if (inv.empty() || ch.empty()) { err = "the saved inventory or characters page is missing"; return false; }
    ea::n7conv::Profile p = ea::n7conv::Parse(ov, inv, ch, chal);
    if (p.kits.empty() || p.items.empty()) { err = "N7 HQ's pages held no kits or items"; return false; }
    MPSaveData cur;
    int have = ReadSave(cur);
    if (have == 2) { err = "the current save is unreadable, so nothing was replaced"; return false; }
    ea::n7conv::SaveReport rep;
    MPSaveData d = ea::n7conv::BuildSave(p, have == 0 ? &cur : nullptr, rep, ea::n7conv::KitClasses(), (long long)time(nullptr));
    L("n7hq: converted: credits %lld, items %d (unmapped %d), consumables %d (unmapped %d), %d classes, characters %d kept + %d new, powers %d set, %d default",
      p.credits, rep.vars.itemsPlaced, rep.vars.itemsUnmapped, rep.vars.consumablesPlaced, rep.vars.consumablesUnmapped,
      rep.classes, rep.charsKept, rep.charsNew, rep.powersSet, rep.powersDefault);
    const ea::n7conv::ChallengeReport& cr = rep.challenges;
    if (rep.challengesSet)
        L("n7hq: challenges: %d golds + %d silvers read (%d unmapped, %d skipped), %d completed, %d progress counters, %lld challenge points",
          cr.golds, cr.silvers, cr.unmapped, cr.skipped, cr.completed, cr.counters, cr.points);
    else
        L("n7hq: challenges: no challenges tab, the save keeps its own");
    for (const std::string& u : rep.vars.unmapped) L("n7hq:   no id: %s", u.c_str());
    for (const std::string& n : rep.notes) L("n7hq:   default powers: %s", n.c_str());
    if (have == 0) {
        SYSTEMTIME st; GetLocalTime(&st);
        wchar_t stamp[40];
        swprintf(stamp, 40, L"%04d%02d%02d-%02d%02d%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        std::wstring keep = g_cloud + L"\\LEMP_mpsave.preimport-" + stamp + L".txt";
        if (!CopyFileW(SavePath().c_str(), keep.c_str(), TRUE)) {
            err = "could not keep a copy of the current save, so nothing was replaced";
            L("n7hq: cannot copy the save to %ls (%lu)", keep.c_str(), GetLastError());
            return false;
        }
        L("n7hq: the previous save is kept as %ls", keep.c_str());
    }
    if (!WriteSave(d)) { err = "the profile could not be written (see the debug log)"; return false; }
    summary = std::to_string(rep.classes) + " classes, " + std::to_string(rep.charsKept + rep.charsNew) + " characters";
    if (rep.challengesSet) summary += ", " + std::to_string(cr.completed) + " challenges";
    return true;
}

// N7 HQ (op 53): a profile's pages read and saved, then converted into the
// save.
static DWORD WINAPI N7Thread(void*) {
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    ea::n7hq::Outcome o;
    std::wstring dir = LempDir() + L"\\n7hq";
    bool ok = ea::n7hq::ReadProfile(g_n7Platform, g_n7Name, dir, o,
        [](int stage, int page) {
            EnterCriticalSection(&g_impCs); g_impStage = stage; g_impPage = page; LeaveCriticalSection(&g_impCs);
            if (page <= 1) L("n7hq: step %d of 4", stage);
        },
        [](const std::string& line) { L("%s", line.c_str()); },
        g_n7Session);
    g_n7Session.assign(g_n7Session.size(), '\0'); g_n7Session.clear();
    int stage;
    EnterCriticalSection(&g_impCs); stage = g_impStage; LeaveCriticalSection(&g_impCs);
    std::string summary;
    if (ok) {
        L("n7hq: saved %d page(s) to %ls\\%s-%s-*.html", o.pages, dir.c_str(), g_n7Platform.c_str(), ea::n7hq::FilePart(o.name).c_str());
        std::string err;
        if (ConvertN7(dir, o.name, summary, err)) {
            L("n7hq: done: imported %s (%s)", o.name.c_str(), summary.c_str());
        } else {
            ok = false;
            o.line1 = "The profile was read but not imported.";
            o.line2 = "Nothing was changed, send mp_save.log.";
            o.detail = err;
            L("n7hq: not imported: %s", err.c_str());
        }
    } else {
        L("n7hq: failed at step %d: %s / %s (%s)", stage, o.line1.c_str(), o.line2.c_str(), o.detail.c_str());
    }
    EnterCriticalSection(&g_impCs);
    g_impState = ok ? 2 : 3;
    g_impName = o.name; g_impPages = o.pages; g_impSummary = summary;
    g_impError = ok ? "" : o.line1; g_impHint = ok ? "" : o.line2;
    LeaveCriticalSection(&g_impCs);
    return 0;
}

static void ServeImport(UObject* self) {
    int32_t* op = IntProp(self, "AsiOp");
    int32_t* result = IntProp(self, "AsiResult");
    FStringRaw* buf = StrProp(self, "AsiBuf");
    int32_t* len = IntProp(self, "AsiLen");
    if (!op || !result || !buf || !len) { L("import: SFXMPProfileName lacks AsiOp/AsiResult/AsiBuf/AsiLen"); if (result) *result = 5; return; }
    if (*op == 53) {
        std::u16string text; std::string why, ascii;
        if (!ReadFString(buf, text, why)) { L("n7hq: AsiBuf: %s", why.c_str()); *result = 2; return; }
        for (char16_t c : text) {
            if (c > 126 || c < 32) { L("n7hq: refused: the request is not plain text"); *result = 2; return; }
            ascii += (char)c;
        }
        auto m = online::ParseOptions(ascii);
        std::string platform = m["platform"], name = m["name"];
        if (!ea::n7hq::FindPlatform(platform) || !ea::n7hq::ValidName(name)) {
            L("n7hq: refused: platform '%s', name of %zu char(s)", platform.c_str(), name.size()); *result = 2; return;
        }
        EnterCriticalSection(&g_impCs);
        bool running = g_impState == 1;
        if (!running) {
            g_impState = 1; g_impStage = 0; g_impKind = 1; g_impPage = 0; g_impPages = 0;
            g_impName.clear(); g_impSummary.clear(); g_impError.clear(); g_impHint.clear();
        }
        LeaveCriticalSection(&g_impCs);
        if (running) { *result = 1; return; }
        if (g_impThread) { CloseHandle(g_impThread); g_impThread = nullptr; }
        g_n7Platform = platform; g_n7Name = name;
        // The player's pasted N7 HQ sign-in (their ME3N7HQSID session), from
        // the op 53 request: a browser session carries N7 HQ's full scopes,
        // which the EA app's token cannot, so the read uses it in place of an
        // EA sign-in. The menu already extracts the id from what was pasted;
        // this accepts only its characters and caps the length. It is a
        // credential and is never logged (only whether one was given).
        g_n7Session.clear();
        {
            std::string sid = m["session"];
            bool okSid = !sid.empty() && sid.size() <= 128;
            for (char ch : sid) if (!(isalnum((unsigned char)ch) || ch == '-' || ch == '_')) okSid = false;
            if (okSid) g_n7Session = sid;
            else if (!sid.empty()) L("n7hq: the pasted sign-in is not a valid session, ignoring it");
        }
        L("n7hq: started (the player agreed): platform=%s name='%s'%s", platform.c_str(), name.c_str(),
          g_n7Session.empty() ? " (no pasted sign-in)" : " (using the pasted N7 HQ sign-in)");
        g_impThread = CreateThread(nullptr, 0, N7Thread, nullptr, 0, nullptr);
        if (!g_impThread) {
            EnterCriticalSection(&g_impCs);
            g_impState = 3; g_impError = "LEMP could not start the import."; g_impHint = "Restart the game and try again.";
            LeaveCriticalSection(&g_impCs);
        }
        *result = 0;
        return;
    }
    if (*op == 50) {
        EnterCriticalSection(&g_impCs);
        bool running = g_impState == 1;
        if (!running) { g_impState = 1; g_impStage = 0; g_impKind = 0; g_impName.clear(); g_impSummary.clear(); g_impError.clear(); g_impHint.clear(); }
        LeaveCriticalSection(&g_impCs);
        if (running) { *result = 1; return; }
        if (g_impThread) { CloseHandle(g_impThread); g_impThread = nullptr; }
        L("import: started (the player agreed)");
        g_impThread = CreateThread(nullptr, 0, ImportThread, nullptr, 0, nullptr);
        if (!g_impThread) {
            EnterCriticalSection(&g_impCs); g_impState = 3; g_impError = "no thread"; LeaveCriticalSection(&g_impCs);
        }
        *result = 0;
        return;
    }
    static const char* kStates[] = { "idle", "running", "done", "failed" };
    EnterCriticalSection(&g_impCs);
    std::string text = std::string("?state=") + kStates[g_impState] + "?stage=" + std::to_string(g_impStage) +
                       "?name=" + OptionValue(g_impName) + "?summary=" + OptionValue(g_impSummary) + "?error=" + OptionValue(g_impError);
    if (g_impKind == 1)
        text += "?kind=n7hq?page=" + std::to_string(g_impPage) + "?pages=" + std::to_string(g_impPages) + "?hint=" + OptionValue(g_impHint);
    LeaveCriticalSection(&g_impCs);
    std::u16string v; ea::Utf8To16(text, v);
    if (*op == 51) { *len = (int32_t)v.size(); *result = 0; }
    else *result = FillBuf(buf, v, "import") ? 0 : 4;
}

static std::string BuildKeyUtf8() {
    return std::string(g_buildKey.begin(), g_buildKey.end());   // ASCII (build_key.h)
}

static void ServeOnline(UObject* self) {
    int32_t* op = IntProp(self, "AsiOp");
    int32_t* result = IntProp(self, "AsiResult");
    FStringRaw* buf = StrProp(self, "AsiBuf");
    int32_t* len = IntProp(self, "AsiLen");
    int32_t* idx = IntProp(self, "AsiIndex");
    // AsiIndex only for 21 and 29: the main menu's SFXMPProfileName (ops 32/33) has none.
    if (!op || !result || !buf || !len || (!idx && (*op == 21 || *op == 29 || *op == 42))) { L("online: %s lacks AsiOp/AsiResult/AsiBuf/AsiLen/AsiIndex", ClassNameOf(self)); if (result) *result = 5; return; }
    std::u16string in; std::string why, text;
    auto input = [&]() -> std::string {
        if (!ReadFString(buf, in, why)) return "";
        std::string a;
        for (char16_t c : in) a += (c < 0x80) ? (char)c : '?';
        return a;
    };
    auto fill = [&](const std::string& value, int lenOp) {
        std::u16string v(value.begin(), value.end());
        if (*op == lenOp) { *len = (int32_t)v.size(); *result = 0; }
        else *result = FillBuf(buf, v, "online") ? 0 : 4;
    };
    switch (*op) {
    case 20: *result = online::StartSearch(input()); return;
    case 21: *idx = online::PollSearch(); *result = 0; return;
    case 22: case 23: fill(online::SearchText(), 22); return;
    case 24: online::CancelSearch(); *result = 0; return;
    case 25: *result = online::ReportJoinFailed(); return;
    case 26: *result = online::UpdateLobby(input()); return;
    case 27: *result = online::RenewLobby(); return;
    case 28: *result = online::DestroyLobby(); return;
    case 29: case 30: { int r = -1; text = online::LobbyStatus(r); if (*op == 29) *idx = r; fill(text, 29); return; }
    case 31: L("script: %s", input().c_str()); *result = 0; return;
    case 32: case 33: fill(online::StatsText(), 32); return;
    case 34: online::SetStatsFilter(input()); *result = 0; return;
    // The leaderboards (lemp_online.h). 37/38 carry players' names: UTF-8
    // from the server, so converted, not widened byte by byte like the rest.
    case 35: *result = online::ReportStats(input()); return;
    case 36: *result = online::StartBoard(input()); return;
    case 37: case 38: {
        std::u16string v = online::Utf8To16(online::BoardText());
        if (*op == 37) { *len = (int32_t)v.size(); *result = 0; }
        else *result = FillBuf(buf, v, "online") ? 0 : 4;
        return;
    }
    // The release check (lemp_online.h): 39 sets the release, 40/41 the verdict.
    case 39: *result = online::SetVersion(input()); return;
    case 40: case 41: fill(online::VersionText(), 40); return;
    // The release this lemp.asi was built for: the DLC's script compares its own.
    case 55: case 56: fill(online::Release(), 55); return;
    // UTC seconds, the clock the native challenge filters read through
    // online_api.asi: script's own clock,
    // GetComponentAPI().GetCurrentTime(), is None here and reads 0.
    case 42: *idx = (int32_t)time(nullptr); *result = 0; return;
    // Host migration (lemp_online.h): the hosted lobby's id and key, which
    // the host hands to the players in its match.
    case 43: case 44: fill(online::MigrationTicket(), 43); return;
    // And how well this machine could host instead (the host's order).
    case 53: case 54: fill(online::HostQuality(), 53); return;
    }
    L("online: unknown AsiOp %d", *op);
    *result = 6;
}

// ---------------------------------------------------------------------------
// The level package map's digest (ops 45-49).
//
// UE3 names a replicated object as (package-map entry, NetIndex), and the
// entries are numbered by summing their object counts in list order, so a
// host and a client that list different packages, or one package with
// different counts, misname every object after the first difference — forced
// packages change counts, as does VocalizationBanks 2 vs 0. UE3 compared the
// lists' GUIDs at join and refused a mismatch; join_patch turns that off (LE3
// gives SFXGameContent and PlotManagerAuto* per-process GUIDs), so
// nothing compared them any more. Script does it with these ops: the host
// sends its digest to a joiner, which compares it with its own.
//
// Layout: repl_probe's calibration of UPackageMapLevel on this exe (every
// run): the list TArray at +0x68, entries 0x98 apart, PackageName
// (FName) at +0x0, ObjectCount at +0x24 (ObjectBase at +0x20 follows from the
// counts). The array's Count reads twice the named entries (680 for 340),
// so entries are taken up to the first slot without a plausible name,
// and the first must be Core: otherwise the layout is wrong and the map is
// not used.
// ---------------------------------------------------------------------------
static const size_t PKGMAP_LIST = 0x68, PKGMAP_STRIDE = 0x98, PKGMAP_NAME = 0x0, PKGMAP_COUNT = 0x24;

struct PkgEntry { std::string name; int32_t count; };

static bool PlausiblePkgName(const FName& n, std::string& out) {
    if (n.Chunk > 7 || !g_pools || IsBadReadPtr(g_pools + n.Chunk, sizeof(void*)) || !g_pools[n.Chunk]) return false;
    auto* e = (FNameEntry*)((uint8_t*)g_pools[n.Chunk] + n.Offset);
    if (IsBadReadPtr(e, 16)) return false;
    const char* p = e->AnsiName;
    int len = 0;
    for (; len < 64 && !IsBadReadPtr(p + len, 1) && p[len]; ++len)
        if (!((p[len] >= 'A' && p[len] <= 'Z') || (p[len] >= 'a' && p[len] <= 'z') ||
              (p[len] >= '0' && p[len] <= '9') || p[len] == '_')) return false;
    if (len == 0 || len >= 64) return false;
    out.assign(p, len);
    return true;
}

// IsBadReadPtr for one scan of GObjects: the readable regions VirtualQuery
// has already reported are remembered, so the objects that share one cost one
// system call, not one each. Sound only while nothing can free memory: the
// scan runs inside a script call on the game thread (ServePackages), and the
// cache lives no longer than that call.
//
// MISTAKE, recorded: the scan called
// IsBadReadPtr (a VirtualQuery since safe_read.h) about five times per object,
// over every object in GObjects, twice per joiner (ops 45 and 46). On a
// Windows host that took ~11.5 s per scan on the game thread: 23 s in which
// the host sent nothing, so every client already in the lobby heard no
// heartbeat for 10 s and migrated. Under Proton it took ~0.7 s, so it was
// never seen until the first three-player session with a Windows host.
struct ScanReadable {
    struct Range { uintptr_t lo, hi; };
    Range r[16];
    int n = 0, next = 0;
    bool ok(const void* p, size_t len) {
        uintptr_t a = (uintptr_t)p, e = a + len;
        if (!p || e < a) return false;
        for (int i = 0; i < n; ++i)
            if (a >= r[i].lo && e <= r[i].hi) return true;
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(p, &mbi, sizeof mbi)) return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
        if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) return false;
        uintptr_t lo = (uintptr_t)mbi.BaseAddress, hi = lo + mbi.RegionSize;
        if (e > hi) return !IsBadReadPtr(p, len);   // spans regions: the full check
        r[next] = {lo, hi};
        next = (next + 1) % 16;
        if (n < 16) ++n;
        return true;
    }
};

// The live level package map with the most named entries (a host has one per
// connection besides its own; they list the same packages). The answer is
// kept for 2 s: the host asks twice per joiner (45, 46), the joiner once per
// 64-entry piece (47), all within a frame or a few.
static bool ReadPackageMap(std::vector<PkgEntry>& out) {
    static std::vector<PkgEntry> kept;
    static DWORD keptAt = 0;
    out.clear();
    if (!kept.empty() && GetTickCount() - keptAt < 2000) { out = kept; return true; }
    if (!g_objs || IsBadReadPtr(g_objs, sizeof(*g_objs))) return false;
    DWORD t0 = GetTickCount();
    // The game thread is the one here, so GObjects cannot grow under the scan:
    // its header is read once and its slots checked once.
    TArray<UObject*> objs = *g_objs;
    if (!objs.Data || objs.Count < 0 || objs.Count > objs.Max ||
        IsBadReadPtr(objs.Data, (size_t)objs.Count * sizeof(UObject*))) return false;
    ScanReadable readable;
    std::unordered_map<UObject*, bool> classes;   // class -> is PackageMapLevel
    for (int i = 0; i < objs.Count; ++i) {
        UObject* o = objs.Data[i];
        if (!o || !readable.ok(o, PKGMAP_LIST + 16)) continue;
        UObject* c = o->Class;
        if (!c) continue;
        auto it = classes.find(c);
        if (it == classes.end())
            it = classes.emplace(c, readable.ok(c, sizeof(UObject)) && _stricmp(NameOf(c->Name), "PackageMapLevel") == 0).first;
        if (!it->second) continue;
        if (strncmp(NameOf(o->Name), "Default__", 9) == 0) continue;
        auto* arr = (TArray<uint8_t>*)((uint8_t*)o + PKGMAP_LIST);
        if (!arr->Data || arr->Count < 1 || arr->Count > 20000 || arr->Max < arr->Count) continue;
        std::vector<PkgEntry> list;
        for (int k = 0; k < arr->Count; ++k) {
            uint8_t* e = arr->Data + (size_t)k * PKGMAP_STRIDE;
            if (IsBadReadPtr(e, PKGMAP_STRIDE)) break;
            std::string name;
            if (!PlausiblePkgName(*(FName*)(e + PKGMAP_NAME), name)) break;
            list.push_back({name, *(int32_t*)(e + PKGMAP_COUNT)});
        }
        if (list.empty() || _stricmp(list[0].name.c_str(), "Core") != 0) continue;
        if (list.size() > out.size()) out.swap(list);
    }
    L("packages: scanned %d objects (%zu classes) in %lu ms", objs.Count, classes.size(),
      (unsigned long)(GetTickCount() - t0));
    if (out.empty()) return false;
    kept = out;
    keptAt = GetTickCount();
    return true;
}

// Four hex digits per entry: FNV-1a over the lower-cased name and the count.
static uint16_t PkgEntryHash(const PkgEntry& e) {
    uint32_t h = 2166136261u;
    for (char c : e.name) { h ^= (uint8_t)((c >= 'A' && c <= 'Z') ? c + 32 : c); h *= 16777619u; }
    for (int b = 0; b < 4; ++b) { h ^= (uint8_t)((uint32_t)e.count >> (8 * b)); h *= 16777619u; }
    return (uint16_t)(h ^ (h >> 16));
}

static int         g_pkgMismatch = -1;   // the comparison's first differing entry
static std::string g_pkgMismatchText;    // "<name>:<count>" here

static void ServePackages(UObject* self) {
    int32_t* op = IntProp(self, "AsiOp");
    int32_t* result = IntProp(self, "AsiResult");
    FStringRaw* buf = StrProp(self, "AsiBuf");
    int32_t* len = IntProp(self, "AsiLen");
    int32_t* idx = IntProp(self, "AsiIndex");
    if (!op || !result || !buf || !len || !idx) { L("packages: %s lacks AsiOp/AsiResult/AsiBuf/AsiLen/AsiIndex", ClassNameOf(self)); if (result) *result = 5; return; }
    auto fill = [&](const std::string& value, int lenOp) {
        std::u16string v(value.begin(), value.end());
        if (*op == lenOp) { *len = (int32_t)v.size(); *result = 0; }
        else *result = FillBuf(buf, v, "packages") ? 0 : 4;
    };
    std::vector<PkgEntry> map;
    switch (*op) {
    case 45: case 46: {
        if (!ReadPackageMap(map)) { L("packages: no level package map"); *result = 2; return; }
        std::string s = std::to_string(map.size()) + ":";
        char h[8];
        for (auto& e : map) { snprintf(h, sizeof(h), "%04x", PkgEntryHash(e)); s += h; }
        if (*op == 45) L("packages: digest of %zu entries", map.size());
        fill(s, 45);
        return;
    }
    case 47: {
        std::u16string in; std::string why;
        if (!ReadFString(buf, in, why)) { L("packages: could not read AsiBuf: %s", why.c_str()); *result = 1; return; }
        int first = *idx;
        if (first == 0) { g_pkgMismatch = -1; g_pkgMismatchText.clear(); }
        if (!ReadPackageMap(map)) { L("packages: no level package map"); *result = 2; return; }
        size_t n = in.size() / 4;
        for (size_t k = 0; k < n && g_pkgMismatch < 0 && first >= 0; ++k) {
            size_t i = (size_t)first + k;
            char hex[5] = {(char)in[k * 4], (char)in[k * 4 + 1], (char)in[k * 4 + 2], (char)in[k * 4 + 3], 0};
            unsigned theirs = (unsigned)strtoul(hex, nullptr, 16);
            if (i >= map.size()) {
                g_pkgMismatch = (int)i;
                g_pkgMismatchText = "(none):0";
                L("packages: entry %zu: the host lists one, this process only %zu", i, map.size());
            } else if (PkgEntryHash(map[i]) != theirs) {
                g_pkgMismatch = (int)i;
                g_pkgMismatchText = map[i].name + ":" + std::to_string(map[i].count);
                L("packages: entry %zu differs from the host's: here %s with %d objects", i, map[i].name.c_str(), map[i].count);
            }
        }
        *idx = g_pkgMismatch;
        *result = 0;
        return;
    }
    case 48: case 49:
        fill(g_pkgMismatchText, 48);
        return;
    }
    L("packages: unknown AsiOp %d", *op);
    *result = 6;
}

// ---------------------------------------------------------------------------
// Ops 57-59, to SFXMPLocalSave: the engine's `set`/`get`, without the console.
//
// SFXGRIMP applies MP-only values to classes the campaign shares (weapon
// damage, ammo, weight) with `set <Class> <Prop> <Value>` at match start and
// restores them after. Through ConsoleCommand that does nothing in a network
// session: every `get` answers empty and no value changes. The console layer
// refuses there; the command code below it has no such check. So this calls
// it directly:
//   AsiOp 57        AsiBuf = "<Class> <Prop> <Value>": PerformSetCommand, the
//                   function SET and SETNOPEC call (bNotifyObjectOfChange = 1,
//                   as SET). It imports the text as config loading does and
//                   writes it into the class default object and every live
//                   object of the class.
//                   Result 0 done. A WORKING set is NOT silent here: with
//                   bNotify=1 this exe echoes "Executing set command <value>"
//                   every time it runs (this op
//                   used to treat ANY output as a failure, so a real set was
//                   logged and counted the same as one that never ran;
//                   balance_classify.h). A genuine problem: 1 some other
//                   engine message (logged), 2 not available in this exe, 3
//                   "Unrecognized property <P> on class <C>" (the class
//                   loaded, has no such property — SFXGRIMP does not retry
//                   this one).
//   AsiOp 58 / 59   AsiBuf = "<Class> <Prop>": GET through the command
//                   dispatcher, length / fill: the value as text.
//                   The same class/property lookup prints the same two
//                   failure messages for GET [R: inferred from 57's text and
//                   the counts it explains in the reopened build 6 run — 58
//                   never logged its own text before this fix, so this is not
//                   yet seen directly for GET]: AsiLen/AsiBuf answer "" and
//                   result 4 for "Unrecognized class or object" (not loaded
//                   yet: SFXGRIMP retries it), result 5 for "Unrecognized
//                   property" (found the class, never resolves: SFXGRIMP
//                   marks it and stops). Any other message: "" and result 1
//                   (logged, once per distinct "<Class> <Prop>" this
//                   process — SFXGRIMP reruns the whole list at every menu,
//                   lobby and match transition, and a still-pending entry is
//                   asked again every 2 s). 58 answers 2 as 57 does.
//
// Neither has a symbol. They are pinned for this exe and used only if the
// code at both call sites still reads: lea rdx,"SET" ... call PerformSetCommand,
// lea rdx,"SETNOPEC" ... call PerformSetCommand, and lea rdx,"GET" inside the
// dispatcher. Any other exe gets result 2, never a guess.
static const uintptr_t RVA_EXEC_DISPATCH = 0x132E60;   // static (const TCHAR* Cmd, FOutputDevice& Ar)
static const uintptr_t RVA_PERFORM_SET   = 0x12B700;   // (const TCHAR* Str, FOutputDevice& Ar, UBOOL bNotify)
static const uintptr_t RVA_SET_LEA       = 0x133CD5, RVA_SET_CALL      = 0x133CF3;
static const uintptr_t RVA_SETNOPEC_LEA  = 0x133CFD, RVA_SETNOPEC_CALL = 0x133D1D;
static const uintptr_t RVA_GET_LEA       = 0x132F05;

typedef void (*ExecDispatchFn)(const char16_t* cmd, void* ar);
typedef void (*PerformSetFn)(const char16_t* str, void* ar, int32_t notify);
static int            g_setState = 0;   // 0 not checked, 1 verified, -1 refused
static ExecDispatchFn g_execDispatch = nullptr;
static PerformSetFn   g_performSet = nullptr;

// The rel32 target of a 7-byte `lea r64,[rip+disp32]` or a 5-byte `call rel32`.
static uint8_t* RelTarget(uint8_t* at, size_t len, size_t dispAt) {
    if (at < g_base || at + len > g_end || IsBadReadPtr(at, len)) return nullptr;
    int32_t disp; memcpy(&disp, at + dispAt, 4);
    return at + len + disp;
}
static bool LeaRdxTo(uintptr_t rva, const char16_t* want) {
    uint8_t* at = g_base + rva;
    if (at + 7 > g_end || IsBadReadPtr(at, 7) || at[0] != 0x48 || at[1] != 0x8D || at[2] != 0x15) return false;
    const char16_t* s = (const char16_t*)RelTarget(at, 7, 3);
    size_t n = 0; while (want[n]) ++n;
    if (!s || (uint8_t*)s < g_base || (uint8_t*)(s + n + 1) > g_end || IsBadReadPtr(s, (n + 1) * 2)) return false;
    return memcmp(s, want, (n + 1) * 2) == 0;
}
static bool CallTo(uintptr_t rva, uintptr_t targetRva) {
    uint8_t* at = g_base + rva;
    if (at + 5 > g_end || IsBadReadPtr(at, 5) || at[0] != 0xE8) return false;
    return RelTarget(at, 5, 1) == g_base + targetRva;
}
static bool VerifySetCommand() {
    if (g_setState) return g_setState > 0;
    bool ok = LeaRdxTo(RVA_SET_LEA, u"SET") && CallTo(RVA_SET_CALL, RVA_PERFORM_SET)
           && LeaRdxTo(RVA_SETNOPEC_LEA, u"SETNOPEC") && CallTo(RVA_SETNOPEC_CALL, RVA_PERFORM_SET)
           && LeaRdxTo(RVA_GET_LEA, u"GET");
    if (ok) {
        // Both sites must lie in the dispatcher the GET op calls.
        DWORD64 imageBase = 0;
        PRUNTIME_FUNCTION f = RtlLookupFunctionEntry((DWORD64)(g_base + RVA_SET_LEA), &imageBase, nullptr);
        PRUNTIME_FUNCTION g = RtlLookupFunctionEntry((DWORD64)(g_base + RVA_GET_LEA), &imageBase, nullptr);
        ok = f && g && f->BeginAddress == RVA_EXEC_DISPATCH && g->BeginAddress == RVA_EXEC_DISPATCH;
    }
    g_setState = ok ? 1 : -1;
    if (ok) {
        g_execDispatch = (ExecDispatchFn)(g_base + RVA_EXEC_DISPATCH);
        g_performSet = (PerformSetFn)(g_base + RVA_PERFORM_SET);
    }
    L("balance: set/get command code %s", ok ? "verified" : "NOT as expected in this exe; ops 57-59 answer 2");
    return ok;
}

// A minimal FOutputDevice: vtable slot 1 is Serialize(const TCHAR*, EName),
// which Log/Logf call; every other slot does nothing. It collects the text.
// In this exe FOutputDevice::Log (rva 0x113130, the call GET makes with the
// value) returns at once when the dword at +8 is set, or +0xC and a global
// are; otherwise it jumps through [vtable+8] with the text in rdx. The
// device is static, so both flags stay 0 and every line reaches slot 1.
struct CaptureDevice { void** vtbl; uint32_t flags[8]; };
static std::u16string g_capture;
static void* DevNop(void* self, void*, void*, void*) { return self; }
// Readability is checked once per page, not per character: IsBadReadPtr is
// a VirtualQuery here (safe_read.h), and a per-character call made a long
// GET cost thousands of them. The old 4096-character cap clipped the two
// difficulty tables' values (their GET text is longer), which a restore
// would then have written back clipped; 1M characters is a runaway guard
// only. A char16_t never straddles a page, so the page check covers it.
static void DevSerialize(void* self, const char16_t* v, int32_t event) {
    if (!v) return;
    for (size_t n = 0; n < (1u << 20); ++n) {
        if ((n == 0 || ((uintptr_t)(v + n) & 0xFFF) == 0) && IsBadReadPtr(v + n, 2)) break;
        if (!v[n]) break;
        g_capture += v[n];
    }
}
static void* g_devVtbl[16];
static CaptureDevice* Device() {
    static CaptureDevice dev;
    if (!dev.vtbl) {
        for (auto& p : g_devVtbl) p = (void*)&DevNop;
        g_devVtbl[1] = (void*)&DevSerialize;
        dev.vtbl = g_devVtbl;
    }
    g_capture.clear();
    return &dev;
}

static std::u16string g_getText;

// GET's own failure text, logged once per distinct "<Class> <Prop>" per
// process rather than every time it is asked: SFXGRIMP reruns the whole
// MPBalanceSettings list at every menu/lobby/match transition, and asks
// again every 2 s for as long as an entry stays pending, so without this a
// single build 6 session wrote the same "Unrecognized ..." line for one
// not-yet-loaded weapon dozens of times.
static std::unordered_set<std::string> g_getLogged;
static void LogGetProblem(const std::string& ascii, const std::u16string& raw) {
    if (!g_getLogged.insert(ascii).second) return;
    L("balance: get %s: %s", ascii.c_str(), std::string(raw.begin(), raw.end()).c_str());
}

static double QpcMicros(LARGE_INTEGER a, LARGE_INTEGER b);
// One SET or GET over 8 ms, by name: the balance timing line gives only the
// average and the maximum per 500 ops, which cannot say which entry or which
// of the two calls stalls a frame. At most 40 lines a process.
static void NoteSlowBalanceOp(int op, const std::string& target, double us) {
    static int logged = 0;
    if (us < 8000.0 || logged >= 40) return;
    ++logged;
    L("balance: slow %s %s: %.1f ms", op == 57 ? "set" : "get", target.c_str(), us / 1000.0);
}

static void ServeBalance(UObject* self) {
    int32_t* op = IntProp(self, "AsiOp");
    int32_t* result = IntProp(self, "AsiResult");
    FStringRaw* buf = StrProp(self, "AsiBuf");
    int32_t* len = IntProp(self, "AsiLen");
    if (!op || !result || !buf || !len) { L("balance: %s lacks AsiOp/AsiResult/AsiBuf/AsiLen", ClassNameOf(self)); if (result) *result = 5; return; }
    if (*op == 59) { *result = FillBuf(buf, g_getText, "balance") ? 0 : 4; return; }
    if (!VerifySetCommand()) { *result = 2; return; }
    std::u16string in; std::string why;
    if (!ReadFString(buf, in, why) || in.empty()) { L("balance: could not read AsiBuf: %s", why.c_str()); *result = 1; return; }
    std::string ascii(in.begin(), in.end());   // for the log only
    if (*op == 57) {
        CaptureDevice* dev = Device();
        // bNotify = 0, as SETNOPEC: no PreEditChange/PostEditChange on the
        // class default and on every live object of the class. With 1, one
        // set of a weapon property took up to ~150 ms on the game thread
        // (the balance timing line's serve max), a hitch each time a weapon
        // class loaded mid-match and its entries were applied. The values set
        // here (damage, ammo, weight, spread) are read when used, and the
        // script reads each one back after the set, so the notification adds
        // nothing. A working SETNOPEC prints nothing: Outcome::Nothing below.
        LARGE_INTEGER s0, s1;
        QueryPerformanceCounter(&s0);
        g_performSet(in.c_str(), dev, 0);
        QueryPerformanceCounter(&s1);
        NoteSlowBalanceOp(57, ascii, QpcMicros(s0, s1));
        // Nothing and "Executing set command ..." both mean the set ran
        // (balance_classify.h): only a message naming an actual problem is a
        // failure. Before this fix every non-empty capture — including that
        // trace of a WORKING set — was logged and reported as one.
        balance::Outcome r = balance::Classify(g_capture);
        if (r != balance::Outcome::Nothing && r != balance::Outcome::Success) {
            L("balance: set %s: %s", ascii.c_str(), std::string(g_capture.begin(), g_capture.end()).c_str());
        }
        *result = (r == balance::Outcome::Nothing || r == balance::Outcome::Success) ? 0
                : (r == balance::Outcome::PropertyNotFound) ? 3 : 1;
        return;
    }
    // 58: GET's length (59, above, fills AsiBuf from the text this leaves in
    // g_getText). Unlike SET, "nothing" and the class/property lookup's own
    // failure text both mean "no value" here: that is the one signal
    // SFXGRIMP's pending check (AsiGet(...) == "") has ever had, and a real
    // GET success always has SOME text (at minimum the value itself), so an
    // empty capture is never mistaken for one. GET's text is classified by
    // ClassifyGet, not SET's Classify: with Classify, a real value and GET's
    // "Unrecognized class <C>" were both Other, so no GET ever succeeded.
    std::u16string cmd = u"GET " + in;
    CaptureDevice* dev = Device();
    LARGE_INTEGER g0, g1;
    QueryPerformanceCounter(&g0);
    g_execDispatch(cmd.c_str(), dev);
    QueryPerformanceCounter(&g1);
    NoteSlowBalanceOp(58, ascii, QpcMicros(g0, g1));
    std::u16string raw = g_capture;
    while (!raw.empty() && (raw.back() == u'\n' || raw.back() == u'\r')) raw.pop_back();
    balance::Outcome r = balance::ClassifyGet(raw);
    if (r == balance::Outcome::Success) {
        g_getText = raw;
        *len = (int32_t)g_getText.size();
        *result = 0;
        return;
    }
    g_getText.clear();
    *len = 0;
    if (r != balance::Outcome::Nothing) LogGetProblem(ascii, raw);
    *result = (r == balance::Outcome::ClassNotFound || r == balance::Outcome::Nothing) ? 4
            : (r == balance::Outcome::PropertyNotFound) ? 5 : 1;
}

// ---------------------------------------------------------------------------
// The live config layer. ME3's MP took part of its balance from a coalesced
// file the server sent at login, which the engine added to its config as a
// layer named "LiveINI": classes then read it as config when they loaded,
// weapon damage and the weapon types' mod lists among it. LE3 keeps that code.
// LEMP's MP balance for the classes the campaign shares is such a file,
// LEMPBalance.bin in the DLC's CookedPCConsole, and is added the same way:
//
//   - before the engine loads an MP map (MPLobby, BioP_MP*): AddLayer(GConfig,
//     file, "LEMPBalance", 3, 1), the call LE3's LiveINI flush makes, if it
//     is not on yet; before any other map: RemoveLayer(GConfig, layer, 1),
//     so the campaign plays LE3's values. (2012 kept its live file for the
//     whole session; here it is MP-only.)
//   - op 78 (SFXGRIMP, at the start of every MP map): the layer on if it is
//     not, in case the map's name could not be read.
//   - after either, config is loaded again on the class defaults and live
//     objects of every class the layer names that is loaded already (the
//     engine lists them: GConfig's touched-class list), with one object walk.
//     Classes that load later read the layer as config by themselves.
//
// Seen in game with a probe of this code: the pistol base's mod list 9 -> 10
// entries with the layer, 9 again after RemoveLayer; weapons loaded mid-match
// already had the layer's values; MP rebuilds the layer list when it starts
// (8 layers) and keeps this one at priority 3, above the DLCs' 2.
//
// LEMP\nobalancelayer.txt is the control: no layer, LE3's values in MP.
//
// No symbols: every address is used only if the code around LE3's LiveINI
// flush, the RELOADCONFIG command and UGameEngine::Tick's LoadMap call still
// reads as pinned here.
static const uintptr_t RVA_GCONFIG          = 0x17CD5B8;  // FConfigCacheIni* GConfig
static const uintptr_t RVA_GENGINE          = 0x18B31D0;  // UGameEngine* GEngine
static const uintptr_t RVA_ADD_LAYER        = 0x091700;   // (GConfig, const BYTE* Data, const TCHAR* Name, INT Priority, UBOOL bApply) -> layer
static const uintptr_t RVA_REMOVE_LAYER     = 0x09F3E0;   // (GConfig, layer, UBOOL bApply)
static const uintptr_t RVA_LOAD_CONFIG      = 0x128810;   // UObject::LoadConfig(this, UClass*, const TCHAR*, DWORD Flags, UProperty*)
static const uintptr_t RVA_LIVEINI_NAME_LEA = 0xAF6D24;   // lea r8,"LiveINI"
static const uintptr_t RVA_LIVEINI_GCONFIG  = 0xAF6D2B;   // mov rcx,[GConfig]
static const uintptr_t RVA_LIVEINI_ADD      = 0xAF6D48;   // call AddLayer
static const uintptr_t RVA_LIVEINI_REMOVE   = 0xAF6D7B;   // call RemoveLayer
static const uintptr_t RVA_RELOADCFG_LEA    = 0x13407F;   // lea rdx,"RELOADCONFIG"
static const uintptr_t RVA_RELOADCFG_CALL   = 0x134249;   // call LoadConfig (flags 9)
static const uintptr_t RVA_APPLY_COUNT      = 0x08F373;   // movsxd rdi,[rsi+0x34]: the touched-class list's count
static const uintptr_t RVA_APPLY_DATA       = 0x08F37B;   // mov rax,[rsi+0x2c]: its data
static const uintptr_t RVA_TICK_LOADMAP     = 0x550A53;   // call [rax+0x3e8]: UGameEngine::Tick's LoadMap(URL, Pending, Error)
static const size_t    SLOT_LOADMAP    = 0x3E8 / 8;
static const size_t    OFF_URL_MAP     = 0x20;   // FURL: Protocol, Host, Map (FStrings), Op, Portal, then Port:
                                                 // LE3's order (GameEngine.uc's URL struct), not stock UE3's,
                                                 // where Port comes before Map; the exe's LoadMap reads [URL+0x20]
static const size_t    OFF_CFG_LAYERS  = 0x0C;   // TArray of 16-byte {INT Priority; layer*}
static const size_t    OFF_CFG_TOUCHED = 0x2C;   // TArray<UClass*>, appended by AddLayer/RemoveLayer's apply step
static const size_t    OFF_LAYER_NAME  = 0x08;   // FString
// LoadConfig flags, as RELOADCONFIG passes them: read the parent classes'
// sections (1), reloading (8). Children's defaults and live objects are
// reached by one walk here, not by the engine's per-class walks.
static const uint32_t  LOADCONFIG_FLAGS = 0x9;

typedef void* (*AddLayerFn)(void* config, const uint8_t* data, const char16_t* name, int64_t priority, int32_t apply);
typedef void  (*RemoveLayerFn)(void* config, void* layer, int32_t apply);
typedef void  (*LoadConfigFn)(UObject* self, UObject* configClass, const char16_t* file, uint32_t flags, void* prop);
typedef int   (*LoadMapFn)(void* self, void* url, void* pending, void* error);

static int                  g_layerCode = 0;    // 0 not checked, 1 verified, -1 refused
static std::vector<uint8_t> g_layerBuf;         // the engine keeps pointers into it: never freed
static void*                g_layer = nullptr;
static LoadMapFn            g_origLoadMap = nullptr;

static bool LeaR8To(uintptr_t rva, const char16_t* want) {
    uint8_t* at = g_base + rva;
    if (at + 7 > g_end || IsBadReadPtr(at, 7) || at[0] != 0x4C || at[1] != 0x8D || at[2] != 0x05) return false;
    const char16_t* s = (const char16_t*)RelTarget(at, 7, 3);
    size_t n = 0; while (want[n]) ++n;
    if (!s || (uint8_t*)s < g_base || (uint8_t*)(s + n + 1) > g_end || IsBadReadPtr(s, (n + 1) * 2)) return false;
    return memcmp(s, want, (n + 1) * 2) == 0;
}
static bool MovRcxFrom(uintptr_t rva, uintptr_t targetRva) {
    uint8_t* at = g_base + rva;
    if (at + 7 > g_end || IsBadReadPtr(at, 7) || at[0] != 0x48 || at[1] != 0x8B || at[2] != 0x0D) return false;
    return RelTarget(at, 7, 3) == g_base + targetRva;
}
static bool BytesAt(uintptr_t rva, const uint8_t* want, size_t n) {
    uint8_t* at = g_base + rva;
    return at + n <= g_end && !IsBadReadPtr(at, n) && memcmp(at, want, n) == 0;
}
static bool VerifyLayerCode() {
    if (g_layerCode) return g_layerCode > 0;
    static const uint8_t cnt[] = {0x48, 0x63, 0x7E, 0x34}, dat[] = {0x48, 0x8B, 0x46, 0x2C};
    bool ok = LeaR8To(RVA_LIVEINI_NAME_LEA, u"LiveINI") && MovRcxFrom(RVA_LIVEINI_GCONFIG, RVA_GCONFIG)
           && CallTo(RVA_LIVEINI_ADD, RVA_ADD_LAYER) && CallTo(RVA_LIVEINI_REMOVE, RVA_REMOVE_LAYER)
           && LeaRdxTo(RVA_RELOADCFG_LEA, u"RELOADCONFIG") && CallTo(RVA_RELOADCFG_CALL, RVA_LOAD_CONFIG)
           && BytesAt(RVA_APPLY_COUNT, cnt, 4) && BytesAt(RVA_APPLY_DATA, dat, 4);
    g_layerCode = ok ? 1 : -1;
    L("layer: config layer code %s", ok ? "verified" : "NOT as expected in this exe; no MP balance layer");
    return ok;
}
static void* GConfigPtr() {
    void** p = (void**)(g_base + RVA_GCONFIG);
    return IsBadReadPtr(p, 8) ? nullptr : *p;
}
static std::string Narrow(const std::u16string& s) { return std::string(s.begin(), s.end()); }

static std::string LayerList() {
    uint8_t* cfg = (uint8_t*)GConfigPtr();
    if (!cfg || IsBadReadPtr(cfg + OFF_CFG_LAYERS, 12)) return "no GConfig";
    TArray<uint8_t> a; memcpy(&a, cfg + OFF_CFG_LAYERS, sizeof(a));
    std::string line = std::to_string(a.Count) + ":";
    for (int i = 0; i < a.Count && i < 64; ++i) {
        uint8_t* e = a.Data + 16 * i;
        if (IsBadReadPtr(e, 16)) break;
        int32_t prio; void* layer; memcpy(&prio, e, 4); memcpy(&layer, e + 8, 8);
        std::u16string name; std::string why;
        if (!layer || IsBadReadPtr((uint8_t*)layer + OFF_LAYER_NAME, 16)
            || !ReadFString((FStringRaw*)((uint8_t*)layer + OFF_LAYER_NAME), name, why)) name = u"?";
        std::string n = Narrow(name);
        size_t slash = n.find_last_of('\\');
        if (slash != std::string::npos) n = n.substr(slash + 1);
        line += " " + n + "(" + std::to_string(prio) + ")";
    }
    return line;
}
static std::vector<UObject*> TouchedClasses() {
    std::vector<UObject*> out;
    uint8_t* cfg = (uint8_t*)GConfigPtr();
    if (!cfg || IsBadReadPtr(cfg + OFF_CFG_TOUCHED, 12)) return out;
    UObject** data; int32_t n;
    memcpy(&data, cfg + OFF_CFG_TOUCHED, 8); memcpy(&n, cfg + OFF_CFG_TOUCHED + 8, 4);
    for (int i = 0; i < n && i < 4096; ++i)
        if (!IsBadReadPtr(data + i, 8) && data[i] && !IsBadReadPtr(data[i], sizeof(UObject))) out.push_back(data[i]);
    return out;
}
// The pistol base's mod list as GET prints it: entries, and whether MP5's
// Power Magnifier (only in the layer's list) is in it.
static std::string PistolModList() {
    if (!VerifySetCommand()) return "?";
    g_execDispatch(u"GET SFXWeapon_Pistol_Base AllowableWeaponMods", Device());
    std::string v = Narrow(g_capture);
    int n = v.empty() ? 0 : 1; for (char c : v) n += c == ',';
    return std::to_string(n) + " entries, MP5 " + (v.find("PistolPowerDamage_MP5") != std::string::npos ? "in" : "absent");
}
// Config loaded again for every class default and live object whose class is
// one of the touched classes or under one: what UE3's propagation flags do with
// one walk per class, done here with one walk for all.
static void ReloadTouched(const char* when) {
    std::vector<UObject*> touched = TouchedClasses();
    std::unordered_set<UObject*> roots(touched.begin(), touched.end());
    std::unordered_map<UObject*, bool> under;
    auto isUnder = [&](UObject* cls) {
        auto it = under.find(cls);
        if (it != under.end()) return it->second;
        bool r = false;
        for (UObject* c = cls; c && !IsBadReadPtr(c, 0x80) && !r; c = *(UObject**)((uint8_t*)c + OFF_FIELD_SUPER))
            r = roots.count(c) != 0;
        under[cls] = r;
        return r;
    };
    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    auto loadConfig = (LoadConfigFn)(g_base + RVA_LOAD_CONFIG);
    int defaults = 0, objects = 0;
    int count = (!roots.empty() && g_objs && !IsBadReadPtr(g_objs, sizeof(*g_objs))) ? g_objs->Count : 0;
    for (int i = 0; i < count; ++i) {
        UObject* o = SlotAt(g_objs, i);
        if (!o || IsBadReadPtr(o, sizeof(UObject)) || !o->Class || IsBadReadPtr(o->Class, 0x80)) continue;
        if (!isUnder(o->Class)) continue;
        loadConfig(o, nullptr, nullptr, LOADCONFIG_FLAGS, nullptr);
        (strncmp(NameOf(o->Name), "Default__", 9) == 0 ? defaults : objects)++;
    }
    QueryPerformanceCounter(&t1);
    L("layer: %s: %zu loaded class(es) named by it, config loaded again on %d default(s) and %d object(s) in %.1f ms",
      when, touched.size(), defaults, objects, QpcMicros(t0, t1) / 1000.0);
}

// The DLC's CookedPCConsole, from the exe's path (...\Game\ME3\Binaries\Win64).
static std::wstring LayerPath() {
    wchar_t exe[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring p = exe;
    for (int up = 0; up < 3; ++up) p = p.substr(0, p.find_last_of(L'\\'));
    return p + L"\\BioGame\\DLC\\DLC_MOD_LEMultiplayer\\CookedPCConsole\\LEMPBalance.bin";
}
// 0 on, 1 off (the control), 2 refused (this exe), 3 no file.
static int LayerOn(const char* why) {
    if (g_layer) return 0;
    static bool controlLogged = false, fileLogged = false;
    if (GetFileAttributesW((LempDir() + L"\\nobalancelayer.txt").c_str()) != INVALID_FILE_ATTRIBUTES) {
        if (!controlLogged) L("layer: nobalancelayer.txt: no MP balance layer (%s)", why);
        controlLogged = true;
        return 1;
    }
    if (!VerifyLayerCode() || !GConfigPtr()) return 2;
    if (g_layerBuf.empty()) {
        std::wstring path = LayerPath();
        FILE* f = _wfopen(path.c_str(), L"rb");
        long size = 0;
        if (f) {
            fseek(f, 0, SEEK_END); size = ftell(f); fseek(f, 0, SEEK_SET);
            if (size > 32) {
                g_layerBuf.resize((size_t)size);
                if (fread(g_layerBuf.data(), 1, (size_t)size, f) != (size_t)size || memcmp(g_layerBuf.data(), "mrmf", 4) != 0)
                    g_layerBuf.clear();
            }
            fclose(f);
        }
        if (g_layerBuf.empty()) {
            if (!fileLogged) L("layer: %ls missing or not a coalesced file (%ld bytes): no MP balance layer", path.c_str(), size);
            fileLogged = true;
            return 3;
        }
    }
    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    g_layer = ((AddLayerFn)(g_base + RVA_ADD_LAYER))(GConfigPtr(), g_layerBuf.data(), u"LEMPBalance", 3, 1);
    QueryPerformanceCounter(&t1);
    if (!g_layer) { L("layer: AddLayer returned null (%s)", why); return 2; }
    L("layer: on (%s), %zu bytes, AddLayer %.1f ms; layers %s", why, g_layerBuf.size(), QpcMicros(t0, t1) / 1000.0, LayerList().c_str());
    ReloadTouched("on");
    L("layer: on: pistol base mod list %s", PistolModList().c_str());
    return 0;
}
static void LayerOff(const char* why) {
    if (!g_layer) return;
    ((RemoveLayerFn)(g_base + RVA_REMOVE_LAYER))(GConfigPtr(), g_layer, 1);
    g_layer = nullptr;
    L("layer: off (%s); layers %s", why, LayerList().c_str());
    ReloadTouched("off");
    L("layer: off: pistol base mod list %s", PistolModList().c_str());
}

// The map a LoadMap is about to load, from its FURL; "" if it does not read
// as a map name.
static std::string UrlMap(void* url) {
    if (!url || IsBadReadPtr((uint8_t*)url + OFF_URL_MAP, 16)) return "";
    FStringRaw* s = (FStringRaw*)((uint8_t*)url + OFF_URL_MAP);
    std::u16string m; std::string why;
    if (!ReadFString(s, m, why) || m.empty() || m.size() > 128) return "";
    for (char16_t c : m)
        if (!(c == u'_' || c == u'-' || c == u'.' || (c >= u'0' && c <= u'9') || (c >= u'A' && c <= u'Z') || (c >= u'a' && c <= u'z'))) return "";
    return Narrow(m);
}
static bool IsMpMap(const std::string& m) {
    return _stricmp(m.c_str(), "MPLobby") == 0 || _strnicmp(m.c_str(), "BioP_MP", 7) == 0;
}
static int HookLoadMap(void* self, void* url, void* pending, void* error) {
    std::string map = UrlMap(url);
    if (map.empty()) {
        // Off: an MP map's GRI turns the layer on again (op 78); left on, it
        // would stay on for whatever loads next, the campaign included.
        static int unread = 0;
        if (unread++ < 3) L("layer: LoadMap: the map name does not read; layer off");
        LayerOff("a LoadMap whose map name does not read");
    } else if (IsMpMap(map)) {
        std::string why = "loading " + map;
        LayerOn(why.c_str());
    } else {
        std::string why = "loading " + map;
        LayerOff(why.c_str());
    }
    return g_origLoadMap(self, url, pending, error);
}
// GEngine's LoadMap slot, once GEngine exists. The slot is the one
// UGameEngine::Tick calls for a travel; checked at that call site.
static DWORD WINAPI LoadMapHookThread(LPVOID) {
    static const uint8_t call3e8[] = {0xFF, 0x90, 0xE8, 0x03, 0x00, 0x00};
    if (!BytesAt(RVA_TICK_LOADMAP, call3e8, sizeof(call3e8))) {
        L("layer: UGameEngine::Tick's LoadMap call NOT as expected; the layer follows the GRI only (op 78)");
        return 0;
    }
    for (int t = 0; t < 2400; ++t) {
        if (lemp::Exiting()) return 0;
        void** pge = (void**)(g_base + RVA_GENGINE);
        void* ge = (!IsBadReadPtr(pge, 8)) ? *pge : nullptr;
        if (ge && !IsBadReadPtr(ge, 8)) {
            void** vt = *(void***)ge;
            void* cur = IsBadReadPtr(vt + SLOT_LOADMAP, 8) ? nullptr : vt[SLOT_LOADMAP];
            // The exe's own LoadMap, or loadmap_hook.cpp's diagnostic hook
            // (this module, debug mode), which forwards every call to the
            // exe's: chained, since a refusal here would leave the layer on
            // after the first MP map with nothing to take it off. Anything
            // else (another mod's code) is still refused.
            bool inExe = cur && (uint8_t*)cur >= g_base && (uint8_t*)cur < g_end;
            HMODULE self = nullptr, owner = nullptr;
            GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCWSTR)&HookLoadMap, &self);
            if (cur && !inExe)
                GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCWSTR)cur, &owner);
            bool ours = !inExe && self && owner == self;
            if (!inExe && !ours) {
                L("layer: GEngine's LoadMap slot reads %p: not hooked; the layer follows the GRI only (op 78)", cur);
                return 0;
            }
            DWORD old;
            if (!VirtualProtect(vt + SLOT_LOADMAP, 8, PAGE_READWRITE, &old)) { L("layer: VirtualProtect (%lu)", GetLastError()); return 0; }
            // Set before the swap (the game thread may call it at once); the
            // swap only if the slot still holds what was read, else read again.
            g_origLoadMap = (LoadMapFn)cur;
            bool swapped = InterlockedCompareExchangePointer(vt + SLOT_LOADMAP, (void*)&HookLoadMap, cur) == cur;
            VirtualProtect(vt + SLOT_LOADMAP, 8, old, &old);
            if (!swapped) { Sleep(250); continue; }
            if (inExe)
                L("layer: HOOKED GEngine LoadMap (slot %zu, was rva 0x%llx): the MP balance layer follows the map",
                  SLOT_LOADMAP, (unsigned long long)((uint8_t*)cur - g_base));
            else
                L("layer: HOOKED GEngine LoadMap (slot %zu, chained onto this module's diagnostic hook at %p): the MP balance layer follows the map",
                  SLOT_LOADMAP, cur);
            return 0;
        }
        Sleep(250);
    }
    L("layer: GEngine never set: the layer follows the GRI only (op 78)");
    return 0;
}

// Op 78, from SFXGRIMP when an MP map's GRI begins play: the layer on.
static void ServeLayer(UObject* self) {
    int32_t* result = IntProp(self, "AsiResult");
    if (!result) { L("layer: SFXMPLocalSave has no AsiResult"); return; }
    *result = LayerOn("an MP map's GRI");
}

// ---------------------------------------------------------------------------
// The field of view (ops 72/73): SFXPlayerCameraMP reads it when it spawns
// and writes it from the `fov` command and the options row. One line,
// LEMP\camera.txt "fov=<70..110>"; a machine setting like voice.txt, so it
// stays out of the synced Save\ME3. No file, or a value out of range: 70,
// the game's own.

static const int kFovDefault = 70, kFovMin = 70, kFovMax = 110;
static int g_fov = -1;   // -1: not read yet

static std::wstring CameraPath() { return LempDir() + L"\\camera.txt"; }

static int ReadFov() {
    if (g_fov >= 0) return g_fov;
    g_fov = kFovDefault;
    if (FILE* f = _wfopen(CameraPath().c_str(), L"r")) {
        int v = 0;
        if (fscanf(f, " fov=%d", &v) == 1 && v >= kFovMin && v <= kFovMax) g_fov = v;
        fclose(f);
    }
    L("camera: fov %d", g_fov);
    return g_fov;
}

static void ServeCamera(UObject* self) {
    int32_t* op = IntProp(self, "AsiOp");
    int32_t* idx = IntProp(self, "AsiIndex");
    int32_t* result = IntProp(self, "AsiResult");
    if (!op || !idx || !result) { L("camera: SFXMPLocalSave has no AsiOp/AsiIndex/AsiResult"); return; }
    // The control: LEMP\nofov.txt refuses both ops, and the camera is LE3's.
    if (GetFileAttributesW((LempDir() + L"\\nofov.txt").c_str()) != INVALID_FILE_ATTRIBUTES) {
        L("camera: nofov.txt, op %d refused", *op); *result = 3; return;
    }
    if (*op == 72) { *idx = ReadFov(); *result = 0; return; }
    int v = *idx < kFovMin ? kFovMin : *idx > kFovMax ? kFovMax : *idx;
    g_fov = v;
    FILE* f = _wfopen(CameraPath().c_str(), L"w");
    if (!f) { L("camera: could not write camera.txt"); *result = 1; return; }
    fprintf(f, "fov=%d\n", v);
    fclose(f);
    L("camera: fov %d saved", v);
    *result = 0;
}

// ---------------------------------------------------------------------------
// The log row (ops 74/75, SFXGUI_Option_MPLog): 74 reads whether the log is on
// (AsiIndex 1/0), 75 sets it from AsiIndex. lemp.cpp keeps the setting
// (LEMP\nodebug.txt) and starts or stops this launch's lines.

// The Consistent Mouse Speed row (ops 76/77): on unless LEMP\nomouserate.txt
// exists. 76 reads it into AsiIndex (1 on, 0 off); 77 writes AsiIndex (0
// creates the file, 1 deletes it). The script scales the mouse dampening
// curve by the frame time while it is on.
static std::wstring MouseRatePath() { return LempDir() + L"\\nomouserate.txt"; }
static void ServeMouse(UObject* self) {
    int32_t* op = IntProp(self, "AsiOp");
    int32_t* idx = IntProp(self, "AsiIndex");
    int32_t* result = IntProp(self, "AsiResult");
    if (!op || !idx || !result) { L("mouse row: SFXMPLocalSave has no AsiOp/AsiIndex/AsiResult"); return; }
    if (*op == 76) {
        *idx = GetFileAttributesW(MouseRatePath().c_str()) == INVALID_FILE_ATTRIBUTES ? 1 : 0;
        *result = 0;
        return;
    }
    if (*idx != 0) {
        *result = (DeleteFileW(MouseRatePath().c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND) ? 0 : 1;
    } else {
        HANDLE h = CreateFileW(MouseRatePath().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        *result = h != INVALID_HANDLE_VALUE ? 0 : 1;
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    L("mouse row: consistent mouse speed %s", *idx != 0 ? "on" : "off");
}

static void ServeLog(UObject* self) {
    int32_t* op = IntProp(self, "AsiOp");
    int32_t* idx = IntProp(self, "AsiIndex");
    int32_t* result = IntProp(self, "AsiResult");
    if (!op || !idx || !result) { L("log row: SFXMPLocalSave has no AsiOp/AsiIndex/AsiResult"); return; }
    if (*op == 74) { *idx = LempLogOn() ? 1 : 0; *result = 0; return; }
    *result = LempSetLogOn(*idx != 0) ? 0 : 1;
}

// What ops 57-59 cost on the game thread, logged per 500 ops: the engine's
// own SaveConfig (which every op runs first; this class is config) apart from
// the serving. SFXGRIMP's balance retry makes these calls during play, so
// their cost is a frame-time cost.
struct BalanceTiming { int n = 0; double cfgSum = 0, cfgMax = 0, serveSum = 0, serveMax = 0; };
static BalanceTiming g_balTiming;
static double QpcMicros(LARGE_INTEGER a, LARGE_INTEGER b) {
    static LARGE_INTEGER f = {};
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    return (double)(b.QuadPart - a.QuadPart) * 1e6 / (double)f.QuadPart;
}
static void NoteBalanceTiming(double cfgUs, double serveUs) {
    BalanceTiming& t = g_balTiming;
    ++t.n; t.cfgSum += cfgUs; t.serveSum += serveUs;
    if (cfgUs > t.cfgMax) t.cfgMax = cfgUs;
    if (serveUs > t.serveMax) t.serveMax = serveUs;
    if (t.n < 500) return;
    L("balance: timing: %d ops 57-59, SaveConfig avg %.0f us (max %.0f), serve avg %.0f us (max %.0f)",
      t.n, t.cfgSum / t.n, t.cfgMax, t.serveSum / t.n, t.serveMax);
    t = BalanceTiming();
}

static void HookSaveConfig(UObject* self, void* stack, void* result) {
    LARGE_INTEGER t0, t1, t2;
    QueryPerformanceCounter(&t0);
    g_origSaveConfig(self, stack, result);
    QueryPerformanceCounter(&t1);
    if (!self || IsBadReadPtr(self, sizeof(UObject))) return;
    const char* cls = ClassNameOf(self);
    if (_stricmp(cls, "SFXMPLocalSave") == 0) {
        // Ops 5/6 (read the MP player name) are served to the class package's
        // SFXMPLocalSave too: it runs in the lobby and match, where
        // MPMainMenu.SFXMPProfileName is not loaded, and the local player
        // re-asserts its name after each seamless travel
        // (SFXPRIMP.IsInvalidName). Read only: the
        // name is saved from the Multiplayer screen alone. Ops 13/14 (the build
        // key) go the same way: the host reads its own for PreLogin. Ops
        // 11/12 (the clipboard): the lobby's Join Lobby by Code page pastes.
        int32_t* op = IntProp(self, "AsiOp");
        if (op && *op >= 60 && *op <= 71) {
            // Voice chat's options rows (lemp_voice.cpp).
            int32_t* idx = IntProp(self, "AsiIndex");
            int32_t* result = IntProp(self, "AsiResult");
            if (idx && result) *result = VoiceAsiOp(*op, idx);
        }
        else if (op && (*op == 5 || *op == 6 || *op == 11 || *op == 12 || *op == 13 || *op == 14)) ServeName(self);
        else if (op && ((*op >= 20 && *op <= 38) || (*op >= 42 && *op <= 44) || *op == 53 || *op == 54)) ServeOnline(self);
        else if (op && *op >= 45 && *op <= 49) ServePackages(self);
        else if (op && *op >= 57 && *op <= 59) {
            ServeBalance(self);
            QueryPerformanceCounter(&t2);
            NoteBalanceTiming(QpcMicros(t0, t1), QpcMicros(t1, t2));
        }
        else if (op && (*op == 72 || *op == 73)) ServeCamera(self);
        else if (op && (*op == 74 || *op == 75)) ServeLog(self);
        else if (op && (*op == 76 || *op == 77)) ServeMouse(self);
        else if (op && *op == 78) ServeLayer(self);
        else Serve(self);
    }
    else if (_stricmp(cls, "SFXMPProfileName") == 0) {
        int32_t* op = IntProp(self, "AsiOp");
        // The online statistics, the release check and lemp.asi's release (no
        // AsiIndex needed); a code join's search, 20-25 (21 needs its AsiIndex);
        // a line for this log, 31.
        if (op && (*op == 31 || *op == 32 || *op == 33 || (*op >= 39 && *op <= 41) || *op == 55 || *op == 56 || (*op >= 20 && *op <= 25))) ServeOnline(self);
        else if (op && *op >= 50 && *op <= 53) ServeImport(self);
        else ServeName(self);
    }
}

// ---------------------------------------------------------------------------
// Install.

struct Native { int index; void* func; };

static bool InExe(void* p) { return (uint8_t*)p >= g_base && (uint8_t*)p < g_end; }

static void** FindGNatives(void* saveConfigFunc, const std::vector<Native>& natives) {
    auto* dos = (IMAGE_DOS_HEADER*)g_base;
    auto* nt = (IMAGE_NT_HEADERS64*)(g_base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    void** found = nullptr;
    int candidates = 0, accepted = 0;
    for (int s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
        if (sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
        if (!(sec[s].Characteristics & IMAGE_SCN_MEM_READ)) continue;
        uint8_t* a = g_base + sec[s].VirtualAddress;
        size_t n = sec[s].Misc.VirtualSize / 8;
        void** q = (void**)a;
        for (size_t i = 0; i < n; ++i) {
            if (q[i] != saveConfigFunc) continue;
            ++candidates;
            if (i < (size_t)SAVECONFIG_NATIVE) continue;
            void** table = q + i - SAVECONFIG_NATIVE;
            if ((uint8_t*)(table + MAX_NATIVES) > a + sec[s].Misc.VirtualSize) continue;
            int match = 0, miss = 0;
            for (auto& nv : natives) (table[nv.index] == nv.func ? match : miss)++;
            L("GNATIVES: candidate rva 0x%llx: %d of %zu indexed natives agree, %d disagree",
              (unsigned long long)((uint8_t*)table - g_base), match, natives.size(), miss);
            if (match >= 20 && miss == 0) { found = table; ++accepted; }
        }
    }
    if (accepted != 1) {
        L("GNATIVES: %d candidate(s), %d accepted: refusing to hook", candidates, accepted);
        return nullptr;
    }
    return found;
}

static bool Install(TArray<UObject*>* objs) {
    UObject* saveConfig = nullptr;
    std::vector<Native> natives;
    for (int i = 0; i < objs->Count; ++i) {
        UObject* o = SlotAt(objs, i);
        if (!o || IsBadReadPtr(o, 0xF0)) continue;
        if (_stricmp(ClassNameOf(o), "Function") != 0) continue;
        uint32_t flags = *(uint32_t*)((uint8_t*)o + OFF_FUNC_FLAGS);
        int16_t inative = *(int16_t*)((uint8_t*)o + OFF_FUNC_INATIVE);
        void* func = *(void**)((uint8_t*)o + OFF_FUNC_FUNC);
        if ((flags & FUNC_NATIVE) && inative > 0 && inative < MAX_NATIVES && InExe(func))
            natives.push_back({inative, func});
        if (_stricmp(NameOf(o->Name), "SaveConfig") == 0 && o->Outer
            && _stricmp(NameOf(o->Outer->Name), "Object") == 0)
            saveConfig = o;
    }
    if (!saveConfig) return false;   // Core not up yet; try again
    if (!g_propOffsetAt) {
        int cal = CalibratePropertyOffset(objs);
        if (cal == 0) return false;  // Engine not up yet; try again
        if (cal < 0) { L("ABORT: property offsets uncalibrated; saves stay off"); return true; }
    }
    int16_t idx = *(int16_t*)((uint8_t*)saveConfig + OFF_FUNC_INATIVE);
    void** funcSlot = (void**)((uint8_t*)saveConfig + OFF_FUNC_FUNC);
    void* func = *funcSlot;
    if (idx != SAVECONFIG_NATIVE || !InExe(func)) {
        L("ABORT: SaveConfig reads iNative=%d Func=%p: the UFunction layout is not LExSDK's", idx, func);
        return true;   // do not retry
    }
    L("SaveConfig: iNative %d, exec thunk rva 0x%llx; %zu indexed natives in GObjects",
      idx, (unsigned long long)((uint8_t*)func - g_base), natives.size());
    void** gnatives = FindGNatives(func, natives);
    if (!gnatives) { L("ABORT: GNatives not found; saves stay off"); return true; }
    g_sharedGNatives.store(gnatives, std::memory_order_relaxed);

    g_origSaveConfig = (ExecFn)func;
    DWORD old;
    void** slot = &gnatives[SAVECONFIG_NATIVE];
    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old)) { L("ABORT: VirtualProtect (%lu)", GetLastError()); return true; }
    *slot = (void*)&HookSaveConfig;
    VirtualProtect(slot, sizeof(void*), old, &old);
    *funcSlot = (void*)&HookSaveConfig;   // the UFunction path too, whichever the VM takes
    L("HOOKED: SaveConfig (GNatives rva 0x%llx [%d], and its UFunction). Save file: %ls",
      (unsigned long long)((uint8_t*)gnatives - g_base), SAVECONFIG_NATIVE, SavePath().c_str());
    CloseHandle(CreateThread(nullptr, 0, LoadMapHookThread, nullptr, 0, nullptr));
    return true;
}

static DWORD WINAPI Thread(LPVOID) {
    InitializeCriticalSection(&g_impCs);
    g_dir = LempDir();
    const std::wstring le = g_dir.substr(0, g_dir.rfind(L'\\'));   // ...\Mass Effect Legendary Edition
    g_cloud = le + L"\\Save";
    CreateDirectoryW(g_cloud.c_str(), nullptr);
    g_cloud += L"\\ME3";
    CreateDirectoryW(g_cloud.c_str(), nullptr);
    g_base = (uint8_t*)GetModuleHandleA("MassEffect3.exe");
    if (!g_base) g_base = (uint8_t*)GetModuleHandleA(nullptr);
    uint32_t peOff = *(uint32_t*)(g_base + 0x3C);
    g_end = g_base + *(uint32_t*)(g_base + peOff + 0x18 + 0x38);
    g_pools = (FNameEntry**)(g_base + RVA_NAME_POOLS);
    auto* objs = (TArray<UObject*>*)(g_base + RVA_OBJOBJECTS);
    g_objs = objs;
    L("== mp_save ==  pid %lu, dir %ls, saves in %ls", (unsigned long)GetCurrentProcessId(), g_dir.c_str(), g_cloud.c_str());
    g_keyThread = CreateThread(nullptr, 0, KeyThread, nullptr, 0, nullptr);
    online::Init(g_dir, L, g_keyThread, BuildKeyUtf8);
    online::SetPlayerFile(g_cloud + L"\\LEMP_player.txt");

    // Poll until Core's and Engine's classes are in GObjects: long before any
    // MP lobby can call SaveConfig.
    for (int t = 0; t < 600; ++t) {
        Sleep(250);
        if (lemp::Exiting()) { L("stopping: engine exiting"); return 0; }
        if (IsBadReadPtr(objs, sizeof(*objs)) || !objs->Data || objs->Count < 1000) continue;
        if (Install(objs)) return 0;
    }
    L("ABORT: SaveConfig never appeared in GObjects; saves stay off");
    return 0;
}

// lemp.h: nullptr until Install() above has found and verified GNatives.
void** LempGNatives() { return g_sharedGNatives.load(std::memory_order_relaxed); }

void MpSaveStart() {
    CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
}
