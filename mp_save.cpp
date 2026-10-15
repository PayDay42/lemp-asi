// mp_save — the MP records' storage: a file in Documents, since LE3 has none.
//
// NOT A PROBE. THIS ASI WRITES TO GAME MEMORY, like join_patch and tick_hook:
// one GNatives slot and one UFunction::Func pointer (both SaveConfig's), plus
// the script properties of SFXMPLocalSave objects it is asked to serve.
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
//                    = its counts
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
#include <vector>
#include "mp_save_format.h"
#include "build_key.h"
#include "lemp_online.h"
#include "ea_import.h"
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
static FILE*        g_log = nullptr;
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
    std::string opts = buildkey::JoinOptions(
        buildkey::ShortKey(full), buildkey::RunningExeVersion(),
        buildkey::HashFileList(game, buildkey::kPlayAsis, sizeof buildkey::kPlayAsis / sizeof *buildkey::kPlayAsis, cache),
        buildkey::HashFileList(game, buildkey::kBaseFiles, sizeof buildkey::kBaseFiles / sizeof *buildkey::kBaseFiles, cache),
        buildkey::OtherMods(game, L"DLC_MOD_LEMultiplayer"));
    cache.Save();
    g_buildKey.assign(opts.begin(), opts.end());
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

static void ServeImport(UObject* self) {
    int32_t* op = IntProp(self, "AsiOp");
    int32_t* result = IntProp(self, "AsiResult");
    FStringRaw* buf = StrProp(self, "AsiBuf");
    int32_t* len = IntProp(self, "AsiLen");
    if (!op || !result || !buf || !len) { L("import: SFXMPProfileName lacks AsiOp/AsiResult/AsiBuf/AsiLen"); if (result) *result = 5; return; }
    if (*op == 50) {
        EnterCriticalSection(&g_impCs);
        bool running = g_impState == 1;
        if (!running) { g_impState = 1; g_impStage = 0; g_impName.clear(); g_impSummary.clear(); g_impError.clear(); }
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

static void HookSaveConfig(UObject* self, void* stack, void* result) {
    g_origSaveConfig(self, stack, result);
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
        else Serve(self);
    }
    else if (_stricmp(cls, "SFXMPProfileName") == 0) {
        int32_t* op = IntProp(self, "AsiOp");
        // The online statistics and the release check (no AsiIndex needed);
        // a code join's search, 20-25 (21 needs its AsiIndex).
        if (op && (*op == 32 || *op == 33 || (*op >= 39 && *op <= 41) || (*op >= 20 && *op <= 25))) ServeOnline(self);
        else if (op && *op >= 50 && *op <= 52) ServeImport(self);
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
    // One file per run, so a launch never erases the previous run's log (how
    // earlier runs' saves were lost to diagnosis, when it
    // was one file truncated at each start). Debug mode only (lemp.h).
    g_log = LempOpenDebugLog("mp_save");

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
