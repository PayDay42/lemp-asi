// repl_probe.asi — Phase 1 stage 2b: does a second instance actually connect?
//
// Stage 2a established that `open BioP_MPCer?listen` binds a UDP socket on
// 3659. Stage 2b asks the only question left in Phase 1: if a second instance
// runs `open 127.0.0.1`, does UE3 replication actually carry it?
//
// Nothing will render. The MP game mode is deleted, so neither instance spawns
// a pawn and both show a black screen (BioP_MPCer is
// a 3,644-byte shell whose geometry streams on the game mode's cue). So the
// answer has to come from the object graph, not the screen:
//
//   NetMode                 2 = listen server (host), 3 = client
//   live UNetConnection      the connection itself — the headline signal
//   live UPlayerController   a connected client gets one spawned server-side
//   PlayerReplicationInfo    1 = host alone, 2 = someone joined
//
// A second NetConnection appearing on the host is the pass condition. A second
// PlayerReplicationInfo means replication is not merely connected but actually
// propagating actors, which is the stronger result.
//
// BOTH instances share one game directory, so the log name carries the pid:
//   Binaries/Win64/repl_probe_<pid>.txt
// Run this on both; the host's log and the client's log are read together.
//
// Timestamped, unlike netmode_probe and socket_probe — their lack of a clock
// was the one real gap when correlating against socket captures.
//
// Read-only: counts objects, calls nothing, writes nothing to game memory.

#include <windows.h>
#include "lemp.h"
#include "safe_read.h"  // guard-page-safe IsBadReadPtr/IsBadWritePtr
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>

static const uintptr_t RVA_NAME_POOLS = 0x17B33D0;
static const uintptr_t RVA_OBJOBJECTS = 0x1887E40;
static const size_t    OFF_NETMODE    = 0x07C8;   // AWorldInfo, per LExSDK
static const size_t    OFF_WI_GAME    = 0x06B0;   // AWorldInfo::Game
static const size_t    OFF_CONTROLLER_PAWN = 0x03BC;  // AController::Pawn
static const size_t    OFF_ACTOR_LOCATION  = 0x0108;  // AActor::Location, per LExSDK
static const size_t    OFF_ACTOR_PHYSICS   = 0x0268;  // AActor::Physics
static const size_t    OFF_ACTOR_COLLCOMP  = 0x01E0;  // AActor::CollisionComponent
static const size_t    OFF_PC_VIEWTARGET   = 0x069C;  // APlayerController::ViewTarget
static const size_t    OFF_PC_CAMERA       = 0x0684;  // APlayerController::PlayerCamera
// ACamera keeps its OWN view target, and it is the one the view is actually
// computed from. The controller's ViewTarget field reading "the pawn" says
// nothing about the camera agreeing — which is the whole question when the
// pawn is demonstrably moving and the view is not.
// ACamera::ViewTarget is at 0x3D8, but FTViewTarget does NOT start with
// Target: Engine_structs.h has POV first (0x1C bytes), then Target at +0x1C.
// Reading 0x3D8 read POV.Location as a pointer and reported NONE on the HOST,
// whose camera demonstrably works — the positive control catching a broken
// measurement before it became a finding, which is the house rule here.
static const size_t    OFF_CAM_VIEWTARGET  = 0x03D8 + 0x1C;  // = 0x3F4
// ME3 gates input actions, the HUD and the camera behaviour behind a game
// mode: USFXGameModeManager::GetCameraMode picks the camera from it. The mode
// the client is in is therefore one reading that covers three symptoms at
// once — no HUD, a camera that will not follow, and input that walks but does
// not shoot.
// UObject::ObjectArchetype. UE3 sends a dynamic actor's archetype along with
// its class, and the receiving side spawns from that template. If the client
// cannot resolve it, it falls back to the class default — a pawn with no mesh,
// which is both invisible and useless as something for a camera to follow.
// Does the pawn have a body? ME3's camera follows a socket on the pawn's
// skeletal mesh, so a pawn with no mesh gives a camera nothing to attach to and
// it orbits the origin — which is what the client shows even now that the
// archetype resolves. APawn::Mesh, then USkeletalMeshComponent::SkeletalMesh.
static const size_t    OFF_PAWN_MESH       = 0x03F4;
// APawn::InvManager / APawn::Weapon, and the bNoWeaponFiring bit, all from
// LExSDK's Engine_classes.h. Three separate reported symptoms turn on these:
// the joining player has no weapon at all, the host has one it cannot fire,
// and the host's weapon is invisible on the client. "Weapons were created but
// never equipped" and "no weapons were created" want different fixes, and
// only the pawn's own pointers tell them apart — per pawn, on both ends.
static const size_t    OFF_PAWN_INVMANAGER = 0x0414;
static const size_t    OFF_PAWN_WEAPON     = 0x041C;
static const size_t    OFF_PAWN_FLAGS_NOFIRE = 0x0578;
static const uint32_t  BIT_NO_WEAPON_FIRING  = 0x00010000;
// ABioPawn::bCombatPawn, CPF_Const — native, unassignable from script. It
// gates BioWare's own weapon equip, and a non-combat pawn is a pawn ME3 does
// not expect to shoot, so it is the first thing to read about a player that
// holds a weapon and will not fire.
static const size_t    OFF_BIOPAWN_COMBATFLAGS = 0x0E18;
static const uint32_t  BIT_COMBAT_PAWN         = 0x00000008;
// ASFXWeapon::bWeaponExpanded. ME3's weapons fold, and the equip STATE ends
// with Expand(). A weapon that was attached without running that state looks
// like a gun and cannot be used — which is the reported symptom on both
// sides: movement, cover, sprint and melee work, and firing and zoom-aim do
// nothing.
static const size_t    OFF_WEAPON_FLAGS_EXPANDED = 0x03BC;
static const uint32_t  BIT_WEAPON_EXPANDED       = 0x00000001;
// USkeletalMeshComponent::AnimTreeTemplate and ::Animations — the template,
// and the instanced tree built from it. On the HOST, the joining player's
// pawn does not animate while every other pawn on both machines does, so the
// question is whether that pawn has an instanced AnimTree at all on the
// authority. A template with no instance is a different fault from an
// instance that is simply never driven.
static const size_t    OFF_SMC_ANIMTREETEMPLATE = 0x0268;
static const size_t    OFF_SMC_ANIMATIONS       = 0x0270;
static const size_t    OFF_SMC_SKELMESH    = 0x0258;
static const size_t    OFF_OBJ_ARCHETYPE   = 0x0058;
// UObject::StateFrame. UnrealScript states change what input does — ME3's
// sprint and Escape are configured by the controller's state, not by
// possession — so "did GotoState('PlayerWalking') actually take" is a question
// the probe should answer rather than script being trusted to have worked.
// FStateFrame's layout is not in LExSDK, so the UState pointer is found by
// scanning the first words of the frame for an object whose class is State.
static const size_t    OFF_OBJ_STATEFRAME  = 0x0024;
static const size_t    OFF_PC_GAMEMODEMGR  = 0x0C38;  // ABioPlayerController::GameModeManager2
static const size_t    OFF_GMM_CURRENTMODE = 0x00A8;  // USFXGameModeManager::CurrentMode
// The input lock and the per-mode binding flag, both from LExSDK.
//
// Measured: setting bFire by hand fires the weapon, so the mouse is simply
// never setting it. What works is axis input and state; what does not is
// every BOUND ACTION — fire, zoom, the power wheel, Escape. Bindings are
// collected per game mode (SFXGameModeBase's first flag is
// bBindingsCollected) and the manager carries its own bDisableInput lock, so
// these two bits say whether the theory is right before another build is
// spent on it.
// APlayerController::PlayerInput, and UInput::Bindings on it.
//
// `bFire` is CPF_Input at 0x0480 on the controller: it is written by the
// input system when a bound key fires, not by script. The game mode reports
// active WITH bindings collected and no input lock, so the next question is
// whether the PlayerInput object this controller actually owns holds any
// bindings at all — "the mode collected them" and "this input has them" are
// not the same claim.
static const size_t    OFF_PC_PLAYERINPUT  = 0x06DC;
static const size_t    OFF_INPUT_BINDINGS  = 0x00B0;
static const size_t    OFF_GMM_FLAGS       = 0x00A4;
static const uint32_t  BIT_GMM_DISABLEINPUT = 0x00000001;
static const size_t    OFF_GMM_GAMEMODES   = 0x0070;  // TArray<USFXGameModeBase*>
static const size_t    OFF_MODE_FLAGS      = 0x00D0;
static const uint32_t  BIT_MODE_BINDINGS   = 0x00000001;  // bBindingsCollected
static const uint32_t  BIT_MODE_ACTIVE     = 0x00000002;  // bIsActive

// EGameModes, from LExSDK. Named rather than numbered because 9 meaning "GUI"
// is exactly what makes 2012's DisableMode(9) legible.
static const char* GameModeName(int m) {
    static const char* n[] = {
        "Default", "Vehicle", "Atlas", "PowerWheel", "WeaponWheel", "Command",
        "InjuredShepard", "Conversation", "Cinematic", "GUI", "Movie", "Galaxy",
        "Orbital", "MultiLand", "Photo", "CheatMenu", "AIDebug", "Prototyping",
        "DreamSequence", "IllusiveManConflict", "Spectator", "Dying", "FlyCam",
        "ReplicationDebug", "Lobby"
    };
    return (m >= 0 && m < 25) ? n[m] : "?";
}

// The delay is to let the game finish building GObjects before anything walks
// it; 30 s was a guess, and it delayed the first sample long past the point
// where the game is up. The sample interval used to be 5 s, which put up to 5 s
// of latency on every state change the test script waits for — three of those
// per run, plus the same lag on anything read by hand.
static const DWORD START_DELAY_MS = 10000;
static const DWORD INTERVAL_MS    = 1000;
static const int   TICKS          = 10800;  // 3 hours — an expiring
                                            // probe cost us the client's data
                                            // mid-test once already

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

// One slot of a live engine array, read from ANOTHER THREAD. This probe
// samples on its own thread while the game thread grows and reallocates
// GObjects during a map load. Caching Count and indexing Data killed the
// host (crash_log: repl_probe.asi+0x4b64,
// `mov rbx,[rax+rsi*8]`, element 24372 past the live buffer, 7 s into
// loading BioP_MPCer): the probe, not the game, faulted. So re-read the
// header on every access and test the slot before reading it.
static inline UObject* SlotAt(TArray<UObject*>* a, int i) {
    if (!a || IsBadReadPtr(a, sizeof(*a))) return nullptr;
    UObject** data = a->Data;
    if (!data || i < 0 || i >= a->Count || i >= a->Max) return nullptr;
    if (IsBadReadPtr(data + i, sizeof(UObject*))) return nullptr;
    return data[i];
}
#pragma pack(pop)

static uint8_t*     g_base = nullptr;
static uint8_t*     g_end  = nullptr;
static FNameEntry** g_pools = nullptr;
static FILE*        g_log = nullptr;
static UObject* volatile g_stallWI = nullptr;   // see StallThread
static volatile size_t   g_stallOff = 0;

// One line per call, whole: StallThread logs alongside the sampler.
static SRWLOCK g_logLock = SRWLOCK_INIT;
static void L(const char* fmt, ...) {
    SYSTEMTIME st; GetLocalTime(&st);
    va_list a; va_start(a, fmt);
    AcquireSRWLockExclusive(&g_logLock);
    if (g_log) {
        fprintf(g_log, "%02d:%02d:%02d.%03d  ",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        vfprintf(g_log, fmt, a);
        fputc('\n', g_log);
        fflush(g_log);
    }
    ReleaseSRWLockExclusive(&g_logLock);
    va_end(a);
}
static void CloseLog() {
    AcquireSRWLockExclusive(&g_logLock);
    if (g_log) fclose(g_log);
    g_log = nullptr;
    ReleaseSRWLockExclusive(&g_logLock);
}
static const char* NameOf(const FName& n) {
    if (!g_pools || n.Chunk > 7) return "<bad>";
    FNameEntry* c = g_pools[n.Chunk];
    if (!c) return "<null>";
    auto* e = (FNameEntry*)((uint8_t*)c + n.Offset);
    return IsBadReadPtr(e, 16) ? "<unreadable>" : e->AnsiName;
}
// ---------------------------------------------------------------------------
// Resolving a script property BY NAME, and reading a string out of it.
//
// This is the log channel. LE3 has no other: `Launch.log` sits in .rdata with
// no code referencing it, so the file log device is compiled out; ClientMessage
// goes to BioHUD, which draws nothing; the console prints nothing.
// Counts through this probe have been the
// only signal, and a count cannot carry a string.
//
// Script writes into `var string MPDebug` on SFXPlayerControllerMP; this reads
// it out of memory and puts it in the probe log, where it can actually be read.
//
// Layout, from LExSDK LE3 Core_classes.h:
//     UField.SuperField  0x60      UField.Next  0x68
//     UStruct.Children   0x70
// UProperty::Offset is NOT in LExSDK — it carries UnknownData00[0x60] at 0x70 —
// so it is DISCOVERED rather than guessed. See CalibratePropertyOffset.
// ---------------------------------------------------------------------------
static const size_t OFF_FIELD_SUPER    = 0x60;
static const size_t OFF_FIELD_NEXT     = 0x68;
static const size_t OFF_STRUCT_CHILDREN = 0x70;
static size_t g_propOffsetAt = 0;     // where UProperty::Offset lives; 0 = unknown

struct FStringRaw { wchar_t* Data; int32_t Count, Max; };

static const char* ClassNameOf(UObject* o) {
    UObject* c = o->Class;
    return (c && !IsBadReadPtr(c, sizeof(UObject))) ? NameOf(c->Name) : "?";
}
// Walk a class and its supers for a field of this name.
static UObject* FindFieldByName(UObject* cls, const char* want) {
    for (UObject* c = cls; c && !IsBadReadPtr(c, 0x80);
         c = *(UObject**)((uint8_t*)c + OFF_FIELD_SUPER)) {
        for (UObject* f = *(UObject**)((uint8_t*)c + OFF_STRUCT_CHILDREN);
             f && !IsBadReadPtr(f, 0x80);
             f = *(UObject**)((uint8_t*)f + OFF_FIELD_NEXT)) {
            if (strcmp(NameOf(f->Name), want) == 0) return f;
        }
    }
    return nullptr;
}

// Find where UProperty::Offset lives, by checking a property whose offset is
// already known.
//
// LExSDK does not carry this field, and guessing it would put a wrong number
// under every later reading — exactly the failure this project keeps writing
// rules about. Instead: take Pawn.Mesh, whose offset LExSDK DOES give as
// OFF_PAWN_MESH, walk to its UProperty, and scan the object for the int that
// equals it. The position that matches is the answer, and it is a
// measurement rather than an assumption.
//
// Scanned over a deliberately narrow window past UField, and REJECTED unless
// exactly one candidate matches — two matches would mean the calibration
// cannot tell which field it found, and a coincidence adopted here would be
// invisible everywhere else.
static void CalibratePropertyOffset(TArray<UObject*>* objs) {
    UObject* pawnCls = nullptr;
    for (int i = 0; i < objs->Count && !pawnCls; ++i) {
        UObject* o = SlotAt(objs, i);
        if (!o || IsBadReadPtr(o, 0x40)) continue;
        if (strcmp(ClassNameOf(o), "Class") == 0 && strcmp(NameOf(o->Name), "Pawn") == 0)
            pawnCls = o;
    }
    if (!pawnCls) { L("PROPCAL: no Pawn class object found"); return; }

    UObject* meshProp = FindFieldByName(pawnCls, "Mesh");
    if (!meshProp) { L("PROPCAL: Pawn has no field named Mesh"); return; }

    size_t hit = 0; int hits = 0;
    for (size_t off = 0x70; off <= 0xB0; off += 4) {
        if (IsBadReadPtr((uint8_t*)meshProp + off, 4)) continue;
        if (*(uint32_t*)((uint8_t*)meshProp + off) == (uint32_t)OFF_PAWN_MESH) {
            hit = off; ++hits;
        }
    }
    if (hits == 1) {
        g_propOffsetAt = hit;
        L("PROPCAL: UProperty::Offset is at +0x%zx  (Pawn.Mesh == 0x%zx)", hit, OFF_PAWN_MESH);
    } else {
        L("PROPCAL: %d candidates for UProperty::Offset — refusing to guess", hits);
    }
}

// Dump every script property an object's class declares, with its offset.
//
// Written after five camera theories died in a row. Each one guessed which
// field mattered and then needed a build and a run to find out; this asks the
// object what it HAS, once, and turns the next question into a lookup instead
// of a guess.
//
// Walks the class and its supers, so inherited properties show too, and
// prints the class each came from — which is the part that matters when the
// question is "does SFXPlayerCamera expose this, or is it native?".
static void DumpClassProperties(UObject* obj, const char* label) {
    if (!obj || IsBadReadPtr(obj, 0x40) || !g_propOffsetAt) return;
    L("PROPS %s (%s):", label, ClassNameOf(obj));
    int n = 0;
    for (UObject* c = obj->Class; c && !IsBadReadPtr(c, 0x80);
         c = *(UObject**)((uint8_t*)c + OFF_FIELD_SUPER)) {
        const char* cn = NameOf(c->Name);
        std::string line;
        for (UObject* f = *(UObject**)((uint8_t*)c + OFF_STRUCT_CHILDREN);
             f && !IsBadReadPtr(f, 0x80);
             f = *(UObject**)((uint8_t*)f + OFF_FIELD_NEXT)) {
            if (IsBadReadPtr((uint8_t*)f + g_propOffsetAt, 4)) continue;
            uint32_t off = *(uint32_t*)((uint8_t*)f + g_propOffsetAt);
            if (off == 0) continue;                 // functions and states
            char b[96];
            snprintf(b, sizeof(b), " %s@%x", NameOf(f->Name), off);
            line += b; ++n;
            if (line.size() > 300) { L("   [%s]%s", cn, line.c_str()); line.clear(); }
        }
        if (!line.empty()) L("   [%s]%s", cn, line.c_str());
        if (n > 400) break;
    }
}

// The byte offset of a named script property on an object's class, or 0.
static size_t PropertyOffset(UObject* obj, const char* name) {
    if (!g_propOffsetAt || !obj || IsBadReadPtr(obj, 0x40)) return 0;
    UObject* f = FindFieldByName(obj->Class, name);
    if (!f || IsBadReadPtr((uint8_t*)f + g_propOffsetAt, 4)) return 0;
    return *(uint32_t*)((uint8_t*)f + g_propOffsetAt);
}

// Read a script `float` by name. Same resolver, so same guarantee: it returns
// nothing rather than a plausible wrong number if calibration failed.

// Find a live UObject by its exact name. Used to read a CLASS DEFAULT OBJECT
// without hardcoding UClass's default-object offset: Default__X is an ordinary
// entry in GObjects, so looking it up by name is both simpler and verifiable.
static TArray<UObject*>* g_objsForLookup = nullptr;
static UObject* FindObjectByName(const char* want)
{
    if (!g_objsForLookup || IsBadReadPtr(g_objsForLookup, sizeof(*g_objsForLookup)))
        return nullptr;
    for (int i = 0; i < g_objsForLookup->Count; ++i) {
        UObject* o = SlotAt(g_objsForLookup, i);
        if (!o || IsBadReadPtr(o, sizeof(UObject))) continue;
        if (strcmp(NameOf(o->Name), want) == 0) return o;
    }
    return nullptr;
}

static bool ReadScriptFloat(UObject* obj, const char* prop, float* out) {
    size_t off = PropertyOffset(obj, prop);
    if (!off || IsBadReadPtr((uint8_t*)obj + off, 4)) return false;
    *out = *(float*)((uint8_t*)obj + off);
    return true;
}

// Read a script `string` (FString = TArray<wchar_t>) into ASCII.
static bool ReadScriptString(UObject* obj, const char* prop, char* out, size_t cap) {
    out[0] = 0;
    size_t off = PropertyOffset(obj, prop);
    if (!off || IsBadReadPtr((uint8_t*)obj + off, sizeof(FStringRaw))) return false;
    FStringRaw s;
    memcpy(&s, (uint8_t*)obj + off, sizeof(s));
    // Longer than cap: truncated below, not dropped (a dropped line reads as
    // "script wrote nothing"). 65536 is only a sanity bound on a bad read.
    if (!s.Data || s.Count <= 1 || s.Count > 65536) return false;
    if (IsBadReadPtr(s.Data, (size_t)s.Count * 2)) return false;
    size_t n = 0;
    for (int i = 0; i < s.Count - 1 && n + 1 < cap; ++i) {
        wchar_t w = s.Data[i];
        out[n++] = (w >= 32 && w < 127) ? (char)w : '?';
    }
    out[n] = 0;
    return n > 0;
}

static const char* NetModeName(unsigned char m) {
    switch (m) {
        case 0: return "Standalone";
        case 1: return "Dedicated";
        case 2: return "LISTEN-SERVER";
        case 3: return "CLIENT";
        default: return "??";
    }
}

struct Snapshot {
    int netmode = -1;
    // Did the DLC mount, and did ?game= resolve? Counting connections told us
    // nothing about that, and inferring from controllers=0 was ambiguous.
    bool mpClassLoaded = false;      // a Class object named SFXGameInfoMP exists
    // The main menu's Multiplayer screen:
    // its package MPMainMenu (0 none, 1 the Package, 2 + the Class
    // SFXGUI_MPMainMenuEntry), and whether an instance (the open screen) exists.
    int mmPkg = 0;
    bool mmOpen = false;
    std::string gameInfoClass;       // class of the live WorldInfo.Game
    UObject* worldInfo = nullptr;    // the WorldInfo picked below, for StallThread
    std::string squadDesc;           // the combat-gate chain, see below
    int drivers = 0, conns = 0, controllers = 0, pris = 0, pawns = 0;
    // possessed: PlayerControllers whose AController::Pawn (+0x3bc, per
    // LExSDK) is non-null. `pawns` counts every pawn in the level — 30 on
    // BioP_MPCer, almost all of them scenery NPCs — so it cannot answer the
    // question that matters after two players are in a map: does either of
    // them actually have a body? ME3 keeps the loading movie up until the
    // local player possesses one, which is exactly the state we are in.
    // mppawns: instances of SFXPawn_PlayerMP specifically, i.e. did
    // SpawnDefaultPawnFor's cast succeed and produce our stub class.
    int possessed = 0, mppawns = 0;
    // Every SFXPawn_Player* in the process, with its mesh state — see the
    // comment at the counting site. playerPawnsNoMesh is the number still
    // waiting for a body, which on a client should fall to 0 once
    // MPBuildAppearances has run.
    int playerPawns = 0, playerPawnsNoMesh = 0;
    std::string playerPawnList;
    // See the counting site: does this process have a HUD actor, and of what
    // class. The host draws one and the client does not.
    int huds = 0;
    std::string hudClass;
    // Live SFXWeapon actors. AddPlayerInventory CREATES weapons and only
    // EQUIPS them when bCombatPawn, so "no weapon in hand" has two causes
    // that this number separates: weapons>0 means they exist and nobody is
    // holding them, weapons=0 means CreateWeapons produced nothing.
    int weapons = 0;
    // MPBody's outcome, encoded as a count because this game writes no log and
    // ClientMessage shows nothing in our game mode: 1 no pawn, 2 no mesh
    // component, 3 mesh would not load, 4 applied. 0 means the command never
    // reached our controller at all, which is its own answer.
    int bodyprobe = 0;
    // Is the ported kit package actually in memory here? The client reports
    // bodyprobe=3 — the mesh would not load — for a mesh that is an export of
    // the map it is standing in, while the same path loads on the host. Either
    // the client does not have those objects at all, or the path form fails
    // there, and those want different fixes. The host is the positive control:
    // it must read yes.
    bool kitPkg = false;
    // What a possessed pawn actually IS and WHERE it is. The client reports a
    // possessed pawn while its camera sits at the origin and only rotates, and
    // its input demonstrably moves the other player on the host — so the pawn
    // exists on both ends and only one of them is driving it. A class name and
    // a position separate "wrong pawn", "right pawn at the wrong place" and
    // "right pawn that cannot move" without another guess.
    std::string pawnDesc;
    // Whatever script last wrote into SFXPlayerControllerMP.MPDebug. The only
    // way text gets out of this game — see the block above ClassNameOf.
    std::string scriptLog;
    // MPDebug of every controller WITHOUT a pawn, by controller name. scriptLog
    // reads only the first possessed one, so a match that spawned nobody
    // ("waiting for other players" on both sides) left the
    // script's own account unread, though PlayerTick keeps writing it.
    std::vector<std::pair<std::string, std::string>> unpossessedScript;
    // Does the pawn ARCHETYPE object exist in this process at all?
    //
    // The client resolved the pawn's CLASS, SFXPawn_PlayerVanguardNonCombat,
    // which lives in SFXGameContent — a package with no file. So "objects in
    // fileless packages cannot be named over the wire" is too strong, and the
    // real question is narrower: is the archetype simply NOT LOADED on the
    // client? It lives in SFXCharacterClass_Vanguard.pcc, a real file the host
    // loads when the single-player spawn path asks for it and the client has
    // no reason to touch.
    //
    // no on the client, yes on the host  -> a package-loading problem: make
    //   the client load that file, or ship the archetype in our own package
    // yes on both                        -> it is loaded and still was not
    //   used, which is an addressing problem and a different fix
    bool archObjPresent = false;
    std::string archObjPkg;
    // starts: BioStartLocationMP instances in the world. GameInfo.Login calls
    // FindPlayerStart BEFORE SpawnPlayerController and returns None if it
    // fails, so controllers=0 cannot distinguish "no spawn markers" from
    // "login broke for some other reason". This does.
    // anchors: DynamicAnchors, which FindPlayerStart spawns at a chosen
    // marker — so starts>0 with anchors=0 means the markers loaded but none
    // was selected, a different bug from the markers being absent.
    // pstarts: stock Engine.PlayerStart. A control for "is the DLC map
    // override being loaded at all" — PlayerStart needs no DLC import, so
    // pstarts>0 with starts=0 isolates the fault to our custom class.
    // prelogins: MPProbePreLogin markers, one spawned per GameInfo.PreLogin.
    // The game writes no log and UNetConnection's native fields are not in
    // LExSDK, so this is how we see whether a connecting client reaches script.
    // refused carries a deliberate baseline of 1: SFXGameInfoMP.PostBeginPlay
    // spawns one MPProbeRefused at level start as a positive control. So
    // refused=0 means the counter itself is broken and proves nothing;
    // refused=1 is 'working, nobody refused'; refused>1 counts real refusals.
    int starts = 0, anchors = 0, pstarts = 0, prelogins = 0, refused = 0;
    // logins/loginfail: Login entry and Login returning None, measured rather
    // than inferred from anchors — stock Login has four early returns before
    // FindPlayerStart is ever called.
    int logins = 0, loginfail = 0;
    // pendings: UPendingLevel objects. A client connecting by URL puts the
    // connection in a pending level, which the ENGINE ticks — unlike the
    // host, whose driver is ticked via its loaded world. That asymmetry is
    // the only structural difference between the two roles, and the client's
    // socket filling to 1920 bytes unread is exactly what an unticked pending
    // level looks like. pendings>0 with the socket still unread localises the
    // fault to the engine's tick path rather than to UTcpNetDriver, which both
    // roles share and which demonstrably works on the host.
    int pendings = 0;
    std::string map, connNames;
    // Actor channels, summarised — see DescribeChannels.
    std::string chanDesc;
    // Package-map entries for the packages that matter — see DescribePackageMaps.
    std::string pkgMapDesc;
    // UPackage::NetObjects for the same packages — see DescribeNetObjects.
    std::string netObjDesc;
    bool operator==(const Snapshot& o) const {
        return netmode == o.netmode && mpClassLoaded == o.mpClassLoaded
            && mmPkg == o.mmPkg && mmOpen == o.mmOpen
            && gameInfoClass == o.gameInfoClass
            && drivers == o.drivers && conns == o.conns
            && controllers == o.controllers && pris == o.pris
            && starts == o.starts && anchors == o.anchors
            && pstarts == o.pstarts && prelogins == o.prelogins
            && refused == o.refused && logins == o.logins
            && loginfail == o.loginfail && pendings == o.pendings
            && pawns == o.pawns && possessed == o.possessed
            && mppawns == o.mppawns && bodyprobe == o.bodyprobe
            && kitPkg == o.kitPkg && map == o.map
            && pawnDesc == o.pawnDesc && scriptLog == o.scriptLog
            && archObjPresent == o.archObjPresent
            && playerPawns == o.playerPawns
            && playerPawnsNoMesh == o.playerPawnsNoMesh
            && playerPawnList == o.playerPawnList
            && huds == o.huds && hudClass == o.hudClass
            && weapons == o.weapons && chanDesc == o.chanDesc
            && pkgMapDesc == o.pkgMapDesc && netObjDesc == o.netObjDesc;
    }
};


// One-shot vtable dump of the client's UPendingLevel.
//
// pendings=1 on the client with its socket holding 1920 unread bytes says the
// pending level exists and is not being serviced. Its Tick is a virtual, so if
// BioWare folded that slot onto one of the three shared stub bodies Phase 0
// identified — 0x73820 `ret`, 0x83710 `return false`, 0x86690 `return true` —
// the pending level would construct, hold a live connection, and never pump,
// which is exactly what we observe. This prints the slots so that can be read
// off directly instead of inferred.

// One-shot field-window dump of a connection object, for diffing host against
// client. See the retraction note at the call site.
static bool g_dumpedConn = false;
static void DumpConnFields(UObject* o, const char* cn) {
    if (g_dumpedConn) return;
    g_dumpedConn = true;
    L("CONNFIELDS %s", cn);
    for (int off = 0x60; off < 0x140; off += 0x10) {
        if (IsBadReadPtr((uint8_t*)o + off, 0x10)) break;
        uint32_t* w = (uint32_t*)((uint8_t*)o + off);
        L("  +%03x  %08x %08x %08x %08x", off, w[0], w[1], w[2], w[3]);
    }
}

static bool g_dumpedPending = false;
static void DumpPendingVT(UObject* o, const char* cn) {
    if (g_dumpedPending) return;
    g_dumpedPending = true;
    void** vt = *(void***)o;
    if (IsBadReadPtr(vt, 8) || (uint8_t*)vt < g_base || (uint8_t*)vt >= g_end) {
        L("PENDING %s: vtable %p not in module", cn, (void*)vt);
        return;
    }
    L("PENDING %s vtable_rva=%llx", cn,
      (unsigned long long)((uint8_t*)vt - g_base));
    // 40 was too few: UObject alone carries roughly that many virtuals in UE3,
    // so the first ~40 slots are the UObject prefix and UPendingLevel's own
    // virtuals — Tick among them — start after it. Stub slots inside the
    // prefix mean nothing; Phase 0 measured a third to a half of slots folded
    // onto shared bodies even in components that demonstrably work.
    for (int i = 0; i < 120; ++i) {
        if (IsBadReadPtr(vt + i, 8)) break;
        uint8_t* f = (uint8_t*)vt[i];
        if (f < g_base || f >= g_end) break;
        unsigned long long rva = (unsigned long long)(f - g_base);
        const char* tag = "";
        if (rva == 0x73820) tag = "  <-- STUB ret";
        else if (rva == 0x83710) tag = "  <-- STUB return false";
        else if (rva == 0x86690) tag = "  <-- STUB return true";
        L("  slot %02d off %03x rva %llx  %02x %02x %02x %02x%s",
          i, i * 8, rva, f[0], f[1], f[2], f[3], tag);
    }
}

// ---------------------------------------------------------------------------
// ACTOR CHANNELS: does the host ever SEND the kit pawn, and does the client
// ever RECEIVE it?
//
// Two players, a kit loaded and held on both, and the host's SFXPawn_PlayerMP
// still never reaches the client.
// Every load-order explanation is ruled out. What is left is replication
// itself, and it has two halves that look identical from outside:
//
//   the server never opens a channel for the pawn  -> the HOST lists no
//       channel whose actor is SFXPawn_PlayerMP
//   the server sends it and the client drops it    -> the host lists one;
//       the CLIENT lists a channel with NO actor, and its class field names
//       what it failed to build
//
// UE3 channels are UObjects (UChannel : UObject), so they are in GObjects like
// everything else. LE3's UActorChannel layout is not in LExSDK, so the Actor,
// ActorClass and Connection fields are CALIBRATED, not assumed: every
// ActorChannel is scanned for pointers, and the offset that most often holds a
// live Actor is the Actor field. PRIs, controllers and the GRI replicate fine,
// so they calibrate it; a pawn channel with a NULL actor then reads as NULL at
// the same offset instead of vanishing from the count.
//
// ControlChannel is the presence control: a live connection always has one. If
// conns>0 and ControlChannel=0, this measurement is broken, not replication.
// ---------------------------------------------------------------------------
struct ChanRef { UObject* o; std::string cls; };

static bool IsLiveObject(const void* p) {
    if (!p || (uintptr_t)p < 0x10000 || IsBadReadPtr(p, sizeof(UObject))) return false;
    const UObject* o = (const UObject*)p;
    if ((uint8_t*)o->VfTable <= g_base || (uint8_t*)o->VfTable >= g_end) return false;
    return o->Class && !IsBadReadPtr(o->Class, sizeof(UObject));
}
static bool ClassDerivesFrom(UObject* cls, const char* want) {
    for (int i = 0; cls && i < 64; ++i) {
        if (IsBadReadPtr(cls, OFF_FIELD_SUPER + 8)) return false;
        if (strcmp(NameOf(cls->Name), want) == 0) return true;
        cls = *(UObject**)((uint8_t*)cls + OFF_FIELD_SUPER);
    }
    return false;
}
static bool IsActorObject(UObject* o) {
    return IsLiveObject(o) && strcmp(ClassNameOf(o), "Class") != 0 && ClassDerivesFrom(o->Class, "Actor");
}
static bool IsActorClassObject(UObject* o) {
    return IsLiveObject(o) && strcmp(ClassNameOf(o), "Class") == 0 && ClassDerivesFrom(o, "Actor");
}

// ---------------------------------------------------------------------------
// The objective HUD and the annex objective, read from memory.
//
// Reported twice: the hack objective shows the omnitool in its zone but no
// progress bar and no progress. Reading 2012's code found no blocker either
// time, and the gates that can stop it return SILENTLY:
//   - SFXObjective_Annex_DefendZone.UpdateAnnexZone returns at once unless its
//     SFXModule_MarkerObjective is bActive, AnnexWave and AnnexZone are set;
//     LE3's SFXModule_Marker.Activate refuses (and re-arms itself on
//     ModuleOwner) while GRI.MarkerModuleManager is None.
//   - every SFXPlayerControllerMP HUD feeder returns unless GetMovie('MPHUD')
//     finds an SFXGUI_MPHUD, which a native OpenMovie creates from bioui.ini's
//     movielibrary; and SFXGUI_MPHUD shows the bar only after
//     SetScoreHudObjectiveText gave it a non-zero CurrentObjectiveText.
// A script readout was tried and held out (its class references reordered the
// compile), so this reads the same fields from outside, which changes nothing
// in the build. Each field says which gate it is.
// ---------------------------------------------------------------------------

// Where UBoolProperty::BitMask lives. Discovered, like UProperty::Offset:
// Actor declares bStatic, bHidden, bNoDelete consecutively (LE3 Actor.uc
// :249-251), so they share one word with masks 1, 2, 4. Adopted only if
// exactly one position reads that way on all three.
static size_t g_boolMaskAt = 0;
static void CalibrateBoolMask(UObject* actorCls) {
    if (!g_propOffsetAt || !actorCls) return;
    UObject* p[3] = { FindFieldByName(actorCls, "bStatic"),
                      FindFieldByName(actorCls, "bHidden"),
                      FindFieldByName(actorCls, "bNoDelete") };
    if (!p[0] || !p[1] || !p[2]) { L("BOOLCAL: Actor bools not found"); return; }
    size_t hit = 0; int hits = 0;
    for (size_t off = g_propOffsetAt + 4; off <= g_propOffsetAt + 0x60; off += 4) {
        bool ok = true;
        for (int k = 0; k < 3 && ok; ++k)
            ok = !IsBadReadPtr((uint8_t*)p[k] + off, 4) &&
                 *(uint32_t*)((uint8_t*)p[k] + off) == (1u << k);
        if (ok) { hit = off; ++hits; }
    }
    if (hits == 1) {
        g_boolMaskAt = hit;
        L("BOOLCAL: UBoolProperty::BitMask is at +0x%zx", hit);
    } else {
        L("BOOLCAL: %d candidates for UBoolProperty::BitMask — refusing to guess", hits);
    }
}
// -1 = could not read (unresolved name or no calibration), else 0/1.
static int ReadScriptBool(UObject* obj, const char* prop) {
    if (!g_boolMaskAt || !obj || IsBadReadPtr(obj, 0x40)) return -1;
    UObject* f = FindFieldByName(obj->Class, prop);
    if (!f || IsBadReadPtr((uint8_t*)f + g_boolMaskAt, 4)) return -1;
    size_t off = PropertyOffset(obj, prop);
    uint32_t mask = *(uint32_t*)((uint8_t*)f + g_boolMaskAt);
    if (!off || !mask || IsBadReadPtr((uint8_t*)obj + off, 4)) return -1;
    return (*(uint32_t*)((uint8_t*)obj + off) & mask) ? 1 : 0;
}
static bool ReadScriptInt(UObject* obj, const char* prop, int* out) {
    size_t off = PropertyOffset(obj, prop);
    if (!off || IsBadReadPtr((uint8_t*)obj + off, 4)) return false;
    *out = *(int32_t*)((uint8_t*)obj + off);
    return true;
}
// An object reference: nullptr both for None and for "could not read", so the
// caller prints the resolution separately (see RefTag).
static UObject* ReadScriptObj(UObject* obj, const char* prop, bool* resolved) {
    size_t off = PropertyOffset(obj, prop);
    *resolved = off && !IsBadReadPtr((uint8_t*)obj + off, 8);
    if (!*resolved) return nullptr;
    UObject* v = *(UObject**)((uint8_t*)obj + off);
    return IsLiveObject(v) ? v : nullptr;
}
// "Y" set, "N" None, "?" the property did not resolve — so an unresolved name
// can never read as None, which would be a zero mistaken for an absence.
static const char* RefTag(UObject* obj, const char* prop) {
    bool r; UObject* v = ReadScriptObj(obj, prop, &r);
    return !r ? "?" : (v ? "Y" : "N");
}
static TArray<UObject*>* ReadScriptArray(UObject* obj, const char* prop) {
    size_t off = PropertyOffset(obj, prop);
    if (!off || IsBadReadPtr((uint8_t*)obj + off, sizeof(TArray<UObject*>))) return nullptr;
    return (TArray<UObject*>*)((uint8_t*)obj + off);
}
static int ArrayCount(UObject* obj, const char* prop) {
    TArray<UObject*>* a = ReadScriptArray(obj, prop);
    return a ? a->Count : -1;
}
// A script `byte` (enums: Role, Physics); -1 = could not read.
static int ReadScriptByte(UObject* obj, const char* prop) {
    size_t off = PropertyOffset(obj, prop);
    if (!off || IsBadReadPtr((uint8_t*)obj + off, 1)) return -1;
    return *((uint8_t*)obj + off);
}

// LOBBYTEX: the lobby movie's own textures, live.
// In game most of MPNewLobby's images do not draw (the red panel frame I8B,
// the arrows I8D/I8F, the Galaxy at War art), while the blue frame I49 does,
// and a one-byte A/B showed the SAME texture object failing in I49's slot.
// Every static property matches, so this reads what only the running game
// knows: which Texture2D exports under GUI_SF_MPNewLobby exist right now, and
// whether each has its render resource (UTexture::Resource, +0x60 in LExSDK's
// LE3 layout; NULL = nothing for the renderer to draw). "movie=" counts the
// GFxMovieInfo MPNewLobby, whose References keep the textures alive.
// Names print without the "MPNewLobby_" prefix; "-" after a name = no resource.
static std::string DescribeLobbyTextures(TArray<UObject*>* objs) {
    int movie = 0, n = 0, noRes = 0;
    std::string list;
    for (int i = 0; i < objs->Count; ++i) {
        UObject* o = SlotAt(objs, i);
        if (!IsLiveObject(o)) continue;
        const char* cn = ClassNameOf(o);
        const char* on = NameOf(o->Name);
        if (strcmp(cn, "GFxMovieInfo") == 0 && strcmp(on, "MPNewLobby") == 0) ++movie;
        if (strcmp(cn, "Texture2D") != 0) continue;
        UObject* top = o;
        while (top->Outer && !IsBadReadPtr(top->Outer, sizeof(UObject))) top = top->Outer;
        if (strcmp(NameOf(top->Name), "GUI_SF_MPNewLobby") != 0) continue;
        void* res = nullptr;
        if (!IsBadReadPtr((uint8_t*)o + 0x60, sizeof(void*))) res = *(void**)((uint8_t*)o + 0x60);
        ++n;
        if (!res) ++noRes;
        const char* shortName = strncmp(on, "MPNewLobby_", 11) == 0 ? on + 11 : on;
        if (list.size() < 420)
            list += std::string(list.empty() ? "" : ",") + shortName + (res ? "" : "-");
    }
    char b[96];
    snprintf(b, sizeof b, "movie=%d tex=%d nores=%d ", movie, n, noRes);
    return std::string(b) + list;
}


// ---------------------------------------------------------------------------
// MENUSTATE: every script property, with its value, of the GUI manager, every
// live GUI movie and the local controller's GameModeManager2 — on a main-menu
// map, when the movie list changes and 5 s later. For the missing cursor:
// any main-menu sub-screen (Options, the
// Multiplayer screen), then a lobby, then back = no cursor; straight to the
// lobby and back = cursor [V]. The two dumps are diffed.
static void DumpValues(UObject* obj, const char* label) {
    if (!obj || IsBadReadPtr(obj, 0x60) || !g_propOffsetAt) return;
    L("MENUSTATE %s %s %p:", label, ClassNameOf(obj), (void*)obj);
    std::string line;
    int n = 0;
    for (UObject* c = obj->Class; c && !IsBadReadPtr(c, 0x80);
         c = *(UObject**)((uint8_t*)c + OFF_FIELD_SUPER)) {
        const char* owner = NameOf(c->Name);
        if (strcmp(owner, "Object") == 0) break;
        for (UObject* f = *(UObject**)((uint8_t*)c + OFF_STRUCT_CHILDREN);
             f && !IsBadReadPtr(f, 0x80);
             f = *(UObject**)((uint8_t*)f + OFF_FIELD_NEXT)) {
            const char* fc = ClassNameOf(f);
            if (!strstr(fc, "Property")) continue;
            if (IsBadReadPtr((uint8_t*)f + g_propOffsetAt, 4)) continue;
            uint32_t off = *(uint32_t*)((uint8_t*)f + g_propOffsetAt);
            uint8_t* v = (uint8_t*)obj + off;
            if (off == 0 || IsBadReadPtr(v, 16)) continue;
            char b[160];
            const char* fn = NameOf(f->Name);
            if (!strcmp(fc, "BoolProperty")) {
                uint32_t mask = g_boolMaskAt && !IsBadReadPtr((uint8_t*)f + g_boolMaskAt, 4) ? *(uint32_t*)((uint8_t*)f + g_boolMaskAt) : 0;
                if (!mask) continue;
                snprintf(b, sizeof b, " %s=%d", fn, (*(uint32_t*)v & mask) ? 1 : 0);
            } else if (!strcmp(fc, "IntProperty")) {
                snprintf(b, sizeof b, " %s=%d", fn, *(int32_t*)v);
            } else if (!strcmp(fc, "FloatProperty")) {
                snprintf(b, sizeof b, " %s=%.3g", fn, *(float*)v);
            } else if (!strcmp(fc, "ByteProperty")) {
                snprintf(b, sizeof b, " %s=%u", fn, (unsigned)*v);
            } else if (!strcmp(fc, "NameProperty")) {
                snprintf(b, sizeof b, " %s=%s", fn, NameOf(*(FName*)v));
            } else if (!strcmp(fc, "ObjectProperty") || !strcmp(fc, "ClassProperty") || !strcmp(fc, "ComponentProperty")) {
                UObject* r = *(UObject**)v;
                if (!r) snprintf(b, sizeof b, " %s=None", fn);
                else if (IsBadReadPtr(r, sizeof(UObject))) snprintf(b, sizeof b, " %s=<bad>", fn);
                else snprintf(b, sizeof b, " %s=%s:%s", fn, ClassNameOf(r), NameOf(r->Name));
            } else if (!strcmp(fc, "StrProperty")) {
                struct FStr { wchar_t* d; int32_t n, m; } *fs = (FStr*)v;
                std::string a;
                if (fs->d && fs->n > 0 && fs->n < 200 && !IsBadReadPtr(fs->d, fs->n * 2))
                    for (int i = 0; i < fs->n - 1 && i < 40; ++i) a += (char)(fs->d[i] < 128 ? fs->d[i] : '?');
                snprintf(b, sizeof b, " %s=\"%s\"", fn, a.c_str());
            } else if (!strcmp(fc, "ArrayProperty")) {
                snprintf(b, sizeof b, " %s=[%d]", fn, *(int32_t*)(v + 8));
            } else {
                continue;   // structs, delegates, maps: not needed here
            }
            line += b;
            if (line.size() > 360) { L("   [%s]%s", owner, line.c_str()); line.clear(); }
            if (++n > 600) break;
        }
        if (!line.empty()) { L("   [%s]%s", owner, line.c_str()); line.clear(); }
    }
}
static void DumpMenuState(TArray<UObject*>* objs, const char* why) {
    L("MENUSTATE begin (%s)", why);
    UObject* pc = nullptr;
    for (int i = 0; i < objs->Count; ++i) {
        UObject* o = SlotAt(objs, i);
        if (!IsLiveObject(o)) continue;
        const char* on = NameOf(o->Name);
        if (strncmp(on, "Default__", 9) == 0) continue;
        const char* cn = ClassNameOf(o);
        if (!strcmp(cn, "Class")) continue;
        if (!strcmp(cn, "SFXGUIInteraction")) DumpValues(o, "gui");
        else if (ClassDerivesFrom(o->Class, "SFXGUIMovie")) DumpValues(o, "movie");
        else if (!pc && (!strcmp(cn, "SFXPlayerController") || !strcmp(cn, "BioPlayerController") || !strcmp(cn, "SFXPlayerControllerMP"))) pc = o;
    }
    if (pc) {
        size_t off = PropertyOffset(pc, "GameModeManager2");
        UObject* gm = off && !IsBadReadPtr((uint8_t*)pc + off, 8) ? *(UObject**)((uint8_t*)pc + off) : nullptr;
        L("MENUSTATE pc %s %p GameModeManager2=%p", ClassNameOf(pc), (void*)pc, (void*)gm);
        DumpValues(gm, "gamemodes");
    }
    L("MENUSTATE end");
}

// The escort drone (MP3 Mobile Annex): the objective escort drone was reported
// still invisible. Every static link matched 2012/LE3,
// so these are the run-time steps the drone's only visible part depends on:
// SFXPawn_MobileAnnex.DeferredPostBeginPlay waits for a PRI, then StartOnTarget
// (CE_PawnTemplate) gives PawnTemplateGuid; the effect pins to bone Root of the
// pawn's Mesh. Pawn:
//   r=Role h=bHidden pri= ctl=controller class t=CE_PawnTemplate
//   g=PawnTemplateGuid set m=Mesh/SkeletalMesh mh=Mesh.HiddenGame
//   ph=Physics spd=CurrentSpeed d=bDestroyed
// Objective: a=bActivated p=AnnexPawn dst=AnnexDestination sm=Mesh's StaticMesh.
// psc=E/B/T: live ParticleSystemComponents on Tech_Ball_Escort / on
// Tech_Scanning_Beam_2 / with any template at all (the control: T > 0 means the
// lookup can see a component, so E=0 is an absence, not a broken read).
// Reported: the material is invisible. For the first Tech_Ball_Escort
// component, ball[act= hg= d= np=]: bIsActive, HiddenGame, the distance from its
// LocalToWorld origin to the first escort pawn's Location (the effect follows
// bone Root of a zero-bounds mesh: a large d = drawn elsewhere), and
// InstanceParameters' count (the VCFX's Color_2 reaches the emitters there).
static bool ReadScriptVec(UObject* obj, const char* prop, size_t at, float v[3]) {
    size_t off = PropertyOffset(obj, prop);
    if (!off || IsBadReadPtr((uint8_t*)obj + off + at, 12)) return false;
    memcpy(v, (uint8_t*)obj + off + at, 12);
    return true;
}
// The objective pool: the objective was reported not to show up
// (six objective waves, Retrieve-DLC four times, no escort). 2012's
// SFXWaveManager_Operation.GeneratePotentialWaveList drops every engagement
// whose ObjectivesRequired the map's spawn points cannot meet, then
// GetWaveIndex rolls over WeightedChanceOfSelection. opool=N[name:weight,...]
// is PotentialWaves AFTER that filter, so an absent sfxengagement_mobileannex_0
// means the map cannot host the escort, not bad luck. "opool=?" = no
// coordinator or the array did not resolve.
static std::string DescribeOpPool(TArray<UObject*>* objs) {
    for (int i = 0; i < objs->Count; ++i) {
        UObject* o = SlotAt(objs, i);
        if (!IsLiveObject(o)) continue;
        if (!strncmp(NameOf(o->Name), "Default__", 9) || !strcmp(ClassNameOf(o), "Class")) continue;
        if (!ClassDerivesFrom(o->Class, "SFXWaveCoordinator_HordeOperation")) continue;
        bool r; UObject* mgr = ReadScriptObj(o, "OperationManager", &r);
        TArray<UObject*>* pot = mgr ? ReadScriptArray(mgr, "PotentialWaves") : nullptr;
        if (!pot || pot->Count < 0 || pot->Count > 64) return " opool=?";
        std::string out = " opool=" + std::to_string(pot->Count) + "[";
        char b[96];
        for (int k = 0; k < pot->Count; ++k) {
            UObject* w = SlotAt(pot, k);
            if (!IsLiveObject(w)) { out += k ? ",?" : "?"; continue; }
            float wt = -1;
            ReadScriptFloat(w, "WeightedChanceOfSelection", &wt);
            snprintf(b, sizeof(b), "%s%s:%.1f", k ? "," : "", NameOf(w->Name), wt);
            out += b;
        }
        return out + "]";
    }
    return "";
}

static std::string DescribeEscort(TArray<UObject*>* objs) {
    std::string pawns, objsDesc;
    int nPawn = 0, nObj = 0, pscE = 0, pscB = 0, pscT = 0;
    UObject* firstPawn = nullptr;
    UObject* firstBall = nullptr;
    char b[400];
    for (int i = 0; i < objs->Count; ++i) {
        UObject* o = SlotAt(objs, i);
        if (!IsLiveObject(o)) continue;
        const char* cn = ClassNameOf(o);
        if (strncmp(NameOf(o->Name), "Default__", 9) == 0 || !strcmp(cn, "Class")) continue;
        if (!strcmp(cn, "ParticleSystemComponent")) {
            bool r; UObject* t = ReadScriptObj(o, "Template", &r);
            if (!t) continue;
            ++pscT;
            const char* tn = NameOf(t->Name);
            if (!strcmp(tn, "Tech_Ball_Escort")) { if (!pscE++) firstBall = o; }
            else if (!strcmp(tn, "Tech_Scanning_Beam_2")) ++pscB;
        } else if (!strcmp(cn, "SFXPawn_MobileAnnex")) {
            if (!firstPawn) firstPawn = o;
            if (nPawn++ >= 2) continue;
            bool r;
            UObject* ctl = ReadScriptObj(o, "Controller", &r);
            UObject* mesh = ReadScriptObj(o, "Mesh", &r);
            const char* g = "?";
            size_t goff = PropertyOffset(o, "PawnTemplateGuid");
            if (goff && !IsBadReadPtr((uint8_t*)o + goff, 16)) {
                const uint32_t* q = (const uint32_t*)((uint8_t*)o + goff);
                g = (q[0] | q[1] | q[2] | q[3]) ? "Y" : "N";
            }
            float spd = -1;
            ReadScriptFloat(o, "CurrentSpeed", &spd);
            snprintf(b, sizeof(b),
                     "[r=%d h=%d pri=%s ctl=%s t=%s g=%s m=%s/%s mh=%d ph=%d spd=%.2f d=%d]",
                     ReadScriptByte(o, "Role"), ReadScriptBool(o, "bHidden"),
                     RefTag(o, "PlayerReplicationInfo"), ctl ? ClassNameOf(ctl) : "N",
                     RefTag(o, "CE_PawnTemplate"), g, RefTag(o, "Mesh"),
                     mesh ? RefTag(mesh, "SkeletalMesh") : "-",
                     mesh ? ReadScriptBool(mesh, "HiddenGame") : -1,
                     ReadScriptByte(o, "Physics"), spd, ReadScriptBool(o, "bDestroyed"));
            pawns += b;
        } else if (!strcmp(cn, "SFXObjective_MobileAnnex")) {
            if (nObj++ >= 2) continue;
            bool r; UObject* mesh = ReadScriptObj(o, "Mesh", &r);
            snprintf(b, sizeof(b), "[a=%d p=%s dst=%s sm=%s]", ReadScriptBool(o, "bActivated"),
                     RefTag(o, "AnnexPawn"), RefTag(o, "AnnexDestination"),
                     mesh ? RefTag(mesh, "StaticMesh") : "-");
            objsDesc += b;
        }
    }
    if (!nPawn && !nObj) return "";
    std::string ball;
    if (firstBall) {
        // FMatrix: the translation is row 3 (floats 12..14).
        float bl[3], pl[3];
        char d[24] = "?";
        if (firstPawn && ReadScriptVec(firstBall, "LocalToWorld", 48, bl) &&
            ReadScriptVec(firstPawn, "Location", 0, pl)) {
            float dx = bl[0] - pl[0], dy = bl[1] - pl[1], dz = bl[2] - pl[2];
            snprintf(d, sizeof(d), "%.0f", sqrtf(dx * dx + dy * dy + dz * dz));
        }
        snprintf(b, sizeof(b), "ball[act=%d hg=%d d=%s np=%d]",
                 ReadScriptBool(firstBall, "bIsActive"), ReadScriptBool(firstBall, "HiddenGame"),
                 d, ArrayCount(firstBall, "InstanceParameters"));
        ball = b;
    }
    snprintf(b, sizeof(b), " escort=obj%d%s/pawn%d%s psc=%d/%d/%d%s", nObj, objsDesc.c_str(),
             nPawn, pawns.c_str(), pscE, pscB, pscT, ball.c_str());
    return b;
}

static std::string DescribeObjectiveHud(TArray<UObject*>* objs) {
    static bool calibrated = false;
    int mphud = 0, scoretags = 0, movieInfo = 0, ops = 0, annex = 0;
    std::string hudDesc, griDesc, opDesc, annexDesc, movies;
    char b[512];
    for (int i = 0; i < objs->Count; ++i) {
        UObject* o = SlotAt(objs, i);
        if (!IsLiveObject(o)) continue;
        const char* cn = ClassNameOf(o);
        const char* on = NameOf(o->Name);
        if (!calibrated && strcmp(cn, "Class") == 0 && strcmp(on, "Actor") == 0) {
            CalibrateBoolMask(o);
            calibrated = true;
        }
        if (strcmp(cn, "GFxMovieInfo") == 0 && strcmp(on, "MP_HUD") == 0) ++movieInfo;
        if (strncmp(on, "Default__", 9) == 0) continue;
        if (strcmp(cn, "Class") == 0) continue;
        if (strcmp(cn, "SFXGUI_MPScoretags") == 0) ++scoretags;
        // Every live GUI movie, so an absent MPHUD can be read against its
        // sibling from the same HUDType auto-load (MPScoretags) and the rest.
        if (movies.size() < 400 && ClassDerivesFrom(o->Class, "SFXGUIMovie"))
            movies += std::string(movies.empty() ? "" : ",") + cn;
        if (strcmp(cn, "SFXGUI_MPHUD") == 0) {
            if (mphud++ == 0) {
                int txt = -1, frame = -1;
                ReadScriptInt(o, "CurrentObjectiveText", &txt);
                ReadScriptInt(o, "CurrentObjectiveFrame", &frame);
                snprintf(b, sizeof(b), "[bar=%d circ=%d txt=%d frame=%d init=%d]",
                         ReadScriptBool(o, "ObjectiveBarVisible"),
                         ReadScriptBool(o, "ObjectiveCirclesVisible"), txt, frame,
                         ReadScriptBool(o, "Initialized"));
                hudDesc = b;
            }
        } else if (griDesc.empty() && ClassDerivesFrom(o->Class, "SFXGRI")) {
            int maxp = -1;
            ReadScriptInt(o, "MaxPlayersAllowedMP", &maxp);
            griDesc = std::string(" gri=") + cn + "/mmm=" + RefTag(o, "MarkerModuleManager") +
                      "/maxp=" + std::to_string(maxp);
        } else if (ClassDerivesFrom(o->Class, "SFXWave_Operation")) {
            ++ops;
            int title = -1;
            ReadScriptInt(o, "srScoreHudObjectiveTitle", &title);
            snprintf(b, sizeof(b), " %s[hud=%d title=%d lpc=%s objs=%d]", cn,
                     ReadScriptBool(o, "bUseObjectiveHud"), title,
                     RefTag(o, "LocalPlayerController"), ArrayCount(o, "ObjectiveActors"));
            if (opDesc.size() < 300) opDesc += b;
        } else if (ClassDerivesFrom(o->Class, "SFXObjective_Annex_DefendZone")) {
            ++annex;
            float cc = -1; int in = -1;
            ReadScriptFloat(o, "CompletionCount", &cc);
            ReadScriptInt(o, "PlayersInZone", &in);
            // The marker module: UpdateAnnexZone's first gate.
            std::string mod = "none";
            TArray<UObject*>* mods = ReadScriptArray(o, "Modules");
            if (!mods) mod = "?";
            for (int m = 0; mods && m < mods->Count && m < 8; ++m) {
                UObject* mo = SlotAt(mods, m);
                if (!IsLiveObject(mo) || !ClassDerivesFrom(mo->Class, "SFXModule_MarkerObjective"))
                    continue;
                bool r; UObject* owner = ReadScriptObj(mo, "ModuleOwner", &r);
                snprintf(b, sizeof(b), "act=%d/owner=%s", ReadScriptBool(mo, "bActive"),
                         !r ? "?" : !owner ? "N" : owner == o ? "self" : "other");
                mod = b;
            }
            snprintf(b, sizeof(b),
                     " %s[cc=%.3f in=%d zone=%s aw=%s ow=%s states=%d upd=%d done=%d act=%d mod=%s]",
                     cn, cc, in, RefTag(o, "AnnexZone"), RefTag(o, "AnnexWave"),
                     RefTag(o, "OwnerWave"), ArrayCount(o, "PlayerAnnexStates"),
                     ArrayCount(o, "PlayersToUpdate"), ReadScriptBool(o, "bIsComplete"),
                     ReadScriptBool(o, "bActivated"), mod.c_str());
            if (annexDesc.size() < 400) annexDesc += b;
        }
    }
    snprintf(b, sizeof(b), "mphud=%d%s scoretags=%d movieinfo=%d%s ops=%d",
             mphud, hudDesc.c_str(), scoretags, movieInfo, griDesc.c_str(), ops);
    return std::string(b) + opDesc + " annex=" + std::to_string(annex) + annexDesc +
           DescribeOpPool(objs) + DescribeEscort(objs) + " movies=" + (movies.empty() ? "none" : movies);
}
static void Bump(std::vector<std::pair<std::string, int>>& v, const std::string& k) {
    for (auto& e : v) if (e.first == k) { ++e.second; return; }
    v.push_back({k, 1});
}
static std::string DescribeChannels(const std::vector<ChanRef>& chans) {
    const size_t LO = 0x40, HI = 0x400;
    const int slots = (int)((HI - LO) / 8);
    std::vector<int> actHits(slots), clsHits(slots), connHits(slots);
    std::vector<std::pair<std::string, int>> kinds;
    std::vector<UObject*> actorChans;
    for (const ChanRef& c : chans) {
        Bump(kinds, c.cls);
        if (c.cls != "ActorChannel") continue;
        actorChans.push_back(c.o);
        for (int k = 0; k < slots; ++k) {
            uint8_t* a = (uint8_t*)c.o + LO + k * 8;
            if (IsBadReadPtr(a, 8)) break;
            UObject* v = *(UObject**)a;
            if (IsActorObject(v)) ++actHits[k];
            else if (IsActorClassObject(v)) ++clsHits[k];
            else if (IsLiveObject(v) && strstr(ClassNameOf(v), "Connection")) ++connHits[k];
        }
    }
    auto argmax = [&](const std::vector<int>& h) {
        int best = -1, bv = 0;
        for (int k = 0; k < slots; ++k) if (h[k] > bv) { bv = h[k]; best = k; }
        return best;
    };
    std::string out = "{";
    for (size_t i = 0; i < kinds.size(); ++i) {
        char b[96]; snprintf(b, sizeof(b), "%s%s=%d", i ? " " : "", kinds[i].first.c_str(), kinds[i].second);
        out += b;
    }
    out += "}";
    if (actorChans.empty()) return out + " no ActorChannel";
    int ka = argmax(actHits), kc = argmax(clsHits), kn = argmax(connHits);
    char cal[160];
    snprintf(cal, sizeof(cal), " actor@0x%x(%d/%zu) class@0x%x(%d) conn@0x%x(%d) |",
             ka < 0 ? 0 : (unsigned)(LO + ka * 8), ka < 0 ? 0 : actHits[ka], actorChans.size(),
             kc < 0 ? 0 : (unsigned)(LO + kc * 8), kc < 0 ? 0 : clsHits[kc],
             kn < 0 ? 0 : (unsigned)(LO + kn * 8), kn < 0 ? 0 : connHits[kn]);
    out += cal;
    if (ka < 0) return out + " NO ACTOR FIELD FOUND";
    std::vector<std::pair<std::string, int>> actors, orphans;
    // Raw memory of each NEW actor-less channel, with a known-good channel
    // (a PRI's) dumped beside it once: a good and a failed channel are the
    // same class, so the fields that differ — broken, dormant, a queue of
    // bunches waiting on something — say how the failed one is stuck.
    static std::vector<UObject*> dumped;
    static bool dumpedGood = false;
    auto dumpChan = [&](UObject* ch, const char* why) {
        L("CHANDUMP %s %p vtable_rva=0x%llx", why, (void*)ch,
          (unsigned long long)((uint8_t*)ch->VfTable - g_base));
        for (size_t off = 0x40; off < 0x240; off += 0x10) {
            if (IsBadReadPtr((uint8_t*)ch + off, 16)) break;
            uint32_t* d = (uint32_t*)((uint8_t*)ch + off);
            L("  +%03zx  %08x %08x %08x %08x", off, d[0], d[1], d[2], d[3]);
        }
    };
    for (UObject* ch : actorChans) {
        UObject* a = *(UObject**)((uint8_t*)ch + LO + ka * 8);
        if (!dumpedGood && IsActorObject(a) && strcmp(ClassNameOf(a), "SFXPRIMP") == 0) {
            dumpChan(ch, "GOOD(SFXPRIMP)");
            dumpedGood = true;
        }
        if (!IsActorObject(a)) {
            bool seen = false;
            for (UObject* d : dumped) if (d == ch) seen = true;
            if (!seen && dumped.size() < 6) { dumped.push_back(ch); dumpChan(ch, "NO-ACTOR"); }
        }
        if (IsActorObject(a)) { Bump(actors, ClassNameOf(a)); continue; }
        // A channel with no actor. Its class field, if calibrated, names
        // what the channel is for — on a client, what it could not build.
        std::string why = "?";
        if (kc >= 0) {
            UObject* c = *(UObject**)((uint8_t*)ch + LO + kc * 8);
            why = IsActorClassObject(c) ? NameOf(c->Name) : "noclass";
        }
        Bump(orphans, why);
        // Each actor-less channel once, when first seen (sample resolution,
        // INTERVAL_MS): the CHANNELS line is only written on a change of the
        // whole sample, up to ~10 s apart, too coarse to tell whether an enemy
        // arrived before or after its package's load (the
        // script's `waves: preload:` lines in mp_save have the other half).
        {
            static std::vector<UObject*> orphanSeen;
            bool known = false;
            for (UObject* o : orphanSeen) if (o == ch) { known = true; break; }
            if (!known) {
                if (orphanSeen.size() >= 4096) orphanSeen.clear();
                orphanSeen.push_back(ch);
                L("  NO-ACTOR-NEW %p %s (of %zu actor channels)", (void*)ch, why.c_str(), actorChans.size());
            }
        }
    }
    for (auto& e : actors) {
        char b[96]; snprintf(b, sizeof(b), " %s:%d", e.first.c_str(), e.second);
        out += b;
    }
    if (!orphans.empty()) {
        out += " | NO-ACTOR:";
        for (auto& e : orphans) {
            char b[96]; snprintf(b, sizeof(b), " %s:%d", e.first.c_str(), e.second);
            out += b;
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// PACKAGE MAPS: can the client name the kit's archetype?
//
// Measured by the channel probe: the host sends each SFXPawn_PlayerMP; the
// client opens the channel and ends with Actor = NULL and ActorClass = NULL.
// Classes in SFXGameMPContent resolve (SFXPRIMP, the controller), so what the
// client cannot name is the ARCHETYPE, (BioChar_MPPlayers, 935). A replicated
// object is named as (package-map entry, NetIndex): the entry must exist, and
// its Parent must be the loaded package, or the lookup yields NULL.
//
// UPackageMap is a UObject holding TArray<FPackageInfo> List. From the live-level
// handler at rva 0x8cb640: Info.Parent at
// +0x8 (`mov [r14+0x8],rax` after the in-memory lookup), Info.Guid at
// +0x10..0x1c, Info.PackageName (FName) at +0x34. The List's offset inside the
// map and the entry STRIDE are not documented, so they are calibrated: the
// first TArray whose entries at some stride all carry valid names at +0x34,
// with "Core" among the first eight.
//
// Printed for our packages plus BioChar_Player as the control — the Shepard
// archetypes live there and DO replicate, so its entry is what a working one
// looks like. The four ints after the Guid are printed raw; UE3's FPackageInfo
// has ObjectBase and ObjectCount first.
// ---------------------------------------------------------------------------
static const size_t PKGINFO_PARENT = 0x8, PKGINFO_GUID = 0x10, PKGINFO_NAME = 0x34;

static bool PlausibleName(const FName& n) {
    if (n.Chunk > 7 || !g_pools || !g_pools[n.Chunk]) return false;
    auto* e = (FNameEntry*)((uint8_t*)g_pools[n.Chunk] + n.Offset);
    if (IsBadReadPtr(e, 16)) return false;
    const char* p = e->AnsiName;
    int len = 0;
    for (; len < 64 && p[len]; ++len)
        if (!((p[len] >= 'A' && p[len] <= 'Z') || (p[len] >= 'a' && p[len] <= 'z') ||
              (p[len] >= '0' && p[len] <= '9') || p[len] == '_')) return false;
    return len > 0 && len < 64;
}

static bool IsAnchorName(const char* n) {
    return strcmp(n, "Core") == 0 || strcmp(n, "Engine") == 0 || strcmp(n, "SFXGame") == 0;
}

// One-off raw dump, so a calibration miss still yields the layout: the map's
// first 0x200 bytes, and the first 0x200 bytes behind every TArray-shaped field.
static void DumpPackageMapOnce(UObject* pm) {
    static int dumped = 0;
    if (dumped >= 2 || IsBadReadPtr(pm, 0x200)) return;
    ++dumped;
    L("PKGMAP-RAW %s @%p", ClassNameOf(pm), (void*)pm);
    for (size_t off = 0; off < 0x200; off += 0x10) {
        uint32_t* d = (uint32_t*)((uint8_t*)pm + off);
        L("  +%03zx  %08x %08x %08x %08x", off, d[0], d[1], d[2], d[3]);
    }
    for (size_t off = 0x40; off < 0x200; off += 8) {
        auto* arr = (TArray<uint8_t>*)((uint8_t*)pm + off);
        if (!arr->Data || arr->Count < 1 || arr->Count > 20000 || arr->Max < arr->Count
            || IsBadReadPtr(arr->Data, 0x200)) continue;
        L("  TArray@+%03zx count=%d max=%d data=%p:", off, arr->Count, arr->Max, (void*)arr->Data);
        for (size_t o = 0; o < 0x200; o += 0x10) {
            uint32_t* d = (uint32_t*)(arr->Data + o);
            L("      +%03zx  %08x %08x %08x %08x", o, d[0], d[1], d[2], d[3]);
        }
    }
}

static std::string DescribePackageMaps(const std::vector<UObject*>& maps) {
    static const char* want[] = {"BioChar_MPPlayers", "BIOG_MP_ADP_ASA", "SFXGameMPContent",
                                 "Asari_Adept_MP", "Startup_MOD_LEMultiplayer_INT", "BioP_MPCer", "BioChar_Player"};
    // The search is up to ~10^6 probes per map. Found once, the layout is
    // reused; a miss is retried at most every 10 s, so the sampler never
    // stalls the game.
    static size_t cOff = 0, cStride = 0, cName = 0;
    static DWORD lastTry = 0;
    std::string out;
    for (UObject* pm : maps) {
        DumpPackageMapOnce(pm);
        char hdr[200];
        bool found = false;
        if (!cStride && GetTickCount() - lastTry < 10000) {
            snprintf(hdr, sizeof(hdr), "%s%s (calibration pending)", out.empty() ? "" : " || ", ClassNameOf(pm));
            out += hdr;
            continue;
        }
        lastTry = GetTickCount();
        for (size_t off = (cStride ? cOff : 0x40); off < (cStride ? cOff + 1 : 0x400) && !found; off += 8) {
            auto* arr = (TArray<uint8_t>*)((uint8_t*)pm + off);
            if (IsBadReadPtr(arr, sizeof(*arr)) || !arr->Data || arr->Count < 3 || arr->Count > 20000
                || arr->Max < arr->Count || IsBadReadPtr(arr->Data, 0x40)) continue;
            // FPackageInfo is 0x4c bytes: UPackageMap::Compute (rva 0xcac20) walks
            // the list with imul 0x4c. The search used to step by 8 from 0x20, so it
            // could never land there and settled on 0x98 = two entries: every
            // PKGMAP-ALL used to show only the even entries, then
            // reads past the array's end. Start at 0x4c, step 4.
            for (size_t stride = (cStride ? cStride : 0x4c); stride <= (cStride ? cStride : 0x200) && !found; stride += 4) {
                int n = arr->Count < 32 ? arr->Count : 32;
                if (IsBadReadPtr(arr->Data, stride * n)) continue;
                for (size_t nameOff = (cStride ? cName : 0); nameOff + 8 <= stride && !found
                         && (!cStride || nameOff == cName); nameOff += 4) {
                    bool ok = true, anchor = false;
                    for (int i = 0; i < n && ok; ++i) {
                        const FName& nm = *(FName*)(arr->Data + i * stride + nameOff);
                        if (!PlausibleName(nm)) { ok = false; break; }
                        if (IsAnchorName(NameOf(nm))) anchor = true;
                    }
                    if (!ok || !anchor) continue;
                    found = true;
                    cOff = off; cStride = stride; cName = nameOff;
                    snprintf(hdr, sizeof(hdr), "%s%s list@0x%zx stride=0x%zx name@0x%zx entries=%d:",
                             out.empty() ? "" : " || ", ClassNameOf(pm), off, stride, nameOff, arr->Count);
                    out += hdr;
                    // EVERY entry, once per change in the count: which packages
                    // the engine lists at all is the question now. The host
                    // had the kit loaded before the join and still did not list
                    // BioChar_MPPlayers. name base+count, '*' = Parent live.
                    {
                        static std::vector<std::pair<void*, int>> seen;
                        bool fresh = true;
                        for (auto& p : seen) if (p.first == (void*)pm && p.second == arr->Count) fresh = false;
                        if (fresh) {
                            seen.push_back({(void*)pm, arr->Count});
                            std::string all;
                            for (int i = 0; i < arr->Count; ++i) {
                                uint8_t* e = arr->Data + i * stride;
                                if (IsBadReadPtr(e, 0x30)) break;
                                const FName& nm = *(FName*)(e + nameOff);
                                UObject* par = *(UObject**)(e + 0x8);
                                char b[128];
                                // base+count, then /local.remote generation: Compute
                                // takes the count from the LOCAL package's generation
                                // table at min(local, remote), and leaves it as it was
                                // when that package has no generations (a stub).
                                snprintf(b, sizeof(b), " %s%s:%d+%d/%d.%d", PlausibleName(nm) ? NameOf(nm) : "?",
                                         IsLiveObject(par) ? "*" : "", *(int32_t*)(e + 0x20), *(int32_t*)(e + 0x24),
                                         *(int32_t*)(e + 0x28), *(int32_t*)(e + 0x2c));
                                all += b;
                            }
                            L("  PKGMAP-ALL %s @%p entries=%d:%s", ClassNameOf(pm), (void*)pm, arr->Count, all.c_str());
                        }
                    }
                    for (int i = 0; i < arr->Count; ++i) {
                        uint8_t* e = arr->Data + i * stride;
                        if (IsBadReadPtr(e, stride)) break;
                        const FName& nm = *(FName*)(e + nameOff);
                        if (!PlausibleName(nm)) continue;
                        const char* name = NameOf(nm);
                        bool match = false;
                        for (const char* w : want) if (strcmp(name, w) == 0) match = true;
                        if (!match) continue;
                        // Every qword of the entry that points at a live object,
                        // by offset — Parent is among them if it is set.
                        std::string ptrs;
                        for (size_t q = 0; q + 8 <= stride; q += 8) {
                            UObject* v = *(UObject**)(e + q);
                            if (IsLiveObject(v)) {
                                char pb[96]; snprintf(pb, sizeof(pb), " +%zx=%s(%s)", q, NameOf(v->Name), ClassNameOf(v));
                                ptrs += pb;
                            }
                        }
                        char b[160];
                        snprintf(b, sizeof(b), " [%d]%s", i, name);
                        out += b;
                        out += ptrs.empty() ? " NO-LIVE-POINTERS" : ptrs;
                        out += " raw=";
                        for (size_t q = 0; q < stride && q < 0x60; q += 4) {
                            char rb[12]; snprintf(rb, sizeof(rb), "%s%08x", q ? "." : "", *(uint32_t*)(e + q));
                            out += rb;
                        }
                    }
                }
            }
        }
        if (!found) {
            snprintf(hdr, sizeof(hdr), "%s%s LIST NOT FOUND", out.empty() ? "" : " || ", ClassNameOf(pm));
            out += hdr;
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// NET OBJECTS: does the client's in-memory package know object 935?
//
// Measured 00:46: both sides' package-map entry for BioChar_MPPlayers is the
// same slot, GUID, base and count (1254), with a live Parent — and the client
// still builds the Asari's channel with Actor = NULL. The next lookup down is
// the package's own table: an index resolves as Parent->NetObjects[index], and
// only the RECEIVER needs that table. If the client's BioChar_MPPlayers never
// had its table sized or filled, slot 935 is empty and nothing can be built.
//
// UPackage's layout is not in LExSDK, so the table is found the same way as
// before: the first TArray<UObject*> in the package whose non-null entries are
// live objects whose outermost object is this package. BioChar_Player is the
// control: its Shepard archetypes DO resolve on a client.
// ---------------------------------------------------------------------------
static UObject* Outermost(UObject* o) {
    for (int i = 0; o && i < 32; ++i) {
        if (IsBadReadPtr(o, sizeof(UObject))) return nullptr;
        if (!o->Outer) return o;
        o = o->Outer;
    }
    return nullptr;
}

static std::string DescribeNetObjects(const std::vector<UObject*>& pkgs) {
    std::string out;
    for (UObject* pkg : pkgs) {
        char b[320];
        bool found = false;
        for (size_t off = 0x60; off < 0x400 && !found; off += 8) {
            auto* arr = (TArray<UObject*>*)((uint8_t*)pkg + off);
            if (IsBadReadPtr(arr, sizeof(*arr)) || !arr->Data || arr->Count < 1 || arr->Count > 400000
                || arr->Max < arr->Count || IsBadReadPtr(arr->Data, sizeof(void*) * (size_t)arr->Count)) continue;
            int filled = 0, mine = 0, checked = 0;
            for (int i = 0; i < arr->Count && checked < 4000; ++i, ++checked) {
                UObject* v = SlotAt(arr, i);
                if (!v) continue;
                ++filled;
                if (IsLiveObject(v) && Outermost(v) == pkg) ++mine;
            }
            if (filled == 0 || mine * 10 < filled * 9) continue;   // >=90% must belong here
            found = true;
            // The slot the kit pawn's archetype is sent as.
            const char* at935 = "out-of-range";
            char pbuf[256];
            if (arr->Count > 935) {
                UObject* v = SlotAt(arr, 935);
                if (!v) at935 = "EMPTY";
                else if (IsLiveObject(v)) { snprintf(pbuf, sizeof(pbuf), "%s(%s)", NameOf(v->Name), ClassNameOf(v)); at935 = pbuf; }
                else at935 = "DANGLING";
            }
            snprintf(b, sizeof(b), "%s%s netobjs@0x%zx count=%d filled=%d [935]=%s",
                     out.empty() ? "" : " || ", NameOf(pkg->Name), off, arr->Count, filled, at935);
            out += b;
        }
        if (!found) {
            snprintf(b, sizeof(b), "%s%s NETOBJS NOT FOUND", out.empty() ? "" : " || ", NameOf(pkg->Name));
            out += b;
        }
    }
    return out;
}

static Snapshot Sample(TArray<UObject*>* objs) {
    Snapshot s;
    std::vector<UObject*> netPkgs;
    std::vector<UObject*> pkgmaps;
    std::vector<ChanRef> chans;
    for (int i = 0; i < objs->Count; ++i) {
        // Checked every 4096 objects, not every one: lemp::Exiting() is an
        // IsBadReadPtr (one VirtualQuery) each call, and GObjects can hold
        // well over 100,000 entries. 4096 bounds the worst case to a few
        // thousand more objects read after the engine starts exiting, not
        // the rest of a multi-hundred-thousand-object scan.
        if ((i & 0xFFF) == 0 && lemp::Exiting()) return s;
        UObject* o = SlotAt(objs, i);
        if (!o || IsBadReadPtr(o, 0x40)) continue;
        const char* cn = ClassNameOf(o);
        const char* on = NameOf(o->Name);
        // Is our DLC's class tree loaded at all? A Class object named
        // SFXGameInfoMP only exists if the package mounted.
        if (strcmp(cn, "Class") == 0 && strcmp(on, "SFXGameInfoMP") == 0) {
            s.mpClassLoaded = true;
        }
        if (strcmp(cn, "Package") == 0 && strcmp(on, "MPMainMenu") == 0 && s.mmPkg < 1) s.mmPkg = 1;
        if (strcmp(cn, "Class") == 0 && strcmp(on, "SFXGUI_MPMainMenuEntry") == 0) s.mmPkg = 2;
        if (strcmp(cn, "SFXGUI_MPMainMenuEntry") == 0 && strncmp(on, "Default__", 9) != 0) s.mmOpen = true;
        // Before the CDO filter: archetypes are not CDOs, but this is the
        // cheapest place to catch the object by name.
        //
        // A MEASUREMENT THAT COULD NOT SHOW A PRESENCE, and it read NO for an
        // entire session while the kit worked. [V] This tested
        // "MP_ADP_ASAb" — the RESURGENCE Asari Commando's art package. When
        // the shipped kit changed to the base-game Asari Adept the name lost
        // its trailing 'b' (BIOG_MP_ADP_ASA, see KITMESH in build-map.sh) and
        // the test could no longer match anything, on the host OR the client.
        // `kitpkg=NO` was then read as evidence about the client. It was
        // evidence about this line.
        //
        // Dropping the 'b' matches BOTH kits, because the Resurgence name has
        // this one as a prefix — so the field can show a presence whichever
        // kit is installed, which is the property it was missing.
        if (strstr(on, "MP_ADP_ASA")) {
            s.kitPkg = true;
        }
        if (strstr(on, "Shepard_") && strstr(cn, "SFXPawn_Player")) {
            s.archObjPresent = true;
            if (s.archObjPkg.empty()) {
                UObject* top = o;
                while (top->Outer && !IsBadReadPtr(top->Outer, sizeof(UObject)))
                    top = top->Outer;
                s.archObjPkg = std::string(on) + "[" + NameOf(top->Name) + "]";
            }
        }

        if (strncmp(on, "Default__", 9) == 0) continue;   // CDOs don't count
        if (strstr(cn, "Channel") && strcmp(cn, "Class") != 0) chans.push_back({o, cn});
        if (strstr(cn, "PackageMap") && strcmp(cn, "Class") != 0) pkgmaps.push_back(o);
        if (strcmp(cn, "Package") == 0 && !o->Outer
            && (strcmp(on, "BioChar_MPPlayers") == 0 || strcmp(on, "BioChar_Player") == 0)) netPkgs.push_back(o);

        if (strstr(cn, "NetDriver")) ++s.drivers;
        // LE3's connection class is UTcpipConnection — it does NOT contain
        // the substring "NetConnection". Matching on that missed every live
        // connection and reported conns=0 no matter what. Match "Connection",
        // which covers TcpipConnection, SFXOnlineNetConnection, ChildConnection
        // and DemoRecConnection, and print the class names so the log says
        // which kind actually appeared.
        else if (strstr(cn, "Connection")) {
            ++s.conns;
            // UNetConnection::State lives at 0x94, recovered by disassembling
            // UNetPendingLevel::Tick in the unpacked exe — it does
            // `cmpl $1,0x94(%rdx)` on NetDriver->ServerConnection. LExSDK gives
            // none of this class's native layout, so this is the only way to
            // see it. UE3's EConnectionState: 0 Invalid, 1 Closed, 2 Pending,
            // 3 Open.
            //
            // This matters because Tick branches on exactly that value: if the
            // connection reads Closed it takes an error path and never reaches
            // TickDispatch. "Tick is never called" and "Tick is called and
            // short-circuits here" both produce the unread socket we measured,
            // and only this tells them apart. The host's connections are the
            // positive control — they are live, so they must not read Closed.
            // 0x94 was guessed to be State from UNetPendingLevel::Tick's
            // `cmpl $1,0x94(%rdx)`. That reading is RETRACTED: the host's
            // connection is demonstrably live — it received NMT_Login — and it
            // read the same value as the client's, so the field discriminates
            // nothing and at least one link in the chain
            // (pending+0xd8 -> driver+0x80 -> conn+0x94) is wrong.
            //
            // Instead of guessing another offset, dump a window of the object
            // once per process. The host's connection and the client's are in
            // genuinely different states, so whichever words differ between the
            // two dumps are the candidates — found by comparison rather than
            // by assumption.
            DumpConnFields(o, cn);
            if (s.connNames.size() < 160) {
                char buf[96];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s", cn);
                s.connNames += std::string(s.connNames.empty() ? "" : ",") + buf;
            }
        }
        else if (strstr(cn, "PlayerController")) {
            ++s.controllers;
            UObject* pawn = nullptr;
            if (!IsBadReadPtr((uint8_t*)o + OFF_CONTROLLER_PAWN, 8))
                pawn = *(UObject**)((uint8_t*)o + OFF_CONTROLLER_PAWN);
            if (!pawn && s.unpossessedScript.size() < 8) {
                static char umsg[4096];
                if (ReadScriptString(o, "MPDebug", umsg, sizeof(umsg)) && umsg[0])
                    s.unpossessedScript.emplace_back(NameOf(o->Name), umsg);
            }
            if (pawn) {
                ++s.possessed;
                if (s.pawnDesc.size() < 200 && !IsBadReadPtr(pawn, 0x300)) {
                    const char* pc = ClassNameOf(pawn);
                    float x = 0, y = 0, z = 0; int phys = -1; void* coll = nullptr;
                    if (!IsBadReadPtr((uint8_t*)pawn + OFF_ACTOR_LOCATION, 12)) {
                        float* L = (float*)((uint8_t*)pawn + OFF_ACTOR_LOCATION);
                        x = L[0]; y = L[1]; z = L[2];
                    }
                    if (!IsBadReadPtr((uint8_t*)pawn + OFF_ACTOR_PHYSICS, 1))
                        phys = *(unsigned char*)((uint8_t*)pawn + OFF_ACTOR_PHYSICS);
                    if (!IsBadReadPtr((uint8_t*)pawn + OFF_ACTOR_COLLCOMP, 8))
                        coll = *(void**)((uint8_t*)pawn + OFF_ACTOR_COLLCOMP);
                    // The script's own message, if it left one.
                    if (s.scriptLog.empty()) {
                        // 4096, ReadScriptString's own limit: at 512 the match
                        // line was cut off (pwr=, and the per-PRI slots=).
                        static char msg[4096];
                        if (ReadScriptString(o, "MPDebug", msg, sizeof(msg)))
                            s.scriptLog = msg;
                    }
                    // Where the camera is actually looking from. A view
                    // target that is the controller rather than the pawn puts
                    // the camera at the controller's own position and leaves it
                    // rotating in place, which is the reported symptom.
                    const char* vtn = "NONE";
                    UObject* vt = nullptr;
                    if (!IsBadReadPtr((uint8_t*)o + OFF_PC_VIEWTARGET, 8))
                        vt = *(UObject**)((uint8_t*)o + OFF_PC_VIEWTARGET);
                    if (vt && !IsBadReadPtr(vt, 0x40)) vtn = ClassNameOf(vt);
                    void* cam = nullptr;
                    const char* camcls = "NONE";
                    float cx = 0, cy = 0, cz = 0;
                    const char* camvt = "-";
                    bool camvtIsPawn = false;
                    if (!IsBadReadPtr((uint8_t*)o + OFF_PC_CAMERA, 8))
                        cam = *(void**)((uint8_t*)o + OFF_PC_CAMERA);
                    if (cam && !IsBadReadPtr(cam, 0x420)) {
                        camcls = ClassNameOf((UObject*)cam);
                        // FTViewTarget starts with FTPOV, which starts with
                        // Location — so this is the position the view is
                        // actually computed from, as opposed to the target it
                        // is supposed to be following.
                        float* P = (float*)((uint8_t*)cam + 0x3D8);
                        cx = P[0]; cy = P[1]; cz = P[2];
                    }
                    if (cam && !IsBadReadPtr((uint8_t*)cam + OFF_CAM_VIEWTARGET, 8)) {
                        UObject* cvt = *(UObject**)((uint8_t*)cam + OFF_CAM_VIEWTARGET);
                        if (cvt && !IsBadReadPtr(cvt, 0x40)) {
                            camvt = ClassNameOf(cvt);
                            camvtIsPawn = (cvt == pawn);
                        } else camvt = "NONE";
                    }
                    // Mesh component, and whether it actually has a mesh.
                    const char* meshState = "no-component";
                    if (!IsBadReadPtr((uint8_t*)pawn + OFF_PAWN_MESH, 8)) {
                        UObject* smc = *(UObject**)((uint8_t*)pawn + OFF_PAWN_MESH);
                        if (smc && !IsBadReadPtr((uint8_t*)smc + OFF_SMC_SKELMESH, 8)) {
                            UObject* sm = *(UObject**)((uint8_t*)smc + OFF_SMC_SKELMESH);
                            meshState = sm ? "MESH" : "component-but-NO-MESH";
                        }
                    }

                    // Which template the pawn was actually built from.
                    const char* archn = "NONE"; const char* archpkg = "-";
                    if (!IsBadReadPtr((uint8_t*)pawn + OFF_OBJ_ARCHETYPE, 8)) {
                        UObject* ar = *(UObject**)((uint8_t*)pawn + OFF_OBJ_ARCHETYPE);
                        if (ar && !IsBadReadPtr(ar, 0x60)) {
                            archn = NameOf(ar->Name);
                            UObject* top = ar;
                            while (top->Outer && !IsBadReadPtr(top->Outer, sizeof(UObject)))
                                top = top->Outer;
                            archpkg = NameOf(top->Name);
                        }
                    }

                    // Which UnrealScript state this controller is in.
                    const char* stateName = "-";
                    if (!IsBadReadPtr((uint8_t*)o + OFF_OBJ_STATEFRAME, 8)) {
                        uint8_t* sf = *(uint8_t**)((uint8_t*)o + OFF_OBJ_STATEFRAME);
                        if (sf && !IsBadReadPtr(sf, 0x40)) {
                            for (size_t off = 0; off < 0x40; off += 8) {
                                UObject* cand = *(UObject**)(sf + off);
                                if (!cand || IsBadReadPtr(cand, 0x60)) continue;
                                const char* ccn = ClassNameOf(cand);
                                if (ccn && strcmp(ccn, "State") == 0) {
                                    stateName = NameOf(cand->Name);
                                    break;
                                }
                            }
                        }
                    }

                    // Which game mode this controller is in.
                    // How many key bindings this controller's input holds.
                    int nbind = -1;
                    const char* inputCls = "NONE";
                    if (!IsBadReadPtr((uint8_t*)o + OFF_PC_PLAYERINPUT, 8)) {
                        UObject* pi = *(UObject**)((uint8_t*)o + OFF_PC_PLAYERINPUT);
                        if (pi && !IsBadReadPtr(pi, 0x40)) {
                            inputCls = ClassNameOf(pi);
                            if (!IsBadReadPtr((uint8_t*)pi + OFF_INPUT_BINDINGS, 16)) {
                                auto* ba = (TArray<uint8_t>*)((uint8_t*)pi + OFF_INPUT_BINDINGS);
                                if (ba->Count >= 0 && ba->Count < 100000) nbind = ba->Count;
                            }
                        }
                    }
                    int gmode = -1;
                    const char* lock = "?";
                    char modeBits[96]; modeBits[0] = 0;
                    if (!IsBadReadPtr((uint8_t*)o + OFF_PC_GAMEMODEMGR, 8)) {
                        void* gmm = *(void**)((uint8_t*)o + OFF_PC_GAMEMODEMGR);
                        if (gmm && !IsBadReadPtr((uint8_t*)gmm + OFF_GMM_CURRENTMODE, 1))
                            gmode = *(unsigned char*)((uint8_t*)gmm + OFF_GMM_CURRENTMODE);
                        if (gmm && !IsBadReadPtr((uint8_t*)gmm + OFF_GMM_FLAGS, 4))
                            lock = (*(uint32_t*)((uint8_t*)gmm + OFF_GMM_FLAGS)
                                    & BIT_GMM_DISABLEINPUT) ? "INPUT-LOCKED" : "input-ok";
                        // GameModes[0] is GameMode_Default: is it active, and
                        // were its key bindings ever collected? Firing, zoom,
                        // the power wheel and Escape are BOUND ACTIONS; walking
                        // and looking are not, and only the actions are dead.
                        if (gmm && !IsBadReadPtr((uint8_t*)gmm + OFF_GMM_GAMEMODES, 16)) {
                            auto* arr = (TArray<UObject*>*)((uint8_t*)gmm + OFF_GMM_GAMEMODES);
                            if (arr->Count > 0 && arr->Count < 64 && !IsBadReadPtr(arr->Data, 8)) {
                                UObject* m0 = arr->Data[0];
                                if (m0 && !IsBadReadPtr((uint8_t*)m0 + OFF_MODE_FLAGS, 4)) {
                                    uint32_t mf = *(uint32_t*)((uint8_t*)m0 + OFF_MODE_FLAGS);
                                    _snprintf_s(modeBits, sizeof(modeBits), _TRUNCATE,
                                                "modes=%d default[%s,%s]", arr->Count,
                                                (mf & BIT_MODE_ACTIVE) ? "active" : "INACTIVE",
                                                (mf & BIT_MODE_BINDINGS) ? "bound" : "NO-BINDINGS");
                                }
                            }
                        }
                    }
                    char buf[320];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                                "%s%s@(%.0f,%.0f,%.0f) phys=%d coll=%s vt=%s%s "
                                "cam=%s@(%.0f,%.0f,%.0f) camvt=%s%s mode=%d/%s %s %s input=%s/%d "
                                "arch=%s[%s] mesh=%s state=%s",
                                s.pawnDesc.empty() ? "" : " | ", pc, x, y, z, phys,
                                coll ? "yes" : "NONE", vtn,
                                (vt == pawn) ? "(=pawn)" : "",
                                camcls, cx, cy, cz, camvt,
                                camvtIsPawn ? "(=pawn)" : "",
                                gmode, gmode < 0 ? "unread" : GameModeName(gmode),
                                lock, modeBits, inputCls, nbind,
                                archn, archpkg, meshState, stateName);
                    s.pawnDesc += buf;
                    // WHAT THE CAMERA TRACE HIT.
                    //
                    // The direct measurement, after nine hypotheses died by
                    // comparison. m_aTraceInfo is the camera's own record of
                    // its collision traces; every theory so far has been about
                    // what MIGHT stop a trace, and this is the array that says
                    // what DID.
                    //
                    // The element layout is unknown, so this does not pretend
                    // to parse it. It reads the TArray header — count and max,
                    // which alone distinguish "traces are being recorded" from
                    // "this array is empty and the camera is not tracing at
                    // all" — and then scans the first element for values that
                    // look like live UObjects, printing their class and name.
                    //
                    // Scanning for object pointers rather than assuming an
                    // offset is deliberate: an FTraceInfo in UE3 carries the
                    // actor it hit, and a wrong hard-coded offset here would
                    // produce a confident wrong answer, which is exactly what
                    // this session has produced too much of.
                    {
                        size_t tOff = cam ? PropertyOffset((UObject*)cam, "m_aTraceInfo") : 0;
                        if (tOff && !IsBadReadPtr((uint8_t*)cam + tOff, 40)) {
                            // TEN FLOATS, not a TArray.
                            //
                            // Read as a TArray first and the "count" came back
                            // as 1127556710 and the "max" as 1065353216 —
                            // which is 0x3F800000, the bit pattern of 1.0f.
                            // The property dump settles it: CameraModes@508,
                            // m_aTraceInfo@518, AdditiveRotation@540, so this
                            // field is 0x28 = 40 bytes = ten floats, a fixed
                            // struct rather than a 16-byte dynamic array.
                            //
                            // The values fit that reading: 1127556710 is
                            // ~180.0, 1063579794 ~0.90, 1056497811 ~0.49 —
                            // distances and 0..1 alphas, which is what camera
                            // trace bookkeeping looks like. No actor pointers
                            // to find, so the earlier scan was looking for the
                            // wrong kind of thing entirely.
                            // Decoded: Location(12) Normal(12) Actor*(8) ...
                            //
                            //   [0..2]  4856.75,-258.39,137.00   hit location
                            //   [3..5]  -0.10,0.99,0.00          unit normal
                            //   [6..7]  2.36e36, 0.00            NOT floats —
                            //                                    a 64-bit pointer
                            //
                            // 2.36e36 is a pointer bit pattern read as a
                            // float, which is how the layout gave itself away.
                            // The actor the trace hit lives at byte 24.
                            float* F = (float*)((uint8_t*)cam + tOff);
                            UObject* hitActor = *(UObject**)((uint8_t*)cam + tOff + 24);
                            const char* hn = "NONE";
                            const char* hc = "";
                            if (hitActor && !IsBadReadPtr(hitActor, sizeof(UObject))) {
                                hc = ClassNameOf(hitActor);
                                hn = NameOf(hitActor->Name);
                            }
                            char tb[220];
                            snprintf(tb, sizeof(tb),
                                     " trace=hit(%.0f,%.0f,%.0f) n(%.2f,%.2f,%.2f) by=%s(%s)",
                                     F[0], F[1], F[2], F[3], F[4], F[5], hc, hn);
                            s.pawnDesc += tb;
                        }
                    }

                    // The mesh component's BOUNDS.
                    //
                    // The camera distance is dead constant for the kit pawn —
                    // 36, min 36, max 37 across a whole session — while a
                    // Shepard's varies from 124 to 6984. A collision trace
                    // varies with where you stand; a constant does not. So
                    // this was never a trace being blocked, which is what the
                    // last four controls were all quietly assuming.
                    //
                    // What fits instead: the distance is DERIVED from the
                    // mesh. Remove the mesh and it went to 6610; give it the
                    // kit mesh and it is 36 forever. Bounds are the obvious
                    // quantity a camera would scale by, and a cloned mesh is
                    // exactly the thing whose bounds might not have been
                    // recomputed.
                    //
                    // FBoxSphereBounds is Origin(12) BoxExtent(12)
                    // SphereRadius(4); the radius is the last float.
                    {
                        UObject* mc2 = nullptr;
                        if (!IsBadReadPtr((uint8_t*)pawn + OFF_PAWN_MESH, 8))
                            mc2 = *(UObject**)((uint8_t*)pawn + OFF_PAWN_MESH);
                        size_t bo = mc2 ? PropertyOffset(mc2, "Bounds") : 0;
                        if (bo && !IsBadReadPtr((uint8_t*)mc2 + bo, 28)) {
                            float* B = (float*)((uint8_t*)mc2 + bo);
                            char bb[128];
                            // ORIGIN as well as extent. The extent says how
                            // BIG the bounds are; the origin says WHERE they
                            // are, and a camera that is displaced rather than
                            // merely scaled needs the second one.
                            snprintf(bb, sizeof(bb),
                                     " bounds=o(%.0f,%.0f,%.0f)ext(%.0f,%.0f,%.0f)r%.0f",
                                     B[0], B[1], B[2], B[3], B[4], B[5], B[6]);
                            s.pawnDesc += bb;
                        }
                        float ds = 0;
                        if (mc2 && ReadScriptFloat(mc2, "Scale", &ds)) {
                            char sb[48]; snprintf(sb, sizeof(sb), " mscale=%.2f", ds);
                            s.pawnDesc += sb;
                        }
                    }

                    // Does the pawn's BODY MESH block traces?
                    //
                    // Both pawns get SFXCameraMode_Combat, so mode selection
                    // is not the difference and the mode is reading something
                    // off the pawn. The standing asymmetry: a Shepard's
                    // BioPawnSkeletalMeshComponent has NO SkeletalMesh at
                    // spawn — the body is merged in later — while ours
                    // carries the kit body from the archetype. A trace cannot
                    // hit a mesh that is not there.
                    //
                    // So read the component's collision flags rather than
                    // assume them. They are bitfield bools, which is why each
                    // is masked out of the same byte.
                    {
                        UObject* mc = nullptr;
                        if (!IsBadReadPtr((uint8_t*)pawn + OFF_PAWN_MESH, 8))
                            mc = *(UObject**)((uint8_t*)pawn + OFF_PAWN_MESH);
                        if (mc && !IsBadReadPtr(mc, 0x200)) {
                            const char* names[] = { "CollideActors", "BlockActors",
                                                    "BlockZeroExtent", "BlockNonZeroExtent",
                                                    "BlockRigidBody" };
                            std::string f;
                            for (const char* nm : names) {
                                size_t o = PropertyOffset(mc, nm);
                                if (!o || IsBadReadPtr((uint8_t*)mc + o, 4)) continue;
                                uint32_t word = *(uint32_t*)((uint8_t*)mc + o);
                                char b[64];
                                snprintf(b, sizeof(b), " %s=%x", nm, word);
                                f += b;
                            }
                            if (!f.empty()) { s.pawnDesc += " meshcoll:"; s.pawnDesc += f; }
                        }
                    }

                    // WHICH camera mode is live, by name.
                    //
                    // I claimed twice that CurrentCameraMode was native and
                    // unreachable from script. It is not: the property dump
                    // finds it at +0x558, declared on SFXCameraNativeBase — a
                    // parent class whose source is not in the decompiled set,
                    // so grepping LE3_SFXPlayerCamera.uc missed it and I read
                    // "not in this file" as "not reachable".
                    //
                    // This is the measurement the camera work has needed all
                    // along. SFXCameraSetup.GetCameraMode picks between an
                    // explore camera, a cover camera, a storm camera and a
                    // standing combat camera; every theory so far has been a
                    // guess about WHICH. The mode's class name says it
                    // outright, and comparing the kit pawn's against a
                    // Shepard's turns the whole question into one line.
                    {
                        size_t mOff = cam ? PropertyOffset((UObject*)cam, "CurrentCameraMode") : 0;
                        if (mOff && !IsBadReadPtr((uint8_t*)cam + mOff, 8)) {
                            UObject* mode = *(UObject**)((uint8_t*)cam + mOff);
                            char mb[192];
                            // The CLASS name was not enough, and reading only
                            // the class is what stalled the camera work.
                            //
                            // Both pawns print cammode=SFXCameraMode_Combat, and
                            // that was taken to mean "both get the same camera
                            // mode, from the same shared setup object". It means
                            // no such thing: a class name is the same for the
                            // CONFIGURED CONTENT INSTANCE and for the class
                            // default object, which carry different property
                            // values. LE3 authors Offset and HookOffset on the
                            // instance; a pawn that resolved to the CDO instead
                            // would report the identical class name and be
                            // placed from SFXCameraMode's base HookOffset.
                            //
                            // So print the OBJECT NAME and the POINTER too. The
                            // pointer is the part that settles it without any
                            // interpretation: if the kit pawn's mode and a
                            // Shepard's are the same address, the mode is shared
                            // and every "wrong mode object" theory dies in one
                            // line. If they differ, that IS the finding.
                            //
                            // Fifth instance of the house rule on this project:
                            // a measurement that cannot distinguish the two
                            // cases was read as evidence for one of them.
                            snprintf(mb, sizeof(mb), " cammode=%s/%s@%p",
                                     (mode && !IsBadReadPtr(mode, 0x40)) ? ClassNameOf(mode) : "NONE",
                                     (mode && !IsBadReadPtr(mode, 0x40)) ? NameOf(mode->Name) : "-",
                                     (void*)mode);
                            s.pawnDesc += mb;

                            // The two vectors that place the camera, read off
                            // the live mode rather than off the package.
                            //
                            // SFXCameraMode_Combat's authored values are
                            // Offset = (80,-44,15) and HookOffset = (-30,0,80);
                            // the base class SFXCameraMode has HookOffset =
                            // (0,0,98) and no Offset. The kit pawn's camera sits
                            // 36 out and exactly 90 up, and |(36,90)| = 96.9
                            // against |(0,0,98)| = 98 — which is the base
                            // class's value, not Combat's. That is a hypothesis
                            // about which object is live, and these two reads
                            // turn it into a fact.
                            if (mode && !IsBadReadPtr(mode, 0x40)) {
                                // m_pov.Location — the PRE-COLLISION camera
                                // position, and the field the camera work
                                // should have been reading all along.
                                //
                                // `desired=` above reads
                                // SFXPlayerCamera.CameraDesiredPosition, and
                                // that is a dead end for a reason worth
                                // recording: SFXCameraMode_Combat sets
                                // bCameraRubberBand = TRUE, and on that branch
                                // UpdateCameraMode assigns only
                                // CameraDesiredPosition.Rotation, plus a
                                // smoothed Location for REMOTE pawns only. For
                                // a locally controlled pawn the Location is
                                // never written and stays (0,0,0) forever — on
                                // Shepard too, which is exactly what the logs
                                // show. It was read as a broken counter; it is
                                // a field that is correctly never set.
                                //
                                // DoCameraCollision mutates OutVT.POV as an
                                // out-param and never touches m_pov, so
                                // m_pov.Location against the final POV is a
                                // clean before/after pair across collision. If
                                // they are equal, collision is doing nothing
                                // and the placement is being COMPUTED short —
                                // which is the question four separate
                                // eliminations were circling.
                                //
                                // m_pov is a TPOV: Location first, so the
                                // struct's own offset is the Location's.
                                size_t povOff = PropertyOffset(mode, "m_pov");
                                if (povOff && !IsBadReadPtr((uint8_t*)mode + povOff, 12)) {
                                    float* P = (float*)((uint8_t*)mode + povOff);
                                    char pb2[96];
                                    snprintf(pb2, sizeof(pb2), " precoll=(%.0f,%.0f,%.0f)",
                                             P[0], P[1], P[2]);
                                    s.pawnDesc += pb2;
                                }

                                static const char* kCamVecs[] = { "Offset", "HookOffset" };
                                for (const char* vn : kCamVecs) {
                                    size_t vOff = PropertyOffset(mode, vn);
                                    if (!vOff || IsBadReadPtr((uint8_t*)mode + vOff, 12)) continue;
                                    float* V = (float*)((uint8_t*)mode + vOff);
                                    char vb[96];
                                    snprintf(vb, sizeof(vb), " %s=(%.1f,%.1f,%.1f)",
                                             vn, V[0], V[1], V[2]);
                                    s.pawnDesc += vb;
                                }
                            }

                            // THE HOOK. SFXCameraMode hooks its camera to a
                            // bone named 'Camera' (HookName), via native
                            // GetActorCameraHook — and when that fails:
                            //
                            //     if (!GetActorCameraHook(ActorCameraHook))
                            //         ActorCameraHook = vect(0,0,0);
                            //     DoCameraCollisionNative(ActorCameraHook, ...)
                            //
                            // so a missing bone puts the collision hook at the
                            // WORLD ORIGIN. LastHookPos is a script var on the
                            // mode and records where the hook actually landed.
                            // Reading it separates "the mesh has no Camera
                            // bone" from every remaining alternative.
                            if (mode && !IsBadReadPtr(mode, 0x40)) {
                                size_t hOff = PropertyOffset(mode, "LastHookPos");
                                if (hOff && !IsBadReadPtr((uint8_t*)mode + hOff, 12)) {
                                    float* H = (float*)((uint8_t*)mode + hOff);
                                    char hb[96];
                                    snprintf(hb, sizeof(hb), " hook=(%.0f,%.0f,%.0f)", H[0], H[1], H[2]);
                                    s.pawnDesc += hb;
                                }
                            }
                        }
                    }

                    // One-shot: what does the camera actually expose?
                    static bool dumpedCam = false;
                    if (cam && !dumpedCam) { dumpedCam = true; DumpClassProperties((UObject*)cam, "PlayerCamera"); }

                    // The camera's DESIRED position and the pawn's collision,
                    // read directly rather than through a console command.
                    //
                    // Both were only obtainable by typing `mpcaminfo`, which
                    // meant every camera question cost a round trip. The
                    // property resolver removes that: these are script vars
                    // (SFXPlayerCamera.CameraDesiredPosition,
                    // CylinderComponent.CollisionRadius/Height) and the ASI
                    // can now find them by name.
                    //
                    // The question they answer: a camera that lands SHORT of
                    // where it wants to be has had its trace stopped, and the
                    // pawn's own collision is the first thing that could stop
                    // it.
                    if (pawn && !IsBadReadPtr(pawn, 0x400)) {
                        char cbuf[128];
                        size_t dOff = cam ? PropertyOffset((UObject*)cam, "CameraDesiredPosition") : 0;
                        if (dOff && !IsBadReadPtr((uint8_t*)cam + dOff, 12)) {
                            float* D = (float*)((uint8_t*)cam + dOff);
                            snprintf(cbuf, sizeof(cbuf), " desired=(%.0f,%.0f,%.0f)", D[0], D[1], D[2]);
                            s.pawnDesc += cbuf;
                        }
                        // CameraHookScale — the per-pawn camera quantity
                        // earlier investigation went looking for and never
                        // named.
                        //
                        // 2012 has no
                        // per-kit camera, so a Geth Prime must get a suitable
                        // camera by scaling off something on the pawn, and
                        // finding what that quantity is would very
                        // likely answer this. Every candidate tried —
                        // cylinder, bounds, DrawScale, mesh Scale — measured
                        // equal. The property whose name says
                        // exactly that was never tried, because nothing had
                        // dumped BioPawn's own defaults.
                        //
                        // It is declared on Default__BioPawn with value 1, and
                        // it is unoverridden in all three archetypes — ours,
                        // 2012's Asari kit, and LE3's Shepard — which are
                        // byte-identical on this property in ME3 2012 and LE3.
                        // So the STATIC value is 1 for everyone and cannot be
                        // the cause. That is exactly why it has to be read at
                        // RUNTIME: a default of 1 in the package says nothing
                        // about what the pawn carries after spawn, and this
                        // project has already been caught five times reading a
                        // static zero as a runtime one.
                        // Read BOTH scales and PlayerClass together, because
                        // the pair is the test and either alone is not.
                        //
                        //   BioPawn.CameraHookScale   var float           = 1.0
                        //   BioPawn.CameraArmScale    var transient float  NO DEFAULT -> 0.0
                        //
                        // Only SFXPawn_Player.LoadCharacterClassData writes
                        // them, and only behind `if (PlayerClass != None)`,
                        // where they are copied off the character class
                        // (SFXCharacterClass_NativeBase defaults BOTH to 1.0).
                        // "Arm" is the camera boom — the mode's Offset — and
                        // "Hook" is its HookOffset. So a pawn with no
                        // PlayerClass keeps a hook at full scale and an arm at
                        // ZERO, and its camera collapses onto the hook.
                        //
                        // Identical in ME3 2012 and LE3, line for line [V], so
                        // this is not a remaster change: 2012's kit archetype
                        // carries PlayerClass and ours does not, because
                        // --mkarchetype cuts it.
                        //
                        // CameraHookScale is the CONTROL. It must read 1.00 on
                        // both pawns. If it does, the probe can see these
                        // floats at all, and a 0.00 arm on the kit is a real
                        // zero rather than an unresolved property — which is
                        // the single most repeated error on this project.
                        {
                            float chs = -1.0f, cas = -1.0f;
                            bool okH = ReadScriptFloat(pawn, "CameraHookScale", &chs);
                            bool okA = ReadScriptFloat(pawn, "CameraArmScale", &cas);
                            // Written out longhand rather than cleverly: an
                            // unresolved property and a genuine 0.0 must not
                            // print the same thing.
                            std::string cs = " camhookscale=";
                            if (okH) { char t[32]; snprintf(t, sizeof(t), "%.2f", chs); cs += t; }
                            else cs += "UNRESOLVED";
                            cs += " camarmscale=";
                            if (okA) { char t[32]; snprintf(t, sizeof(t), "%.2f", cas); cs += t; }
                            else cs += "UNRESOLVED";
                            s.pawnDesc += cs;

                            // And the cause, one dereference away: does this
                            // pawn have a character class at all?
                            // WHERE the PlayerClass value is lost.
                            //
                            // Six runs have read playerclass=NONE on the kit
                            // pawn while Shepard reads its class fine, through
                            // three different ways of attaching it. Reading the
                            // pawn alone cannot tell "the value never loaded"
                            // from "the value loaded and did not copy", so read
                            // the whole chain and let the three answers
                            // separate:
                            //
                            //   cdo=  the class default object's PlayerClass.
                            //         NONE here means the map's own class
                            //         defaults did not deserialise it, and
                            //         nothing downstream can help.
                            //   arch= the pawn's ObjectArchetype's PlayerClass.
                            //         Set on the CDO but NONE here means the
                            //         archetype overrode it with None, which is
                            //         a package-authoring bug in the kit.
                            //   playerclass= the pawn's own.
                            //         Set on both above but NONE here means
                            //         something at runtime cleared it.
                            {
                                UObject* pArch = nullptr;
                                if (!IsBadReadPtr((uint8_t*)pawn + OFF_OBJ_ARCHETYPE, 8))
                                    pArch = *(UObject**)((uint8_t*)pawn + OFF_OBJ_ARCHETYPE);
                                // A UClass's default object sits at a fixed
                                // offset LExSDK gives; rather than trust one
                                // number, find it by name instead — it is a
                                // real UObject in GObjects called
                                // Default__SFXPawn_PlayerMP.
                                UObject* cdo = FindObjectByName("Default__SFXPawn_PlayerMP");
                                auto readPC = [&](UObject* h) -> const char* {
                                    if (!h || IsBadReadPtr(h, 0x40)) return "-";
                                    size_t o2 = PropertyOffset(h, "PlayerClass");
                                    if (!o2 || IsBadReadPtr((uint8_t*)h + o2, 8)) return "UNRESOLVED";
                                    UObject* v = *(UObject**)((uint8_t*)h + o2);
                                    return (v && !IsBadReadPtr(v, 0x40)) ? ClassNameOf(v) : "NONE";
                                };
                                char cb[192];
                                snprintf(cb, sizeof(cb), " pcCDO=%s pcARCH=%s",
                                         readPC(cdo), readPC(pArch));
                                s.pawnDesc += cb;
                            }

                            // The pawn's own Squad — the far end of the gate.
                            // PlayerSquad non-NONE but this NONE would mean
                            // AddMember never ran, i.e. Possess happened before
                            // the squad existed. That is a real possibility
                            // here, because our squad is spawned in
                            // PostBeginPlay and the login/possess path may well
                            // beat it.
                            {
                                size_t sqOff = PropertyOffset(pawn, "Squad");
                                char sb[96];
                                if (!sqOff || IsBadReadPtr((uint8_t*)pawn + sqOff, 8)) {
                                    snprintf(sb, sizeof(sb), " squad=UNRESOLVED");
                                } else {
                                    UObject* sq = *(UObject**)((uint8_t*)pawn + sqOff);
                                    snprintf(sb, sizeof(sb), " squad=%s",
                                             (sq && !IsBadReadPtr(sq, 0x40)) ? ClassNameOf(sq) : "NONE");
                                }
                                s.pawnDesc += sb;
                            }

                            size_t pcOff = PropertyOffset(pawn, "PlayerClass");
                            if (pcOff && !IsBadReadPtr((uint8_t*)pawn + pcOff, 8)) {
                                UObject* pcls = *(UObject**)((uint8_t*)pawn + pcOff);
                                char pb[96];
                                snprintf(pb, sizeof(pb), " playerclass=%s",
                                         (pcls && !IsBadReadPtr(pcls, 0x40)) ? ClassNameOf(pcls) : "NONE");
                                s.pawnDesc += pb;
                            } else {
                                s.pawnDesc += " playerclass=UNRESOLVED";
                            }
                        }
                        UObject* cyl = nullptr;
                        if (!IsBadReadPtr((uint8_t*)pawn + OFF_ACTOR_COLLCOMP, 8))
                            cyl = *(UObject**)((uint8_t*)pawn + OFF_ACTOR_COLLCOMP);
                        float cr = 0, ch = 0;
                        if (cyl && ReadScriptFloat(cyl, "CollisionRadius", &cr)
                                && ReadScriptFloat(cyl, "CollisionHeight", &ch)) {
                            snprintf(cbuf, sizeof(cbuf), " cyl=%.0fx%.0f", cr, ch);
                            s.pawnDesc += cbuf;
                        }
                    }
                }
            }
        }
        // SFXPRIMP does NOT contain the substring "PlayerReplicationInfo", so
        // matching only on that reads 0 however many of ours exist — the same
        // wrong-class-name trap that once reported conns=0. Match both.
        else if (strstr(cn, "PlayerReplicationInfo") || strstr(cn, "PRI")) ++s.pris;
        else if (strstr(cn, "Pawn")) {
            ++s.pawns;
            if (strcmp(cn, "SFXPawn_PlayerMP") == 0) ++s.mppawns;
            // EVERY player pawn, not just the one this controller possesses.
            //
            // The client can drive its own Shepard and cannot see the host's,
            // while collision with it works both ways — so the host's pawn is
            // replicated and present, and only its appearance is missing. The
            // existing pawnDesc only ever describes a PlayerController's OWN
            // pawn, so it cannot distinguish the two explanations that need
            // different fixes: MPBuildAppearances never reached that pawn
            // (expect NO-MESH here), or it rebuilt it and something else keeps
            // it invisible (expect MESH).
            if (strncmp(cn, "SFXPawn_Player", 14) == 0) {
                ++s.playerPawns;
                const char* pm = "no-component";
                if (!IsBadReadPtr((uint8_t*)o + OFF_PAWN_MESH, 8)) {
                    UObject* smc = *(UObject**)((uint8_t*)o + OFF_PAWN_MESH);
                    if (smc && !IsBadReadPtr((uint8_t*)smc + OFF_SMC_SKELMESH, 8)) {
                        UObject* sm = *(UObject**)((uint8_t*)smc + OFF_SMC_SKELMESH);
                        pm = sm ? "MESH" : "NO-MESH";
                        if (!sm) ++s.playerPawnsNoMesh;
                    }
                }
                float px = 0, py = 0, pz = 0;
                if (!IsBadReadPtr((uint8_t*)o + OFF_ACTOR_LOCATION, 12)) {
                    float* L = (float*)((uint8_t*)o + OFF_ACTOR_LOCATION);
                    px = L[0]; py = L[1]; pz = L[2];
                }
                // wep / inv: does this pawn hold a weapon, and does it have an
                // inventory manager to have got one from. nofire: the pawn's
                // own bNoWeaponFiring bit, which would explain a weapon that
                // is held and will not fire without any input being at fault.
                const char* wep = "?"; const char* inv = "?"; const char* nofire = "?";
                if (!IsBadReadPtr((uint8_t*)o + OFF_PAWN_WEAPON, 8))
                    wep = *(void**)((uint8_t*)o + OFF_PAWN_WEAPON) ? "W" : "-";
                if (!IsBadReadPtr((uint8_t*)o + OFF_PAWN_INVMANAGER, 8))
                    inv = *(void**)((uint8_t*)o + OFF_PAWN_INVMANAGER) ? "I" : "-";
                if (!IsBadReadPtr((uint8_t*)o + OFF_PAWN_FLAGS_NOFIRE, 4))
                    nofire = (*(uint32_t*)((uint8_t*)o + OFF_PAWN_FLAGS_NOFIRE)
                              & BIT_NO_WEAPON_FIRING) ? "NOFIRE" : "fire-ok";
                // If the pawn holds a weapon, is that weapon unfolded?
                // anim=T?I? — AnimTree template present, tree instanced.
                const char* anim = "?";
                if (!IsBadReadPtr((uint8_t*)o + OFF_PAWN_MESH, 8)) {
                    UObject* smc2 = *(UObject**)((uint8_t*)o + OFF_PAWN_MESH);
                    if (smc2 && !IsBadReadPtr((uint8_t*)smc2 + OFF_SMC_ANIMATIONS, 8)) {
                        void* tmpl = *(void**)((uint8_t*)smc2 + OFF_SMC_ANIMTREETEMPLATE);
                        void* inst = *(void**)((uint8_t*)smc2 + OFF_SMC_ANIMATIONS);
                        anim = tmpl ? (inst ? "anim=tree+inst" : "anim=tree-NOINST")
                                    : (inst ? "anim=inst-notmpl" : "anim=NONE");
                    }
                }
                const char* wexp = "-";
                if (!IsBadReadPtr((uint8_t*)o + OFF_PAWN_WEAPON, 8)) {
                    UObject* wp = *(UObject**)((uint8_t*)o + OFF_PAWN_WEAPON);
                    if (wp && !IsBadReadPtr((uint8_t*)wp + OFF_WEAPON_FLAGS_EXPANDED, 4))
                        wexp = (*(uint32_t*)((uint8_t*)wp + OFF_WEAPON_FLAGS_EXPANDED)
                                & BIT_WEAPON_EXPANDED) ? "EXPANDED" : "folded";
                }
                const char* cbt = "?";
                if (!IsBadReadPtr((uint8_t*)o + OFF_BIOPAWN_COMBATFLAGS, 4))
                    cbt = (*(uint32_t*)((uint8_t*)o + OFF_BIOPAWN_COMBATFLAGS)
                           & BIT_COMBAT_PAWN) ? "combat" : "NONCOMBAT";
                // Skip archetype templates: they sit at the origin, they are
                // not actors in the level, and eleven of them filled the
                // budget so the two pawns that matter were truncated away.
                if (px == 0 && py == 0 && pz == 0) continue;
                if (s.playerPawnList.size() < 600) {
                    char pb[200];
                    _snprintf_s(pb, sizeof(pb), _TRUNCATE, "%s%s:%s:%s%s:%s:%s:%s:%s@(%.0f,%.0f,%.0f)",
                                s.playerPawnList.empty() ? "" : " ", cn, pm,
                                wep, inv, nofire, cbt, wexp, anim, px, py, pz);
                    s.playerPawnList += pb;
                }
            }
        }
        // Does a HUD actor exist in this process at all?
        //
        // The host draws a HUD and the client draws none, from the same
        // client-side code — so the question is which half is missing.
        // GameInfo.GenericPlayerInitialization calls PC.ClientSetHUD(HUDType,
        // ScoreBoardType) on every logging-in player, and that RPC is what
        // gives a remote client its HUD. No HUD object here means the call
        // never took effect; a HUD object that draws nothing is a different
        // problem with a different fix, and guessing between them is what
        // this field exists to stop.
        else if (strstr(cn, "HUD")) {
            ++s.huds;
            if (s.hudClass.empty()) s.hudClass = cn;
        }
        else if (strncmp(cn, "SFXWeapon", 9) == 0) ++s.weapons;
        else if (strstr(cn, "MPProbeBody")) ++s.bodyprobe;
        else if (strstr(cn, "MPProbePreLogin")) ++s.prelogins;
        else if (strstr(cn, "MPProbeRefused")) ++s.refused;
        // LoginFailed first: "MPProbeLogin" is a prefix of it.
        else if (strstr(cn, "MPProbeLoginFailed")) ++s.loginfail;
        else if (strstr(cn, "MPProbeLogin")) ++s.logins;
        else if (strstr(cn, "PendingLevel")) { ++s.pendings; DumpPendingVT(o, cn); }
        else if (strstr(cn, "BioStartLocation")) ++s.starts;
        else if (strstr(cn, "PlayerStart")) ++s.pstarts;
        else if (strstr(cn, "DynamicAnchor")) ++s.anchors;

        // Once streamed sublevels load there are several WorldInfo objects,
        // and taking the first one reported "BioSnd_MPCer / Standalone" while
        // the game was demonstrably hosting. Take the highest NetMode instead:
        // a listen server's world (2) outranks a sublevel's default (0), and
        // with all zeros this still picks the first, since netmode starts at -1.
        if (strstr(cn, "WorldInfo") && !IsBadReadPtr(o, OFF_NETMODE + 1)) {
            int nm = *(unsigned char*)((uint8_t*)o + OFF_NETMODE);
            if (nm > s.netmode) {
                s.netmode = nm;
                s.worldInfo = o;
                UObject* p = o;
                while (p->Outer && !IsBadReadPtr(p->Outer, sizeof(UObject)))
                    p = p->Outer;
                s.map = NameOf(p->Name);
                // Which GameInfo is actually running? If ?game= silently fell
                // back, this says so outright.
                UObject* gi = *(UObject**)((uint8_t*)o + OFF_WI_GAME);
                if (gi && !IsBadReadPtr(gi, sizeof(UObject))) {
                    s.gameInfoClass = ClassNameOf(gi);

                    // THE COMBAT GATE, read end to end.
                    //
                    // LE3 gates fire/aim/powers/reload/weapon-switch on the
                    // native BioPlayerInput::IsCombatEnabled(), which reads
                    // BioBaseSquad.m_bCombatEnabled through BioPawn.Squad.
                    // Squad is assigned in exactly one place in all 1222
                    // decompiled LE3 classes — BioBaseSquad.AddMember — reached
                    // only from BioPlayerController.Possess, which calls
                    // PlayerSquad.AddMember(aPawn) with NO None guard. So a
                    // missing squad disables combat in total silence.
                    //
                    // SFXGameInfoMP.PostBeginPlay now spawns one. Whether that
                    // actually produced a squad, and whether its flags are set,
                    // is three pointer reads — and guessing at it has already
                    // cost a run.
                    std::string sd = " squad:";
                    size_t psOff = PropertyOffset(gi, "PlayerSquad");
                    if (!psOff) {
                        sd += "PlayerSquad=UNRESOLVED";
                    } else if (IsBadReadPtr((uint8_t*)gi + psOff, 8)) {
                        sd += "PlayerSquad=BADPTR";
                    } else {
                        UObject* sq = *(UObject**)((uint8_t*)gi + psOff);
                        if (!sq || IsBadReadPtr(sq, 0x40)) {
                            sd += "PlayerSquad=NONE";
                        } else {
                            sd += "PlayerSquad=";
                            sd += ClassNameOf(sq);
                            // The two flags 2012 sets and the generated stub
                            // did not. A squad that exists with
                            // m_bCombatEnabled FALSE looks fixed and is not.
                            // CachedPlayerPawn — the field IsCombatEnabled
                            // actually tests, and the one that was NULL.
                            //
                            // Disassembled at 0x7ff74b2ea9b0: the native reads
                            // BioWorldInfo.m_playerSquad, then
                            // Squad->CachedPlayerPawn, then m_bCombatEnabled,
                            // then CachedPlayerPawn->bCombatPawn. It never
                            // reads BioPawn.Squad — which is why the previous
                            // run measured the squad chain clean and firing
                            // still failed. Read what the function reads.
                            {
                                size_t cpOff = PropertyOffset(sq, "CachedPlayerPawn");
                                char cb2[96];
                                if (!cpOff || IsBadReadPtr((uint8_t*)sq + cpOff, 8)) {
                                    snprintf(cb2, sizeof(cb2), " CachedPlayerPawn=UNRESOLVED");
                                } else {
                                    UObject* cp = *(UObject**)((uint8_t*)sq + cpOff);
                                    snprintf(cb2, sizeof(cb2), " CachedPlayerPawn=%s",
                                             (cp && !IsBadReadPtr(cp, 0x40)) ? ClassNameOf(cp) : "NONE");
                                }
                                sd += cb2;
                            }

                            static const char* kFlags[] = { "m_bCombatEnabled", "bIsPlayerSquad" };
                            for (const char* fn : kFlags) {
                                size_t fo = PropertyOffset(sq, fn);
                                char fb[96];
                                if (!fo || IsBadReadPtr((uint8_t*)sq + fo, 4)) {
                                    snprintf(fb, sizeof(fb), " %s=UNRESOLVED", fn);
                                } else {
                                    // Bools live packed in a bitfield word; the
                                    // resolver gives the word, not the bit, so
                                    // print the word and let a non-zero speak.
                                    snprintf(fb, sizeof(fb), " %s(word)=%x", fn,
                                             *(uint32_t*)((uint8_t*)sq + fo));
                                }
                                sd += fb;
                            }
                        }
                    }
                    s.squadDesc = sd;
                }
            }
        }
    }
    s.chanDesc = DescribeChannels(chans);
    s.pkgMapDesc = DescribePackageMaps(pkgmaps);
    s.netObjDesc = DescribeNetObjects(netPkgs);
    return s;
}

static void Probe() {
    // The pid alone is not enough to keep two instances' logs apart: Windows
    // pids are per-wineserver and the two instances run in separate prefixes,
    // so both came up as pid 312 and wrote one interleaved, torn file, misread
    // more than once. LempOpenDebugLog appends a tick count.
    g_log = LempOpenDebugLog("repl_probe");

    g_base = (uint8_t*)GetModuleHandleA("MassEffect3.exe");
    if (!g_base) g_base = (uint8_t*)GetModuleHandleA(nullptr);
    uint32_t peOff = *(uint32_t*)(g_base + 0x3C);
    g_end = g_base + *(uint32_t*)(g_base + peOff + 0x18 + 0x38);
    g_pools = (FNameEntry**)(g_base + RVA_NAME_POOLS);
    auto* objs = (TArray<UObject*>*)(g_base + RVA_OBJOBJECTS);
    g_objsForLookup = objs;

    L("== repl_probe ==  pid %lu, sampling every %u ms",
      (unsigned long)GetCurrentProcessId(), (unsigned)INTERVAL_MS);
    L("HOST:   open BioP_MPCer?listen     (expect NetMode=LISTEN-SERVER)");
    L("CLIENT: open 127.0.0.1             (expect NetMode=CLIENT)");
    L("PASS = a NetConnection appears on the host. A second");
    L("PlayerReplicationInfo means actors are replicating, which is stronger.");
    L("Only changes are logged, plus a heartbeat every 60 s.");
    L("Runs for 3 hours, then stops. conns= counts ANY *Connection class.");
    L("");
    if (IsBadReadPtr(objs, sizeof(*objs)) || objs->Count < 1000 || !objs->Data) {
        L("ABORT: GObjects implausible — wrong build?");
        CloseLog();
        return;
    }

    // Calibrate the property resolver before anything reads through it. Once,
    // after GObjects is known good; it prints what it found and leaves the
    // resolver disabled rather than guessing if it cannot prove the answer.
    CalibratePropertyOffset(objs);

    Snapshot prev;
    bool first = true;
    for (int n = 0; n < TICKS; ++n) {
        // Exit crashes were seen at lemp.asi+0x30030, near
        // Default__SFXPawn_PlayerMP (looked up inside Sample()'s per-pawn
        // section) — a 3-hour background thread scanning GObjects, with no
        // check for the engine tearing itself down. Checked here (every
        // INTERVAL_MS) and again inside Sample()'s own object loop, since a
        // single full scan is the more likely place to straddle the moment
        // appPreExit sets the flag.
        if (lemp::Exiting()) { L("stopping: engine exiting"); break; }
        Snapshot s = Sample(objs);
        bool changed = first || !(s == prev);
        if (changed || (n % 60) == 0) {
            L("%s map=%-16s NetMode=%d %-14s game=%-22s MPclass=%s MMpkg=%d MMopen=%d "
              "drivers=%d conns=%d [%s] controllers=%d possessed=%d PRIs=%d "
              "pawns=%d mppawns=%d "
              "starts=%d pstarts=%d anchors=%d prelogins=%d refused=%d "
              "logins=%d loginfail=%d pendings=%d bodyprobe=%d kitpkg=%s "
              "hud=%d/%s weapons=%d playerpawns=%d nomesh=%d [%s]  pawn[%s]",
              changed ? "CHANGE " : "  .    ",
              s.map.c_str(), s.netmode, NetModeName((unsigned char)s.netmode),
              s.gameInfoClass.empty() ? "<none>" : s.gameInfoClass.c_str(),
              s.mpClassLoaded ? "LOADED" : "absent", s.mmPkg, (int)s.mmOpen,
              s.drivers, s.conns, s.connNames.c_str(),
              s.controllers, s.possessed, s.pris, s.pawns, s.mppawns,
              s.starts, s.pstarts, s.anchors,
              s.prelogins, s.refused, s.logins, s.loginfail, s.pendings,
              s.bodyprobe, s.kitPkg ? "yes" : "NO",
              s.huds, s.hudClass.empty() ? "NONE" : s.hudClass.c_str(),
              s.weapons, s.playerPawns, s.playerPawnsNoMesh,
              s.playerPawnList.empty() ? "none" : s.playerPawnList.c_str(),
              s.pawnDesc.empty() ? "none" : s.pawnDesc.c_str());
    // The combat gate, on its own line so it is greppable and so a long pawn
    // line cannot truncate it — which has already cost one reading in this
    // session, where a truncated line was misread as a different input state.
    if (!s.squadDesc.empty()) L("       %s", s.squadDesc.c_str());
    {
        static std::string lastChan;
        if (s.chanDesc != lastChan) {
            L("  CHANNELS: %s", s.chanDesc.c_str());
            lastChan = s.chanDesc;
        }
        static std::string lastNet;
        if (s.netObjDesc != lastNet) {
            L("  NETOBJS: %s", s.netObjDesc.empty() ? "(neither package in memory)" : s.netObjDesc.c_str());
            lastNet = s.netObjDesc;
        }
        static std::string lastPkg;
        if (s.pkgMapDesc != lastPkg) {
            L("  PKGMAP: %s", s.pkgMapDesc.empty() ? "(no PackageMap objects)" : s.pkgMapDesc.c_str());
            lastPkg = s.pkgMapDesc;
        }
    }
    // Only when the TEXT changes.
    //
    // The whole snapshot is reported on any change, and a walking player
    // changes position every sample — so a string written once was reprinted
    // every second. The message is the event here, not the frame it was seen
    // in.
    {
        static std::string lastScript;
        if (!s.scriptLog.empty() && s.scriptLog != lastScript) {
            L("  SCRIPT: %s", s.scriptLog.c_str());
            lastScript = s.scriptLog;
        }
        // Unpossessed controllers, each on change of its own text.
        static std::map<std::string, std::string> lastUnpossessed;
        for (const auto& pc : s.unpossessedScript) {
            std::string& last = lastUnpossessed[pc.first];
            if (pc.second != last) {
                L("  SCRIPT(nopawn %s): %s", pc.first.c_str(), pc.second.c_str());
                last = pc.second;
            }
        }
    }
    // The objective HUD and annex gates (see DescribeObjectiveHud), on change.
    {
        static std::string lastObj;
        static std::string lastMenuMovies;
        std::string d = DescribeObjectiveHud(objs);
        if (d != lastObj) {
            L("  OBJHUD: %s", d.c_str());
            lastObj = d;
        }
        // MENUSTATE (above): on a main-menu map, at each movie-list change and
        // once 5 samples later.
        // Wall time, not samples: the sample-counted "later" dump never fired,
        // and the first dump lands 0.03 s after arrival.
        static DWORD menuDumpAt = 0;
        bool menuMap = s.map == "EntryMenu" || s.map == "BIOG_UIWorld";
        if (menuMap && d != lastMenuMovies) { lastMenuMovies = d; DumpMenuState(objs, "movies changed"); menuDumpAt = GetTickCount() + 8000; }
        else if (menuMap && menuDumpAt && GetTickCount() >= menuDumpAt) { menuDumpAt = 0; DumpMenuState(objs, "8 s later"); }
        if (!menuMap) menuDumpAt = 0;
    }
    // The lobby movie's textures and their render resources, on change.
    {
        static std::string lastTex;
        std::string d = DescribeLobbyTextures(objs);
        if (d != lastTex) {
            L("  LOBBYTEX: %s", d.c_str());
            lastTex = d;
        }
    }
            if (changed && s.conns > 0)
                L("        >>> NetConnection present — a peer is connected <<<");
            if (changed && s.pris > 1)
                L("        >>> %d PlayerReplicationInfos — ACTORS ARE REPLICATING <<<",
                  s.pris);
        }
        // Hand the world to StallThread. The offset is resolved here, where the
        // property-offset calibration lives; the thread only reads a float.
        g_stallOff = s.worldInfo ? PropertyOffset(s.worldInfo, "RealTimeSeconds") : 0;
        g_stallWI = s.worldInfo;
        prev = s;
        first = false;
        Sleep(INTERVAL_MS);
    }
    L("done");
    CloseLog();
}

static DWORD WINAPI Thread(LPVOID) { Sleep(START_DELAY_MS); Probe(); return 0; }

// STALL: the game thread stopped ticking — reported as a short freeze after
// Wave 3, when credits are also awarded. The sampler above runs every
// ~7 s, far too coarse to place a freeze against wave end, the credit popups
// (+2.5 s, +5 s) or the forced GC (+2 s). WorldInfo.RealTimeSeconds advances
// once per game tick; read it every 5 ms and log any wall-clock gap of
// STALL_MS or more between two changes. Read only, like the rest of the probe.
// Level loads stall too; the map line around them says which those are.
static const DWORD STALL_MS = 150;
static DWORD WINAPI StallThread(LPVOID) {
    Sleep(START_DELAY_MS);
    UObject* lastWI = nullptr;
    float last = 0.f;
    DWORD lastChange = 0;
    for (;;) {
        Sleep(5);
        if (lemp::Exiting()) { L("stopping: engine exiting"); return 0; }
        UObject* wi = g_stallWI;
        size_t off = g_stallOff;
        if (!wi || !off || IsBadReadPtr((uint8_t*)wi + off, 4)) { lastWI = nullptr; continue; }
        float t = *(float*)((uint8_t*)wi + off);
        DWORD now = GetTickCount();
        if (wi != lastWI) { lastWI = wi; last = t; lastChange = now; continue; }
        if (t == last) continue;
        if (now - lastChange >= STALL_MS)
            L("  STALL: %lu ms without a game tick (RealTimeSeconds %.2f -> %.2f)",
              (unsigned long)(now - lastChange), last, t);
        last = t;
        lastChange = now;
    }
}

static DWORD WINAPI Gate(LPVOID) {
    if (!LempDebug()) return 0;   // a diagnostic: debug mode only
    CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, StallThread, nullptr, 0, nullptr);
    return 0;
}

void ReplProbeStart() { CreateThread(nullptr, 0, Gate, nullptr, 0, nullptr); }
