// lemp.h — what the modules of lemp.asi share: where logs go, debug mode, and
// each module's entry point (lemp.cpp calls them from the one DllMain).
//
// lemp.asi is the eight ASIs that shipped up to 0.1.5, one file each, linked
// into one DLL: crashes are always logged, and debug mode logs everything.
// Each module is unchanged
// apart from its entry point and where it opens its log; they still share no
// state and each still runs on its own thread.
//
// Debug mode is on unless Documents\BioWare\Mass Effect Legendary Edition\LEMP\nodebug.txt
// exists (any content) — on by default; it used to be opt-in
// through LEMP\debug.txt. With nodebug.txt only crash_log writes, and only
// when something faults; the diagnostics (repl_probe, loadmap_hook) do not run.
// Logs go to LEMP\logs\, not beside the exe as the separate ASIs' did: a game
// under Program Files runs unelevated and should not be able to write there
// [R, not seen: no Windows player has sent logs yet].
#pragma once
#include <windows.h>
#include <cstdio>
#include <string>

// Documents\BioWare\Mass Effect Legendary Edition\LEMP, created on first use.
const std::wstring& LempDir();
// LempDir()\logs, created on first use.
const std::wstring& LempLogDir();
// LempDir()\nodebug.txt does not exist. Read once.
bool LempDebug();
// A new log file in LempLogDir() named <name>_<pid>_<tick>.txt (pids repeat
// across Wine prefixes, so two instances on one machine need the tick too).
// nullptr when debug mode is off, or when it cannot be opened.
FILE* LempOpenDebugLog(const char* name);

void CrashLogStart();       // always: says where the game died
void CrashLogExit(bool processExit);  // DLL_PROCESS_DETACH: a clean exit says so
void JoinPatchStart();      // UE3's NoDownload refusal off (join_patch)
void MpMenuStart();         // the main menu's Multiplayer entry loads its screen
void MpSaveStart();         // MP records, server, NAT, build key (mp_save)
void NoFocusPauseStart();   // the host does not pause on alt-tab
void OnlineApiStart();      // the ONLINE_API stand-in (challenge clock)
void VoiceStart();          // voice chat (lemp_voice.cpp); LEMP\novoice.txt = off
// The voice options' ops (60-71), reached from script through mp_save's
// SaveConfig hook (SFXGUI_Option_MPVoice*). Game thread. Returns AsiResult:
// 0 done, -1 voice is off, 6 unknown op; *index is AsiIndex (in and out).
int VoiceAsiOp(int op, int* index);
void LoadMapHookStart();    // debug only: LoadMap's discarded error
void ReplProbeStart();      // debug only: the periodic state probe

// GNatives (the UFunction native jump table): mp_save finds and verifies it
// once, early (Finding GNatives, mp_save.cpp's header comment), to hook
// SaveConfig. Every other module that needs it (voice) reuses this result
// instead of searching independently: an earlier one-shot search in the
// voice module sampled too few already-bound indexed natives on a slower
// machine and gave up for good.
// nullptr until mp_save has found it; never cleared afterwards.
void** LempGNatives();

namespace lemp {
// True once the engine has begun exiting: either our own DLL_PROCESS_DETACH
// has been seen, or appPreExit has run — it zeroes GCallbackEvent, which
// appInit set (lemp.cpp has the disassembly). NOT rva 0x17df7a0, which
// crash_log logs as "preexit-flag": appInit sets that to 1 too, so it is 1
// all run (0.3.1 shipped that check and every module stopped at boot).
//
// Every module thread that polls or scans game memory (GObjects/UObjects/
// GEngine) must check this at the top of each loop iteration — and, for a
// long scan over many objects, periodically inside it too — and stop
// touching game state once it is true. It cannot make an individual read
// provably race-free (nothing here synchronizes with the engine's teardown).
bool Exiting();
// Only DllMain (DLL_PROCESS_DETACH) calls this outside tests; it is here,
// not file-local to lemp.cpp, so test_lemp_crash.cpp can drive the same
// state DllMain would set, without faking DllMain or the engine's PE image.
void SetDetaching();
// Exiting()'s engine half, given GCallbackEvent's current value: false until
// it has been seen non-NULL (appInit), true once it is NULL again
// (appPreExit). Exposed for test_lemp_crash.cpp, like SetDetaching().
bool ObserveCallbackEvent(const void* cbe);
}  // namespace lemp
