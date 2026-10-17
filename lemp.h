// lemp.h — what the modules of lemp.asi share: the log, debug mode, and
// each module's entry point (lemp.cpp calls them from the one DllMain).
//
// lemp.asi is the eight ASIs that shipped up to 0.1.5, one file each, linked
// into one DLL: crashes are always logged, and debug mode logs everything.
// The modules share no state apart from the log, and each still runs on its
// own thread.
//
// The log: one file per launch, LEMP\logs\lemp_<date>_<time>_<pid>_<tick>.txt,
// every module's lines in it, each tagged with the module's name. Each
// module's L() forwards to LempLogV. At start the folder keeps the newest
// ten of these files and drops the per-module files earlier releases wrote.
//
// Debug mode is on unless Documents\BioWare\Mass Effect Legendary Edition\LEMP\nodebug.txt
// exists (any content) — on by default; it used to be opt-in
// through LEMP\debug.txt. The options' log row writes and removes the same
// file (LempSetLogOn). With nodebug.txt only crash_log writes, and only
// when something faults; the diagnostics (repl_probe, loadmap_hook) do not run.
// Logs go to LEMP\logs\, not beside the exe as the separate ASIs' did: a game
// under Program Files runs unelevated and should not be able to write there
// [R, not seen: no Windows player has sent logs yet].
#pragma once
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <string>

// Documents\BioWare\Mass Effect Legendary Edition\LEMP, created on first use.
const std::wstring& LempDir();
// LempDir()\logs, created on first use.
const std::wstring& LempLogDir();
// LempDir()\nodebug.txt did not exist at launch. Read once: it decides
// whether the diagnostics modules run at all.
bool LempDebug();
// Whether lines go into the log now: LempDebug() at launch, then whatever
// the options row last set.
bool LempLogOn();
// The options row: saves the choice (nodebug.txt) for the next launch and
// starts or stops this launch's lines at once. False when the file could not
// be written or removed.
bool LempSetLogOn(bool on);
// One line, "hh:mm:ss.mmm  <module>  <text>", into the log when it is on.
void LempLogV(const char* module, const char* fmt, va_list a);
void LempLog(const char* module, const char* fmt, ...);
// crash_log's two halves, for its exception handler: format a line into
// buf (never allocates; truncates to fit; returns its length), and write a
// formatted line, with force also when the log is off (a crash report) and
// retrying a failed open at once. False when the line did not reach the
// file whole.
size_t LempLogFormatV(char* buf, size_t cap, const char* module, const char* fmt, va_list a);
bool LempLogWriteLine(const char* line, size_t len, bool force);
// The log file is open (not only switched on).
bool LempLogIsOpen();
// Keeps the newest sessions' files in LempLogDir(); Boot calls it once.
void LempLogPrune();

void CrashLogStart();       // always: says where the game died
void CrashLogExit(bool processExit);  // DLL_PROCESS_DETACH: a clean exit says so
void JoinPatchStart();      // UE3's NoDownload refusal off (join_patch)
void MpMenuStart();         // the main menu's Multiplayer entry loads its screen
void MpSaveStart();         // MP records, server, NAT, build key (mp_save)
void NoFocusPauseStart();   // the host does not pause on alt-tab
void OnlineApiStart();      // the ONLINE_API stand-in (challenge clock)
void ShieldRegenStart();    // shields regenerate at their rate at any fps; LEMP\noshieldfix.txt = off
void VoiceStart();          // voice chat (lemp_voice.cpp); LEMP\novoice.txt = off
void GuiSoundProbeStart();  // debug: logs every PlayGuiSound / StopGuiSound (gui_sound_probe.cpp)
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
