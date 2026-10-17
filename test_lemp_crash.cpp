// test_lemp_crash.cpp — lemp.asi's always-on crash log, under Wine: lemp.cpp
// and crash_log.cpp as built into the ASI, the other modules stubbed.
//
//   x86_64-w64-mingw32-g++ -O2 -std=c++17 -static -o test_lemp_crash.exe \
//       test_lemp_crash.cpp lemp.cpp crash_log.cpp
//   WINEPREFIX=<scratch> wine test_lemp_crash.exe quiet|crash|exiting
//
// quiet:   300 debug strings, then a clean exit. With LEMP\nodebug.txt the
//          logs folder must stay empty; without it (the default), the
//          session's lemp_*.txt exists from the start, crash_log's lines in it.
// crash:   the same, then a write to address 8. A lemp_*.txt must
//          appear either way, holding the last 200 debug strings and the
//          report.
// exiting: lemp::Exiting() / SetDetaching() (lemp.h) — the shared check
//          every module thread now makes before touching game memory.
//          Exercises the
//          DLL_PROCESS_DETACH half directly (SetDetaching() is what DllMain
//          calls there) with a background thread standing in for a module's
//          polling loop; the engine-pre-exit-flag half is the same RVA/
//          IsBadReadPtr formula crash_log.cpp's Report() already uses
//          (seen on native Windows), left unexercised here because faking
//          that RVA inside a
//          small test .exe's own image is not representative.
#include "lemp.h"
#include <atomic>
#include <cstring>

void JoinPatchStart() {}
void MpMenuStart() {}
void MpSaveStart() {}
void NoFocusPauseStart() {}
void OnlineApiStart() {}
void VoiceStart() {}
void LoadMapHookStart() {}
void ReplProbeStart() {}
void ShieldRegenStart() {}

static int RunExitingTest() {
    int fail = 0;
    auto CHECK = [&](bool c, const char* what) {
        if (!c) { fail++; printf("FAIL: %s\n", what); }
    };
    CHECK(!lemp::Exiting(), "Exiting() false before SetDetaching()");

    // The engine half: GCallbackEvent is NULL before
    // appInit, non-NULL while the game runs, NULL after appPreExit.
    int dummy;
    CHECK(!lemp::ObserveCallbackEvent(nullptr), "NULL before appInit is not exiting");
    CHECK(!lemp::ObserveCallbackEvent(&dummy), "non-NULL (running) is not exiting");
    CHECK(!lemp::ObserveCallbackEvent(&dummy), "still running, still not exiting");
    CHECK(lemp::ObserveCallbackEvent(nullptr), "NULL after non-NULL is exiting");

    // A stand-in module thread: loops like repl_probe/mp_menu/voice now do,
    // "touching game state" (just a counter here) until it observes
    // Exiting(), then stops on its own — never crashing, never spinning
    // forever once the flag is set.
    std::atomic<int> touches{0};
    std::atomic<bool> stopped{false};
    HANDLE th = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        auto* ctx = (std::pair<std::atomic<int>*, std::atomic<bool>*>*)p;
        for (;;) {
            if (lemp::Exiting()) { ctx->second->store(true); return 0; }
            ctx->first->fetch_add(1);
            Sleep(1);
        }
    }, new std::pair<std::atomic<int>*, std::atomic<bool>*>(&touches, &stopped), 0, nullptr);

    Sleep(50);
    int before = touches.load();
    CHECK(before > 0, "the stand-in thread touched game state before exit began");

    lemp::SetDetaching();
    CHECK(lemp::Exiting(), "Exiting() true right after SetDetaching()");

    // Give the thread up to 1 s to notice and stop; it checks every loop
    // (no Sleep longer than 1 ms here), so this is generous.
    for (int i = 0; i < 100 && !stopped.load(); ++i) Sleep(10);
    CHECK(stopped.load(), "the stand-in thread stopped after SetDetaching()");

    int afterStop = touches.load();
    Sleep(50);
    CHECK(touches.load() == afterStop, "no further touches once the thread had stopped");

    WaitForSingleObject(th, 1000);
    CloseHandle(th);
    printf("%s (%d touch(es) before exit)\n", fail ? "FAIL" : "PASS", before);
    return fail;
}

int main(int argc, char** argv) {
    const bool crash = argc > 1 && !strcmp(argv[1], "crash");
    const bool exiting = argc > 1 && !strcmp(argv[1], "exiting");
    if (exiting) return RunExitingTest() ? 1 : 0;

    CrashLogStart();
    Sleep(1000);   // its thread installs the handlers
    for (int i = 0; i < 300; i++) {
        char b[64];
        snprintf(b, sizeof b, "test line %d", i);
        OutputDebugStringA(b);
    }
    printf("logs: %ls  debug: %d\n", LempLogDir().c_str(), (int)LempDebug());
    fflush(stdout);
    if (crash) *(volatile int*)8 = 1;
    CrashLogExit(true);
    return 0;
}
