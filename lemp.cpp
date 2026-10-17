// lemp.asi — LEMP's one ASI. See lemp.h for what it holds and debug mode.
//
// Build: ./build.sh lemp   (links lemp.cpp with the module files)
#include "lemp.h"
#include "safe_read.h"  // guard-page-safe IsBadReadPtr, for lemp::Exiting()
#include "install_check.h"
#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstring>
#include <vector>

static std::wstring DocumentsDir() {
    typedef HRESULT (WINAPI *SHGetFolderPathW_t)(HWND, int, HANDLE, DWORD, LPWSTR);
    wchar_t p[MAX_PATH] = {0};
    if (HMODULE sh = LoadLibraryW(L"shell32.dll")) {
        auto fn = (SHGetFolderPathW_t)(void*)GetProcAddress(sh, "SHGetFolderPathW");
        if (fn && fn(nullptr, 0x0005 /* CSIDL_PERSONAL */, nullptr, 0, p) == 0) return p;
    }
    DWORD n = GetEnvironmentVariableW(L"USERPROFILE", p, MAX_PATH);
    return (n && n < MAX_PATH) ? std::wstring(p) + L"\\Documents" : std::wstring(L".");
}

// Function-local statics: thread-safe initialisation, and never under the
// loader lock (DllMain only starts threads; SHGetFolderPathW loads shell32).
const std::wstring& LempDir() {
    static const std::wstring dir = [] {
        std::wstring d = DocumentsDir();
        for (const wchar_t* part : {L"\\BioWare", L"\\Mass Effect Legendary Edition", L"\\LEMP"}) {
            d += part;
            CreateDirectoryW(d.c_str(), nullptr);
        }
        return d;
    }();
    return dir;
}

const std::wstring& LempLogDir() {
    static const std::wstring dir = [] {
        std::wstring d = LempDir() + L"\\logs";
        CreateDirectoryW(d.c_str(), nullptr);
        return d;
    }();
    return dir;
}

static std::wstring NoDebugPath() { return LempDir() + L"\\nodebug.txt"; }

// On by default for now; LEMP\nodebug.txt turns it off. debug.txt no longer
// means anything.
bool LempDebug() {
    static const bool on = GetFileAttributesW(NoDebugPath().c_str()) == INVALID_FILE_ATTRIBUTES;
    return on;
}

// ---------------------------------------------------------------------------
// The session's log: one file per launch for every module (lemp.h).
//
// Each line is formatted on the stack and appended with one WriteFile on a
// FILE_APPEND_DATA handle, which the system appends whole: threads need no
// lock between them, and crash_log can write from inside its exception
// handler on whatever thread faulted, even one that faulted mid-line here.
// The handle is never closed (the process exit closes it), so turning the
// log off and on again cannot pull it from under a writer.

namespace {
std::atomic<int>    g_logState{0};        // 0 not open, 1 opening, 2 open, 3 failed
std::atomic<DWORD>  g_logFailTick{0};     // when it last failed (retried after kRetryMs)
std::atomic<DWORD>  g_logOpener{0};       // the thread that set state 1
const DWORD kRetryMs = 10000;
HANDLE              g_logFile = INVALID_HANDLE_VALUE;
std::atomic<int>    g_logOn{-1};          // -1: not read yet (LempDebug())
const int kKeepLogs = 10;                 // the newest sessions' files pruning keeps
const int kKeepCrashMem = 3;              // crash_log's memory snapshots kept
}  // namespace

// False when the line did not reach the file whole (a full disk, a
// Documents folder gone offline): crash_log then keeps it in its ring.
static bool WriteRaw(const char* s, size_t n) {
    DWORD w = 0;
    return WriteFile(g_logFile, s, (DWORD)n, &w, nullptr) && w == (DWORD)n;
}

// lemp_<date>_<time>_<pid>_<tick>.txt: the date sorts the folder, the pid and
// tick keep two instances apart (pids repeat across Wine prefixes, which can
// share one Documents folder). A failed open is tried again after kRetryMs,
// and at once for a crash report (force): one failure (a synced Documents
// folder briefly offline) must not cost the session's crash report.
static bool OpenLogFile(bool force) {
    int st = g_logState.load();
    if (st == 2) return true;
    if (st == 3 && !force && GetTickCount() - g_logFailTick.load() < kRetryMs) return false;
    int expect = st == 3 ? 3 : 0;
    if (!g_logState.compare_exchange_strong(expect, 1)) {
        // Another thread is opening it: a bounded wait. Not when the opener is
        // this thread, re-entered from crash_log's handler: its open is
        // suspended under the exception and state 1 would never change, so
        // each line of a crash report would wait the full second.
        if (g_logState.load() == 1 && g_logOpener.load() == GetCurrentThreadId()) return false;
        for (int i = 0; i < 200 && g_logState.load() == 1; i++) Sleep(5);
        return g_logState.load() == 2;
    }
    g_logOpener = GetCurrentThreadId();
    SYSTEMTIME t; GetLocalTime(&t);
    wchar_t name[96];
    _snwprintf(name, 96, L"\\lemp_%04d-%02d-%02d_%02d-%02d-%02d_%lu_%lu.txt",
               t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond,
               (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
    name[95] = 0;
    // No FILE_SHARE_DELETE: another instance's pruning cannot delete it while
    // this one is writing.
    HANDLE h = CreateFileW((LempLogDir() + name).c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { g_logFailTick = GetTickCount(); g_logState = 3; return false; }
    g_logFile = h;
    char head[160];
#ifdef LEMP_RELEASE
    const char* rel = LEMP_RELEASE;
#else
    const char* rel = "?";
#endif
    int n = snprintf(head, sizeof head, "== LEMP %s ==  pid %lu  %04d-%02d-%02d %02d:%02d:%02d\r\n",
                     rel, (unsigned long)GetCurrentProcessId(),
                     t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    if (n > 0) WriteRaw(head, (size_t)n < sizeof head ? (size_t)n : sizeof head - 1);
    g_logState = 2;   // after the header, so it is the first line
    return true;
}

bool LempLogOn() {
    int on = g_logOn.load();
    if (on < 0) {
        on = LempDebug() ? 1 : 0;
        int expect = -1;
        if (!g_logOn.compare_exchange_strong(expect, on)) on = expect;
    }
    return on == 1;
}

size_t LempLogFormatV(char* buf, size_t cap, const char* module, const char* fmt, va_list a) {
    if (cap < 64) { if (cap) buf[0] = 0; return 0; }
    SYSTEMTIME st; GetLocalTime(&st);
    int n = snprintf(buf, cap, "%02d:%02d:%02d.%03d  %-12s  ",
                     st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, module);
    if (n < 0) n = 0;
    if ((size_t)n >= cap) n = (int)cap - 1;
    va_list c; va_copy(c, a);
    int m = vsnprintf(buf + n, cap - n, fmt, c);
    va_end(c);
    if (m < 0) m = 0;
    size_t len = (size_t)n + (size_t)m;
    return len < cap ? len : cap - 1;   // truncated to fit
}

bool LempLogIsOpen() { return g_logState.load() == 2; }

bool LempLogWriteLine(const char* line, size_t len, bool force) {
    if (!force && !LempLogOn()) return false;
    if (!OpenLogFile(force)) return false;
    // Line and line break in one write, so a line is never split. Larger than
    // any line formatted on the stack (crash_log's included): only the long
    // lines LempLogV puts on the heap take the heap path here.
    char buf[2048];
    if (len + 2 <= sizeof buf) {
        memcpy(buf, line, len);
        buf[len] = '\r'; buf[len + 1] = '\n';
        return WriteRaw(buf, len + 2);
    }
    std::string s(line, len);
    s += "\r\n";
    return WriteRaw(s.data(), s.size());
}

void LempLogV(const char* module, const char* fmt, va_list a) {
    if (!LempLogOn()) return;
    char buf[1024];
    va_list c; va_copy(c, a);
    size_t len = LempLogFormatV(buf, sizeof buf, module, fmt, c);
    va_end(c);
    if (len < sizeof buf - 1) { LempLogWriteLine(buf, len, false); return; }
    // A long line (the probe's object lists): measured, then on the heap.
    va_copy(c, a);
    int m = vsnprintf(nullptr, 0, fmt, c);
    va_end(c);
    if (m < 0) { LempLogWriteLine(buf, len, false); return; }
    std::string big((size_t)m + 64, '\0');
    va_copy(c, a);
    len = LempLogFormatV(&big[0], big.size(), module, fmt, c);
    va_end(c);
    LempLogWriteLine(big.data(), len, false);
}

void LempLog(const char* module, const char* fmt, ...) {
    va_list a; va_start(a, fmt);
    LempLogV(module, fmt, a);
    va_end(a);
}

// The options row (ops 74/75, mp_save). Saved as nodebug.txt, which the next
// launch reads; this launch's log stops or starts at once. A module that only
// runs with logging on (repl_probe, loadmap_hook) starts at the next launch.
bool LempSetLogOn(bool on) {
    bool ok;
    if (on) ok = DeleteFileW(NoDebugPath().c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND;
    else {
        HANDLE h = CreateFileW(NoDebugPath().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        ok = h != INVALID_HANDLE_VALUE;
        if (ok) CloseHandle(h);
    }
    if (!on) LempLog("lemp", "log turned off in the options (nodebug.txt %s)", ok ? "written" : "NOT written");
    g_logOn = on ? 1 : 0;
    if (on) LempLog("lemp", "log turned on in the options (nodebug.txt %s)", ok ? "removed" : "NOT removed");
    return ok;
}

// Deletes all but the newest `keep` files matching `pattern` in the logs
// folder, by last write.
static void PruneMatching(const wchar_t* pattern, int keep) {
    struct F { FILETIME t; std::wstring name; };
    std::vector<F> files;
    WIN32_FIND_DATAW fd;
    HANDLE fh = FindFirstFileW((LempLogDir() + L"\\" + pattern).c_str(), &fd);
    if (fh == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) files.push_back({fd.ftLastWriteTime, fd.cFileName});
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
    std::sort(files.begin(), files.end(), [](const F& x, const F& y) { return CompareFileTime(&x.t, &y.t) > 0; });
    for (size_t i = (size_t)(keep < 0 ? 0 : keep); i < files.size(); i++)
        DeleteFileW((LempLogDir() + L"\\" + files[i].name).c_str());
}

void LempLogPrune() {
    PruneMatching(L"lemp_*.txt", kKeepLogs);
    PruneMatching(L"crash_mem_*.bin", kKeepCrashMem);
    // Up to 0.5.0 each module wrote its own file, <module>_<pid>_<tick>.txt,
    // and nothing removed them.
    for (const wchar_t* m : {L"crash_log", L"join_patch", L"loadmap_hook", L"mp_menu", L"mp_save",
                             L"nofocuspause", L"online_api", L"repl_probe", L"voice", L"shield_regen"})
        PruneMatching((std::wstring(m) + L"_*_*.txt").c_str(), 0);
}

// The separate ASIs lemp.asi replaces (up to 0.1.5; tick_hook was folded in later).
// Beside it, each would install its hook a second time over ours. The
// installers delete them; a by-hand update may not, so look for the files
// (not the loaded modules: the loader's order would decide what is loaded yet).
static const wchar_t* const kOldAsis[] = {
    L"crash_log.asi", L"join_patch.asi", L"loadmap_hook.asi", L"mp_menu.asi", L"mp_save.asi",
    L"nofocuspause.asi", L"online_api.asi", L"repl_probe.asi", L"tick_hook.asi",
};
static HMODULE g_self;

static std::string Utf8(const std::wstring& w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? n : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static std::wstring Wide(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n > 0 ? n : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// The DLC folder against its own PCConsoleTOC.bin (install_check.h), so a
// broken copy is named instead of left to the game's "corrupt" dialog. Its
// own thread: the modules start without waiting, and the message box blocks
// only this one.
static DWORD WINAPI InstallCheck(LPVOID) {
    wchar_t exe[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);          // ...\Game\ME3\Binaries\Win64\MassEffect3.exe
    std::wstring dlc = exe;
    for (int up = 0; up < 3; ++up) dlc = dlc.substr(0, dlc.find_last_of(L'\\'));
    dlc += L"\\BioGame\\DLC\\DLC_MOD_LEMultiplayer";
    installcheck::Fs fs;
    fs.isDir = [&](const std::string& rel) {
        DWORD a = GetFileAttributesW((rel.empty() ? dlc : dlc + L"\\" + Wide(rel)).c_str());
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
    };
    fs.size = [&](const std::string& rel) -> int64_t {
        WIN32_FILE_ATTRIBUTE_DATA d;
        if (!GetFileAttributesExW((dlc + L"\\" + Wide(rel)).c_str(), GetFileExInfoStandard, &d) ||
            (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            return -1;
        return (int64_t)d.nFileSizeHigh << 32 | d.nFileSizeLow;
    };
    fs.listCooked = [&] {
        std::vector<std::string> out;
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW((dlc + L"\\CookedPCConsole\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return out;
        do
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) out.push_back(Utf8(fd.cFileName));
        while (FindNextFileW(h, &fd));
        FindClose(h);
        return out;
    };
    fs.readToc = [&](std::vector<uint8_t>& out) {
        HANDLE h = CreateFileW((dlc + L"\\PCConsoleTOC.bin").c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER n;
        bool ok = GetFileSizeEx(h, &n) && n.QuadPart > 0 && n.QuadPart < (64 << 20);
        DWORD got = 0;
        if (ok) {
            out.resize((size_t)n.QuadPart);
            ok = ReadFile(h, out.data(), (DWORD)out.size(), &got, nullptr) && got == out.size();
        }
        CloseHandle(h);
        return ok;
    };
    DWORD t = GetTickCount();
    installcheck::Report r = installcheck::Check(fs);
    if (!r.Ok() && !r.noFolder) {
        // ME3Tweaks' AutoTOC ASI may be rewriting the TOC at this moment:
        // a problem counts only if it is still there a little later.
        LempLog("install", "DLC folder: %s; again in 5 s", installcheck::Summary(r).c_str());
        Sleep(5000);
        if (lemp::Exiting()) return 0;
        r = installcheck::Check(fs);
    }
    LempLog("install", "DLC folder: %s (%lu ms)", installcheck::Summary(r).c_str(),
            (unsigned long)(GetTickCount() - t));
    std::string m = installcheck::Message(r, Utf8(dlc));
    if (!m.empty()) MessageBoxW(nullptr, Wide(m).c_str(), L"LEMP", MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
    return 0;
}

static DWORD WINAPI Boot(LPVOID) {
    wchar_t self[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_self, self, MAX_PATH);
    std::wstring dir(self, n);
    dir.resize(dir.rfind(L'\\') == std::wstring::npos ? 0 : dir.rfind(L'\\'));
    std::wstring old;
    for (const wchar_t* f : kOldAsis)
        if (GetFileAttributesW((dir + L"\\" + f).c_str()) != INVALID_FILE_ATTRIBUTES) old += std::wstring(L"    ") + f + L"\n";
    if (!old.empty()) {
        MessageBoxW(nullptr, (L"LEMP is switched off: an older LEMP's files are still in\n" + dir + L"\n\n" + old +
                              L"\nDelete them, or run the LEMP installer again, then restart the game.").c_str(),
                    L"LEMP", MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
        return 0;
    }
    LempLogPrune();
    CreateThread(nullptr, 0, InstallCheck, nullptr, 0, nullptr);
    // Each starts its own thread, as each ASI did. The debug-only modules
    // decide in theirs.
    CrashLogStart();
    JoinPatchStart();
    MpMenuStart();
    MpSaveStart();
    NoFocusPauseStart();
    OnlineApiStart();
    ShieldRegenStart();
    VoiceStart();
    GuiSoundProbeStart();
    LoadMapHookStart();
    ReplProbeStart();
    return 0;
}

// lemp::Exiting() — see lemp.h. One implementation, shared by every module.
// 0.3.1 read rva 0x17df7a0 here as "the pre-exit flag", but appInit writes 1 to it as
// well (+0x11d784, beside the Core.System config reads), so it is 1 for the
// whole run: every module stopped within a second of boot and the main menu's
// Multiplayer entry went dead. The exit-only write is appPreExit's first
// instruction (+0x11a65f): GCallbackEvent (rva 0x17d5648) := NULL. Its only
// other writer is appInit (+0x11b80f), and our threads start before appInit,
// so NULL means "exiting" only after it has been seen non-NULL.
namespace lemp {
namespace {
std::atomic<bool> g_detaching{false};
std::atomic<bool> g_engineUp{false};    // GCallbackEvent seen non-NULL once
}  // namespace

bool ObserveCallbackEvent(const void* cbe);

void SetDetaching() { g_detaching.store(true, std::memory_order_relaxed); }

bool Exiting() {
    if (g_detaching.load(std::memory_order_relaxed)) return true;
    // Cached once: GetModuleHandleA is idempotent, so a benign race between
    // threads computing this the first time costs nothing.
    static uint8_t* base = nullptr;
    static uint8_t* end = nullptr;
    if (!base) {
        uint8_t* b = (uint8_t*)GetModuleHandleA("MassEffect3.exe");
        if (!b) b = (uint8_t*)GetModuleHandleA(nullptr);
        if (b && !IsBadReadPtr(b, 0x200)) {
            uint32_t peOff = *(uint32_t*)(b + 0x3C);
            base = b;
            end = b + *(uint32_t*)(b + peOff + 0x18 + 0x38);   // SizeOfImage
        }
    }
    const uintptr_t RVA_GCALLBACKEVENT = 0x17d5648;   // same as crash_log's Report()
    if (!base || (size_t)(end - base) <= RVA_GCALLBACKEVENT + 8) return false;
    void* const* cbe = (void* const*)(base + RVA_GCALLBACKEVENT);
    if (IsBadReadPtr(cbe, sizeof(*cbe))) return false;
    return ObserveCallbackEvent(*cbe);
}

bool ObserveCallbackEvent(const void* cbe) {
    if (cbe) { g_engineUp.store(true, std::memory_order_relaxed); return false; }
    return g_engineUp.load(std::memory_order_relaxed);
}
}  // namespace lemp

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        g_self = h;
        CreateThread(nullptr, 0, Boot, nullptr, 0, nullptr);
    }
    if (reason == DLL_PROCESS_DETACH) {
        // Set first: any module thread still alive checks lemp::Exiting()
        // before its next game-memory read (lemp.h). Most are already gone
        // by the time ExitProcess reaches here (the OS terminates every
        // other thread first), but FreeLibrary and the brief window before
        // ExitProcess's final teardown do not give that guarantee.
        lemp::SetDetaching();
        CrashLogExit(reserved != nullptr);
    }
    return TRUE;
}
