// lemp.asi — LEMP's one ASI. See lemp.h for what it holds and debug mode.
//
// Build: ./build.sh lemp   (links lemp.cpp with the module files)
#include "lemp.h"
#include "safe_read.h"  // guard-page-safe IsBadReadPtr, for lemp::Exiting()
#include <atomic>

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

// On by default for now; LEMP\nodebug.txt turns it off. debug.txt no longer
// means anything.
bool LempDebug() {
    static const bool on = GetFileAttributesW((LempDir() + L"\\nodebug.txt").c_str()) == INVALID_FILE_ATTRIBUTES;
    return on;
}

FILE* LempOpenDebugLog(const char* name) {
    if (!LempDebug()) return nullptr;
    wchar_t file[96];
    _snwprintf(file, 96, L"\\%hs_%lu_%lu.txt", name,
               (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
    file[95] = 0;
    return _wfopen((LempLogDir() + file).c_str(), L"w");
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
    // Each starts its own thread, as each ASI did. The debug-only modules
    // decide in theirs.
    CrashLogStart();
    JoinPatchStart();
    MpMenuStart();
    MpSaveStart();
    NoFocusPauseStart();
    OnlineApiStart();
    VoiceStart();
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
