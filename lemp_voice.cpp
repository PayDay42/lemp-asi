// lemp_voice — voice chat: the engine behind SFXOnlineComponentVoiceInterface.
//
// NOT A PROBE. THIS MODULE WRITES TO GAME MEMORY: the UFunction::Func pointers
// of the voice interface's natives listed in kNatives, and two pointers in
// MassEffect3.exe's import table (ws2_32 recvfrom and sendto, by ordinal).
// It opens the microphone and the speakers while an MP connection is up.
// In debug mode it writes voice_<pid>_<tick>.txt (lemp.h).
//
// ---------------------------------------------------------------------------
// The three parts (see lemp_voice.h for the core and the wire format):
//
// 1. Script -> us. 2012's script calls the interface unchanged: the lobby's
//    RefreshAllSpeakerIcons every 0.5 s (IsHeadsetPresent, IsLocalPlayerTalking,
//    GetRemotePlayerStatus, IsRemotePlayerTalking, IsRemoteTalkerMuted), its
//    ToggleMuteForSlot (Mute/UnmuteRemoteTalker), and SFXPlayerControllerMP's
//    VoicePushToTalkStart/End (Tab). Each of those natives' Func is replaced by
//    an exec function here that reads its parameters off the script stack and
//    answers from the Engine.
//
//    Reading parameters is UE3's Stack.Step: the next opcode byte, then
//    GNatives[op](Stack.Object, Stack, &value). GNatives is found as mp_save
//    finds it. FFrame's layout is not in LExSDK, so it is proven on the first
//    call: Stack.Code must point inside the calling function's own bytecode
//    (Stack.Node->Script, UStruct+0x7C). Until it is proven, and forever if it
//    is not, every call goes to LE3's own native untouched — which is why a
//    native is only taken over once the game has bound it (its Func non-null,
//    as mp_menu waits for CallListFnc): we always hold the original.
//
// 2. The wire. MassEffect3.exe imports recvfrom (ws2_32 ordinal 17) and sendto
//    (ordinal 20) [V, objdump -p MassEffect3_PATCHED.exe]; UE3's net driver is
//    their caller. Their import-table pointers in the exe point here instead;
//    nothing else in the process (our own punch proxy included) is affected.
//    sendto: passes through, noting where the game sends. recvfrom: voice
//    datagrams are consumed (played, relayed) and the next datagram is read,
//    so UE3 never sees one; the game's pass through unchanged. A peer is an
//    address the game both sends to and hears from within 5 s.
//
// 3. Sound. lemp_voice_audio.h: miniaudio + Opus. Opened when the first peer
//    appears, closed 30 s after the last one goes. A worker thread encodes
//    captured frames and decodes received ones; the device threads only move
//    frames through queues and mix.
//
// Identity: frames carry the sender's PRI.UniqueId, which is what the lobby
// asks about. The local one is read from the local PlayerController's PRI on
// the game thread, at most every 2 s, inside the natives. Every id the natives
// are asked about is logged once, so the first run shows what LE3 fills in.
//
// Settings: LEMP\voice.txt (mode=ptt|open|off, input=, output=, volume=).
// The natives SetVoiceMode/SetVolume/SetInputDevice/SetOutputDevice write it.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "lemp.h"
#include "safe_read.h"
#include "lemp_voice.h"
#include "lemp_voice_audio.h"
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace {

const uintptr_t RVA_NAME_POOLS = 0x17B33D0;   // as mp_save / mp_menu
const uintptr_t RVA_OBJOBJECTS = 0x1887E40;
const size_t    OFF_PAWN_MESH  = 0x03F4;      // calibrates UProperty::Offset, as mp_save
const size_t    OFF_FIELD_SUPER     = 0x60;   // LExSDK Core_classes.h
const size_t    OFF_FIELD_NEXT      = 0x68;
const size_t    OFF_STRUCT_CHILDREN = 0x70;
const size_t    OFF_STRUCT_SCRIPT   = 0x7C;   // TArray<BYTE> Script (Data 8, Count 4, Max 4)
const size_t    OFF_FUNC_FUNC       = 0xD8;
const uint8_t   EX_EndFunctionParms = 0x16;

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
typedef int (WSAAPI* RecvFromFn)(SOCKET, char*, int, int, sockaddr*, int*);
typedef int (WSAAPI* SendToFn)(SOCKET, const char*, int, int, const sockaddr*, int);

uint8_t*     g_base = nullptr;
uint8_t*     g_end = nullptr;
FNameEntry** g_pools = nullptr;
TArray<UObject*>* g_objs = nullptr;
FILE*        g_log = nullptr;
void**       g_gnatives = nullptr;
size_t       g_propOffsetAt = 0;
RecvFromFn   g_realRecvFrom = nullptr;
SendToFn     g_realSendTo = nullptr;

void L(const char* fmt, ...) {
    if (!g_log) return;
    SYSTEMTIME st; GetLocalTime(&st);
    va_list a; va_start(a, fmt);
    fprintf(g_log, "%02d:%02d:%02d.%03d  ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    vfprintf(g_log, fmt, a);
    fputc('\n', g_log);
    fflush(g_log);
    va_end(a);
}

// --- GObjects and names (as mp_save) --------------------------------------------

const char* NameOf(const FName& n) {
    if (!g_pools || n.Chunk > 7) return "<bad>";
    FNameEntry* c = g_pools[n.Chunk];
    if (!c) return "<null>";
    auto* e = (FNameEntry*)((uint8_t*)c + n.Offset);
    return IsBadReadPtr(e, 16) ? "<unreadable>" : e->AnsiName;
}
const char* ClassNameOf(UObject* o) {
    UObject* c = o->Class;
    return (c && !IsBadReadPtr(c, sizeof(UObject))) ? NameOf(c->Name) : "?";
}
UObject* SlotAt(int i) {
    if (!g_objs || IsBadReadPtr(g_objs, sizeof(*g_objs))) return nullptr;
    UObject** data = g_objs->Data;
    if (!data || i < 0 || i >= g_objs->Count || i >= g_objs->Max) return nullptr;
    if (IsBadReadPtr(data + i, sizeof(UObject*))) return nullptr;
    return data[i];
}
bool InExe(void* p) { return (uint8_t*)p >= g_base && (uint8_t*)p < g_end; }

UObject* FindFieldByName(UObject* cls, const char* want) {
    for (UObject* c = cls; c && !IsBadReadPtr(c, 0x80); c = *(UObject**)((uint8_t*)c + OFF_FIELD_SUPER))
        for (UObject* f = *(UObject**)((uint8_t*)c + OFF_STRUCT_CHILDREN); f && !IsBadReadPtr(f, 0x80);
             f = *(UObject**)((uint8_t*)f + OFF_FIELD_NEXT))
            if (_stricmp(NameOf(f->Name), want) == 0) return f;
    return nullptr;
}
size_t PropertyOffset(UObject* cls, const char* name) {
    if (!g_propOffsetAt || !cls) return 0;
    UObject* f = FindFieldByName(cls, name);
    if (!f || IsBadReadPtr((uint8_t*)f + g_propOffsetAt, 4)) return 0;
    return *(uint32_t*)((uint8_t*)f + g_propOffsetAt);
}
// mp_save's calibration: Pawn.Mesh's UProperty must hold OFF_PAWN_MESH at
// exactly one position. 1 done, 0 not loaded yet, -1 refused.
int CalibratePropertyOffset() {
    UObject* pawnCls = nullptr;
    for (int i = 0; i < g_objs->Count && !pawnCls; ++i) {
        UObject* o = SlotAt(i);
        if (!o || IsBadReadPtr(o, 0x60)) continue;
        if (_stricmp(ClassNameOf(o), "Class") == 0 && _stricmp(NameOf(o->Name), "Pawn") == 0) pawnCls = o;
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
    return 1;
}

// --- the engine and its lock -------------------------------------------------------

CRITICAL_SECTION g_cs;
struct Lock { Lock() { EnterCriticalSection(&g_cs); } ~Lock() { LeaveCriticalSection(&g_cs); } };
voice::Engine g_engine;

struct Heard { uint64_t sender; uint16_t seq; std::vector<uint8_t> payload; };
std::deque<std::vector<int16_t>> g_captured;   // device thread -> worker
std::deque<Heard> g_heard;                      // recvfrom -> worker
std::map<std::string, SOCKET> g_peerSocket;     // which game socket reaches a peer
struct Seen { uint32_t sent = 0, recv = 0; };
std::map<std::string, Seen> g_seen;             // per address, both directions
uint32_t g_lastPeer = 0;
// What the log's "voice:" summary counts (under g_cs): one-way voice —
// the client heard the host, but the host never heard the client — could
// not be told apart from the logs: a sender whose microphone or
// mode keeps it silent and a datagram dropped on arrival looked the same.
struct VoiceStats { int captured = 0, gateOpen = 0, sent = 0, heard = 0, dropped = 0; };
VoiceStats g_stats;
std::set<std::string> g_loggedDrop;   // one log line per address / id and reason

std::unique_ptr<voice::Audio> g_audio;
voice::Gate g_gate;
int g_inputDev = -1, g_outputDev = -1;
// True once GNatives is known and every SFXOnlineComponentVoiceInterface
// native is hooked — the script side actually works. On one machine,
// GNatives was never found ("ABORT: GNatives not found; natives not hooked;
// voice has no script side"), yet audio started anyway at the first join,
// because NoteTraffic (on the socket hooks, independent of native hooking)
// set g_audioWanted from game traffic alone. Gate audio on this instead.
std::atomic<bool> g_scriptHooked{false};
bool g_audioWanted = false;
bool g_audioRestart = false;   // a device changed: reopen
// MPVoiceContinueOnLostFocus, 2012's "Force Voice Chat Audio": hear voice
// while the game is not the foreground window. Off (2012's default): silent.
bool g_hearUnfocused = false;
volatile bool g_focused = true;   // the worker refreshes it (GetForegroundWindow)

bool GameFocused() {
    DWORD pid = 0;
    HWND fg = GetForegroundWindow();
    if (fg) GetWindowThreadProcessId(fg, &pid);
    return pid == GetCurrentProcessId();
}

uint32_t Now() { return GetTickCount(); }
// An address as family, address and port only, rebuilt zeroed: the game's
// sendto sockaddr may carry junk in sin_zero where recvfrom's has zeros, and
// the same peer must give one key both ways. Empty for other families.
std::string Key(const sockaddr* a, int len) {
    if (a->sa_family == AF_INET && len >= (int)sizeof(sockaddr_in)) {
        sockaddr_in k; memset(&k, 0, sizeof(k));
        k.sin_family = AF_INET;
        k.sin_port = ((const sockaddr_in*)a)->sin_port;
        k.sin_addr = ((const sockaddr_in*)a)->sin_addr;
        return std::string((const char*)&k, sizeof(k));
    }
    if (a->sa_family == AF_INET6 && len >= (int)sizeof(sockaddr_in6)) {
        sockaddr_in6 k; memset(&k, 0, sizeof(k));
        k.sin6_family = AF_INET6;
        k.sin6_port = ((const sockaddr_in6*)a)->sin6_port;
        k.sin6_addr = ((const sockaddr_in6*)a)->sin6_addr;
        k.sin6_scope_id = ((const sockaddr_in6*)a)->sin6_scope_id;
        return std::string((const char*)&k, sizeof(k));
    }
    return std::string();
}
std::string Show(const std::string& key) {
    char host[64] = "?"; unsigned port = 0;
    const sockaddr* a = (const sockaddr*)key.data();
    if (a->sa_family == AF_INET && key.size() >= sizeof(sockaddr_in)) {
        auto* s = (const sockaddr_in*)a; inet_ntop(AF_INET, &s->sin_addr, host, sizeof(host)); port = ntohs(s->sin_port);
    } else if (a->sa_family == AF_INET6 && key.size() >= sizeof(sockaddr_in6)) {
        auto* s = (const sockaddr_in6*)a; inet_ntop(AF_INET6, &s->sin6_addr, host, sizeof(host)); port = ntohs(s->sin6_port);
    }
    return std::string(host) + ":" + std::to_string(port);
}

// --- settings: LEMP\voice.txt -----------------------------------------------------

// 2: the microphone defaults to off (mode 2, "No Voice").
constexpr int kSettingsVersion = 2;
std::wstring SettingsPath() { return LempDir() + L"\\voice.txt"; }
void SaveSettings() {
    FILE* f = _wfopen(SettingsPath().c_str(), L"w");
    if (!f) return;
    voice::Mode m = g_engine.GetMode();
    fprintf(f, "version=%d\nmode=%s\ninput=%d\noutput=%d\nvolume=%d\nunfocused=%d\n",
            kSettingsVersion, m == voice::Mode::OpenMic ? "open" : m == voice::Mode::Off ? "off" : "ptt",
            g_inputDev, g_outputDev, (int)(g_engine.Volume() * 100 + 0.5f), g_hearUnfocused ? 1 : 0);
    fclose(f);
}
void LoadSettings() {
    FILE* f = _wfopen(SettingsPath().c_str(), L"r");
    if (!f) { L("settings: no voice.txt; microphone off, default devices, volume 100"); return; }
    char line[128];
    int version = 0;
    char mode[64] = "off";
    while (fgets(line, sizeof(line), f)) {
        char k[32] = {0}, v[64] = {0};
        if (sscanf(line, "%31[^=]=%63s", k, v) != 2) continue;
        if (!strcmp(k, "version")) version = atoi(v);
        else if (!strcmp(k, "mode")) snprintf(mode, sizeof(mode), "%s", v);
        else if (!strcmp(k, "input")) g_inputDev = atoi(v);
        else if (!strcmp(k, "output")) g_outputDev = atoi(v);
        else if (!strcmp(k, "volume")) g_engine.SetVolume(atoi(v) / 100.0f);
        else if (!strcmp(k, "unfocused")) g_hearUnfocused = atoi(v) != 0;
    }
    fclose(f);
    // A file from before version 2 holds push to talk because that was the
    // default, not a choice: such a
    // file starts with the microphone off too.
    if (version < kSettingsVersion) L("settings: voice.txt from before version %d; microphone off", kSettingsVersion);
    else g_engine.SetMode(!strcmp(mode, "open") ? voice::Mode::OpenMic : !strcmp(mode, "ptt") ? voice::Mode::PushToTalk : voice::Mode::Off);
    L("settings: mode %d, input %d, output %d, volume %.2f", (int)g_engine.GetMode(), g_inputDev, g_outputDev, g_engine.Volume());
}

// --- sending (any thread) ----------------------------------------------------------

void SendAll(const std::vector<voice::Send>& sends) {
    for (auto& s : sends) {
        SOCKET sock;
        {
            Lock l;
            auto it = g_peerSocket.find(s.to);
            if (it == g_peerSocket.end()) continue;
            sock = it->second;
        }
        g_realSendTo(sock, (const char*)s.bytes.data(), (int)s.bytes.size(), 0,
                     (const sockaddr*)s.to.data(), (int)s.to.size());
    }
}

// --- the socket hooks (the game's net thread) -----------------------------------------

std::set<SOCKET> g_udp, g_notUdp;   // under g_cs
bool IsUdp(SOCKET s) {
    if (g_udp.count(s)) return true;
    if (g_notUdp.count(s)) return false;
    int type = 0, len = sizeof(type);
    bool udp = getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&type, &len) == 0 && type == SOCK_DGRAM;
    (udp ? g_udp : g_notUdp).insert(s);
    return udp;
}

void NoteTraffic(SOCKET s, const sockaddr* a, int len, bool sent) {
    if (!a || len <= 0 || len > (int)sizeof(sockaddr_storage)) return;
    uint32_t now = Now();
    std::string k = Key(a, len);
    if (k.empty()) return;
    Lock l;
    if (!IsUdp(s)) return;
    Seen& seen = g_seen[k];
    (sent ? seen.sent : seen.recv) = now;
    if (seen.sent && seen.recv && now - seen.sent < 5000 && now - seen.recv < 5000) {
        bool isNew = !g_peerSocket.count(k);
        g_peerSocket[k] = s;
        g_engine.NoteGameTraffic(k, now);
        g_lastPeer = now;
        // Peer bookkeeping and relay for OTHER already-hooked peers still work
        // either way (Received()/the forward path do not depend on this
        // flag); only OUR OWN audio is gated, so it never opens a mic/speaker
        // — "fully off" in the way that is actually audible — while the
        // script side is not confirmed hooked.
        if (g_scriptHooked.load(std::memory_order_relaxed)) {
            g_audioWanted = true;
        } else {
            static uint32_t lastWarn = 0;
            if (now - lastWarn > 10000) { lastWarn = now; L("traffic seen but script side not hooked yet; audio stays off"); }
        }
        if (isNew) L("peer: %s (socket %llu)", Show(k).c_str(), (unsigned long long)s);
    }
}

int WSAAPI HookSendTo(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen) {
    // Called by the game itself (the game's net thread), not one of our own
    // background threads, so this is not the race the other checks guard
    // against; it is cheap insurance anyway, and stops voice touching
    // GObjects (NoteTraffic -> g_engine) once the engine starts tearing down.
    if (lemp::Exiting()) return g_realSendTo(s, buf, len, flags, to, tolen);
    NoteTraffic(s, to, tolen, true);
    return g_realSendTo(s, buf, len, flags, to, tolen);
}

int WSAAPI HookRecvFrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen) {
    if (lemp::Exiting()) return g_realRecvFrom(s, buf, len, flags, from, fromlen);
    int cap = fromlen ? *fromlen : 0;
    for (;;) {
        if (fromlen) *fromlen = cap;
        int n = g_realRecvFrom(s, buf, len, flags, from, fromlen);
        if (n <= 0 || !from || !fromlen || (flags & MSG_PEEK)) return n;
        if (!voice::IsVoice((const uint8_t*)buf, (size_t)n)) {
            NoteTraffic(s, from, *fromlen, false);
            return n;
        }
        // Ours: play and relay it, then read the next datagram for the game.
        std::vector<voice::Send> fwd;
        {
            Lock l;
            voice::Frame f;
            std::string k = Key(from, *fromlen);
            uint64_t sender = voice::Get64((const uint8_t*)buf + 8);   // IsVoice: the header is whole
            if (!k.empty() && g_peerSocket.count(k)) {   // voice only from a peer of the game's
                bool before = g_engine.RemoteStatus(sender) != 0;
                if (sender && sender == g_engine.LocalId()) {
                    // Received() drops it as our own echo: if it is not ours,
                    // two players share an id and this one is never heard.
                    ++g_stats.dropped;
                    if (g_loggedDrop.insert("own:" + k).second)
                        L("voice from %s carries OUR id %016llx: dropped as our own echo (two players with one id?)",
                          Show(k).c_str(), (unsigned long long)sender);
                }
                fwd = g_engine.Received(k, (const uint8_t*)buf, (size_t)n, Now(), &f);
                if (!f.payload.empty()) ++g_stats.heard;
                if (!before && g_engine.RemoteStatus(sender) != 0)
                    L("heard: first frame from %016llx via %s%s", (unsigned long long)sender, Show(k).c_str(),
                      g_engine.Muted(sender) ? " (muted here)" : "");
                if (!f.payload.empty() && g_heard.size() < 64) g_heard.push_back({f.sender, f.seq, std::move(f.payload)});
            } else {
                ++g_stats.dropped;
                if (g_loggedDrop.insert("addr:" + k).second)
                    L("voice from %s (id %016llx) dropped: not an address the game's socket talks to", Show(k).c_str(),
                      (unsigned long long)sender);
            }
        }
        SendAll(fwd);
        // Read again for the game only if a datagram is waiting: UE3's socket
        // is non-blocking [R], but a blocking one must not stall here.
        fd_set rd; FD_ZERO(&rd); FD_SET(s, &rd);
        timeval zero = {0, 0};
        if (select(0, &rd, nullptr, nullptr, &zero) <= 0) {
            WSASetLastError(WSAEWOULDBLOCK);
            return SOCKET_ERROR;
        }
    }
}

// The exe's import slots for recvfrom/sendto: every pointer-sized value equal
// to the real function in the exe's non-executable sections (the IAT, wherever
// the unpacker put it). The count is logged; each is replaced.
int PatchImport(void* real, void* hook, const char* what) {
    auto* dos = (IMAGE_DOS_HEADER*)g_base;
    auto* nt = (IMAGE_NT_HEADERS64*)(g_base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    int patched = 0;
    for (int s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
        if (sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
        if (!(sec[s].Characteristics & IMAGE_SCN_MEM_READ)) continue;
        void** q = (void**)(g_base + sec[s].VirtualAddress);
        size_t n = sec[s].Misc.VirtualSize / 8;
        for (size_t i = 0; i < n; ++i) {
            if (q[i] != real) continue;
            DWORD old;
            if (!VirtualProtect(&q[i], sizeof(void*), PAGE_READWRITE, &old)) continue;
            q[i] = hook;
            VirtualProtect(&q[i], sizeof(void*), old, &old);
            L("import: %s slot at rva 0x%llx -> hook", what, (unsigned long long)((uint8_t*)&q[i] - g_base));
            ++patched;
        }
    }
    return patched;
}

// --- the script stack -----------------------------------------------------------------

// FFrame: Node, Object, Code at consecutive qwords (UE3's order); g_offCode is
// proven on the first call, 0 until then, SIZE_MAX if it could not be.
size_t g_offCode = 0;
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

bool ProveFrame(uint8_t* stack, const char* fn) {
    if (g_offCode == kUnproven) return false;
    if (g_offCode) return CodeInsideNode(stack, g_offCode);
    static const size_t kTry[] = {0x28, 0x20, 0x30, 0x38};
    int hits = 0; size_t hit = 0;
    for (size_t off : kTry) if (CodeInsideNode(stack, off)) { ++hits; hit = off; }
    if (hits == 1) {
        g_offCode = hit;
        L("FFRAME: Code at +0x%zx (Node +0x%zx, Object +0x%zx), proven on %s", hit, hit - 16, hit - 8, fn);
        return true;
    }
    g_offCode = kUnproven;
    L("FFRAME: %d candidate layouts on %s: refusing to read script stacks; voice stays off", hits, fn);
    return false;
}

uint8_t*& Code(uint8_t* stack) { return *(uint8_t**)(stack + g_offCode); }
UObject* FrameObject(uint8_t* stack) { return *(UObject**)(stack + g_offCode - 8); }

// Stack.Step(Stack.Object, out).
void Step(uint8_t* stack, void* out) {
    uint8_t op = *Code(stack);
    ++Code(stack);
    ((NativeFn)g_gnatives[op])(FrameObject(stack), stack, out);
}
uint8_t GetByte(uint8_t* s)  { alignas(16) uint8_t v[16] = {0}; Step(s, v); return v[0]; }
int32_t GetInt(uint8_t* s)   { alignas(16) uint8_t v[16] = {0}; Step(s, v); int32_t r; memcpy(&r, v, 4); return r; }
float   GetFloat(uint8_t* s) { alignas(16) uint8_t v[16] = {0}; Step(s, v); float r; memcpy(&r, v, 4); return r; }
bool    GetBool(uint8_t* s)  { alignas(16) uint8_t v[16] = {0}; Step(s, v); uint32_t r; memcpy(&r, v, 4); return r != 0; }
uint64_t GetNetId(uint8_t* s){ alignas(16) uint8_t v[32] = {0}; Step(s, v); uint64_t r; memcpy(&r, v, 8); return r; }
void Finish(uint8_t* stack, const char* fn) {
    if (*Code(stack) != EX_EndFunctionParms) {
        static int warned = 0;
        if (warned++ < 5) L("FINISH: %s ends on opcode 0x%02x, not EndFunctionParms", fn, *Code(stack));
    }
    ++Code(stack);   // P_FINISH
}
void RetBool(void* r, bool v) { if (r) *(uint32_t*)r = v ? 1 : 0; }
void RetInt(void* r, int32_t v) { if (r) *(int32_t*)r = v; }

// --- the local player's id -------------------------------------------------------------

UObject* g_localPc = nullptr;
uint32_t g_lastIdScan = 0;
size_t g_offPri = 0, g_offPlayer = 0, g_offUniqueId = 0;

void RefreshLocalId() {
    uint32_t now = Now();
    if (g_lastIdScan && now - g_lastIdScan < 2000) return;
    g_lastIdScan = now;
    if (!g_offPlayer || !g_offPri || !g_offUniqueId) return;
    // Revalidate the cached controller: still in its GObjects slot, still has a Player.
    if (g_localPc && (SlotAt(g_localPc->InternalIndex) != g_localPc || !*(void**)((uint8_t*)g_localPc + g_offPlayer)))
        g_localPc = nullptr;
    if (!g_localPc) {
        for (int i = 0; i < g_objs->Count; ++i) {
            UObject* o = g_objs->Data[i];
            if (!o || !o->Class || _stricmp(NameOf(o->Class->Name), "SFXPlayerControllerMP") != 0) continue;
            if (strncmp(NameOf(o->Name), "Default__", 9) == 0) continue;
            if (*(void**)((uint8_t*)o + g_offPlayer)) { g_localPc = o; break; }
        }
    }
    if (!g_localPc) return;
    uint8_t* pri = *(uint8_t**)((uint8_t*)g_localPc + g_offPri);
    if (!pri) return;
    uint64_t id; memcpy(&id, pri + g_offUniqueId, 8);
    Lock l;
    if (id != g_engine.LocalId()) {
        L("local id: %016llx (was %016llx)%s", (unsigned long long)id, (unsigned long long)g_engine.LocalId(),
          id ? "" : " — zero: this player cannot send until the host gives it an id");
        g_engine.SetLocalId(id);
    }
}

void LogIdOnce(uint64_t id, const char* fn) {
    static std::set<uint64_t> seen;
    if (seen.size() < 64 && seen.insert(id).second) L("asked about id %016llx (%s)", (unsigned long long)id, fn);
}

// --- the natives ------------------------------------------------------------------------

// The game's own thunk of each hooked native, by its index in kNatives
// (written by the install thread before the hook goes in, read on the game
// thread inside the hook).
const int kMaxNatives = 32;
ExecFn volatile g_original[kMaxNatives] = {};
int IndexOf(const char* name);

// Each one: if the stack cannot be read safely, LE3's own native does the call.
#define PROLOGUE(NAME)                                                       \
    if (!ProveFrame(stack, NAME)) {                                          \
        ExecFn o = g_original[IndexOf(NAME)];                                \
        if (o) o(self, stack, result);                                       \
        return;                                                              \
    }                                                                        \
    RefreshLocalId();

void N_PushToTalkStart(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("PushToTalkStart");
    Finish(stack, "PushToTalkStart");
    Lock l; g_engine.PushToTalk(true);
}
void N_PushToTalkEnd(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("PushToTalkEnd");
    Finish(stack, "PushToTalkEnd");
    Lock l; g_engine.PushToTalk(false);
}
void N_IsHeadsetPresent(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("IsHeadsetPresent");
    GetByte(stack); Finish(stack, "IsHeadsetPresent");
    Lock l; RetBool(result, g_engine.Headset());
}
void N_IsLocalPlayerTalking(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("IsLocalPlayerTalking");
    GetByte(stack); Finish(stack, "IsLocalPlayerTalking");
    Lock l; RetBool(result, g_engine.LocalTalking(Now()));
}
void N_IsRemotePlayerTalking(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("IsRemotePlayerTalking");
    uint64_t id = GetNetId(stack); Finish(stack, "IsRemotePlayerTalking");
    LogIdOnce(id, "IsRemotePlayerTalking");
    Lock l; RetBool(result, id && g_engine.RemoteTalking(id, Now()));
}
void N_GetRemotePlayerStatus(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("GetRemotePlayerStatus");
    uint64_t id = GetNetId(stack); Finish(stack, "GetRemotePlayerStatus");
    LogIdOnce(id, "GetRemotePlayerStatus");
    Lock l; RetInt(result, id ? g_engine.RemoteStatus(id) : 0);
}
void N_IsRemoteTalkerMuted(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("IsRemoteTalkerMuted");
    GetByte(stack); uint64_t id = GetNetId(stack); Finish(stack, "IsRemoteTalkerMuted");
    Lock l; RetBool(result, id && g_engine.Muted(id));
}
void N_MuteRemoteTalker(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("MuteRemoteTalker");
    GetByte(stack); uint64_t id = GetNetId(stack); Finish(stack, "MuteRemoteTalker");
    Lock l;
    if (id) { g_engine.Mute(id, true); L("muted %016llx", (unsigned long long)id); }
    RetBool(result, id != 0);
}
void N_UnmuteRemoteTalker(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("UnmuteRemoteTalker");
    GetByte(stack); uint64_t id = GetNetId(stack); Finish(stack, "UnmuteRemoteTalker");
    Lock l;
    if (id) { g_engine.Mute(id, false); L("unmuted %016llx", (unsigned long long)id); }
    RetBool(result, id != 0);
}
void N_MuteAll(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("MuteAll");
    GetByte(stack); GetBool(stack); Finish(stack, "MuteAll");
    Lock l; g_engine.MuteAll(true); RetBool(result, true);
}
void N_UnmuteAll(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("UnmuteAll");
    GetByte(stack); Finish(stack, "UnmuteAll");
    Lock l; g_engine.MuteAll(false); RetBool(result, true);
}
void N_SetVoiceMode(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("SetVoiceMode");
    int32_t m = GetInt(stack); Finish(stack, "SetVoiceMode");
    // MPVoiceChatMode, 2012's OPTION_MPVoiceChatMode (BioSFHandler_Options,
    // TLK 708509-708511): 0 Push To Talk, 1 Always On, 2 No Voice [V].
    L("SetVoiceMode(%d)", m);
    Lock l;
    g_engine.SetMode(m == 1 ? voice::Mode::OpenMic : m == 2 ? voice::Mode::Off : voice::Mode::PushToTalk);
    SaveSettings();
}
void N_SetVolume(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("SetVolume");
    float v = GetFloat(stack); Finish(stack, "SetVolume");
    L("SetVolume(%.3f)", v);
    Lock l;
    g_engine.SetVolume(v > 2.0f ? v / 100.0f : v);   // MPVoiceChatVolume is 0-100
    SaveSettings();
    RetBool(result, true);
}
void N_SetInputDevice(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("SetInputDevice");
    int32_t d = GetInt(stack); Finish(stack, "SetInputDevice");
    L("SetInputDevice(%d)", d);
    Lock l; g_inputDev = d; g_audioRestart = true; SaveSettings(); RetBool(result, true);
}
void N_SetOutputDevice(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("SetOutputDevice");
    int32_t d = GetInt(stack); Finish(stack, "SetOutputDevice");
    L("SetOutputDevice(%d)", d);
    Lock l; g_outputDev = d; g_audioRestart = true; SaveSettings(); RetBool(result, true);
}
void N_GetDefaultInputDevice(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("GetDefaultInputDevice");
    Finish(stack, "GetDefaultInputDevice");
    RetInt(result, voice::DefaultInputDevice());
}
void N_GetDefaultOutputDevice(UObject* self, uint8_t* stack, void* result) {
    PROLOGUE("GetDefaultOutputDevice");
    Finish(stack, "GetDefaultOutputDevice");
    RetInt(result, voice::DefaultOutputDevice());
}

struct Hooked {
    const char* name;
    ExecFn      ours;
    UObject*    fn;
};
Hooked kNatives[] = {
    {"PushToTalkStart", N_PushToTalkStart, nullptr},
    {"PushToTalkEnd", N_PushToTalkEnd, nullptr},
    {"IsHeadsetPresent", N_IsHeadsetPresent, nullptr},
    {"IsLocalPlayerTalking", N_IsLocalPlayerTalking, nullptr},
    {"IsRemotePlayerTalking", N_IsRemotePlayerTalking, nullptr},
    {"GetRemotePlayerStatus", N_GetRemotePlayerStatus, nullptr},
    {"IsRemoteTalkerMuted", N_IsRemoteTalkerMuted, nullptr},
    {"MuteRemoteTalker", N_MuteRemoteTalker, nullptr},
    {"UnmuteRemoteTalker", N_UnmuteRemoteTalker, nullptr},
    {"MuteAll", N_MuteAll, nullptr},
    {"UnmuteAll", N_UnmuteAll, nullptr},
    {"SetVoiceMode", N_SetVoiceMode, nullptr},
    {"SetVolume", N_SetVolume, nullptr},
    {"SetInputDevice", N_SetInputDevice, nullptr},
    {"SetOutputDevice", N_SetOutputDevice, nullptr},
    {"GetDefaultInputDevice", N_GetDefaultInputDevice, nullptr},
    {"GetDefaultOutputDevice", N_GetDefaultOutputDevice, nullptr},
};
const int kNativeCount = sizeof(kNatives) / sizeof(kNatives[0]);
static_assert(sizeof(kNatives) / sizeof(kNatives[0]) <= kMaxNatives, "g_original too small");
int IndexOf(const char* name) {
    for (int i = 0; i < kNativeCount; ++i) if (!strcmp(kNatives[i].name, name)) return i;
    return 0;
}

// --- install -------------------------------------------------------------------------------

// GNatives: no longer searched here. mp_save finds and verifies it (its own
// header comment, "Finding GNatives"), reusing SaveConfig's thunk and the
// indexed natives bound in GObjects AT THAT MOMENT as the needle; it is a
// one-shot search there too, but one taken much earlier in boot (mp_save's
// gate is just Core/Engine up), when apparently enough natives are already
// bound.
//
// voice's OWN one-shot search, gated on the SFXOnlineComponent-
// VoiceInterface natives additionally being present (necessarily later in
// boot than mp_save's gate), once failed outright on a slower machine ("ABORT:
// GNatives not found") while mp_save's own search succeeded there (its
// mp_save_*.txt has the GNATIVES line) — two independent one-shot searches,
// each exposed to whatever indexed natives happen to be bound at its own
// sampling instant, is strictly worse than one proven search shared by both.
// So: wait for mp_save's result instead of searching again.

// 1 done, 0 not yet (retry), -1 give up (a genuine build mismatch, not "not found yet").
int Install() {
    int voiceFns = 0;
    for (int i = 0; i < g_objs->Count; ++i) {
        UObject* o = SlotAt(i);
        if (!o || IsBadReadPtr(o, 0xF0) || _stricmp(ClassNameOf(o), "Function") != 0) continue;
        const char* on = NameOf(o->Name);
        const char* outer = (o->Outer && !IsBadReadPtr(o->Outer, sizeof(UObject))) ? NameOf(o->Outer->Name) : "";
        if (_stricmp(outer, "SFXOnlineComponentVoiceInterface") == 0)
            for (int k = 0; k < kNativeCount; ++k)
                if (_stricmp(on, kNatives[k].name) == 0) { kNatives[k].fn = o; ++voiceFns; }
    }
    if (voiceFns < kNativeCount) return 0;   // SFXOnlineComponentVoiceInterface not loaded yet
    if (!g_propOffsetAt) {
        int cal = CalibratePropertyOffset();
        if (cal == 0) return 0;
        if (cal < 0) return -1;
    }
    g_gnatives = LempGNatives();
    if (!g_gnatives) return 0;   // mp_save has not found it yet (or never will): keep waiting
    L("GNatives at rva 0x%llx (mp_save's result, shared); %d voice natives found",
      (unsigned long long)((uint8_t*)g_gnatives - g_base), voiceFns);

    // Property offsets for the local id (by name; LExSDK: 0x3C4, 0x67C, 0x270).
    UObject* pcCls = nullptr; UObject* priCls = nullptr;
    for (int i = 0; i < g_objs->Count && (!pcCls || !priCls); ++i) {
        UObject* o = SlotAt(i);
        if (!o || IsBadReadPtr(o, 0x60) || _stricmp(ClassNameOf(o), "Class") != 0) continue;
        if (_stricmp(NameOf(o->Name), "PlayerController") == 0) pcCls = o;
        if (_stricmp(NameOf(o->Name), "PlayerReplicationInfo") == 0) priCls = o;
    }
    g_offPri = PropertyOffset(pcCls, "PlayerReplicationInfo");
    g_offPlayer = PropertyOffset(pcCls, "Player");
    g_offUniqueId = PropertyOffset(priCls, "UniqueId");
    L("offsets: Controller.PlayerReplicationInfo +0x%zx, PlayerController.Player +0x%zx, PRI.UniqueId +0x%zx",
      g_offPri, g_offPlayer, g_offUniqueId);
    return 1;
}

// Take each native over once the game has bound it (we keep its thunk as the
// original); one not yet bound is taken over only once the frame layout is
// proven (it then never needs the original). Again whenever the game re-binds.
void HookNatives() {
    for (int k = 0; k < kNativeCount; ++k) {
        Hooked& h = kNatives[k];
        if (!h.fn) continue;
        void** slot = (void**)((uint8_t*)h.fn + OFF_FUNC_FUNC);
        // Once, on 0.4.3, this read faulted (lemp.asi+0x50915,
        // READ of an unmapped UFunction) while the game was being closed, with
        // GCallbackEvent still set, so lemp::Exiting() had not tripped yet.
        // The engine frees objects before appPreExit; check as mp_menu does.
        if (IsBadReadPtr(slot, sizeof(void*))) continue;
        void* cur = *slot;
        if (cur == (void*)h.ours) continue;
        if (cur) {
            if (!InExe(cur)) continue;
            g_original[k] = (ExecFn)cur;
            *slot = (void*)h.ours;
            L("HOOKED %s (game's thunk rva 0x%llx)", h.name, (unsigned long long)((uint8_t*)cur - g_base));
        } else if (g_offCode && g_offCode != kUnproven) {
            *slot = (void*)h.ours;
            L("HOOKED %s (not yet bound by the game)", h.name);
        }
    }
}

// --- the worker: encode, decode, open and close the devices -----------------------------------

std::map<uint64_t, voice::Decoder> g_decoders;

void StartAudio() {
    g_audio.reset(new voice::Audio);
    g_audio->onCaptured = [](const int16_t* pcm) {
        Lock l;
        if (g_captured.size() < 10) g_captured.emplace_back(pcm, pcm + voice::kFrameSamples);
    };
    g_audio->onPlayback = [](int16_t* out) {
        Lock l;
        g_engine.Mix(out);   // drains the queues either way
        if (!g_hearUnfocused && !g_focused) memset(out, 0, voice::kFrameSamples * sizeof(int16_t));
    };
    // The options rows show devices by number; this says which is which.
    if (FILE* f = _wfopen((LempDir() + L"\\voice_devices.txt").c_str(), L"w")) {
        fprintf(f, "LEMP voice chat devices, as the options screen numbers them.\n\nInput (microphone):\n");
        auto ins = voice::InputDevices(), outs = voice::OutputDevices();
        for (size_t i = 0; i < ins.size(); ++i) fprintf(f, "  Device %zu: %s\n", i + 1, ins[i].c_str());
        fprintf(f, "\nOutput (speakers):\n");
        for (size_t i = 0; i < outs.size(); ++i) fprintf(f, "  Device %zu: %s\n", i + 1, outs[i].c_str());
        fclose(f);
    }
    int in, out;
    { Lock l; in = g_inputDev; out = g_outputDev; }
    bool ok = g_audio->Start(in, out);
    Lock l;
    g_engine.SetHeadset(g_audio->CaptureRunning());
    L("audio: %s (microphone %s, speakers %s) %s", ok ? "started" : "FAILED",
      g_audio->CaptureRunning() ? "on" : "off", g_audio->PlaybackRunning() ? "on" : "off", g_audio->Error().c_str());
}
void StopAudio(const char* why) {
    g_audio.reset();
    Lock l;
    g_engine.SetHeadset(false);
    g_captured.clear();
    L("audio: stopped (%s)", why);
}

DWORD WINAPI Worker(LPVOID) {
    voice::Encoder enc;
    if (!enc.Ok()) L("opus: encoder failed");
    std::vector<int16_t> pcm(voice::kFrameSamples);
    for (;;) {
        Sleep(5);
        // lemp.asi+0x44f95 is in this
        // module (strings "local id" / ws2_32 nearby in the stripped build);
        // which of voice's several background loops it actually is was not
        // narrowed further (0.3.0 was stripped). This is the one that runs
        // unconditionally every 5 ms for as long as the process lives, so it
        // gets the check regardless.
        if (lemp::Exiting()) { L("stopping: engine exiting"); return 0; }
        uint32_t now = Now();
        g_focused = GameFocused();
        bool want, restart, have = g_audio != nullptr;
        {
            Lock l;
            want = g_audioWanted && now - g_lastPeer < 30000;
            if (!want) g_audioWanted = false;
            restart = g_audioRestart; g_audioRestart = false;
        }
        if (have && restart) { StopAudio("a device changed"); have = false; }
        if (want && !have) StartAudio();
        else if (!want && have) StopAudio("no peers for 30 s");

        // Captured frames -> Opus -> every peer.
        for (;;) {
            std::vector<int16_t> frame;
            bool tx;
            {
                Lock l;
                if (g_captured.empty()) break;
                frame = std::move(g_captured.front()); g_captured.pop_front();
                bool voiced = g_gate.Voiced(frame.data(), (int)frame.size());
                tx = g_engine.Transmitting(voiced);
                ++g_stats.captured;
                if (voiced) ++g_stats.gateOpen;
            }
            if (!tx) continue;
            std::vector<uint8_t> pkt = enc.Encode(frame.data());
            std::vector<voice::Send> sends;
            { Lock l; sends = g_engine.LocalFrame(pkt, Now()); if (!sends.empty()) ++g_stats.sent; }
            SendAll(sends);
        }
        // Every 15 s with the devices open: what was captured, what passed
        // the gate, what went out and came in, and every reason not to send.
        static uint32_t lastStats = 0;
        if (!lastStats) lastStats = now;
        if (now - lastStats >= 15000) {
            lastStats = now;
            Lock l;
            if (g_audio && (g_stats.captured || g_stats.heard || g_stats.dropped)) {
                static const char* kModes[] = {"push to talk", "always on", "off"};
                L("voice: 15 s: captured %d, above gate %d (peak %d, gate %d), sent %d, heard %d, dropped %d;"
                  " mode %s, tab %d, mic %d, id %016llx, peers %d",
                  g_stats.captured, g_stats.gateOpen, g_gate.TakePeak(), g_gate.Threshold(), g_stats.sent,
                  g_stats.heard, g_stats.dropped, kModes[(int)g_engine.GetMode()], g_engine.PushToTalkDown(),
                  g_engine.Headset(), (unsigned long long)g_engine.LocalId(), (int)g_engine.Peers(now).size());
            }
            g_stats = VoiceStats();
        }
        // Received frames -> PCM -> the talker's playout queue.
        for (;;) {
            Heard h;
            { Lock l; if (g_heard.empty()) break; h = std::move(g_heard.front()); g_heard.pop_front(); }
            voice::Decoder& d = g_decoders[h.sender];
            if (d.Decode(h.payload.data(), h.payload.size(), pcm.data())) { Lock l; g_engine.Queue(h.sender, pcm); }
        }
    }
    return 0;
}

// --- device names in the options rows ----------------------------------------------
//
// 2012's options native put each device's name into the Input/Output Device
// rows as text. LE3's movie still takes text (TextSliderMenuItem copies
// control.children[i].label into its text box), but LE3's native builds that
// text from the config line's string ids. So
// the ids the rows use are ours alone (lemp-strings.txt: 935821-935828 the
// microphones, 935831-935838 the speakers, "Device N" in the table) and the
// game's string lookup answers them with the device's name here.
//
// The lookup [V, static, MassEffect3_PATCHED.exe]: rva 0x97400,
// int (TlkManager*, int id, FString* out, int gender, int flag), 1 = found.
// Reached from Object.GetTokenisedString's native (via rva 0x97640) and every
// wrapper (rva 0x972d0, 59 callers; 0x973e0; 0x97330). Its first 12 bytes are
// position-independent (mov [rsp+10],edx; mov r11,rsp; push rdi/r12/r13), so
// they move to a trampoline whole. The FString is written through the game's
// own TArray resize (rva 0x73440: (array, prev, n, elemSize) -> appRealloc,
// as execGetTokenisedString copies its result), so the game frees it.
// Control: LEMP\novoice.txt (nothing hooked at all).
constexpr uintptr_t RVA_TLK_LOOKUP = 0x97400;
constexpr uintptr_t RVA_ARRAY_RESIZE = 0x73440;
constexpr int TLK_INPUT_FIRST = 935821, TLK_OUTPUT_FIRST = 935831, TLK_SLOTS = 8;
const uint8_t TLK_LOOKUP_PROLOGUE[12] = {0x89, 0x54, 0x24, 0x10, 0x4C, 0x8B, 0xDC, 0x57, 0x41, 0x54, 0x41, 0x55};
const uint8_t ARRAY_RESIZE_PROLOGUE[9] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9};

struct FStringRaw { wchar_t* data; int32_t num; int32_t max; };
typedef int (*TlkLookupFn)(void* mgr, int id, FStringRaw* out, int gender, int flag);
typedef void (*ArrayResizeFn)(void* array, int prev, int n, int elemSize);
TlkLookupFn g_tlkOriginal = nullptr;   // the trampoline
ArrayResizeFn g_arrayResize = nullptr;

CRITICAL_SECTION g_namesCs;
std::vector<std::wstring> g_inNames, g_outNames;
bool g_nameLogged[2][TLK_SLOTS] = {};

std::vector<std::wstring> Wide(const std::vector<std::string>& v) {
    std::vector<std::wstring> out;
    for (const std::string& s : v) {
        int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        std::wstring w(n > 0 ? n - 1 : 0, L'\0');
        if (n > 1) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
        out.push_back(w);
    }
    return out;
}
// Enumerating is slow (the backend asks the system); the game thread's lookup
// only reads this copy. Refreshed at start and each time the rows are built.
void RefreshDeviceNames() {
    auto ins = Wide(voice::InputDevices()), outs = Wide(voice::OutputDevices());
    EnterCriticalSection(&g_namesCs);
    g_inNames.swap(ins); g_outNames.swap(outs);
    LeaveCriticalSection(&g_namesCs);
}

// DIAGNOSTIC: the device rows render blank, and
// this hook never logged a device id. Log the first lookup of each id the
// Sound page's rows use (row labels and stories, Voice Mode's values, which
// render, the device ids, which do not, and the base-game "Default"/"1".."8"
// the input row tries instead), answered here or not, so one run says
// whether the options screen asks this lookup for value labels at all.
int WatchSlot(int id) {
    static const int ranges[][2] = {{661520, 661525}, {708505, 708514}, {724749, 724750},
                                    {935820, 935838}, {163476, 163476}, {174566, 174573}};
    int base = 0;
    for (const auto& r : ranges) {
        if (id >= r[0] && id <= r[1]) return base + id - r[0];
        base += r[1] - r[0] + 1;
    }
    return -1;
}
std::atomic<bool> g_watchSeen[64];

int TlkLookupHook(void* mgr, int id, FStringRaw* out, int gender, int flag) {
    int watch = WatchSlot(id);
    if (watch >= 0 && !g_watchSeen[watch].exchange(true))
        L("tlk asked %d (gender %d, flag %d, out %s)", id, gender, flag, out ? "set" : "null");
    int list =id >= TLK_INPUT_FIRST && id < TLK_INPUT_FIRST + TLK_SLOTS ? 0
             : id >= TLK_OUTPUT_FIRST && id < TLK_OUTPUT_FIRST + TLK_SLOTS ? 1 : -1;
    if (list >= 0 && out) {
        int slot = id - (list ? TLK_OUTPUT_FIRST : TLK_INPUT_FIRST);
        std::wstring name;
        bool first = false;
        EnterCriticalSection(&g_namesCs);
        const auto& names = list ? g_outNames : g_inNames;
        if (slot < (int)names.size()) {
            name = names[slot];
            first = !g_nameLogged[list][slot];
            g_nameLogged[list][slot] = true;
        }
        LeaveCriticalSection(&g_namesCs);
        if (!name.empty()) {
            int n = (int)name.size() + 1;   // FString counts its terminator
            g_arrayResize(out, 0, n, sizeof(wchar_t));
            out->num = out->max = n;
            memcpy(out->data, name.c_str(), n * sizeof(wchar_t));
            if (first) L("tlk %d -> %s device %d: %ls", id, list ? "output" : "input", slot + 1, name.c_str());
            return 1;
        }
    }
    return g_tlkOriginal(mgr, id, out, gender, flag);
}

// Waits for the unpacker like the import patch; refuses on any byte mismatch.
void HookTlkLookup() {
    uint8_t* at = g_base + RVA_TLK_LOOKUP;
    uint8_t* resize = g_base + RVA_ARRAY_RESIZE;
    for (int t = 0;; ++t) {
        if (!memcmp(at, TLK_LOOKUP_PROLOGUE, sizeof(TLK_LOOKUP_PROLOGUE)) &&
            !memcmp(resize, ARRAY_RESIZE_PROLOGUE, sizeof(ARRAY_RESIZE_PROLOGUE))) break;
        if (t == 240 || lemp::Exiting()) {
            L("tlk: the string lookup at rva 0x%llx does not match this build; device rows keep \"Device N\"",
              (unsigned long long)RVA_TLK_LOOKUP);
            return;
        }
        Sleep(250);
    }
    // Trampoline: the 12 moved bytes, then jmp [rip+0] back to at+12.
    uint8_t* tramp = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) { L("tlk: VirtualAlloc %lu", GetLastError()); return; }
    memcpy(tramp, at, 12);
    uint8_t back[14] = {0xFF, 0x25, 0, 0, 0, 0};
    uint64_t ret = (uint64_t)(uintptr_t)(at + 12);
    memcpy(back + 6, &ret, 8);
    memcpy(tramp + 12, back, sizeof(back));
    FlushInstructionCache(GetCurrentProcess(), tramp, 64);
    g_tlkOriginal = (TlkLookupFn)tramp;
    g_arrayResize = (ArrayResizeFn)resize;

    uint8_t jmp[12] = {0x48, 0xB8};   // mov rax, imm64; jmp rax (rax is free at entry)
    uint64_t target = (uint64_t)(uintptr_t)&TlkLookupHook;
    memcpy(jmp + 2, &target, 8);
    jmp[10] = 0xFF; jmp[11] = 0xE0;
    DWORD old = 0;
    if (!VirtualProtect(at, sizeof(jmp), PAGE_EXECUTE_READWRITE, &old)) { L("tlk: VirtualProtect %lu", GetLastError()); return; }
    memcpy(at, jmp, sizeof(jmp));
    VirtualProtect(at, sizeof(jmp), old, &old);
    FlushInstructionCache(GetCurrentProcess(), at, sizeof(jmp));
    L("HOOKED the string lookup (rva 0x%llx): ids %d-%d / %d-%d name the input / output devices",
      (unsigned long long)RVA_TLK_LOOKUP, TLK_INPUT_FIRST, TLK_INPUT_FIRST + TLK_SLOTS - 1,
      TLK_OUTPUT_FIRST, TLK_OUTPUT_FIRST + TLK_SLOTS - 1);
}

DWORD WINAPI Thread(LPVOID) {
    g_log = LempOpenDebugLog("voice");
    g_base = (uint8_t*)GetModuleHandleA("MassEffect3.exe");
    if (!g_base) g_base = (uint8_t*)GetModuleHandleA(nullptr);
    uint32_t peOff = *(uint32_t*)(g_base + 0x3C);
    g_end = g_base + *(uint32_t*)(g_base + peOff + 0x18 + 0x38);
    g_pools = (FNameEntry**)(g_base + RVA_NAME_POOLS);
    g_objs = (TArray<UObject*>*)(g_base + RVA_OBJOBJECTS);
    L("== voice ==  pid %lu", (unsigned long)GetCurrentProcessId());
    LoadSettings();

    // The socket hooks: as early as possible, before any MP connection.
    HMODULE ws = LoadLibraryA("ws2_32.dll");
    g_realRecvFrom = (RecvFromFn)GetProcAddress(ws, MAKEINTRESOURCEA(17));
    g_realSendTo = (SendToFn)GetProcAddress(ws, MAKEINTRESOURCEA(20));
    if (!g_realRecvFrom || !g_realSendTo) { L("ABORT: ws2_32 recvfrom/sendto not found"); return 0; }
    for (int t = 0; t < 120; ++t) {   // the unpacker fills the import table at start-up
        if (lemp::Exiting()) { L("stopping: engine exiting (import slots never found)"); return 0; }
        int r = PatchImport((void*)g_realRecvFrom, (void*)&HookRecvFrom, "recvfrom");
        int s = PatchImport((void*)g_realSendTo, (void*)&HookSendTo, "sendto");
        if (r && s) break;
        if (t == 119) { L("ABORT: import slots not found (recvfrom %d, sendto %d)", r, s); return 0; }
        Sleep(250);
    }
    CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
    RefreshDeviceNames();
    HookTlkLookup();

    // Waits as long as it takes: GNatives (shared with mp_save, above) and
    // SFXOnlineComponentVoiceInterface's natives can take an unpredictable
    // time to appear, and arrive later on a slower machine. A fixed cap here
    // is exactly what once left a voice module permanently half-started —
    // it tried once, failed on a slow sample, and
    // gave up for the rest of the session while NoteTraffic kept setting
    // g_audioWanted regardless (now gated on g_scriptHooked instead).
    // Only a genuine build mismatch (CalibratePropertyOffset refusing to
    // guess) gives up early; everything else retries until lemp::Exiting().
    for (int t = 0;; ++t) {
        Sleep(250);
        if (lemp::Exiting()) { L("stopping: engine exiting (script side never hooked)"); return 0; }
        if (IsBadReadPtr(g_objs, sizeof(*g_objs)) || !g_objs->Data || g_objs->Count < 1000) continue;
        int r = Install();
        if (r < 0) { L("ABORT: property offsets uncalibrated (wrong build?); voice has no script side"); return 0; }
        if (r > 0) break;
        if (t && t % 120 == 0) L("still waiting for GNatives / SFXOnlineComponentVoiceInterface natives (%d s)", t / 4);
    }
    g_scriptHooked.store(true, std::memory_order_relaxed);
    L("script side hooked: natives bound, audio may start on traffic");
    for (;;) {
        if (lemp::Exiting()) { L("stopping: engine exiting"); return 0; }
        HookNatives();
        Sleep(250);
    }
    return 0;
}

}  // namespace

namespace { bool g_started = false; }

// The options rows (SFXGUI_Option_MPVoice*):
//   60/61 mode (0 push to talk, 1 always on, 2 off)   62/63 volume 0-100
//   64/65 input device (-1 default)  66/67 output device
//   68/69 how many input / output devices
//   70/71 "Force Voice Chat Audio" (MPVoiceContinueOnLostFocus) 0/1
// The device setters are the interface's natives; 65/67 are here too.
int VoiceAsiOp(int op, int* index) {
    if (!g_started) return -1;
    switch (op) {
    case 68: case 69: {
        RefreshDeviceNames();   // the rows are being built: their names from now
        EnterCriticalSection(&g_namesCs);
        *index = (int)(op == 68 ? g_inNames.size() : g_outNames.size());
        LeaveCriticalSection(&g_namesCs);
        return 0;
    }
    }
    Lock l;
    switch (op) {
    case 60: { voice::Mode m = g_engine.GetMode(); *index = m == voice::Mode::OpenMic ? 1 : m == voice::Mode::Off ? 2 : 0; return 0; }
    case 61: g_engine.SetMode(*index == 1 ? voice::Mode::OpenMic : *index == 2 ? voice::Mode::Off : voice::Mode::PushToTalk); break;
    case 62: *index = (int)(g_engine.Volume() * 100 + 0.5f); return 0;
    case 63: g_engine.SetVolume(*index / 100.0f); break;
    case 64: *index = g_inputDev; return 0;
    case 65: g_inputDev = *index; g_audioRestart = true; break;
    case 66: *index = g_outputDev; return 0;
    case 67: g_outputDev = *index; g_audioRestart = true; break;
    case 70: *index = g_hearUnfocused ? 1 : 0; return 0;
    case 71: g_hearUnfocused = *index != 0; break;
    default: return 6;
    }
    L("option op %d = %d", op, *index);
    SaveSettings();
    return 0;
}

// LEMP\novoice.txt: the control. Nothing is hooked and no device is opened.
void VoiceStart() {
    if (GetFileAttributesW((LempDir() + L"\\novoice.txt").c_str()) != INVALID_FILE_ATTRIBUTES) return;
    InitializeCriticalSection(&g_cs);
    InitializeCriticalSection(&g_namesCs);
    g_started = true;
    CreateThread(nullptr, 0, Thread, nullptr, 0, nullptr);
}
