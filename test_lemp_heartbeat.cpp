// lemp_online.h's hosted lobby over minutes, under Wine, against a running
// master server (the dir argument holds server.txt): register, renew the lease
// every 10 s as SFXGameInfoMP does, and print the status every 10 s. Written
// when lobbies vanished from the server while their hosts were running.
//   x86_64-w64-mingw32-g++ -std=c++17 -O2 -municode -static -o test_lemp_heartbeat.exe test_lemp_heartbeat.cpp -lwinhttp -lws2_32 -lbcrypt
#include <winsock2.h>
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include "lemp_online.h"

static void Log(const char* fmt, ...) {
    SYSTEMTIME st; GetLocalTime(&st);
    printf("%02d:%02d:%02d  ", st.wHour, st.wMinute, st.wSecond);
    va_list a; va_start(a, fmt); vprintf(fmt, a); va_end(a); printf("\n"); fflush(stdout);
}
static std::string GetBuild() { return "LEMPBuild=heartbeattest"; }

int wmain(int argc, wchar_t** argv) {
    online::Init(argc > 1 ? argv[1] : L".", Log, nullptr, GetBuild);
    int seconds = argc > 2 ? _wtoi(argv[2]) : 180;
    online::UpdateLobby("?create=1?private=0?open=1?map=0?enemy=0?difficulty=0?players=1?max=4?port=3659");
    for (int t = 0; t < seconds; t += 10) {
        Sleep(10000);
        int r = online::RenewLobby();
        int reach = -1;
        Log("t=%d renew=%d status=%s heartbeatMs=%lu", t + 10, r, online::LobbyStatus(reach).c_str(), (unsigned long)online::g_heartbeatMs);
    }
    return 0;
}
