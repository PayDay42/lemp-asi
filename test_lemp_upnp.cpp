// lemp_upnp.h against a fake router on loopback, natively or under Wine: an
// SSDP responder (unicast here, multicast on a real LAN), and an HTTP server
// for the device description (chunked) and the SOAP control URL. The router
// takes only permanent mappings (725 to a lease), as some do. Checks the
// mapping made for the host's proxy, its endpoint, and its removal when the
// proxy closes.
//   g++ -std=c++17 -O2 -pthread -o test_lemp_upnp test_lemp_upnp.cpp && ./test_lemp_upnp
//   x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -o test_lemp_upnp.exe test_lemp_upnp.cpp -lws2_32 && wine test_lemp_upnp.exe
#include "lemp_upnp.h"
#include <cstdarg>
#include <cstdio>

using namespace punch;

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } else printf("ok   %s\n", #c); } while (0)

static void Log(const char* fmt, ...) {
    va_list a; va_start(a, fmt); printf("  log: "); vprintf(fmt, a); va_end(a); printf("\n"); fflush(stdout);
}

static uint16_t g_httpPort;
static sock_t g_ssdp, g_listen;
static Lock g_seenLock;
static std::vector<std::string> g_actions;   // "Add <ext> <client> <lease>" / "Delete <ext>"

PUNCH_THREAD(SsdpServer) {
    char buf[2048];
    for (;;) {
        sockaddr_in a;
        socklen_t len = sizeof a;
        int n = (int)recvfrom(g_ssdp, buf, sizeof buf, 0, (sockaddr*)&a, &len);
        if (n <= 0) { SleepMs(5); continue; }
        if (std::string(buf, n).find("M-SEARCH") != 0) continue;
        std::string r = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                        "Location: http://127.0.0.1:" + std::to_string(g_httpPort) + "/igd.xml\r\n\r\n";
        sendto(g_ssdp, r.data(), (int)r.size(), 0, (sockaddr*)&a, len);
    }
    PUNCH_THREAD_RETURN;
}

static const char* kDesc =
    "<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\"><device>"
    "<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><deviceList><device>"
    "<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><serviceList><service>"
    "<serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/ctl/CmnIfCfg</controlURL>"
    "</service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>"
    "<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>"
    "<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>ctl/IPConn</controlURL></service></serviceList>"
    "</device></deviceList></device></deviceList></device></root>";

static std::string Between(const std::string& s, const std::string& a, const std::string& b) {
    size_t i = s.find(a);
    if (i == std::string::npos) return "";
    i += a.size();
    return s.substr(i, s.find(b, i) - i);
}

PUNCH_THREAD(HttpServer) {
    for (;;) {
        sock_t c = accept(g_listen, nullptr, nullptr);
        if (c == kBad) { SleepMs(5); continue; }
        upnp::SetTimeouts(c, 2000);
        std::string req;
        char buf[4096];
        for (;;) {
            int n = (int)recv(c, buf, sizeof buf, 0);
            if (n <= 0) break;
            req.append(buf, n);
            size_t he = req.find("\r\n\r\n");
            if (he != std::string::npos) {
                size_t cl = (size_t)atoi(Between(upnp::Lower(req), "content-length: ", "\r\n").c_str());
                if (req.size() >= he + 4 + cl) break;
            }
        }
        std::string resp;
        if (req.find("GET /igd.xml") == 0) {
            // Chunked, in two pieces.
            std::string d = kDesc, a = d.substr(0, 100), b = d.substr(100);
            char h[64];
            snprintf(h, sizeof h, "%zx\r\n", a.size());
            std::string body = h + a + "\r\n";
            snprintf(h, sizeof h, "%zx\r\n", b.size());
            body += h + b + "\r\n0\r\n\r\n";
            resp = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nTransfer-Encoding: chunked\r\n\r\n" + body;
        } else if (req.find("POST /ctl/IPConn") == 0) {
            std::string action = Between(req, "#", "\"");
            std::string out;
            int status = 200;
            if (action == "GetExternalIPAddress") {
                out = "<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>";
            } else if (action == "AddPortMapping") {
                std::string lease = Between(req, "<NewLeaseDuration>", "<");
                if (lease != "0") {
                    status = 500;
                    out = "<s:Fault><detail><UPnPError><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported"
                          "</errorDescription></UPnPError></detail></s:Fault>";
                }
                Guard lk(g_seenLock);
                g_actions.push_back("Add " + Between(req, "<NewExternalPort>", "<") + " " + Between(req, "<NewInternalClient>", "<") + " " + lease);
            } else if (action == "DeletePortMapping") {
                Guard lk(g_seenLock);
                g_actions.push_back("Delete " + Between(req, "<NewExternalPort>", "<"));
            }
            std::string body = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>" +
                               (status == 200 ? "<u:" + action + "Response xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">" + out +
                                                    "</u:" + action + "Response>"
                                              : out) +
                               "</s:Body></s:Envelope>";
            resp = std::string(status == 200 ? "HTTP/1.1 200 OK" : "HTTP/1.1 500 Internal Server Error") +
                   "\r\nContent-Type: text/xml\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        } else {
            resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        }
        send(c, resp.data(), (int)resp.size(), 0);
        CloseSock(c);
    }
    PUNCH_THREAD_RETURN;
}

static bool Seen(const std::string& prefix) {
    Guard lk(g_seenLock);
    for (auto& a : g_actions) if (a.find(prefix) == 0) return true;
    return false;
}

int main() {
    NetInit();
    // Units.
    Ep e;
    CHECK(ParseEp("100.64.1.1:1", e) && upnp::Private(e.ip));
    CHECK(ParseEp("192.168.178.1:1", e) && upnp::Private(e.ip));
    CHECK(ParseEp("172.31.0.1:1", e) && upnp::Private(e.ip));
    CHECK(ParseEp("172.32.0.1:1", e) && !upnp::Private(e.ip));
    CHECK(ParseEp("203.0.113.7:1", e) && !upnp::Private(e.ip));
    upnp::Url base, u;
    CHECK(upnp::ParseUrl("http://192.168.178.1:49000/igddesc.xml", base) && EpStr(base.host) == "192.168.178.1:49000" && base.path == "/igddesc.xml");
    CHECK(upnp::ParseUrl("ctl/IPConn", u, &base) && u.path == "/ctl/IPConn" && u.host == base.host);
    CHECK(upnp::ParseUrl("http://10.0.0.1/x", u) && u.host.port == 80);
    // A forged description (anything on the LAN can answer SSDP): no header
    // splicing through the path, and no control URL on another host.
    CHECK(!upnp::ParseUrl("/ctl\r\nX-Injected: 1\r\n\r\nGET /admin HTTP/1.1", u, &base));
    CHECK(!upnp::ParseUrl("http://10.0.0.1/a b", u));
    {
        upnp::Url ctl;
        std::string svc;
        const std::string wan = "<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/c</controlURL>";
        CHECK(!upnp::FindService("<URLBase>http://10.9.9.9:8080/</URLBase>" + wan, base, ctl, svc));
        CHECK(upnp::FindService("<URLBase>http://192.168.178.1:5000/</URLBase>" + wan, base, ctl, svc) && ctl.host.port == 5000);
        CHECK(!upnp::FindService("<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>"
                                 "<controlURL>http://10.9.9.9/c</controlURL>", base, ctl, svc));
    }
    CHECK(upnp::Dechunk("4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n") == "abcdef");
    CHECK(upnp::Dechunk("ff\r\nabc") == "");   // a chunk longer than what came: stops
    CHECK(upnp::Tag("<s:Body><u:X><NewExternalIPAddress> 1.2.3.4 </NewExternalIPAddress></u:X>", "NewExternalIPAddress") == "1.2.3.4");

    uint16_t sp;
    g_ssdp = OpenUdp(htonl(0x7f000001), 0, sp);
    g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a = ToSa(Loopback(0));
    socklen_t len = sizeof a;
    bind(g_listen, (sockaddr*)&a, sizeof a);
    getsockname(g_listen, (sockaddr*)&a, &len);
    g_httpPort = ntohs(a.sin_port);
    listen(g_listen, 8);
    StartThread(SsdpServer);
    StartThread(HttpServer);

    Init({"127.0.0.1:9"}, Log);   // STUN unanswered: this test is about the router
    CHECK(HostStart(3659));
    HostInfo h = GetHostInfo();
    upnp::Start(Log, "127.0.0.1:" + std::to_string(sp));
    upnp::Want(upnp::HOST, (uint16_t)h.localPort);
    Ep m;
    for (int t = 0; t < 8000 && !(m = upnp::Mapped(upnp::HOST)).ok(); t += 50) SleepMs(50);
    printf("     mapped %s (proxy port %d)\n", EpStr(m).c_str(), h.localPort);
    CHECK(EpStr(m) == "203.0.113.7:" + std::to_string(h.localPort));
    CHECK(upnp::Usable());
    CHECK(Seen("Add " + std::to_string(h.localPort) + " 127.0.0.1 3600"));   // a lease first,
    CHECK(Seen("Add " + std::to_string(h.localPort) + " 127.0.0.1 0"));      // permanent after 725

    // The proxy closes: the mapping goes.
    HostStop();
    for (int t = 0; t < 3000 && !Seen("Delete"); t += 50) SleepMs(50);
    CHECK(Seen("Delete " + std::to_string(h.localPort)));
    CHECK(!upnp::Mapped(upnp::HOST).ok());

    printf("%s (%d failed)\n", fails ? "FAILED" : "PASSED", fails);
    return fails ? 1 : 0;
}
