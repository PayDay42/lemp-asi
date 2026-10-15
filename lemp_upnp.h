// lemp_upnp.h — UPnP-IGD port mapping for the hole-punching proxy
// (lemp_punch.h), done from the ASI itself.
//
// Punching fails when one side's NAT maps per destination ("symmetric") and
// the other's filters per port. A port mapping on the router opens the
// proxy's port to everyone, so either side with one is reachable from any
// NAT. Most home routers speak UPnP-IGD; behind CGNAT (the router's own
// external address is private) a mapping does not help and is not used.
//
// Only the proxy's own UDP port is mapped, never the game's: the game's port
// stays closed to strangers (the proxy's token gate).
// A mapping is leased for an hour and renewed while it is wanted, deleted
// when it is not; a crash leaves it to expire. Routers that take only
// permanent mappings (error 725) get one, on the proxy's fixed preferred
// port, so a later run reuses it instead of adding another.
//
// One background thread: discovery (SSDP, then the device description), then
// the queued Map/Unmap requests (SOAP over plain HTTP to the router). Nothing
// here runs on the game thread or blocks the proxy's thread.
//
// Builds on Windows and POSIX, as lemp_punch.h (whose platform layer it uses).
#pragma once
#include "lemp_punch.h"
#include <cstdlib>

namespace upnp {

using punch::Ep;
using punch::Guard;
using punch::Lock;
using punch::sock_t;
using punch::kBad;

// ---- HTTP over a plain TCP socket (the router speaks HTTP/1.1, LAN only) ------------

#ifdef _WIN32
static void SetTimeouts(sock_t s, int ms) {
    DWORD t = (DWORD)ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof t);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof t);
}
#else
static void SetTimeouts(sock_t s, int ms) {
    timeval t = {ms / 1000, (ms % 1000) * 1000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof t);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof t);
}
#endif

struct Url {
    Ep host;           // IPv4 only: a router's description URL is an address
    std::string path;  // "/..."
};
// "http://a.b.c.d[:port]/path"; relative paths resolve against base. The
// path goes into the request line verbatim, so a space, CR, LF or any other
// control byte (a description whose controlURL splices headers or a second
// request into ours) refuses the URL.
static bool ParseUrl(const std::string& u, Url& out, const Url* base = nullptr) {
    for (unsigned char c : u)
        if (c <= ' ' || c >= 0x7f) return false;
    if (u.compare(0, 7, "http://") != 0) {
        if (!base || u.empty()) return false;
        out.host = base->host;
        out.path = u[0] == '/' ? u : "/" + u;
        return true;
    }
    size_t hs = 7, slash = u.find('/', hs);
    std::string hp = u.substr(hs, slash == std::string::npos ? std::string::npos : slash - hs);
    if (hp.find(':') == std::string::npos) hp += ":80";
    if (!punch::ParseEp(hp, out.host)) return false;
    out.path = slash == std::string::npos ? "/" : u.substr(slash);
    return true;
}

static std::string Lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

// Undoes "Transfer-Encoding: chunked"; bounded by the body it is given.
static std::string Dechunk(const std::string& b) {
    std::string out;
    size_t at = 0;
    while (at < b.size()) {
        size_t eol = b.find("\r\n", at);
        if (eol == std::string::npos) break;
        unsigned long n = strtoul(b.substr(at, eol - at).c_str(), nullptr, 16);
        at = eol + 2;
        if (n == 0 || at + n > b.size()) break;
        out.append(b, at, n);
        at += n + 2;
    }
    return out;
}

// One request, Connection: close. status 0 on no answer. local: our address
// on the router's network (what the router must send a mapping's traffic to).
static int Http(const Url& url, const std::string& method, const std::string& headers, const std::string& body,
                std::string& resp, uint32_t* local = nullptr) {
    resp.clear();
    sock_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == kBad) return 0;
    SetTimeouts(s, 3000);
    sockaddr_in a = punch::ToSa(url.host);
    if (connect(s, (sockaddr*)&a, sizeof a) != 0) { punch::CloseSock(s); return 0; }
    if (local) {
        sockaddr_in me;
        socklen_t len = sizeof me;
        if (getsockname(s, (sockaddr*)&me, &len) == 0) *local = me.sin_addr.s_addr;
    }
    std::string req = method + " " + url.path + " HTTP/1.1\r\nHost: " + punch::EpStr(url.host) +
                      "\r\nConnection: close\r\nContent-Length: " + std::to_string(body.size()) + "\r\n" + headers + "\r\n" + body;
    for (size_t sent = 0; sent < req.size();) {
        int n = (int)send(s, req.data() + sent, (int)(req.size() - sent), 0);
        if (n <= 0) { punch::CloseSock(s); return 0; }
        sent += n;
    }
    std::string all;
    char buf[4096];
    for (;;) {
        int n = (int)recv(s, buf, sizeof buf, 0);
        if (n <= 0) break;
        all.append(buf, n);
        if (all.size() > 256 * 1024) break;   // a description is a few KB
    }
    punch::CloseSock(s);
    size_t he = all.find("\r\n\r\n");
    if (all.compare(0, 5, "HTTP/") != 0 || he == std::string::npos) return 0;
    int status = atoi(all.c_str() + all.find(' ') + 1);
    std::string head = Lower(all.substr(0, he));
    resp = all.substr(he + 4);
    if (head.find("transfer-encoding: chunked") != std::string::npos) resp = Dechunk(resp);
    return status;
}

// The text of the first <tag>…</tag> (namespace prefixes ignored), from at.
static std::string Tag(const std::string& x, const std::string& tag, size_t at = 0, size_t* end = nullptr) {
    for (size_t i = x.find('<', at); i != std::string::npos; i = x.find('<', i + 1)) {
        size_t close = x.find('>', i);
        if (close == std::string::npos) return "";
        std::string name = x.substr(i + 1, close - i - 1);
        size_t sp = name.find_first_of(" \t\r\n/");
        if (sp != std::string::npos) name.resize(sp);
        size_t colon = name.find(':');
        if (colon != std::string::npos) name = name.substr(colon + 1);
        if (name != tag) continue;
        size_t stop = x.find("</", close);
        if (stop == std::string::npos) return "";
        if (end) *end = stop;
        std::string v = x.substr(close + 1, stop - close - 1);
        size_t a = v.find_first_not_of(" \t\r\n"), b = v.find_last_not_of(" \t\r\n");
        return a == std::string::npos ? "" : v.substr(a, b - a + 1);
    }
    return "";
}

// ---- state ------------------------------------------------------------------------------

enum Slot { HOST = 0, JOIN = 1, SLOTS = 2 };

struct Mapping {
    uint16_t want = 0;       // the internal port wanted mapped, 0 none
    uint16_t have = 0;       // the internal port mapped now
    uint16_t external = 0;   // its external port
    uint16_t failed = 0;     // a port the router refused: not asked again
    bool permanent = false;
    uint64_t renewAt = 0;
};

struct State {
    Lock lock;
    punch::LogFn log = nullptr;
    bool started = false;
    std::string ssdpTarget = "239.255.255.250:1900";   // tests: a unicast fake
    // The router, once found.
    bool discovered = false, found = false;
    Url control;
    std::string service;
    uint32_t localIp = 0;
    uint32_t externalIp = 0;
    bool usable = false;     // externally public (not double NAT)
    Mapping slot[SLOTS];
};
static State g;

#define ULOG(...) do { if (g.log) g.log(__VA_ARGS__); } while (0)

static const uint32_t kLeaseS = 3600;

// A private, shared (CGNAT) or otherwise unroutable IPv4 address.
static bool Private(uint32_t ipNet) {
    uint32_t ip = ntohl(ipNet);
    return (ip >> 24) == 10 || (ip >> 20) == 0xAC1 || (ip >> 16) == 0xC0A8 || (ip >> 22) == (100u << 2 | 1)
        || (ip >> 24) == 127 || (ip >> 16) == 0xA9FE || ip == 0;
}

// ---- discovery ---------------------------------------------------------------------------

// SSDP is unauthenticated: anything on the LAN may answer. A Location is
// kept only when it names the private address its answer came from, so a
// reply cannot point our HTTP requests at a third host (FindService then
// keeps the control URL on that host too).
static std::vector<std::string> Ssdp(const std::string& target) {
    std::vector<std::string> locations;
    Ep to;
    if (!punch::ParseEp(target, to)) return locations;
    uint16_t port;
    sock_t s = punch::OpenUdp(INADDR_ANY, 0, port);
    if (s == kBad) return locations;
    const char* types[] = {"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                           "urn:schemas-upnp-org:device:InternetGatewayDevice:2"};
    for (int round = 0; round < 2; round++) {
        for (auto t : types) {
            std::string m = std::string("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ") + t + "\r\n\r\n";
            punch::SendTo(s, to, m.data(), (int)m.size());
        }
        for (uint64_t until = punch::NowMs() + 1200; punch::NowMs() < until;) {
            char buf[2048];
            sockaddr_in from;
            socklen_t flen = sizeof from;
            int n = (int)recvfrom(s, buf, sizeof buf - 1, 0, (sockaddr*)&from, &flen);
            if (n <= 0) { punch::SleepMs(20); continue; }
            uint32_t src = punch::FromSa(from).ip;
            std::string r(buf, n), low = Lower(r);
            size_t at = low.find("\nlocation:");
            if (at == std::string::npos) continue;
            at += 10;
            size_t eol = r.find("\r\n", at);
            std::string loc = r.substr(at, eol == std::string::npos ? std::string::npos : eol - at);
            size_t a = loc.find_first_not_of(" \t");
            loc = a == std::string::npos ? "" : loc.substr(a);
            Url lu;
            if (!ParseUrl(loc, lu) || lu.host.ip != src || !Private(src)) continue;
            bool have = false;
            for (auto& x : locations) have = have || x == loc;
            if (!have) locations.push_back(loc);
        }
        if (!locations.empty()) break;
    }
    punch::CloseSock(s);
    return locations;
}

// The WAN connection service in a device description: its control URL.
static bool FindService(const std::string& xml, const Url& location, Url& control, std::string& service) {
    static const char* wanted[] = {"urn:schemas-upnp-org:service:WANIPConnection:2",
                                   "urn:schemas-upnp-org:service:WANIPConnection:1",
                                   "urn:schemas-upnp-org:service:WANPPPConnection:1"};
    Url base = location;
    std::string urlBase = Tag(xml, "URLBase");
    if (!urlBase.empty()) ParseUrl(urlBase, base, &location);
    for (auto w : wanted) {
        for (size_t at = 0;;) {
            size_t end = 0;
            std::string type = Tag(xml, "serviceType", at, &end);
            if (type.empty()) break;
            if (type == w) {
                std::string ctl = Tag(xml, "controlURL", end);
                // On the host that served the description (any port): a
                // URLBase or controlURL naming another host is refused.
                if (!ctl.empty() && ParseUrl(ctl, control, &base) && control.host.ip == location.host.ip) { service = w; return true; }
            }
            at = end + 1;
        }
    }
    return false;
}

static int Soap(const std::string& action, const std::string& args, std::string& resp, uint32_t* local = nullptr) {
    std::string body =
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:" + action + " xmlns:u=\"" + g.service + "\">" +
        args + "</u:" + action + "></s:Body></s:Envelope>\r\n";
    std::string headers = "Content-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"" + g.service + "#" + action + "\"\r\n";
    return Http(g.control, "POST", headers, body, resp, local);
}

static void Discover() {
    std::string target;
    {
        Guard lk(g.lock);
        target = g.ssdpTarget;
    }
    std::vector<std::string> locs = Ssdp(target);
    for (auto& loc : locs) {
        Url u;
        std::string xml;
        if (!ParseUrl(loc, u) || Http(u, "GET", "", "", xml) != 200) continue;
        Url control;
        std::string service;
        if (!FindService(xml, u, control, service)) continue;
        Guard lk(g.lock);
        g.control = control;
        g.service = service;
        g.found = true;
        break;
    }
    if (!g.found) {
        ULOG("upnp: no router answered (%s): no port mapping", locs.empty() ? "no SSDP reply" : "no WAN service");
        return;
    }
    std::string resp;
    uint32_t local = 0;
    int st = Soap("GetExternalIPAddress", "", resp, &local);
    Ep ext;
    std::string ip = Tag(resp, "NewExternalIPAddress");
    bool ok = st == 200 && punch::ParseEp(ip + ":1", ext);
    Guard lk(g.lock);
    g.localIp = local;
    g.externalIp = ok ? ext.ip : 0;
    g.usable = ok && !Private(ext.ip);
    // An empty address is a router without a public IPv4 of its own (DS-Lite
    // or CGNAT; a Fritz!Box answers so [V]) or with port sharing off.
    ULOG("upnp: router %s (%s), external address %s", punch::EpStr(g.control.host).c_str(), g.service.c_str(),
         !ok ? "none (no public IPv4 on the router, or UPnP port sharing off): no mapping"
             : g.usable ? ip.c_str() : (ip + " (private: another NAT beyond it): no mapping").c_str());
}

// ---- mapping --------------------------------------------------------------------------------

static std::string Ip(uint32_t ipNet) {
    Ep e; e.ip = ipNet; e.port = 1;
    std::string s = punch::EpStr(e);
    return s.substr(0, s.size() - 2);
}

static int ErrorCode(const std::string& resp) { return atoi(Tag(resp, "errorCode").c_str()); }

static bool AddMapping(Mapping& m, uint16_t internal) {
    for (int attempt = 0; attempt < 4; attempt++) {
        uint16_t ext = (uint16_t)(internal + attempt);
        for (int lease = 0; lease < 2; lease++) {
            uint32_t secs = lease == 0 ? kLeaseS : 0;
            std::string args = "<NewRemoteHost></NewRemoteHost><NewExternalPort>" + std::to_string(ext) +
                               "</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>" + std::to_string(internal) +
                               "</NewInternalPort><NewInternalClient>" + Ip(g.localIp) +
                               "</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>LEMP</NewPortMappingDescription>"
                               "<NewLeaseDuration>" + std::to_string(secs) + "</NewLeaseDuration>";
            std::string resp;
            int st = Soap("AddPortMapping", args, resp);
            if (st == 200) {
                m.have = internal;
                m.external = ext;
                m.permanent = secs == 0;
                m.renewAt = punch::NowMs() + (secs ? (uint64_t)secs * 1000 / 2 : 0);
                return true;
            }
            int code = ErrorCode(resp);
            if (code == 725) continue;            // OnlyPermanentLeasesSupported: lease 0
            if (code == 718) break;               // ConflictInMappingEntry: the next external port
            ULOG("upnp: mapping refused (HTTP %s, error %s)", std::to_string(st).c_str(), std::to_string(code).c_str());
            return false;
        }
    }
    ULOG("upnp: no free external port near %s", std::to_string(internal).c_str());
    return false;
}

static void DeleteMapping(Mapping& m) {
    if (!m.have) return;
    std::string resp;
    Soap("DeletePortMapping", "<NewRemoteHost></NewRemoteHost><NewExternalPort>" + std::to_string(m.external) +
                              "</NewExternalPort><NewProtocol>UDP</NewProtocol>", resp);
    ULOG("upnp: mapping %s removed", std::to_string(m.external).c_str());
    m.have = m.external = 0;
}

PUNCH_THREAD(UpnpThread) {
    Discover();
    {
        Guard lk(g.lock);
        g.discovered = true;
        if (!g.usable) PUNCH_THREAD_RETURN;
    }
    for (;;) {
        punch::SleepMs(200);
        for (int i = 0; i < SLOTS; i++) {
            // A proxy socket that closed on its own (a joiner's idle timeout,
            // a BYE) no longer wants its mapping.
            uint16_t asked;
            {
                Guard lk(g.lock);
                asked = g.slot[i].want;
            }
            if (asked && !punch::PortOpen(asked)) {
                Guard lk(g.lock);
                if (g.slot[i].want == asked) g.slot[i].want = 0;
            }
            Mapping m;
            {
                Guard lk(g.lock);
                m = g.slot[i];
            }
            uint64_t now = punch::NowMs();
            bool del = m.have && m.have != m.want;
            bool add = m.want && m.want != m.have && m.want != m.failed;
            bool renew = m.have && m.have == m.want && !m.permanent && now >= m.renewAt;
            if (!del && !add && !renew) continue;
            // The SOAP calls run outside the lock; only this thread changes
            // have/external/failed, the API only want.
            if (del) DeleteMapping(m);
            if (add || renew) {
                if (AddMapping(m, m.want)) {
                    if (add) ULOG("upnp: UDP %s mapped to %s:%s", std::to_string(m.want).c_str(), Ip(g.externalIp).c_str(), std::to_string(m.external).c_str());
                } else {
                    m.failed = m.want;
                    m.have = 0;
                }
            }
            Guard lk(g.lock);
            uint16_t want = g.slot[i].want;
            g.slot[i] = m;
            g.slot[i].want = want;   // the API may have asked for another meanwhile: next round
        }
    }
    PUNCH_THREAD_RETURN;
}

// ---- API ---------------------------------------------------------------------------------

static void Start(punch::LogFn log, const std::string& ssdpTarget = "") {
    Guard lk(g.lock);
    if (g.started) return;
    g.log = log;
    if (!ssdpTarget.empty()) g.ssdpTarget = ssdpTarget;
    g.started = punch::StartThread(UpnpThread);
}

// Wants internal UDP port mapped (0: none) for a slot. Returns at once.
static void Want(int slot, uint16_t internal) {
    Guard lk(g.lock);
    g.slot[slot].want = internal;
}

// The slot's external endpoint, once mapped on a public router; else not ok().
static Ep Mapped(int slot) {
    Guard lk(g.lock);
    Ep e;
    const Mapping& m = g.slot[slot];
    if (g.usable && m.have && m.have == m.want) { e.ip = g.externalIp; e.port = m.external; }
    return e;
}

// Discovery done and the router can map: worth waiting a moment for Mapped.
static bool Usable() {
    Guard lk(g.lock);
    return g.discovered && g.usable;
}

}  // namespace upnp
