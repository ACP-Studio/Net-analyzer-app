// netanalyzer.cpp - Command-line network analyzer for Windows and Linux (no GUI)
//
// Build on Windows (MSYS2 MinGW-w64 g++):
//   g++ -std=c++17 -O2 -Wall -Wextra -static -o netanalyzer.exe netanalyzer.cpp -liphlpapi -lws2_32
// Build on Linux:
//   g++ -std=c++17 -O2 -Wall -Wextra -pthread -o netanalyzer netanalyzer.cpp
//
// Commands:
//   info                    Show local network information (adapters, IPs, gateway, DNS)
//   ping <host> [options]   Measure latency (min/avg/max/jitter/loss)
//   test [host[:port] ...]  Test the devices listed in devices.conf and analyze the results
//   scan                    List every device currently visible on the local network
//   track                   Follow your phones' IP addresses (phones.conf, matched by MAC)
//   init                    Create sample devices.conf and phones.conf
//
// Every command records its results in its own CSV file inside ./netlogs/
//
// No administrator/root rights needed. Windows uses the IP Helper API for ping and ARP;
// Linux uses unprivileged ICMP sockets when allowed and falls back to TCP connect timing.

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <direct.h>
#include <sys/stat.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

using Clock = std::chrono::steady_clock;

#ifdef _WIN32
using sock_t = SOCKET;
const sock_t kBadSock = INVALID_SOCKET;
#else
using sock_t = int;
const sock_t kBadSock = -1;
#endif

namespace {

volatile std::sig_atomic_t g_stop = 0;

#ifdef _WIN32
BOOL WINAPI onCtrl(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        g_stop = 1;
        return TRUE;
    }
    return FALSE;
}
#else
void onSignal(int) { g_stop = 1; }
#endif

// ============================================================ options

struct Options {
    int count = 5;         // probes per target
    int intervalMs = 200;  // pause between probes
    int timeoutMs = 1000;  // per-probe timeout
    int port = 0;          // TCP port for "ping" (0 = ICMP)
    int everySec = 0;      // repeat test/track every N seconds (0 = once)
    int settleSec = 5;     // how long scan/track wait for ARP replies
    bool forceTcp = false;
    std::string logDir = "netlogs";
    std::string file;   // config file override
    std::string iface;  // interface override for scan/track
    std::vector<std::string> args;
};

// ============================================================ small helpers

#if defined(__GNUC__)
std::string fmt(const char* f, ...) __attribute__((format(printf, 1, 2)));
#endif
std::string fmt(const char* f, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, f);
    vsnprintf(buf, sizeof buf, f, ap);
    va_end(ap);
    return buf;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> out;
    std::string cur;
    std::istringstream ss(s);
    while (std::getline(ss, cur, d)) out.push_back(trim(cur));
    return out;
}

std::string lower(std::string s) {
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

std::string nowStamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

double msSince(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

int popcount32(uint32_t v) {
    int n = 0;
    while (v) { v &= v - 1; ++n; }
    return n;
}

bool makeDir(const std::string& p) {
#ifdef _WIN32
    return _mkdir(p.c_str()) == 0 || errno == EEXIST;
#else
    return ::mkdir(p.c_str(), 0755) == 0 || errno == EEXIST;
#endif
}

bool fileExists(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0;
}

std::string humanBytes(unsigned long long b) {
    const char* u[] = {"B", "KB", "MB", "GB", "TB"};
    double v = (double)b;
    int i = 0;
    while (v >= 1024 && i < 4) { v /= 1024; ++i; }
    return fmt("%.1f %s", v, u[i]);
}

std::string ipToStr(uint32_t hostOrder) {
    in_addr a;
    a.s_addr = htonl(hostOrder);
    char b[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, b, sizeof b);
    return b;
}

void sleepInterruptible(int seconds) {
    for (int i = 0; i < seconds * 5 && !g_stop; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

// ============================================================ CSV logging

std::string csvSafe(std::string s) {
    for (auto& c : s)
        if (c == ',' || c == '\n' || c == '\r') c = ' ';
    return s;
}

std::string joinCsv(const std::vector<std::string>& f) {
    std::string out;
    for (size_t i = 0; i < f.size(); ++i) {
        if (i) out += ',';
        out += csvSafe(f[i]);
    }
    return out;
}

void appendLog(const Options& o, const std::string& file, const std::string& header,
               const std::vector<std::string>& row) {
    makeDir(o.logDir);
    std::string path = o.logDir + "/" + file;
    struct stat st{};
    bool fresh = ::stat(path.c_str(), &st) != 0 || st.st_size == 0;
    std::ofstream out(path, std::ios::app);
    if (!out) {
        std::fprintf(stderr, "warning: cannot write to %s\n", path.c_str());
        return;
    }
    if (fresh) out << header << '\n';
    out << joinCsv(row) << '\n';
}

// Last logged row whose column `keyCol` equals `key` (empty vector if none).
std::vector<std::string> lastRow(const Options& o, const std::string& file, size_t keyCol,
                                 const std::string& key) {
    std::ifstream in(o.logDir + "/" + file);
    std::string line;
    std::vector<std::string> best;
    std::string k = csvSafe(key);
    while (std::getline(in, line)) {
        auto f = split(line, ',');
        if (f.size() > keyCol && f[keyCol] == k) best = f;
    }
    return best;
}

// Reads "a, b, c" lines, skipping blanks and # comments.
bool readConfig(const std::string& path, std::vector<std::vector<std::string>>& rows) {
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        rows.push_back(split(line, ','));
    }
    return true;
}

// ============================================================ statistics

struct Stats {
    double min = 0, max = 0, avg = 0, jitter = 0, stddev = 0;
};

Stats computeStats(const std::vector<double>& v) {
    Stats s;
    if (v.empty()) return s;
    s.min = *std::min_element(v.begin(), v.end());
    s.max = *std::max_element(v.begin(), v.end());
    double sum = 0;
    for (double x : v) sum += x;
    s.avg = sum / (double)v.size();
    double var = 0;
    for (double x : v) var += (x - s.avg) * (x - s.avg);
    s.stddev = std::sqrt(var / (double)v.size());
    if (v.size() > 1) {  // jitter = mean absolute difference of consecutive RTTs
        double d = 0;
        for (size_t i = 1; i < v.size(); ++i) d += std::fabs(v[i] - v[i - 1]);
        s.jitter = d / (double)(v.size() - 1);
    }
    return s;
}

// ============================================================ system info

struct V4 {
    uint32_t ip, mask;  // host byte order
};

struct Iface {
    std::string name, desc, mac, kind;
    bool up = false, running = false, loop = false;
    std::vector<V4> v4;
    std::vector<std::string> v6, dns;
    long mtu = 0;
    long long speedMbps = 0;
    unsigned long long rx = 0, tx = 0;
    bool haveStats = false;
    unsigned ifIndex = 0;
};

struct Route {
    std::string iface, gw;
};

#ifdef _WIN32

std::string wideToUtf8(const wchar_t* w) {
    if (!w) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return "";
    std::string s((size_t)n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}

std::map<std::string, Iface> getIfaces() {
    std::map<std::string, Iface> out;
    ULONG size = 32 * 1024, rc = ERROR_BUFFER_OVERFLOW;
    std::vector<unsigned char> buf;
    for (int tries = 0; tries < 5 && rc == ERROR_BUFFER_OVERFLOW; ++tries) {
        buf.assign(size, 0);
        rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    }
    if (rc != NO_ERROR) return out;

    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a; a = a->Next) {
        Iface I;
        I.name = wideToUtf8(a->FriendlyName);
        I.desc = wideToUtf8(a->Description);
        if (I.name.empty()) I.name = I.desc;
        I.ifIndex = a->IfIndex;
        I.loop = a->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
        I.up = a->OperStatus == IfOperStatusUp;
        I.running = I.up;
        I.kind = I.loop                              ? "loopback"
                 : a->IfType == IF_TYPE_IEEE80211    ? "Wi-Fi"
                 : a->IfType == IF_TYPE_ETHERNET_CSMACD ? "Ethernet"
                                                     : "other/virtual";
        I.mtu = a->Mtu == 0xFFFFFFFFu ? 0 : (long)a->Mtu;
        if (a->TransmitLinkSpeed && a->TransmitLinkSpeed != (ULONG64)-1)
            I.speedMbps = (long long)(a->TransmitLinkSpeed / 1000000ULL);
        if (a->PhysicalAddressLength == 6)
            I.mac = fmt("%02x:%02x:%02x:%02x:%02x:%02x", a->PhysicalAddress[0], a->PhysicalAddress[1],
                        a->PhysicalAddress[2], a->PhysicalAddress[3], a->PhysicalAddress[4],
                        a->PhysicalAddress[5]);
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr) continue;
            int fam = u->Address.lpSockaddr->sa_family;
            if (fam == AF_INET) {
                V4 v;
                v.ip = ntohl(((sockaddr_in*)u->Address.lpSockaddr)->sin_addr.s_addr);
                unsigned prefix = u->OnLinkPrefixLength;
                v.mask = prefix == 0 ? 0 : (prefix >= 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - prefix)));
                I.v4.push_back(v);
            } else if (fam == AF_INET6) {
                char b[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &((sockaddr_in6*)u->Address.lpSockaddr)->sin6_addr, b, sizeof b);
                I.v6.push_back(b);
            }
        }
        for (auto* d = a->FirstDnsServerAddress; d; d = d->Next) {
            if (d->Address.lpSockaddr && d->Address.lpSockaddr->sa_family == AF_INET) {
                char b[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((sockaddr_in*)d->Address.lpSockaddr)->sin_addr, b, sizeof b);
                I.dns.push_back(b);
            }
        }
        MIB_IF_ROW2 row;
        std::memset(&row, 0, sizeof row);
        row.InterfaceIndex = a->IfIndex;
        if (GetIfEntry2(&row) == NO_ERROR) {
            I.rx = row.InOctets;
            I.tx = row.OutOctets;
            I.haveStats = true;
        }
        std::string key = I.name;
        if (out.count(key)) key += fmt(" (#%u)", I.ifIndex);
        I.name = key;
        out[key] = I;
    }
    return out;
}

Route defaultRoute() {
    Route r;
    MIB_IPFORWARDROW row;
    std::memset(&row, 0, sizeof row);
    if (GetBestRoute(inet_addr("1.1.1.1"), 0, &row) != NO_ERROR) return r;
    if (row.dwForwardNextHop) {
        in_addr a;
        a.s_addr = row.dwForwardNextHop;
        char b[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, b, sizeof b);
        r.gw = b;
    }
    for (auto& kv : getIfaces())
        if (kv.second.ifIndex == row.dwForwardIfIndex) {
            r.iface = kv.first;
            break;
        }
    return r;
}

std::vector<std::string> readDns() {
    std::vector<std::string> out;
    auto ifs = getIfaces();
    auto add = [&](const Iface& I) {
        for (auto& d : I.dns)
            if (std::find(out.begin(), out.end(), d) == out.end()) out.push_back(d);
    };
    auto it = ifs.find(defaultRoute().iface);
    if (it != ifs.end()) add(it->second);
    if (out.empty())
        for (auto& kv : ifs)
            if (kv.second.up && !kv.second.loop) add(kv.second);
    return out;
}

#else  // ---------------------------------------------------------------- Linux

std::string readFileTrim(const std::string& path) {
    std::ifstream in(path);
    std::string s;
    std::getline(in, s);
    return trim(s);
}

bool dirExists(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

std::map<std::string, Iface> getIfaces() {
    std::map<std::string, Iface> out;
    ifaddrs* list = nullptr;
    if (getifaddrs(&list) != 0) return out;
    for (ifaddrs* p = list; p; p = p->ifa_next) {
        if (!p->ifa_addr) continue;
        Iface& I = out[p->ifa_name];
        I.name = p->ifa_name;
        I.up = p->ifa_flags & IFF_UP;
        I.running = p->ifa_flags & IFF_RUNNING;
        I.loop = p->ifa_flags & IFF_LOOPBACK;
        int fam = p->ifa_addr->sa_family;
        if (fam == AF_INET && p->ifa_netmask) {
            V4 a;
            a.ip = ntohl(((sockaddr_in*)p->ifa_addr)->sin_addr.s_addr);
            a.mask = ntohl(((sockaddr_in*)p->ifa_netmask)->sin_addr.s_addr);
            I.v4.push_back(a);
        } else if (fam == AF_INET6) {
            char b[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &((sockaddr_in6*)p->ifa_addr)->sin6_addr, b, sizeof b);
            I.v6.push_back(b);
        } else if (fam == AF_PACKET) {
            auto* s = (sockaddr_ll*)p->ifa_addr;
            if (s->sll_halen == 6)
                I.mac = fmt("%02x:%02x:%02x:%02x:%02x:%02x", s->sll_addr[0], s->sll_addr[1],
                            s->sll_addr[2], s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
        }
    }
    freeifaddrs(list);

    for (auto& kv : out) {
        Iface& I = kv.second;
        std::string base = "/sys/class/net/" + I.name;
        I.kind = I.loop ? "loopback"
                 : (dirExists(base + "/wireless") || dirExists(base + "/phy80211")) ? "Wi-Fi"
                                                                                     : "wired/virtual";
        I.mtu = std::atol(readFileTrim(base + "/mtu").c_str());
        I.speedMbps = std::atoll(readFileTrim(base + "/speed").c_str());
        I.ifIndex = (unsigned)std::atoi(readFileTrim(base + "/ifindex").c_str());
        std::string rx = readFileTrim(base + "/statistics/rx_bytes");
        std::string tx = readFileTrim(base + "/statistics/tx_bytes");
        if (!rx.empty() && !tx.empty()) {
            I.rx = std::stoull(rx);
            I.tx = std::stoull(tx);
            I.haveStats = true;
        }
    }
    return out;
}

Route defaultRoute() {
    std::ifstream in("/proc/net/route");
    std::string line;
    std::getline(in, line);  // header
    Route best;
    unsigned bestMetric = ~0u;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::string iface, dest, gw;
        unsigned flags = 0, ref = 0, use = 0, metric = 0;
        ss >> iface >> dest >> gw >> std::hex >> flags >> std::dec >> ref >> use >> metric;
        if (dest == "00000000" && (flags & 0x2) && metric < bestMetric) {
            in_addr a;
            a.s_addr = (uint32_t)std::stoul(gw, nullptr, 16);
            char b[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, b, sizeof b);
            best.iface = iface;
            best.gw = b;
            bestMetric = metric;
        }
    }
    return best;
}

std::vector<std::string> readDns() {
    for (const char* path : {"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"}) {
        std::ifstream in(path);
        std::string line;
        std::vector<std::string> out;
        while (std::getline(in, line)) {
            line = trim(line);
            if (line.rfind("nameserver", 0) == 0) {
                std::string v = trim(line.substr(10));
                if (!v.empty()) out.push_back(v);
            }
        }
        if (!out.empty()) return out;
    }
    return {};
}

#endif

// ============================================================ probes (latency)

enum class Outcome { Ok, Refused, Timeout, Error };

struct Probe {
    Outcome outcome = Outcome::Error;
    double rtt = 0;
    std::string detail;
};

// ---- tiny socket portability layer
#ifdef _WIN32
std::string winErrStr(unsigned long code) {
    char* buf = nullptr;
    DWORD n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, code, 0, (LPSTR)&buf, 0, nullptr);
    std::string s = (n && buf) ? trim(std::string(buf, n)) : fmt("error %lu", code);
    if (buf) LocalFree(buf);
    return s;
}
int lastSockError() { return WSAGetLastError(); }
std::string sockErrStr(int e) { return winErrStr((unsigned long)e); }
std::string resolveErrStr(int rc) { return winErrStr((unsigned long)rc); }
void closeSock(sock_t s) { closesocket(s); }
bool isInProgress(int e) { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
const int kConnRefused = WSAECONNREFUSED;

sock_t openTcpSocket() {
    sock_t fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd != INVALID_SOCKET) {
        u_long nb = 1;
        ioctlsocket(fd, FIONBIO, &nb);
    }
    return fd;
}
// 1 = connect finished (success or failure), 0 = timeout, -1 = error
int waitConnect(sock_t fd, int timeoutMs) {
    fd_set w, e;
    FD_ZERO(&w);
    FD_ZERO(&e);
    FD_SET(fd, &w);
    FD_SET(fd, &e);
    timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    int r = select(0, nullptr, &w, &e, &tv);
    return r == SOCKET_ERROR ? -1 : (r == 0 ? 0 : 1);
}
#else
int lastSockError() { return errno; }
std::string sockErrStr(int e) { return std::strerror(e); }
std::string resolveErrStr(int rc) { return gai_strerror(rc); }
void closeSock(sock_t s) { ::close(s); }
bool isInProgress(int e) { return e == EINPROGRESS; }
const int kConnRefused = ECONNREFUSED;

sock_t openTcpSocket() { return ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); }
int waitConnect(sock_t fd, int timeoutMs) {
    pollfd pfd{fd, POLLOUT, 0};
    int pr;
    do { pr = ::poll(&pfd, 1, timeoutMs); } while (pr < 0 && errno == EINTR && !g_stop);
    return pr < 0 ? -1 : (pr == 0 ? 0 : 1);
}
#endif

#ifdef _WIN32

bool icmpAvailable() { return true; }  // IcmpSendEcho needs no special rights on Windows

Probe probeIcmp(const sockaddr_in& dst, int /*seq*/, int timeoutMs) {
    Probe p;
    HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) {
        p.detail = winErrStr(GetLastError());
        return p;
    }
    char payload[32];
    std::memset(payload, 'a', sizeof payload);
    std::vector<char> reply(sizeof(ICMP_ECHO_REPLY) + sizeof payload + 128);
    auto t0 = Clock::now();
    DWORD n = IcmpSendEcho(h, dst.sin_addr.s_addr, payload, (WORD)sizeof payload, nullptr, reply.data(),
                           (DWORD)reply.size(), (DWORD)timeoutMs);
    double rtt = msSince(t0);  // measured here: IcmpSendEcho's own RoundTripTime is whole milliseconds
    if (n == 0) {
        DWORD e = GetLastError();
        if (e == IP_REQ_TIMED_OUT) p.outcome = Outcome::Timeout;
        else p.detail = fmt("ICMP error %lu", (unsigned long)e);
    } else {
        auto* r = reinterpret_cast<ICMP_ECHO_REPLY*>(reply.data());
        if (r->Status == IP_SUCCESS) {
            p.outcome = Outcome::Ok;
            p.rtt = rtt;
        } else if (r->Status == IP_REQ_TIMED_OUT) {
            p.outcome = Outcome::Timeout;
        } else {
            p.detail = fmt("destination unreachable (ICMP status %lu)", (unsigned long)r->Status);
        }
    }
    IcmpCloseHandle(h);
    return p;
}

#else

bool icmpAvailable() {
    static const bool ok = [] {
        int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_ICMP);
        if (fd < 0) return false;
        ::close(fd);
        return true;
    }();
    return ok;
}

uint16_t inetChecksum(const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += (uint32_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len) sum += (uint32_t)(p[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return htons((uint16_t)(~sum & 0xFFFF));
}

Probe probeIcmp(const sockaddr_in& dst, int seq, int timeoutMs) {
    Probe p;
    int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_ICMP);
    if (fd < 0) {
        p.detail = std::strerror(errno);
        return p;
    }
    uint8_t pkt[64];
    std::memset(pkt, 0, sizeof pkt);
    auto* h = reinterpret_cast<icmphdr*>(pkt);
    h->type = ICMP_ECHO;
    h->code = 0;
    h->un.echo.id = htons((uint16_t)(getpid() & 0xFFFF));
    h->un.echo.sequence = htons((uint16_t)(seq & 0xFFFF));
    for (size_t i = sizeof(icmphdr); i < sizeof pkt; ++i) pkt[i] = (uint8_t)i;
    h->checksum = inetChecksum(pkt, sizeof pkt);

    auto t0 = Clock::now();
    if (::sendto(fd, pkt, sizeof pkt, 0, (const sockaddr*)&dst, sizeof dst) < 0) {
        p.detail = std::strerror(errno);
        ::close(fd);
        return p;
    }
    for (;;) {
        int remaining = timeoutMs - (int)msSince(t0);
        if (remaining <= 0) { p.outcome = Outcome::Timeout; break; }
        pollfd pfd{fd, POLLIN, 0};
        int r = ::poll(&pfd, 1, remaining);
        if (r < 0) {
            if (errno == EINTR && !g_stop) continue;
            p.detail = std::strerror(errno);
            break;
        }
        if (r == 0) { p.outcome = Outcome::Timeout; break; }
        uint8_t rb[512];
        ssize_t n = ::recv(fd, rb, sizeof rb, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            p.detail = std::strerror(errno);  // e.g. "No route to host"
            break;
        }
        if ((size_t)n < sizeof(icmphdr)) continue;
        auto* rh = reinterpret_cast<const icmphdr*>(rb);
        if (rh->type == ICMP_ECHOREPLY && ntohs(rh->un.echo.sequence) == (seq & 0xFFFF)) {
            p.outcome = Outcome::Ok;
            p.rtt = msSince(t0);
            p.detail.clear();
            break;
        }
        if (rh->type == ICMP_DEST_UNREACH) { p.detail = "destination unreachable"; break; }
    }
    ::close(fd);
    return p;
}

#endif

// TCP connect timing. A "connection refused" still proves the host is alive,
// so it is reported separately (Outcome::Refused) and carries a valid RTT.
Probe probeTcp(sockaddr_in dst, int port, int timeoutMs) {
    Probe p;
    dst.sin_port = htons((uint16_t)port);
    sock_t fd = openTcpSocket();
    if (fd == kBadSock) {
        p.detail = sockErrStr(lastSockError());
        return p;
    }
    auto t0 = Clock::now();
    int r = ::connect(fd, (const sockaddr*)&dst, sizeof dst);
    int err = 0;
    if (r == 0) {
        err = 0;
    } else if (isInProgress(lastSockError())) {
        int pr = waitConnect(fd, timeoutMs);
        if (pr == 0) { closeSock(fd); p.outcome = Outcome::Timeout; return p; }
        if (pr < 0) { p.detail = sockErrStr(lastSockError()); closeSock(fd); return p; }
        socklen_t len = sizeof err;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
    } else {
        err = lastSockError();
    }
    p.rtt = msSince(t0);
    closeSock(fd);
    if (err == 0) p.outcome = Outcome::Ok;
    else if (err == kConnRefused) p.outcome = Outcome::Refused;
    else p.detail = sockErrStr(err);
    return p;
}

bool resolveV4(const std::string& host, sockaddr_in& out, std::string& err) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res) {
        err = "cannot resolve: " + (rc ? resolveErrStr(rc) : std::string("no address"));
        return false;
    }
    out = *(sockaddr_in*)res->ai_addr;
    freeaddrinfo(res);
    return true;
}

struct Series {
    std::string target, ip, method, error;
    int port = 0, sent = 0, received = 0, refused = 0;
    std::vector<double> rtts;
    Stats st;
    double lossPct() const { return sent ? 100.0 * (sent - received) / sent : 100.0; }
};

Series runSeriesCb(const std::string& target, int port, const Options& o, bool verbose,
                   const std::function<void(int, const Probe&)>& cb) {
    Series s;
    s.target = target;
    s.port = port;
    std::string host = target;
    if (target == "gateway") {
        host = defaultRoute().gw;
        if (host.empty()) { s.error = "no default gateway found"; return s; }
    }
    sockaddr_in dst{};
    if (!resolveV4(host, dst, s.error)) return s;
    char ipb[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst.sin_addr, ipb, sizeof ipb);
    s.ip = ipb;

    bool tcp = port > 0 || o.forceTcp || !icmpAvailable();
    int tport = port > 0 ? port : 80;
    s.method = tcp ? fmt("TCP:%d", tport) : "ICMP";
    if (verbose) std::printf("PING %s (%s) via %s\n", target.c_str(), s.ip.c_str(), s.method.c_str());

    for (int i = 1; i <= o.count && !g_stop; ++i) {
        Probe p = tcp ? probeTcp(dst, tport, o.timeoutMs) : probeIcmp(dst, i, o.timeoutMs);
        ++s.sent;
        bool replied = p.outcome == Outcome::Ok || p.outcome == Outcome::Refused;
        if (replied) {
            ++s.received;
            if (p.outcome == Outcome::Refused) ++s.refused;
            s.rtts.push_back(p.rtt);
        } else if (!p.detail.empty()) {
            s.error = p.detail;
        }
        if (verbose) {
            if (p.outcome == Outcome::Ok)
                std::printf("  seq=%d  reply        time=%.2f ms\n", i, p.rtt);
            else if (p.outcome == Outcome::Refused)
                std::printf("  seq=%d  port closed  time=%.2f ms (host is up)\n", i, p.rtt);
            else if (p.outcome == Outcome::Timeout)
                std::printf("  seq=%d  timeout\n", i);
            else
                std::printf("  seq=%d  error: %s\n", i, p.detail.c_str());
            std::fflush(stdout);
        }
        if (cb) cb(i, p);
        if (i < o.count) std::this_thread::sleep_for(std::chrono::milliseconds(o.intervalMs));
    }
    s.st = computeStats(s.rtts);
    return s;
}

Series runSeries(const std::string& target, int port, const Options& o, bool verbose) {
    return runSeriesCb(target, port, o, verbose, nullptr);
}

// ============================================================ ARP discovery

struct ArpEntry {
    std::string ip, mac, dev;
};

#ifdef _WIN32

std::vector<ArpEntry> readArp() {
    std::vector<ArpEntry> out;
    ULONG size = 0;
    std::vector<unsigned char> buf;
    DWORD rc = ERROR_INSUFFICIENT_BUFFER;
    for (int tries = 0; tries < 5 && rc == ERROR_INSUFFICIENT_BUFFER; ++tries) {
        buf.assign(size ? size : 1, 0);
        rc = GetIpNetTable(reinterpret_cast<MIB_IPNETTABLE*>(buf.data()), &size, FALSE);
    }
    if (rc != NO_ERROR) return out;
    auto* t = reinterpret_cast<MIB_IPNETTABLE*>(buf.data());
    std::map<unsigned, std::string> names;
    for (auto& kv : getIfaces()) names[kv.second.ifIndex] = kv.first;
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        const MIB_IPNETROW& r = t->table[i];
        if (r.dwPhysAddrLen != 6) continue;
        if (r.dwType != MIB_IPNET_TYPE_DYNAMIC && r.dwType != MIB_IPNET_TYPE_STATIC) continue;
        if (r.bPhysAddr[0] & 0x01) continue;  // broadcast / multicast entries
        in_addr a;
        a.s_addr = r.dwAddr;
        char b[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, b, sizeof b);
        std::string mac = fmt("%02x:%02x:%02x:%02x:%02x:%02x", r.bPhysAddr[0], r.bPhysAddr[1], r.bPhysAddr[2],
                              r.bPhysAddr[3], r.bPhysAddr[4], r.bPhysAddr[5]);
        auto it = names.find(r.dwIndex);
        out.push_back({b, mac, it == names.end() ? "" : it->second});
    }
    return out;
}

#else

std::vector<ArpEntry> readArp() {
    std::vector<ArpEntry> out;
    std::ifstream in("/proc/net/arp");
    std::string line;
    std::getline(in, line);  // header
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::string ip, hw, flags, mac, mask, dev;
        if (!(ss >> ip >> hw >> flags >> mac >> mask >> dev)) continue;
        unsigned f = (unsigned)std::strtoul(flags.c_str(), nullptr, 16);
        if ((f & 0x2) && mac != "00:00:00:00:00:00") out.push_back({ip, lower(mac), dev});
    }
    return out;
}

#endif

sock_t openUdpSocket() {
#ifdef _WIN32
    sock_t fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd != INVALID_SOCKET) {
        u_long nb = 1;
        ioctlsocket(fd, FIONBIO, &nb);
    }
    return fd;
#else
    return ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#endif
}

// Sends one tiny UDP packet to every address in the subnet. That forces the
// OS to ARP for each one, which fills its ARP table with whoever answers.
void sweep(uint32_t net, uint32_t bcast, uint32_t self) {
    sock_t fd = openUdpSocket();
    if (fd == kBadSock) return;
    int n = 0;
    for (uint64_t a = (uint64_t)net + 1; a < bcast; ++a) {
        if (a == self) continue;
        sockaddr_in d{};
        d.sin_family = AF_INET;
        d.sin_port = htons(9);
        d.sin_addr.s_addr = htonl((uint32_t)a);
        char b = 0;
        ::sendto(fd, &b, 1, 0, (const sockaddr*)&d, sizeof d);
        if (++n % 32 == 0) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    closeSock(fd);
}

bool discover(const Options& o, std::vector<ArpEntry>& out, std::string& ifName, std::string& err) {
    auto ifs = getIfaces();
    ifName = o.iface.empty() ? defaultRoute().iface : o.iface;
    if (ifName.empty()) {  // no default route: first usable non-loopback interface
        for (auto& kv : ifs)
            if (!kv.second.loop && kv.second.up && !kv.second.v4.empty()) {
                ifName = kv.first;
                break;
            }
    }
    auto it = ifs.find(ifName);
    if (ifName.empty() || it == ifs.end() || it->second.v4.empty()) {
        err = "no usable network interface with an IPv4 address (try --iface <name>)";
        return false;
    }
    V4 a = it->second.v4[0];
    uint32_t mask = a.mask;
    if (popcount32(mask) < 22) mask = 0xFFFFFF00u;  // never sweep more than ~1000 hosts
    if (popcount32(mask) > 30) {
        err = "subnet too small to scan";
        return false;
    }
    uint32_t net = a.ip & mask, bcast = net | ~mask;
    std::printf("Scanning %s/%d on %s (about %d s)...\n", ipToStr(net).c_str(), popcount32(mask),
                ifName.c_str(), o.settleSec + 1);
    std::fflush(stdout);

    sweep(net, bcast, a.ip);
    for (int i = 0; i < 5 && !g_stop; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(200));
    sweep(net, bcast, a.ip);  // second pass catches phones that were asleep the first time
    for (int i = 0; i < o.settleSec * 5 && !g_stop; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

    out.clear();
    std::string self = ipToStr(a.ip);
    for (auto& e : readArp()) {
        if (e.dev != ifName || e.ip == self) continue;
        if (e.mac == "00:00:00:00:00:00") continue;  // unanswered ARP slot, not a real device
        uint32_t eip = ntohl(inet_addr(e.ip.c_str()));
        if ((eip & mask) != net) continue;  // ignore multicast and other subnets
        out.push_back(e);
    }

#ifdef _WIN32
    // Windows keeps old ARP entries around for a long time, so confirm every candidate
    // with a fresh ARP request. An entry is dropped only when Windows reports a definite
    // "no answer"; any other result keeps it, so an unexpected error never hides a device.
    std::vector<std::future<bool>> checks;
    for (auto& e : out)
        checks.push_back(std::async(std::launch::async, [ip = e.ip, src = a.ip] {
            in_addr d;
            inet_pton(AF_INET, ip.c_str(), &d);
            ULONG mac[2] = {0, 0}, len = 6;
            DWORD rc = SendARP(d.s_addr, htonl(src), mac, &len);
            return !(rc == ERROR_BAD_NET_NAME || rc == ERROR_GEN_FAILURE);
        }));
    std::vector<ArpEntry> confirmed;
    for (size_t i = 0; i < out.size(); ++i)
        if (checks[i].get()) confirmed.push_back(out[i]);
    out.swap(confirmed);
#endif

    std::sort(out.begin(), out.end(), [](const ArpEntry& x, const ArpEntry& y) {
        return ntohl(inet_addr(x.ip.c_str())) < ntohl(inet_addr(y.ip.c_str()));
    });
    return true;
}

bool normalizeMac(std::string in, std::string& out) {
    in = lower(trim(in));
    for (auto& c : in)
        if (c == '-') c = ':';
    if (in.size() != 17) return false;
    for (int i = 0; i < 17; ++i) {
        if (i % 3 == 2) { if (in[i] != ':') return false; }
        else if (!std::isxdigit((unsigned char)in[i])) return false;
    }
    out = in;
    return true;
}

// Locally-administered bit set => private/randomized MAC (what phones use on Wi-Fi).
bool isRandomizedMac(const std::string& mac) {
    return mac.size() >= 2 && (std::stoi(mac.substr(0, 2), nullptr, 16) & 0x02) != 0;
}

std::string reverseDns(const std::string& ip) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    char host[NI_MAXHOST];
    if (getnameinfo((sockaddr*)&sa, sizeof sa, host, sizeof host, nullptr, 0, NI_NAMEREQD) == 0) return host;
    return "";
}

// ============================================================ command: info

std::string v4String(const Iface& I) {
    std::string s;
    for (auto& a : I.v4) {
        if (!s.empty()) s += ", ";
        s += fmt("%s/%d", ipToStr(a.ip).c_str(), popcount32(a.mask));
    }
    return s;
}

struct NetInfo {
    std::string hostname;
    Route route;
    std::vector<std::string> dns;
    std::map<std::string, Iface> ifaces;
};

NetInfo gatherInfo() {
    NetInfo n;
    char host[256] = "unknown";
    gethostname(host, sizeof host);
    n.hostname = host;
    n.route = defaultRoute();
    n.dns = readDns();
    n.ifaces = getIfaces();
    return n;
}

void logInfo(const Options& o, const NetInfo& n) {
    for (auto& kv : n.ifaces) {
        const Iface& I = kv.second;
        if (I.loop || I.v4.empty()) continue;
        appendLog(o, "interface_info.csv", "timestamp,interface,state,ipv4,mac,gateway,rx_bytes,tx_bytes",
                  {nowStamp(), I.name, I.running ? "UP" : "DOWN", v4String(I), I.mac,
                   I.name == n.route.iface ? n.route.gw : "", I.haveStats ? std::to_string(I.rx) : "",
                   I.haveStats ? std::to_string(I.tx) : ""});
    }
}

int cmdInfo(const Options& o) {
    NetInfo n = gatherInfo();
    std::printf("=== Local Network Information ===  (%s)\n", nowStamp().c_str());
    std::printf("Hostname        : %s\n", n.hostname.c_str());
    std::printf("Default gateway : %s\n",
                n.route.gw.empty() ? "none" : (n.route.gw + " via " + n.route.iface).c_str());
    std::printf("DNS servers     : ");
    if (n.dns.empty()) std::printf("unknown");
    for (size_t i = 0; i < n.dns.size(); ++i) std::printf("%s%s", i ? ", " : "", n.dns[i].c_str());
    std::printf("\n");

    int hidden = 0;
    for (auto& kv : n.ifaces) {
        const Iface& I = kv.second;
        if (!I.up && I.v4.empty()) { ++hidden; continue; }  // unplugged / unused adapters
        std::printf("\n[%s] %s - %s\n", I.name.c_str(), I.kind.c_str(),
                    !I.up ? "DOWN" : I.running ? "UP" : "UP (no link)");
        if (!I.desc.empty() && I.desc != I.name) std::printf("  Adapter   : %s\n", I.desc.c_str());
        if (!I.mac.empty() && !I.loop) std::printf("  MAC       : %s\n", I.mac.c_str());
        std::string v4str = v4String(I);
        std::printf("  IPv4      : %s\n", v4str.empty() ? "-" : v4str.c_str());
        for (auto& a : I.v6) std::printf("  IPv6      : %s\n", a.c_str());
        if (I.mtu > 0) std::printf("  MTU       : %ld\n", I.mtu);
        if (I.speedMbps > 0) std::printf("  Link speed: %lld Mb/s\n", I.speedMbps);
        if (I.haveStats)
            std::printf("  Traffic   : %s received, %s sent\n", humanBytes(I.rx).c_str(), humanBytes(I.tx).c_str());
    }
    if (hidden) std::printf("\n(%d inactive adapter(s) without an IP address not shown)\n", hidden);
    logInfo(o, n);
    std::printf("\nLogged to %s/interface_info.csv\n", o.logDir.c_str());
    return 0;
}

// ============================================================ command: ping

void logPing(const Options& o, const Series& s) {
    appendLog(o, "latency_stats.csv",
              "timestamp,target,ip,method,sent,received,loss_pct,min_ms,avg_ms,max_ms,jitter_ms,stddev_ms",
              {nowStamp(), s.target, s.ip, s.method, std::to_string(s.sent), std::to_string(s.received),
               fmt("%.1f", s.lossPct()), fmt("%.2f", s.st.min), fmt("%.2f", s.st.avg), fmt("%.2f", s.st.max),
               fmt("%.2f", s.st.jitter), fmt("%.2f", s.st.stddev)});
}

int cmdPing(const Options& o) {
    if (o.args.empty()) {
        std::fprintf(stderr, "usage: netanalyzer ping <host> [-c count] [-i interval_ms] [-t timeout_ms] [-p tcp_port | --tcp]\n");
        return 1;
    }
    Series s = runSeries(o.args[0], o.port, o, true);
    if (s.sent == 0) {
        std::fprintf(stderr, "error: %s\n", s.error.c_str());
        return 1;
    }
    std::printf("\n--- %s (%s) statistics ---\n", s.target.c_str(), s.ip.c_str());
    std::printf("%d sent, %d received, %.0f%% loss\n", s.sent, s.received, s.lossPct());
    if (s.received)
        std::printf("rtt min/avg/max/jitter/stddev = %.2f/%.2f/%.2f/%.2f/%.2f ms\n", s.st.min, s.st.avg,
                    s.st.max, s.st.jitter, s.st.stddev);
    logPing(o, s);
    std::printf("Logged to %s/latency_stats.csv\n", o.logDir.c_str());
    return s.received ? 0 : 2;
}

// ============================================================ command: test

struct Device {
    std::string name, host;
    int port = 0;
};

bool loadDevices(const Options& o, std::vector<Device>& out, std::string& err) {
    if (!o.args.empty()) {  // targets given on the command line: host or host:port
        for (auto& a : o.args) {
            Device d;
            d.name = a;
            d.host = a;
            size_t c = a.rfind(':');
            if (c != std::string::npos) {
                d.host = a.substr(0, c);
                d.port = std::atoi(a.c_str() + c + 1);
            }
            out.push_back(d);
        }
        return true;
    }
    std::string path = o.file.empty() ? "devices.conf" : o.file;
    std::vector<std::vector<std::string>> rows;
    if (!readConfig(path, rows)) {
        err = "cannot open " + path + " (run: netanalyzer init)";
        return false;
    }
    for (auto& r : rows) {
        if (r.size() < 2) continue;
        Device d;
        d.name = r[0];
        d.host = r[1];
        if (r.size() > 2) d.port = std::atoi(r[2].c_str());
        out.push_back(d);
    }
    if (out.empty()) {
        err = path + " has no devices";
        return false;
    }
    return true;
}

[[maybe_unused]] bool saveDevices(const Options& o, const std::vector<Device>& devices) {
    std::ofstream f(o.file.empty() ? "devices.conf" : o.file);
    if (!f) return false;
    f << "# Devices to test.   Format:  name, host, [tcp_port]\n"
         "#  - No port: measures ping (ICMP) latency.\n"
         "#  - With a port: checks that the service accepts connections (80, 443, 22, ...).\n"
         "#  - \"gateway\" means your default router.\n";
    for (auto& d : devices) {
        f << csvSafe(d.name) << ", " << csvSafe(d.host);
        if (d.port > 0) f << ", " << d.port;
        f << "\n";
    }
    return true;
}

std::string classify(const Series& s) {
    if (s.sent == 0) return "UNRESOLVED";
    if (s.received == 0) return "DOWN";
    if (s.port > 0 && s.refused == s.received) return "PORT_CLOSED";
    double loss = s.lossPct();
    if (loss >= 20 || s.st.avg >= 200) return "POOR";
    if (loss > 0 || s.st.jitter > 30 || s.st.avg >= 100) return "DEGRADED";
    if (s.st.avg < 20 && s.st.jitter < 5) return "EXCELLENT";
    return "GOOD";
}

// Sub-10 ms values keep two decimals (LAN latency is often well under 1 ms).
std::string msCell(const Series& s, double v) {
    if (!s.received) return "-";
    return v < 10 ? fmt("%.2f", v) : fmt("%.1f", v);
}

struct DeviceResult {
    Device dev;
    Series s;
    std::string status, trend;
    std::vector<std::string> notes;
};

// Tests every device in parallel, analyzes the results, compares with the previous
// logged run, and records one row per device in device_stats.csv.
std::vector<DeviceResult> evaluateDevices(const Options& o, const std::vector<Device>& devices) {
    std::vector<std::future<Series>> jobs;
    for (auto& d : devices)
        jobs.push_back(std::async(std::launch::async, runSeries, d.host, d.port, std::cref(o), false));

    std::vector<DeviceResult> out;
    for (size_t i = 0; i < devices.size(); ++i) {
        DeviceResult r;
        r.dev = devices[i];
        r.s = jobs[i].get();
        r.status = classify(r.s);
        r.trend = "-";

        // Compare with the previous logged run of this device (read before logging the new row).
        auto prev = lastRow(o, "device_stats.csv", 1, r.dev.name);
        if (r.s.received && prev.size() > 10 && prev[7] != "0") {
            double pavg = std::atof(prev[10].c_str());
            double delta = r.s.st.avg - pavg;
            r.trend = fmt("%+.1f ms", delta);
            if (delta > std::max(10.0, pavg * 0.5)) r.notes.push_back("latency noticeably higher than last run");
        }
        if (r.s.sent && r.s.lossPct() > 0 && r.s.received) r.notes.push_back(fmt("%.0f%% packet loss", r.s.lossPct()));
        if (r.s.received && r.s.st.jitter > 30) r.notes.push_back("unstable latency (high jitter)");
        if (r.status == "PORT_CLOSED") r.notes.push_back("host answers but the port refuses connections");
        if (r.status == "DOWN" && !r.s.error.empty()) r.notes.push_back(r.s.error);
        if (r.status == "UNRESOLVED") r.notes.push_back(r.s.error);

        std::string noteStr;
        for (auto& n : r.notes) noteStr += (noteStr.empty() ? "" : "; ") + n;
        appendLog(o, "device_stats.csv",
                  "timestamp,device,target,ip,method,port,sent,received,loss_pct,min_ms,avg_ms,max_ms,jitter_ms,status,notes",
                  {nowStamp(), r.dev.name, r.dev.host, r.s.ip, r.s.method, std::to_string(r.dev.port),
                   std::to_string(r.s.sent), std::to_string(r.s.received), fmt("%.1f", r.s.lossPct()),
                   fmt("%.2f", r.s.st.min), fmt("%.2f", r.s.st.avg), fmt("%.2f", r.s.st.max),
                   fmt("%.2f", r.s.st.jitter), r.status, noteStr});
        out.push_back(std::move(r));
    }
    return out;
}

int testCycle(const Options& o, const std::vector<Device>& devices) {
    std::printf("\n=== Device test  %s  (%d probes each) ===\n", nowStamp().c_str(), o.count);
    std::fflush(stdout);
    auto results = evaluateDevices(o, devices);

    std::printf("%-18s %-16s %-9s %5s %7s %7s %7s %7s  %-11s %s\n", "DEVICE", "ADDRESS", "VIA", "LOSS",
                "MIN", "AVG", "MAX", "JITTER", "STATUS", "TREND");
    std::map<std::string, int> tally;
    for (auto& r : results) {
        const Series& s = r.s;
        ++tally[r.status];
        std::printf("%-18.18s %-16s %-9s %4.0f%% %7s %7s %7s %7s  %-11s %s\n", r.dev.name.c_str(),
                    s.ip.empty() ? "?" : s.ip.c_str(), s.method.empty() ? "-" : s.method.c_str(), s.lossPct(),
                    msCell(s, s.st.min).c_str(), msCell(s, s.st.avg).c_str(), msCell(s, s.st.max).c_str(),
                    msCell(s, s.st.jitter).c_str(), r.status.c_str(), r.trend.c_str());
        for (auto& n : r.notes) std::printf("%-18s   - %s\n", "", n.c_str());
    }

    std::printf("\nSummary: ");
    bool first = true;
    for (auto& kv : tally) {
        std::printf("%s%d %s", first ? "" : ", ", kv.second, kv.first.c_str());
        first = false;
    }
    std::printf("\nLogged to %s/device_stats.csv\n", o.logDir.c_str());
    int bad = tally["DOWN"] + tally["UNRESOLVED"];
    return bad ? 2 : 0;
}

int cmdTest(const Options& o) {
    std::vector<Device> devices;
    std::string err;
    if (!loadDevices(o, devices, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }
    int rc = 0;
    do {
        rc = testCycle(o, devices);
        if (o.everySec <= 0) break;
        sleepInterruptible(o.everySec);
    } while (!g_stop);
    return rc;
}

// ============================================================ command: scan

struct Host {
    std::string ip, mac, name;
    bool randomized = false;
};

bool scanNetwork(const Options& o, std::vector<Host>& out, std::string& ifn, std::string& err) {
    std::vector<ArpEntry> found;
    if (!discover(o, found, ifn, err)) return false;
    std::vector<std::future<std::string>> names;
    for (auto& h : found) names.push_back(std::async(std::launch::async, reverseDns, h.ip));
    std::string stamp = nowStamp();
    out.clear();
    for (size_t i = 0; i < found.size(); ++i) {
        Host h;
        h.ip = found[i].ip;
        h.mac = found[i].mac;
        h.name = names[i].get();
        h.randomized = isRandomizedMac(h.mac);
        appendLog(o, "network_scan.csv", "timestamp,interface,ip,mac,hostname,randomized_mac",
                  {stamp, ifn, h.ip, h.mac, h.name, h.randomized ? "yes" : "no"});
        out.push_back(h);
    }
    return true;
}

int cmdScan(const Options& o) {
    std::vector<Host> hosts;
    std::string ifn, err;
    if (!scanNetwork(o, hosts, ifn, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }
    std::printf("\n%-16s %-18s %-30s %s\n", "IP", "MAC", "HOSTNAME", "NOTE");
    for (auto& h : hosts)
        std::printf("%-16s %-18s %-30.30s %s\n", h.ip.c_str(), h.mac.c_str(), h.name.empty() ? "-" : h.name.c_str(),
                    h.randomized ? "private/randomized MAC (likely a phone)" : "");
    std::printf("\n%d device(s) found. Logged to %s/network_scan.csv\n", (int)hosts.size(), o.logDir.c_str());
    return 0;
}

// ============================================================ command: track (phones)

struct Phone {
    std::string name, mac;
};

bool loadPhones(const Options& o, std::vector<Phone>& out, std::string& err) {
    std::string path = o.file.empty() ? "phones.conf" : o.file;
    std::vector<std::vector<std::string>> rows;
    if (!readConfig(path, rows)) {
        err = "cannot open " + path + " (run: netanalyzer init)";
        return false;
    }
    for (auto& r : rows) {
        if (r.size() < 2) continue;
        Phone p;
        p.name = r[0];
        if (!normalizeMac(r[1], p.mac)) {
            std::fprintf(stderr, "warning: skipping '%s' - invalid MAC '%s'\n", r[0].c_str(), r[1].c_str());
            continue;
        }
        out.push_back(p);
    }
    if (out.empty()) {
        err = path + " has no phones (add lines like:  My Phone, aa:bb:cc:dd:ee:ff)";
        return false;
    }
    return true;
}

[[maybe_unused]] bool savePhones(const Options& o, const std::vector<Phone>& phones) {
    std::ofstream f(o.file.empty() ? "phones.conf" : o.file);
    if (!f) return false;
    f << "# Phones to follow.   Format:  name, MAC address\n"
         "# Use the MAC your phone shows for THIS Wi-Fi network (private/randomized MAC),\n"
         "# not the factory MAC. Run a scan to see which devices are on your network.\n";
    for (auto& p : phones) f << csvSafe(p.name) << ", " << p.mac << "\n";
    return true;
}

struct PhoneResult {
    Phone ph;
    bool online = false;
    std::string ip, prevIp, event, latency, latencyCsv;  // latency = text for display
};

std::string eventText(const PhoneResult& r) {
    std::string t = r.event;
    if ((r.event == "IP_CHANGED" || r.event == "BACK_ONLINE_NEW_IP") && !r.prevIp.empty()) t += " (was " + r.prevIp + ")";
    if (r.event == "WENT_OFFLINE") t += " (last IP " + r.prevIp + ")";
    return t;
}

// Scans the network, matches phones by MAC, works out what changed since the last
// logged check (new IP / came online / went offline) and records it in phone_tracking.csv.
bool evaluatePhones(const Options& o, const std::vector<Phone>& phones, std::vector<PhoneResult>& out,
                    std::string& err) {
    std::vector<ArpEntry> hosts;
    std::string ifn;
    if (!discover(o, hosts, ifn, err)) return false;
    std::map<std::string, std::string> macToIp;
    for (auto& h : hosts) macToIp[h.mac] = h.ip;

    Options quick = o;
    quick.count = 3;
    quick.intervalMs = 100;

    out.clear();
    for (auto& ph : phones) {
        PhoneResult r;
        r.ph = ph;
        auto it = macToIp.find(ph.mac);
        r.online = it != macToIp.end();
        auto prev = lastRow(o, "phone_tracking.csv", 1, ph.name);  // ts,phone,mac,status,ip,prev_ip,event,latency
        std::string prevStatus = prev.size() > 4 ? prev[3] : "";
        r.prevIp = prev.size() > 4 ? prev[4] : "";
        r.ip = r.online ? it->second : r.prevIp;  // when offline keep "last seen at"

        if (prevStatus.empty()) r.event = r.online ? "FIRST_SEEN" : "NOT_FOUND_YET";
        else if (r.online && prevStatus == "OFFLINE")
            r.event = (!r.prevIp.empty() && r.ip != r.prevIp) ? "BACK_ONLINE_NEW_IP" : "BACK_ONLINE";
        else if (r.online && r.ip != r.prevIp) r.event = "IP_CHANGED";
        else if (!r.online && prevStatus == "ONLINE") r.event = "WENT_OFFLINE";

        r.latency = "-";
        if (r.online) {
            Series s = runSeries(r.ip, 0, quick, false);
            if (s.received) {
                r.latency = fmt("%.2f ms", s.st.avg);
                r.latencyCsv = fmt("%.2f", s.st.avg);
            } else {
                r.latency = "no reply";  // many phones ignore ping while asleep; ARP still proves presence
            }
        }
        appendLog(o, "phone_tracking.csv", "timestamp,phone,mac,status,ip,previous_ip,event,latency_ms",
                  {nowStamp(), ph.name, ph.mac, r.online ? "ONLINE" : "OFFLINE", r.ip, r.prevIp, r.event,
                   r.latencyCsv});
        out.push_back(r);
    }
    return true;
}

int trackCycle(const Options& o, const std::vector<Phone>& phones) {
    std::printf("\n=== Phone tracking  %s ===\n", nowStamp().c_str());
    std::vector<PhoneResult> results;
    std::string err;
    if (!evaluatePhones(o, phones, results, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }
    std::printf("\n%-16s %-18s %-8s %-16s %-10s %s\n", "PHONE", "MAC", "STATUS", "IP", "LATENCY", "EVENT");
    for (auto& r : results)
        std::printf("%-16.16s %-18s %-8s %-16s %-10s %s\n", r.ph.name.c_str(), r.ph.mac.c_str(),
                    r.online ? "ONLINE" : "OFFLINE", r.ip.empty() ? "-" : r.ip.c_str(), r.latency.c_str(),
                    eventText(r).c_str());
    std::printf("\nLogged to %s/phone_tracking.csv\n", o.logDir.c_str());
    return 0;
}

int cmdTrack(const Options& o) {
    std::vector<Phone> phones;
    std::string err;
    if (!loadPhones(o, phones, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }
    int rc = 0;
    do {
        rc = trackCycle(o, phones);
        if (o.everySec <= 0 || rc != 0) break;
        sleepInterruptible(o.everySec);
    } while (!g_stop);
    return rc;
}

// ============================================================ command: init

int cmdInit(const Options&) {
    std::string gw = defaultRoute().gw;
    if (gw.empty()) gw = "192.168.1.1";

    if (!fileExists("devices.conf")) {
        std::ofstream f("devices.conf");
        f << "# Devices to test.   Format:  name, host, [tcp_port]\n"
             "#  - No port: measures ping (ICMP) latency.\n"
             "#  - With a port: checks that the service accepts connections (80, 443, 22, ...).\n"
             "#  - \"gateway\" means your default router.\n"
             "Router, gateway\n"
             "Cloudflare DNS, 1.1.1.1\n"
             "Google DNS, 8.8.8.8\n"
             "Google (HTTPS), google.com, 443\n"
             "# Router admin page, " << gw << ", 80\n";
        std::printf("Created devices.conf\n");
    } else {
        std::printf("devices.conf already exists - left untouched\n");
    }
    if (!fileExists("phones.conf")) {
        std::ofstream f("phones.conf");
        f << "# Phones to follow.   Format:  name, MAC address\n"
             "#\n"
             "# Use the MAC your phone shows for THIS Wi-Fi network\n"
             "# (Settings > Wi-Fi > this network > details/advanced), not the factory MAC.\n"
             "# Phones use a private (randomized) MAC per network; it stays the same for that\n"
             "# network until you forget it or change the setting.\n"
             "# Run \"netanalyzer scan\" to see which devices are on your network right now.\n"
             "#\n"
             "# My Phone, aa:bb:cc:dd:ee:ff\n";
        std::printf("Created phones.conf  (edit it and add your phones)\n");
    } else {
        std::printf("phones.conf already exists - left untouched\n");
    }
    return 0;
}

// ============================================================ CLI

void usage() {
    std::printf(
        "netanalyzer - command-line network analyzer (Windows / Linux)\n\n"
        "Usage: netanalyzer <command> [options]\n\n"
        "Commands:\n"
        "  info                     Local network information (adapters, IPs, gateway, DNS)\n"
        "  ping <host>              Latency: min/avg/max/jitter/loss\n"
        "  test [host[:port] ...]   Test devices from devices.conf (or the targets you list)\n"
        "  scan                     List every device visible on the local network\n"
        "  track                    Follow your phones' IPs (phones.conf, matched by MAC)\n"
        "  init                     Create sample devices.conf and phones.conf\n\n"
        "Options:\n"
        "  -c, --count N        probes per target            (default 5)\n"
        "  -i, --interval MS    pause between probes         (default 200)\n"
        "  -t, --timeout MS     per-probe timeout            (default 1000)\n"
        "  -p, --port N         ping: use TCP connect to this port\n"
        "      --tcp            ping: force TCP (port 80) instead of ICMP\n"
        "      --every SEC      test/track: repeat every SEC seconds until Ctrl+C\n"
        "      --settle SEC     scan/track: wait for ARP replies      (default 5)\n"
        "      --iface NAME     scan/track: adapter to use, e.g. eth0 or \"Wi-Fi\"   (default: auto)\n"
        "  -f, --file PATH      use another devices/phones config file\n"
        "      --log-dir DIR    where CSV logs are written   (default ./netlogs)\n"
        "  -h, --help           this help\n\n"
        "Logs (in the log dir): interface_info.csv, latency_stats.csv, device_stats.csv,\n"
        "                       network_scan.csv, phone_tracking.csv\n");
}

bool parseArgs(int argc, char** argv, Options& o, std::string& err) {
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        auto needVal = [&]() -> const char* {
            if (i + 1 >= argc) { err = "missing value for " + a; return nullptr; }
            return argv[++i];
        };
        const char* v = nullptr;
        if (a == "-c" || a == "--count") { if (!(v = needVal())) return false; o.count = std::atoi(v); }
        else if (a == "-i" || a == "--interval") { if (!(v = needVal())) return false; o.intervalMs = std::atoi(v); }
        else if (a == "-t" || a == "--timeout") { if (!(v = needVal())) return false; o.timeoutMs = std::atoi(v); }
        else if (a == "-p" || a == "--port") { if (!(v = needVal())) return false; o.port = std::atoi(v); }
        else if (a == "--every") { if (!(v = needVal())) return false; o.everySec = std::atoi(v); }
        else if (a == "--settle") { if (!(v = needVal())) return false; o.settleSec = std::atoi(v); }
        else if (a == "--iface") { if (!(v = needVal())) return false; o.iface = v; }
        else if (a == "-f" || a == "--file") { if (!(v = needVal())) return false; o.file = v; }
        else if (a == "--log-dir") { if (!(v = needVal())) return false; o.logDir = v; }
        else if (a == "--tcp") o.forceTcp = true;
        else if (a.size() > 1 && a[0] == '-') { err = "unknown option " + a; return false; }
        else o.args.push_back(a);
    }
    o.count = std::max(1, std::min(o.count, 1000));
    o.intervalMs = std::max(0, o.intervalMs);
    o.timeoutMs = std::max(50, o.timeoutMs);
    o.settleSec = std::max(1, o.settleSec);
    return true;
}

}  // namespace

#ifndef NETANALYZER_NO_MAIN
int main(int argc, char** argv) {
    if (argc < 2 || std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help" ||
        std::string(argv[1]) == "help") {
        usage();
        return argc < 2 ? 1 : 0;
    }
    std::string cmd = argv[1];
    Options o;
    std::string err;
    if (!parseArgs(argc, argv, o, err)) {
        std::fprintf(stderr, "error: %s\n(see: netanalyzer --help)\n", err.c_str());
        return 1;
    }
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(onCtrl, TRUE);
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::fprintf(stderr, "error: cannot start Winsock\n");
        return 1;
    }
#else
    struct sigaction sa{};
    sa.sa_handler = onSignal;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
#endif
    (void)icmpAvailable();  // initialize once, before any threads start

    if (cmd == "info") return cmdInfo(o);
    if (cmd == "ping") return cmdPing(o);
    if (cmd == "test") return cmdTest(o);
    if (cmd == "scan") return cmdScan(o);
    if (cmd == "track") return cmdTrack(o);
    if (cmd == "init") return cmdInit(o);
    std::fprintf(stderr, "error: unknown command '%s'\n\n", cmd.c_str());
    usage();
    return 1;
}
#endif  // NETANALYZER_NO_MAIN
