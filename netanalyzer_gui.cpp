// netanalyzer_gui.cpp - Windows GUI for the network analyzer
//
// Needs netanalyzer.cpp in the same folder (it is the shared engine). Build only this file:
//   g++ -std=c++17 -O2 -Wall -Wextra -static -mwindows -o netanalyzer_gui.exe netanalyzer_gui.cpp -liphlpapi -lws2_32 -lgdi32 -lshell32
//
// Tabs: Overview (local network info) | Ping (live latency graph) | Devices (test + analysis)
//       Scan (devices on your network) | Phones (follow their IPs) | Logs (statistics logs)
//
// Settings and logs live next to the .exe: devices.conf, phones.conf and the netlogs folder.

#ifndef _WIN32
#error "netanalyzer_gui.cpp only builds on Windows"
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define NETANALYZER_NO_MAIN
#pragma GCC diagnostic ignored "-Wunused-function"
#include "netanalyzer.cpp"

#include <commctrl.h>
#include <shellapi.h>

#include <atomic>

namespace {

// ============================================================ ids and globals

constexpr UINT WM_UI_CALL = WM_APP + 1;  // run a closure on the UI thread

enum Pg { PG_OVERVIEW, PG_PING, PG_DEVICES, PG_SCAN, PG_PHONES, PG_LOGS, PG_N };
const wchar_t* const kTabNames[PG_N] = {L"Overview", L"Ping", L"Devices", L"Scan", L"Phones", L"Logs"};
const char* const kLogFiles[] = {"device_stats.csv", "phone_tracking.csv", "latency_stats.csv", "network_scan.csv",
                                 "interface_info.csv"};

enum {
    ID_TAB = 100, ID_STATUSBAR,
    ID_OV_SUMMARY = 200, ID_OV_REFRESH, ID_OV_LIST,
    ID_PG_HOST = 300, ID_PG_COUNT, ID_PG_INTERVAL, ID_PG_TCP, ID_PG_PORT, ID_PG_START, ID_PG_STOP, ID_PG_SUMMARY,
    ID_PG_GRAPH, ID_PG_LIST,
    ID_DV_NAME = 400, ID_DV_HOST, ID_DV_PORT, ID_DV_ADD, ID_DV_REMOVE, ID_DV_RUN, ID_DV_AUTO, ID_DV_EVERY,
    ID_DV_SUMMARY, ID_DV_LIST,
    ID_SC_SCAN = 500, ID_SC_INFO, ID_SC_LIST, ID_SC_NAME, ID_SC_ADD,
    ID_PH_NAME = 600, ID_PH_MAC, ID_PH_ADD, ID_PH_REMOVE, ID_PH_CHECK, ID_PH_AUTO, ID_PH_EVERY, ID_PH_INFO,
    ID_PH_LIST,
    ID_LG_COMBO = 700, ID_LG_REFRESH, ID_LG_OPEN, ID_LG_LIST
};

struct Item {  // a control plus its layout rule (unscaled pixels; negative = anchored to far edge)
    HWND h;
    int x, y, w, hh;
};

HINSTANCE g_inst;
HWND g_main, g_tab, g_status, g_page[PG_N];
HFONT g_font, g_fontBold;
int g_dpi = 96;
std::vector<Item> g_items[PG_N];
std::atomic<bool> g_job{false};
Options g_opt;
std::vector<Device> g_devices;
std::vector<Phone> g_phones;
std::vector<Host> g_hosts;
std::vector<std::string> g_devStatus, g_phStatus, g_phEvent;
std::vector<double> g_graphVals;
long g_pSent = 0, g_pRecv = 0;
double g_pMin = 0, g_pMax = 0, g_pSum = 0;

int S(int v) { return MulDiv(v, g_dpi, 96); }
int U(int px) { return MulDiv(px, 96, g_dpi); }
int clampi(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

// ============================================================ text helpers

std::wstring W(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

std::string U8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

std::string getText(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring w((size_t)n + 1, L'\0');
    GetWindowTextW(h, &w[0], n + 1);
    w.resize((size_t)n);
    return U8(w);
}

void setText(HWND h, const std::string& s) { SetWindowTextW(h, W(s).c_str()); }

void setStatus(const std::wstring& s) { SendMessageW(g_status, SB_SETTEXTW, 0, (LPARAM)s.c_str()); }

void warn(const wchar_t* msg) { MessageBoxW(g_main, msg, L"Network Analyzer", MB_OK | MB_ICONINFORMATION); }

HWND ctl(int pg, int id) { return GetDlgItem(g_page[pg], id); }

void ui(std::function<void()> f) {
    auto* p = new std::function<void()>(std::move(f));
    if (!PostMessageW(g_main, WM_UI_CALL, 0, (LPARAM)p)) delete p;
}

// ============================================================ control creation

HWND mk(int pg, const wchar_t* cls, const wchar_t* text, DWORD style, DWORD ex, int id, int x, int y, int w, int h) {
    HWND hw = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, g_page[pg],
                              (HMENU)(INT_PTR)id, g_inst, nullptr);
    g_items[pg].push_back({hw, x, y, w, h});
    return hw;
}

HWND label(int pg, const wchar_t* t, int x, int y, int w, int h, int id = 0) {
    return mk(pg, L"STATIC", t, SS_LEFT | SS_NOPREFIX, 0, id, x, y, w, h);
}
HWND edit(int pg, int id, const wchar_t* t, int x, int y, int w, int h, bool number = false) {
    return mk(pg, L"EDIT", t, WS_TABSTOP | ES_AUTOHSCROLL | (number ? ES_NUMBER : 0), WS_EX_CLIENTEDGE, id, x, y, w, h);
}
HWND button(int pg, int id, const wchar_t* t, int x, int y, int w, int h) {
    return mk(pg, L"BUTTON", t, WS_TABSTOP | BS_PUSHBUTTON, 0, id, x, y, w, h);
}
HWND check(int pg, int id, const wchar_t* t, int x, int y, int w, int h) {
    return mk(pg, L"BUTTON", t, WS_TABSTOP | BS_AUTOCHECKBOX, 0, id, x, y, w, h);
}
HWND listView(int pg, int id, int x, int y, int w, int h) {
    HWND lv = mk(pg, L"SysListView32", L"", WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                 WS_EX_CLIENTEDGE, id, x, y, w, h);
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    return lv;
}

void addCol(HWND lv, int i, const wchar_t* title, int width) {
    LVCOLUMNW c{};
    c.mask = LVCF_TEXT | LVCF_WIDTH;
    c.pszText = const_cast<LPWSTR>(title);
    c.cx = S(width);
    SendMessageW(lv, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&c);
}

int lvAdd(HWND lv, const std::string& first) {
    std::wstring w = W(first);
    LVITEMW it{};
    it.mask = LVIF_TEXT;
    it.iItem = ListView_GetItemCount(lv);
    it.pszText = &w[0];
    return (int)SendMessageW(lv, LVM_INSERTITEMW, 0, (LPARAM)&it);
}

void lvSet(HWND lv, int row, int col, const std::string& s) {
    std::wstring w = W(s);
    LVITEMW it{};
    it.iSubItem = col;
    it.pszText = &w[0];
    SendMessageW(lv, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&it);
}

void lvClear(HWND lv) { ListView_DeleteAllItems(lv); }
int lvSelected(HWND lv) { return ListView_GetNextItem(lv, -1, LVNI_SELECTED); }

// ============================================================ layout

void layoutPage(int pg) {
    RECT rc;
    GetClientRect(g_page[pg], &rc);
    int pw = U(rc.right), ph = U(rc.bottom);
    for (auto& it : g_items[pg]) {
        int x = it.x;
        int y = it.y < 0 ? ph + it.y : it.y;
        int w = it.w < 0 ? pw - x + it.w : it.w;
        int h = it.hh < 0 ? ph - y + it.hh : it.hh;
        MoveWindow(it.h, S(x), S(y), S(w < 10 ? 10 : w), S(h < 10 ? 10 : h), TRUE);
    }
}

void layoutMain() {
    RECT rc;
    GetClientRect(g_main, &rc);
    SendMessageW(g_status, WM_SIZE, 0, 0);
    RECT sb;
    GetWindowRect(g_status, &sb);
    int sbh = sb.bottom - sb.top;
    int parts[2] = {rc.right - S(380), -1};
    if (parts[0] < S(200)) parts[0] = S(200);
    SendMessageW(g_status, SB_SETPARTS, 2, (LPARAM)parts);
    MoveWindow(g_tab, 0, 0, rc.right, rc.bottom - sbh, TRUE);
    RECT d = {0, 0, rc.right, rc.bottom - sbh};
    TabCtrl_AdjustRect(g_tab, FALSE, &d);
    for (int i = 0; i < PG_N; ++i) MoveWindow(g_page[i], d.left, d.top, d.right - d.left, d.bottom - d.top, TRUE);
}

void selectTab(int i);
void loadLog();

// ============================================================ job handling (one background task at a time)

void setBusy(bool b) {
    const int ids[][2] = {{PG_OVERVIEW, ID_OV_REFRESH}, {PG_PING, ID_PG_START}, {PG_DEVICES, ID_DV_RUN},
                          {PG_SCAN, ID_SC_SCAN},        {PG_PHONES, ID_PH_CHECK}};
    for (auto& p : ids) EnableWindow(ctl(p[0], p[1]), !b);
    EnableWindow(ctl(PG_PING, ID_PG_STOP), b);
}

bool beginJob(const wchar_t* text) {
    bool expected = false;
    if (!g_job.compare_exchange_strong(expected, true)) {
        setStatus(L"Another task is still running - please wait a moment.");
        return false;
    }
    g_stop = 0;
    setBusy(true);
    setStatus(text);
    return true;
}

void endJob(const std::wstring& text) {
    g_job = false;
    setBusy(false);
    setStatus(text);
}

std::wstring clockNow() { return W(nowStamp().substr(11)); }

// ============================================================ Overview

void fillOverview(const NetInfo& n) {
    std::string dns;
    for (auto& d : n.dns) dns += (dns.empty() ? "" : ", ") + d;
    std::string t = "Computer:   " + n.hostname + "\r\nDefault gateway:   " +
                    (n.route.gw.empty() ? std::string("none") : n.route.gw + "   via   " + n.route.iface) +
                    "\r\nDNS servers:   " + (dns.empty() ? std::string("unknown") : dns);
    setText(ctl(PG_OVERVIEW, ID_OV_SUMMARY), t);
    HWND lv = ctl(PG_OVERVIEW, ID_OV_LIST);
    lvClear(lv);
    for (auto& kv : n.ifaces) {
        const Iface& I = kv.second;
        if (!I.up && I.v4.empty()) continue;  // unplugged / unused adapters
        int r = lvAdd(lv, I.name);
        lvSet(lv, r, 1, I.kind);
        lvSet(lv, r, 2, !I.up ? "Down" : "Up");
        std::string v4 = v4String(I);
        lvSet(lv, r, 3, v4.empty() ? "-" : v4);
        lvSet(lv, r, 4, I.loop ? "" : I.mac);
        lvSet(lv, r, 5, I.speedMbps > 0 ? std::to_string(I.speedMbps) + " Mb/s" : "");
        lvSet(lv, r, 6, I.haveStats ? humanBytes(I.rx) : "");
        lvSet(lv, r, 7, I.haveStats ? humanBytes(I.tx) : "");
    }
}

void refreshOverview() {
    if (!beginJob(L"Reading network information...")) return;
    Options o = g_opt;
    std::thread([o] {
        NetInfo n = gatherInfo();
        logInfo(o, n);
        ui([n] {
            fillOverview(n);
            endJob(L"Network information updated at " + clockNow() + L".");
        });
    }).detach();
}

// ============================================================ Ping

void updatePingSummary(const Series* final) {
    std::string t = fmt("Sent %ld    Received %ld    Loss %.0f%%", g_pSent, g_pRecv,
                        g_pSent ? 100.0 * (g_pSent - g_pRecv) / g_pSent : 0.0);
    if (g_pRecv)
        t += fmt("    |    min %.2f   avg %.2f   max %.2f ms", g_pMin, g_pSum / (double)g_pRecv, g_pMax);
    if (final && final->received > 1) t += fmt("   jitter %.2f ms", final->st.jitter);
    setText(ctl(PG_PING, ID_PG_SUMMARY), t);
}

void addPingRow(int seq, const Probe& p) {
    HWND lv = ctl(PG_PING, ID_PG_LIST);
    int r = lvAdd(lv, std::to_string(seq));
    std::string res, tm = "-";
    bool replied = p.outcome == Outcome::Ok || p.outcome == Outcome::Refused;
    switch (p.outcome) {
        case Outcome::Ok: res = "Reply"; break;
        case Outcome::Refused: res = "Port closed (host is up)"; break;
        case Outcome::Timeout: res = "Timeout"; break;
        default: res = "Error: " + p.detail; break;
    }
    if (replied) tm = p.rtt < 10 ? fmt("%.2f ms", p.rtt) : fmt("%.1f ms", p.rtt);
    lvSet(lv, r, 1, res);
    lvSet(lv, r, 2, tm);
    ListView_EnsureVisible(lv, r, FALSE);

    ++g_pSent;
    if (replied) {
        if (g_pRecv == 0 || p.rtt < g_pMin) g_pMin = p.rtt;
        if (g_pRecv == 0 || p.rtt > g_pMax) g_pMax = p.rtt;
        g_pSum += p.rtt;
        ++g_pRecv;
    }
    g_graphVals.push_back(replied ? p.rtt : -1.0);
    InvalidateRect(ctl(PG_PING, ID_PG_GRAPH), nullptr, FALSE);
    updatePingSummary(nullptr);
}

void startPing() {
    std::string host = trim(getText(ctl(PG_PING, ID_PG_HOST)));
    if (host.empty()) {
        warn(L"Enter a host name or IP address to ping.");
        return;
    }
    int count = clampi(std::atoi(getText(ctl(PG_PING, ID_PG_COUNT)).c_str()), 1, 100000);
    int interval = clampi(std::atoi(getText(ctl(PG_PING, ID_PG_INTERVAL)).c_str()), 50, 10000);
    bool tcp = SendMessageW(ctl(PG_PING, ID_PG_TCP), BM_GETCHECK, 0, 0) == BST_CHECKED;
    int port = tcp ? clampi(std::atoi(getText(ctl(PG_PING, ID_PG_PORT)).c_str()), 1, 65535) : 0;
    if (!beginJob(L"Pinging...")) return;

    lvClear(ctl(PG_PING, ID_PG_LIST));
    g_graphVals.clear();
    g_pSent = g_pRecv = 0;
    g_pMin = g_pMax = g_pSum = 0;
    InvalidateRect(ctl(PG_PING, ID_PG_GRAPH), nullptr, FALSE);
    setText(ctl(PG_PING, ID_PG_SUMMARY), "");

    Options o = g_opt;
    o.count = count;
    o.intervalMs = interval;
    o.timeoutMs = 1000;
    std::thread([host, port, o] {
        Series s = runSeriesCb(host, port, o, false, [](int seq, const Probe& p) { ui([seq, p] { addPingRow(seq, p); }); });
        if (s.sent > 0) logPing(o, s);
        ui([s, host] {
            if (s.sent == 0) {
                setText(ctl(PG_PING, ID_PG_SUMMARY), "Could not ping " + host + ": " + s.error);
                endJob(L"Ping failed.");
                return;
            }
            updatePingSummary(&s);
            endJob(L"Ping finished - " + W(s.target) + L" (" + W(s.ip) + L") via " + W(s.method) + L".");
        });
    }).detach();
}

void drawGraph(HDC hdc, const RECT& rc) {
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    if (w <= 0 || h <= 0) return;
    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
    HGDIOBJ oldBmp = SelectObject(mem, bmp);
    HGDIOBJ oldFont = SelectObject(mem, g_font);

    RECT all = {0, 0, w, h};
    FillRect(mem, &all, (HBRUSH)GetStockObject(WHITE_BRUSH));

    int padL = S(46), padR = S(10), padT = S(10), padB = S(10);
    int plotW = w - padL - padR, plotH = h - padT - padB;
    if (plotW < 20 || plotH < 20) goto done;
    {
        const size_t kWindow = 100;
        size_t first = g_graphVals.size() > kWindow ? g_graphVals.size() - kWindow : 0;
        double ymax = 5.0;
        for (size_t i = first; i < g_graphVals.size(); ++i) ymax = std::max(ymax, g_graphVals[i] * 1.15);

        HPEN grid = CreatePen(PS_SOLID, 1, RGB(225, 225, 225));
        HGDIOBJ oldPen = SelectObject(mem, grid);
        SetBkMode(mem, TRANSPARENT);
        SetTextColor(mem, RGB(110, 110, 110));
        for (int g = 0; g <= 4; ++g) {
            int y = padT + plotH - plotH * g / 4;
            MoveToEx(mem, padL, y, nullptr);
            LineTo(mem, padL + plotW, y);
            std::wstring lab = W(fmt("%.0f ms", ymax * g / 4));
            RECT tr = {0, y - S(8), padL - S(6), y + S(8)};
            DrawTextW(mem, lab.c_str(), -1, &tr, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        }
        SelectObject(mem, oldPen);
        DeleteObject(grid);

        double step = plotW / (double)(kWindow - 1);
        HPEN line = CreatePen(PS_SOLID, std::max(1, S(2)), RGB(0, 120, 215));
        HPEN lost = CreatePen(PS_SOLID, 1, RGB(210, 0, 0));
        bool pen = false;
        for (size_t i = first; i < g_graphVals.size(); ++i) {
            int x = padL + (int)((double)(i - first) * step);
            double v = g_graphVals[i];
            if (v < 0) {  // lost probe: red marker, breaks the line
                SelectObject(mem, lost);
                MoveToEx(mem, x, padT, nullptr);
                LineTo(mem, x, padT + plotH);
                pen = false;
                continue;
            }
            int y = padT + plotH - (int)(plotH * v / ymax);
            SelectObject(mem, line);
            if (!pen) MoveToEx(mem, x, y, nullptr); else LineTo(mem, x, y);
            pen = true;
            Ellipse(mem, x - S(2), y - S(2), x + S(3), y + S(3));
        }
        SelectObject(mem, oldPen);
        DeleteObject(line);
        DeleteObject(lost);
        if (g_graphVals.empty()) {
            RECT tr = {padL, padT, padL + plotW, padT + plotH};
            DrawTextW(mem, L"Press Start to measure latency", -1, &tr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
    }
done:
    BitBlt(hdc, rc.left, rc.top, w, h, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldFont);
    SelectObject(mem, oldBmp);
    DeleteObject(bmp);
    DeleteDC(mem);
}

LRESULT CALLBACK GraphProc(HWND hw, UINT m, WPARAM wp, LPARAM lp) {
    if (m == WM_ERASEBKGND) return 1;
    if (m == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hw, &ps);
        RECT rc;
        GetClientRect(hw, &rc);
        drawGraph(dc, rc);
        EndPaint(hw, &ps);
        return 0;
    }
    return DefWindowProcW(hw, m, wp, lp);
}

// ============================================================ Devices

std::string devAddr(const Device& d) { return d.host + (d.port > 0 ? ":" + std::to_string(d.port) : ""); }

void loadDeviceRows() {
    HWND lv = ctl(PG_DEVICES, ID_DV_LIST);
    lvClear(lv);
    g_devStatus.assign(g_devices.size(), "");
    for (auto& d : g_devices) {
        int r = lvAdd(lv, d.name);
        lvSet(lv, r, 1, devAddr(d));
    }
}

void fillDevices(const std::vector<DeviceResult>& res) {
    HWND lv = ctl(PG_DEVICES, ID_DV_LIST);
    if ((int)res.size() != ListView_GetItemCount(lv)) return;
    std::map<std::string, int> tally;
    g_devStatus.assign(res.size(), "");
    for (size_t i = 0; i < res.size(); ++i) {
        const DeviceResult& r = res[i];
        const Series& s = r.s;
        int row = (int)i;
        lvSet(lv, row, 1, (s.ip.empty() ? r.dev.host : s.ip) + (r.dev.port > 0 ? ":" + std::to_string(r.dev.port) : ""));
        lvSet(lv, row, 2, s.method.empty() ? "-" : s.method);
        lvSet(lv, row, 3, fmt("%.0f%%", s.lossPct()));
        lvSet(lv, row, 4, msCell(s, s.st.min));
        lvSet(lv, row, 5, msCell(s, s.st.avg));
        lvSet(lv, row, 6, msCell(s, s.st.max));
        lvSet(lv, row, 7, msCell(s, s.st.jitter));
        lvSet(lv, row, 8, r.status);
        lvSet(lv, row, 9, r.trend);
        std::string notes;
        for (auto& n : r.notes) notes += (notes.empty() ? "" : "; ") + n;
        lvSet(lv, row, 10, notes);
        g_devStatus[i] = r.status;
        ++tally[r.status];
    }
    std::string sum = fmt("%d device(s) tested:  ", (int)res.size());
    bool first = true;
    for (auto& kv : tally) {
        sum += (first ? "" : ",  ") + std::to_string(kv.second) + " " + kv.first;
        first = false;
    }
    setText(ctl(PG_DEVICES, ID_DV_SUMMARY), sum);
    InvalidateRect(lv, nullptr, TRUE);
}

void runDeviceTest() {
    if (g_devices.empty()) {
        setStatus(L"Add at least one device first.");
        return;
    }
    if (!beginJob(L"Testing devices...")) return;
    auto devs = g_devices;
    Options o = g_opt;
    o.count = 5;
    std::thread([devs, o] {
        auto res = evaluateDevices(o, devs);
        ui([res] {
            fillDevices(res);
            endJob(L"Device test finished at " + clockNow() + L".");
        });
    }).detach();
}

void addDevice() {
    if (g_job) { setStatus(L"Wait for the running task to finish first."); return; }
    std::string name = trim(getText(ctl(PG_DEVICES, ID_DV_NAME)));
    std::string host = trim(getText(ctl(PG_DEVICES, ID_DV_HOST)));
    int port = std::atoi(getText(ctl(PG_DEVICES, ID_DV_PORT)).c_str());
    if (host.empty()) { warn(L"Enter a host name or IP address (or the word  gateway  for your router)."); return; }
    if (port < 0 || port > 65535) { warn(L"The port must be between 1 and 65535 (or empty for ping)."); return; }
    for (auto& c : host) if (c == ',') c = ' ';
    Device d;
    d.host = host;
    d.name = name.empty() ? host : name;
    d.port = port;
    g_devices.push_back(d);
    saveDevices(g_opt, g_devices);
    int r = lvAdd(ctl(PG_DEVICES, ID_DV_LIST), d.name);
    lvSet(ctl(PG_DEVICES, ID_DV_LIST), r, 1, devAddr(d));
    g_devStatus.push_back("");
    setText(ctl(PG_DEVICES, ID_DV_NAME), "");
    setText(ctl(PG_DEVICES, ID_DV_HOST), "");
    setText(ctl(PG_DEVICES, ID_DV_PORT), "");
    setStatus(L"Device added and saved to devices.conf.");
}

void removeDevice() {
    if (g_job) { setStatus(L"Wait for the running task to finish first."); return; }
    HWND lv = ctl(PG_DEVICES, ID_DV_LIST);
    int sel = lvSelected(lv);
    if (sel < 0 || sel >= (int)g_devices.size()) { setStatus(L"Select a device in the list first."); return; }
    g_devices.erase(g_devices.begin() + sel);
    g_devStatus.erase(g_devStatus.begin() + sel);
    ListView_DeleteItem(lv, sel);
    saveDevices(g_opt, g_devices);
    setStatus(L"Device removed.");
}

// ============================================================ Scan

void finishScan(bool ok, const std::vector<Host>& hosts, const std::string& ifn, const std::string& err) {
    HWND lv = ctl(PG_SCAN, ID_SC_LIST);
    lvClear(lv);
    g_hosts = hosts;
    if (!ok) {
        setText(ctl(PG_SCAN, ID_SC_INFO), "Scan failed: " + err);
        endJob(L"Scan failed.");
        return;
    }
    for (auto& h : hosts) {
        int r = lvAdd(lv, h.ip);
        lvSet(lv, r, 1, h.mac);
        lvSet(lv, r, 2, h.name.empty() ? "-" : h.name);
        lvSet(lv, r, 3, h.randomized ? "Private MAC - usually a phone" : "");
    }
    setText(ctl(PG_SCAN, ID_SC_INFO),
            fmt("%d device(s) found on %s.  Select a phone and click \"Track selected as phone\".", (int)hosts.size(),
                ifn.c_str()));
    endJob(L"Scan finished at " + clockNow() + L".");
}

void startScan() {
    if (!beginJob(L"Scanning the local network (about 10 seconds)...")) return;
    lvClear(ctl(PG_SCAN, ID_SC_LIST));
    setText(ctl(PG_SCAN, ID_SC_INFO), "Scanning...");
    Options o = g_opt;
    std::thread([o] {
        std::vector<Host> hosts;
        std::string ifn, err;
        bool ok = scanNetwork(o, hosts, ifn, err);
        ui([ok, hosts, ifn, err] { finishScan(ok, hosts, ifn, err); });
    }).detach();
}

// ============================================================ Phones

void loadPhoneRows() {
    HWND lv = ctl(PG_PHONES, ID_PH_LIST);
    lvClear(lv);
    g_phStatus.assign(g_phones.size(), "");
    g_phEvent.assign(g_phones.size(), "");
    for (auto& p : g_phones) {
        int r = lvAdd(lv, p.name);
        lvSet(lv, r, 1, p.mac);
        auto prev = lastRow(g_opt, "phone_tracking.csv", 1, p.name);
        if (prev.size() > 4) {
            lvSet(lv, r, 2, "last: " + prev[3]);
            lvSet(lv, r, 3, prev[4]);
        } else {
            lvSet(lv, r, 2, "not checked yet");
        }
    }
}

bool addPhone(std::string name, const std::string& macIn, std::wstring& err) {
    std::string mac;
    if (!normalizeMac(macIn, mac)) {
        err = L"That is not a valid MAC address. Use the format  aa:bb:cc:dd:ee:ff.";
        return false;
    }
    for (auto& p : g_phones)
        if (p.mac == mac) {
            err = L"This MAC address is already being tracked.";
            return false;
        }
    for (auto& c : name) if (c == ',') c = ' ';
    name = trim(name);
    if (name.empty()) name = "Phone " + std::to_string(g_phones.size() + 1);
    g_phones.push_back({name, mac});
    savePhones(g_opt, g_phones);
    HWND lv = ctl(PG_PHONES, ID_PH_LIST);
    int r = lvAdd(lv, name);
    lvSet(lv, r, 1, mac);
    lvSet(lv, r, 2, "not checked yet");
    g_phStatus.push_back("");
    g_phEvent.push_back("");
    return true;
}

void addPhoneFromEdits() {
    std::wstring err;
    if (!addPhone(getText(ctl(PG_PHONES, ID_PH_NAME)), getText(ctl(PG_PHONES, ID_PH_MAC)), err)) {
        warn(err.c_str());
        return;
    }
    setText(ctl(PG_PHONES, ID_PH_NAME), "");
    setText(ctl(PG_PHONES, ID_PH_MAC), "");
    setStatus(L"Phone added and saved to phones.conf.");
}

void fillPhones(const std::vector<PhoneResult>& res) {
    HWND lv = ctl(PG_PHONES, ID_PH_LIST);
    if ((int)res.size() != ListView_GetItemCount(lv)) return;
    int online = 0;
    for (size_t i = 0; i < res.size(); ++i) {
        const PhoneResult& r = res[i];
        int row = (int)i;
        lvSet(lv, row, 2, r.online ? "ONLINE" : "OFFLINE");
        lvSet(lv, row, 3, r.ip.empty() ? "-" : r.ip + (r.online ? "" : "  (last seen)"));
        lvSet(lv, row, 4, r.latency);
        lvSet(lv, row, 5, eventText(r));
        lvSet(lv, row, 6, nowStamp().substr(11));
        g_phStatus[i] = r.online ? "ONLINE" : "OFFLINE";
        g_phEvent[i] = r.event;
        if (r.online) ++online;
    }
    InvalidateRect(lv, nullptr, TRUE);
    setStatus(W(fmt("%d of %d phone(s) online - checked at ", online, (int)res.size())) + clockNow() + L".");
}

void runPhoneCheck() {
    if (g_phones.empty()) {
        setStatus(L"Add a phone first (use the Scan tab to find its MAC address).");
        return;
    }
    if (!beginJob(L"Looking for your phones on the network (about 10 seconds)...")) return;
    auto phones = g_phones;
    Options o = g_opt;
    std::thread([phones, o] {
        std::vector<PhoneResult> res;
        std::string err;
        bool ok = evaluatePhones(o, phones, res, err);
        ui([ok, res, err] {
            if (ok) {
                fillPhones(res);
                g_job = false;
                setBusy(false);  // status text was set by fillPhones
            } else {
                endJob(L"Phone check failed: " + W(err));
            }
        });
    }).detach();
}

// ============================================================ Logs

void loadLog() {
    HWND lv = ctl(PG_LOGS, ID_LG_LIST);
    int sel = (int)SendMessageW(ctl(PG_LOGS, ID_LG_COMBO), CB_GETCURSEL, 0, 0);
    if (sel < 0) sel = 0;
    std::string path = g_opt.logDir + "/" + kLogFiles[sel];
    lvClear(lv);
    while (ListView_DeleteColumn(lv, 0)) {}
    std::ifstream in(path);
    if (!in) {
        setStatus(L"No log yet: " + W(path) + L" (it is created the first time that tool runs).");
        return;
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line))
        if (!trim(line).empty()) lines.push_back(line);
    if (lines.empty()) return;
    auto head = split(lines[0], ',');
    for (size_t c = 0; c < head.size(); ++c) {
        std::string h = head[c];
        int w = h == "timestamp" ? 140 : h == "notes" ? 320 : (h == "hostname" || h == "event") ? 170
              : (h == "device" || h == "phone" || h == "target" || h == "interface") ? 130 : 95;
        addCol(lv, (int)c, W(h).c_str(), w);
    }
    int shown = 0;
    for (size_t i = lines.size() - 1; i >= 1 && shown < 5000; --i, ++shown) {  // newest first
        auto f = split(lines[i], ',');
        if (f.empty()) continue;
        int r = lvAdd(lv, f[0]);
        for (size_t c = 1; c < f.size() && c < head.size(); ++c) lvSet(lv, r, (int)c, f[c]);
    }
    setStatus(W(fmt("%s - %d row(s), newest first.", kLogFiles[sel], (int)lines.size() - 1)));
}

void openLogFolder() {
    makeDir(g_opt.logDir);
    wchar_t full[MAX_PATH];
    if (GetFullPathNameW(W(g_opt.logDir).c_str(), MAX_PATH, full, nullptr))
        ShellExecuteW(g_main, L"open", full, nullptr, nullptr, SW_SHOWNORMAL);
}

// ============================================================ auto-repeat timers

void updateAutoTimer(int pg) {
    UINT_PTR tid = pg == PG_DEVICES ? 1 : 2;
    int chkId = pg == PG_DEVICES ? ID_DV_AUTO : ID_PH_AUTO, editId = pg == PG_DEVICES ? ID_DV_EVERY : ID_PH_EVERY;
    KillTimer(g_main, tid);
    if (SendMessageW(ctl(pg, chkId), BM_GETCHECK, 0, 0) != BST_CHECKED) return;
    int minSec = pg == PG_DEVICES ? 10 : 20;
    int secs = clampi(std::atoi(getText(ctl(pg, editId)).c_str()), minSec, 86400);
    SetTimer(g_main, tid, (UINT)secs * 1000, nullptr);
}

// ============================================================ colors (status columns)

COLORREF statusColor(const std::string& s) {
    if (s == "EXCELLENT" || s == "GOOD" || s == "ONLINE") return RGB(0, 130, 60);
    if (s == "DEGRADED" || s == "PORT_CLOSED") return RGB(200, 120, 0);
    if (s == "POOR") return RGB(205, 70, 0);
    if (s == "DOWN" || s == "UNRESOLVED") return RGB(200, 0, 0);
    if (s == "OFFLINE") return RGB(120, 120, 120);
    return GetSysColor(COLOR_WINDOWTEXT);
}

LRESULT onCustomDraw(NMLVCUSTOMDRAW* cd, int id) {
    switch (cd->nmcd.dwDrawStage) {
        case CDDS_PREPAINT: return CDRF_NOTIFYITEMDRAW;
        case CDDS_ITEMPREPAINT: return CDRF_NOTIFYSUBITEMDRAW;
        case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
            int row = (int)cd->nmcd.dwItemSpec, col = cd->iSubItem;
            const std::vector<std::string>& st = id == ID_DV_LIST ? g_devStatus : g_phStatus;
            int statusCol = id == ID_DV_LIST ? 8 : 2;
            cd->clrText = GetSysColor(COLOR_WINDOWTEXT);
            SelectObject(cd->nmcd.hdc, g_font);  // reset: the previous cell may have used the bold font
            if (row >= 0 && row < (int)st.size()) {
                if (col == statusCol && !st[row].empty()) {
                    cd->clrText = statusColor(st[row]);
                    SelectObject(cd->nmcd.hdc, g_fontBold);
                } else if (id == ID_PH_LIST && col == 5 && row < (int)g_phEvent.size() &&
                           (g_phEvent[row] == "IP_CHANGED" || g_phEvent[row] == "BACK_ONLINE_NEW_IP")) {
                    cd->clrText = RGB(200, 120, 0);
                    SelectObject(cd->nmcd.hdc, g_fontBold);
                }
            }
            return CDRF_NEWFONT;
        }
    }
    return CDRF_DODEFAULT;
}

// ============================================================ building the pages

void buildOverview() {
    const int p = PG_OVERVIEW;
    label(p, L"", 8, 8, -8, 58, ID_OV_SUMMARY);
    button(p, ID_OV_REFRESH, L"Refresh", 8, 72, 100, 28);
    HWND lv = listView(p, ID_OV_LIST, 8, 108, -8, -8);
    addCol(lv, 0, L"Adapter", 190);
    addCol(lv, 1, L"Type", 90);
    addCol(lv, 2, L"Status", 60);
    addCol(lv, 3, L"IPv4", 150);
    addCol(lv, 4, L"MAC", 130);
    addCol(lv, 5, L"Speed", 90);
    addCol(lv, 6, L"Received", 90);
    addCol(lv, 7, L"Sent", 90);
}

void buildPing() {
    const int p = PG_PING;
    label(p, L"Host:", 8, 12, 36, 18);
    edit(p, ID_PG_HOST, L"8.8.8.8", 46, 8, 170, 24);
    label(p, L"Probes:", 226, 12, 46, 18);
    edit(p, ID_PG_COUNT, L"20", 274, 8, 52, 24, true);
    label(p, L"Interval (ms):", 336, 12, 82, 18);
    edit(p, ID_PG_INTERVAL, L"500", 420, 8, 56, 24, true);
    check(p, ID_PG_TCP, L"TCP port", 490, 10, 76, 22);
    edit(p, ID_PG_PORT, L"443", 568, 8, 52, 24, true);
    button(p, ID_PG_START, L"Start", 634, 7, 80, 26);
    HWND stop = button(p, ID_PG_STOP, L"Stop", 720, 7, 80, 26);
    EnableWindow(stop, FALSE);
    label(p, L"", 8, 42, -8, 20, ID_PG_SUMMARY);
    mk(p, L"NAGraph", L"", 0, WS_EX_CLIENTEDGE, ID_PG_GRAPH, 8, 66, -8, 140);
    HWND lv = listView(p, ID_PG_LIST, 8, 214, -8, -8);
    addCol(lv, 0, L"#", 50);
    addCol(lv, 1, L"Result", 200);
    addCol(lv, 2, L"Time", 100);
}

void buildDevices() {
    const int p = PG_DEVICES;
    label(p, L"Name:", 8, 12, 40, 18);
    edit(p, ID_DV_NAME, L"", 50, 8, 130, 24);
    label(p, L"Host / IP:", 190, 12, 58, 18);
    edit(p, ID_DV_HOST, L"", 250, 8, 170, 24);
    label(p, L"Port:", 430, 12, 30, 18);
    edit(p, ID_DV_PORT, L"", 462, 8, 52, 24, true);
    button(p, ID_DV_ADD, L"Add", 524, 7, 70, 26);
    button(p, ID_DV_REMOVE, L"Remove selected", 600, 7, 120, 26);
    button(p, ID_DV_RUN, L"Run test now", 8, 40, 110, 28);
    check(p, ID_DV_AUTO, L"Repeat every", 132, 45, 100, 22);
    edit(p, ID_DV_EVERY, L"60", 234, 43, 50, 24, true);
    label(p, L"seconds", 290, 47, 52, 18);
    label(p, L"", 352, 47, -8, 20, ID_DV_SUMMARY);
    HWND lv = listView(p, ID_DV_LIST, 8, 78, -8, -8);
    const wchar_t* cols[] = {L"Device", L"Address", L"Via", L"Loss", L"Min ms", L"Avg ms", L"Max ms", L"Jitter", L"Status", L"Trend", L"Notes"};
    const int widths[] = {130, 120, 80, 50, 60, 60, 60, 60, 100, 80, 300};
    for (int i = 0; i < 11; ++i) addCol(lv, i, cols[i], widths[i]);
}

void buildScan() {
    const int p = PG_SCAN;
    button(p, ID_SC_SCAN, L"Scan network", 8, 7, 120, 28);
    label(p, L"", 140, 13, -8, 20, ID_SC_INFO);
    HWND lv = listView(p, ID_SC_LIST, 8, 44, -8, -52);
    addCol(lv, 0, L"IP address", 130);
    addCol(lv, 1, L"MAC address", 150);
    addCol(lv, 2, L"Host name", 240);
    addCol(lv, 3, L"Note", 260);
    label(p, L"Phone name:", 8, -34, 80, 18);
    edit(p, ID_SC_NAME, L"", 92, -38, 170, 24);
    button(p, ID_SC_ADD, L"Track selected as phone", 272, -39, 190, 26);
}

void buildPhones() {
    const int p = PG_PHONES;
    label(p, L"Name:", 8, 12, 40, 18);
    edit(p, ID_PH_NAME, L"", 50, 8, 140, 24);
    label(p, L"MAC:", 202, 12, 34, 18);
    edit(p, ID_PH_MAC, L"", 238, 8, 150, 24);
    button(p, ID_PH_ADD, L"Add", 398, 7, 70, 26);
    button(p, ID_PH_REMOVE, L"Remove selected", 474, 7, 120, 26);
    button(p, ID_PH_CHECK, L"Check now", 8, 40, 110, 28);
    check(p, ID_PH_AUTO, L"Repeat every", 132, 45, 100, 22);
    edit(p, ID_PH_EVERY, L"60", 234, 43, 50, 24, true);
    label(p, L"seconds", 290, 47, 52, 18);
    HWND lv = listView(p, ID_PH_LIST, 8, 78, -8, -56);
    const wchar_t* cols[] = {L"Phone", L"MAC address", L"Status", L"IP address", L"Latency", L"Event", L"Checked"};
    const int widths[] = {150, 140, 110, 190, 80, 220, 80};
    for (int i = 0; i < 7; ++i) addCol(lv, i, cols[i], widths[i]);
    label(p, L"Use the MAC address your phone shows for THIS Wi-Fi network (Settings > Wi-Fi > network details), "
             L"not the factory one. Phones use a private MAC per network. Use the Scan tab to find it.",
          8, -48, -8, 40, ID_PH_INFO);
}

void buildLogs() {
    const int p = PG_LOGS;
    label(p, L"Log file:", 8, 12, 56, 18);
    HWND combo = mk(p, L"COMBOBOX", L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, 0, ID_LG_COMBO, 66, 8, 200, 200);
    for (auto f : kLogFiles) SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)W(f).c_str());
    SendMessageW(combo, CB_SETCURSEL, 0, 0);
    button(p, ID_LG_REFRESH, L"Refresh", 276, 7, 80, 26);
    button(p, ID_LG_OPEN, L"Open logs folder", 364, 7, 130, 26);
    listView(p, ID_LG_LIST, 8, 42, -8, -8);
}

// ============================================================ window procedures

void selectTab(int i) {
    if (i < 0 || i >= PG_N) return;
    TabCtrl_SetCurSel(g_tab, i);
    for (int k = 0; k < PG_N; ++k) ShowWindow(g_page[k], k == i ? SW_SHOW : SW_HIDE);
    if (i == PG_LOGS) loadLog();
}

void primaryAction() {
    switch (TabCtrl_GetCurSel(g_tab)) {
        case PG_OVERVIEW: refreshOverview(); break;
        case PG_PING: startPing(); break;
        case PG_DEVICES: addDevice(); break;
        case PG_SCAN: startScan(); break;
        case PG_PHONES: addPhoneFromEdits(); break;
        default: break;
    }
}

void onCommand(int id, int code) {
    switch (id) {
        case ID_OV_REFRESH: refreshOverview(); break;
        case ID_PG_START: startPing(); break;
        case ID_PG_STOP: g_stop = 1; setStatus(L"Stopping..."); break;
        case ID_DV_ADD: addDevice(); break;
        case ID_DV_REMOVE: removeDevice(); break;
        case ID_DV_RUN: runDeviceTest(); break;
        case ID_DV_AUTO: updateAutoTimer(PG_DEVICES); if (SendMessageW(ctl(PG_DEVICES, ID_DV_AUTO), BM_GETCHECK, 0, 0) == BST_CHECKED) runDeviceTest(); break;
        case ID_DV_EVERY: if (code == EN_CHANGE) updateAutoTimer(PG_DEVICES); break;
        case ID_SC_SCAN: startScan(); break;
        case ID_SC_ADD: {
            int sel = lvSelected(ctl(PG_SCAN, ID_SC_LIST));
            if (sel < 0 || sel >= (int)g_hosts.size()) { setStatus(L"Select a device in the list first."); break; }
            std::string name = trim(getText(ctl(PG_SCAN, ID_SC_NAME)));
            if (name.empty()) name = g_hosts[sel].name;  // fall back to the device's own host name
            std::wstring err;
            if (!addPhone(name, g_hosts[sel].mac, err)) { warn(err.c_str()); break; }
            setText(ctl(PG_SCAN, ID_SC_NAME), "");
            selectTab(PG_PHONES);
            setStatus(L"Phone added to phones.conf - click \"Check now\" to look for it.");
            break;
        }
        case ID_PH_ADD: addPhoneFromEdits(); break;
        case ID_PH_REMOVE: {
            if (g_job) { setStatus(L"Wait for the running task to finish first."); break; }
            HWND lv = ctl(PG_PHONES, ID_PH_LIST);
            int sel = lvSelected(lv);
            if (sel < 0 || sel >= (int)g_phones.size()) { setStatus(L"Select a phone in the list first."); break; }
            g_phones.erase(g_phones.begin() + sel);
            g_phStatus.erase(g_phStatus.begin() + sel);
            g_phEvent.erase(g_phEvent.begin() + sel);
            ListView_DeleteItem(lv, sel);
            savePhones(g_opt, g_phones);
            setStatus(L"Phone removed.");
            break;
        }
        case ID_PH_CHECK: runPhoneCheck(); break;
        case ID_PH_AUTO: updateAutoTimer(PG_PHONES); if (SendMessageW(ctl(PG_PHONES, ID_PH_AUTO), BM_GETCHECK, 0, 0) == BST_CHECKED) runPhoneCheck(); break;
        case ID_PH_EVERY: if (code == EN_CHANGE) updateAutoTimer(PG_PHONES); break;
        case ID_LG_COMBO: if (code == CBN_SELCHANGE) loadLog(); break;
        case ID_LG_REFRESH: loadLog(); break;
        case ID_LG_OPEN: openLogFolder(); break;
        default: break;
    }
}

LRESULT CALLBACK PageProc(HWND hw, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
        case WM_SIZE: {
            int pg = (int)GetWindowLongPtrW(hw, GWLP_USERDATA) - 1;
            if (pg >= 0 && pg < PG_N) layoutPage(pg);
            return 0;
        }
        case WM_COMMAND:
        case WM_NOTIFY: return SendMessageW(g_main, m, wp, lp);
        case WM_CTLCOLORSTATIC: {
            HDC dc = (HDC)wp;
            SetBkMode(dc, TRANSPARENT);
            return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
        }
    }
    return DefWindowProcW(hw, m, wp, lp);
}

LRESULT CALLBACK MainProc(HWND hw, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
        case WM_SIZE:
            if (g_tab && g_status) layoutMain();
            return 0;
        case WM_GETMINMAXINFO: {
            auto* mm = (MINMAXINFO*)lp;
            mm->ptMinTrackSize.x = S(880);
            mm->ptMinTrackSize.y = S(520);
            return 0;
        }
        case WM_NOTIFY: {
            auto* h = (NMHDR*)lp;
            if (h->idFrom == ID_TAB && h->code == TCN_SELCHANGE) { selectTab(TabCtrl_GetCurSel(g_tab)); return 0; }
            if (h->code == NM_CUSTOMDRAW && (h->idFrom == ID_DV_LIST || h->idFrom == ID_PH_LIST))
                return onCustomDraw((NMLVCUSTOMDRAW*)lp, (int)h->idFrom);
            return 0;
        }
        case WM_COMMAND:
            onCommand(LOWORD(wp), HIWORD(wp));
            return 0;
        case WM_TIMER:
            if (!g_job) {
                if (wp == 1) runDeviceTest();
                else if (wp == 2) runPhoneCheck();
            }
            return 0;
        case WM_UI_CALL: {
            auto* f = (std::function<void()>*)lp;
            (*f)();
            delete f;
            return 0;
        }
        case WM_CLOSE:
            g_stop = 1;  // let a running task wind down (up to ~4 s)
            for (int i = 0; i < 80 && g_job; ++i) Sleep(50);
            DestroyWindow(hw);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hw, m, wp, lp);
}

BOOL CALLBACK setFontProc(HWND h, LPARAM) {
    SendMessageW(h, WM_SETFONT, (WPARAM)g_font, TRUE);
    return TRUE;
}

// Turns on the modern (visual-styles) look without needing a manifest resource.
void initCommonControls() {
    static const char xml[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n"
        "<dependency><dependentAssembly>\n"
        "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" "
        "processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"/>\n"
        "</dependentAssembly></dependency>\n</assembly>\n";
    wchar_t tmp[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tmp)) {
        std::wstring path = std::wstring(tmp) + L"netanalyzer_gui.manifest";
        if (FILE* f = _wfopen(path.c_str(), L"wb")) {
            fwrite(xml, 1, sizeof xml - 1, f);
            fclose(f);
            ACTCTXW ctx{};
            ctx.cbSize = sizeof ctx;
            ctx.lpSource = path.c_str();
            HANDLE h = CreateActCtxW(&ctx);
            if (h != INVALID_HANDLE_VALUE) {
                ULONG_PTR cookie = 0;
                ActivateActCtx(h, &cookie);  // stays active for the life of the process
            }
            DeleteFileW(path.c_str());
        }
    }
    using InitFn = BOOL(WINAPI*)(const INITCOMMONCONTROLSEX*);
    HMODULE cc = LoadLibraryW(L"comctl32.dll");
    InitFn init = cc ? reinterpret_cast<InitFn>(reinterpret_cast<void*>(GetProcAddress(cc, "InitCommonControlsEx"))) : nullptr;
    INITCOMMONCONTROLSEX icc = {sizeof icc, ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES};
    if (init) init(&icc);
}

}  // namespace

int WINAPI WinMain(HINSTANCE hi, HINSTANCE, LPSTR cmdLine, int show) {
    g_inst = hi;
    SetProcessDPIAware();

    // Keep settings and logs next to the .exe, wherever it was started from.
    wchar_t exe[MAX_PATH];
    if (GetModuleFileNameW(nullptr, exe, MAX_PATH)) {
        wchar_t* slash = wcsrchr(exe, L'\\');
        if (slash) { *slash = 0; SetCurrentDirectoryW(exe); }
    }

    initCommonControls();
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    (void)icmpAvailable();

    HDC sdc = GetDC(nullptr);
    g_dpi = GetDeviceCaps(sdc, LOGPIXELSX);
    ReleaseDC(nullptr, sdc);
    NONCLIENTMETRICSW ncm{};
    ncm.cbSize = sizeof ncm;
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof ncm, &ncm, 0);
    g_font = CreateFontIndirectW(&ncm.lfMessageFont);
    LOGFONTW bold = ncm.lfMessageFont;
    bold.lfWeight = FW_BOLD;
    g_fontBold = CreateFontIndirectW(&bold);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof wc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpfnWndProc = MainProc;
    wc.lpszClassName = L"NAMain";
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    RegisterClassExW(&wc);
    wc.lpfnWndProc = PageProc;
    wc.lpszClassName = L"NAPage";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassExW(&wc);
    wc.lpfnWndProc = GraphProc;
    wc.lpszClassName = L"NAGraph";
    wc.hbrBackground = nullptr;
    RegisterClassExW(&wc);

    g_main = CreateWindowExW(0, L"NAMain", L"Network Analyzer", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT,
                             CW_USEDEFAULT, S(1040), S(720), nullptr, nullptr, hi, nullptr);
    g_tab = CreateWindowExW(0, L"SysTabControl32", L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP, 0, 0, 10,
                            10, g_main, (HMENU)(INT_PTR)ID_TAB, hi, nullptr);
    g_status = CreateWindowExW(0, L"msctls_statusbar32", L"", WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, g_main,
                               (HMENU)(INT_PTR)ID_STATUSBAR, hi, nullptr);
    SendMessageW(g_tab, WM_SETFONT, (WPARAM)g_font, TRUE);
    SendMessageW(g_status, WM_SETFONT, (WPARAM)g_font, TRUE);
    for (int i = 0; i < PG_N; ++i) {
        TCITEMW it{};
        it.mask = TCIF_TEXT;
        it.pszText = const_cast<LPWSTR>(kTabNames[i]);
        SendMessageW(g_tab, TCM_INSERTITEMW, (WPARAM)i, (LPARAM)&it);
    }
    for (int i = 0; i < PG_N; ++i) {
        g_page[i] = CreateWindowExW(WS_EX_CONTROLPARENT, L"NAPage", L"", WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, 0, 0,
                                    10, 10, g_main, nullptr, hi, nullptr);
        SetWindowLongPtrW(g_page[i], GWLP_USERDATA, i + 1);
    }
    SetWindowPos(g_tab, HWND_BOTTOM, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);  // pages must sit above it
    buildOverview();
    buildPing();
    buildDevices();
    buildScan();
    buildPhones();
    buildLogs();
    for (int i = 0; i < PG_N; ++i) EnumChildWindows(g_page[i], setFontProc, 0);

    // Sample config files on first run, then load them.
    cmdInit(g_opt);
    std::string err;
    loadDevices(g_opt, g_devices, err);
    loadPhones(g_opt, g_phones, err);
    loadDeviceRows();
    loadPhoneRows();
    updatePingSummary(nullptr);

    int startTab = PG_OVERVIEW;
    std::string cl = cmdLine ? cmdLine : "";
    size_t tp = cl.find("--tab");
    if (tp != std::string::npos) startTab = clampi(std::atoi(cl.c_str() + tp + 5), 0, PG_N - 1);

    ShowWindow(g_main, show);
    layoutMain();
    {
        wchar_t full[MAX_PATH];
        std::wstring lp = GetFullPathNameW(W(g_opt.logDir).c_str(), MAX_PATH, full, nullptr) ? full : W(g_opt.logDir);
        SendMessageW(g_status, SB_SETTEXTW, 1, (LPARAM)(L"Logs: " + lp).c_str());
    }
    selectTab(startTab);
    UpdateWindow(g_main);
    refreshOverview();

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            wchar_t cls[16] = {0};
            GetClassNameW(GetFocus(), cls, 16);
            if (!_wcsicmp(cls, L"Edit")) {  // Enter inside a text box = the page's main action
                primaryAction();
                continue;
            }
        }
        if (!IsDialogMessageW(g_main, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}
