# NetAnalyzer

A small, dependency-free network analyzer written in C++17. It measures latency, checks whether your devices are reachable, lists everything on your local network, and tracks your phones as their IP addresses change. All results are saved to CSV files.

It comes in two parts that share one engine:

| File | What it is | Platforms |
|------|-----------|-----------|
| `netanalyzer.cpp` | Command-line tool **and** the shared engine (all the networking logic) | Windows + Linux |
| `netanalyzer_gui.cpp` | Windows GUI (tabbed window) that `#include`s `netanalyzer.cpp` | Windows only |

No administrator/root rights are needed.

---

## Features

- **info**: adapters, IPv4/IPv6, MAC, MTU, link speed, traffic counters, default gateway, DNS servers
- **ping**: latency with min / avg / max / jitter / standard deviation / packet loss (ICMP or TCP)
- **test**: pings many devices **in parallel**, classifies each one (EXCELLENT … DOWN), and compares with the previous run
- **scan**: finds every device on your subnet (IP, MAC, hostname, randomized-MAC hint)
- **track**: follows your phones by MAC address and reports when they come online, go offline, or change IP
- **init**: creates sample `devices.conf` and `phones.conf`
- **Logging**: every command appends to its own CSV in `./netlogs/`

---

## Build

### Linux (CLI)
```bash
g++ -std=c++17 -O2 -Wall -Wextra -pthread -o netanalyzer netanalyzer.cpp
```

### Windows (CLI), MSYS2 MinGW-w64
```bash
g++ -std=c++17 -O2 -Wall -Wextra -static -o netanalyzer.exe netanalyzer.cpp -liphlpapi -lws2_32
```

### Windows (GUI)
Both `.cpp` files must be in the same folder. **Compile only the GUI file.** It includes the engine itself.
```bash
g++ -std=c++17 -O2 -Wall -Wextra -static -mwindows -o netanalyzer_gui.exe netanalyzer_gui.cpp -liphlpapi -lws2_32 -lgdi32 -lshell32
```

---

## Usage (CLI)

```
netanalyzer <command> [options]
```

| Command | Description |
|---------|-------------|
| `info` | Local network information |
| `ping <host>` | Latency statistics for one host |
| `test [host[:port] ...]` | Test devices from `devices.conf`, or the targets you list |
| `scan` | List devices visible on the local network |
| `track` | Follow phones listed in `phones.conf` |
| `init` | Create sample config files |

### Options

| Option | Meaning | Default |
|--------|---------|---------|
| `-c, --count N` | Probes per target (1–1000) | 5 |
| `-i, --interval MS` | Pause between probes | 200 |
| `-t, --timeout MS` | Per-probe timeout (min 50) | 1000 |
| `-p, --port N` | `ping`: use a TCP connect to this port | – |
| `--tcp` | `ping`: force TCP (port 80) instead of ICMP | off |
| `--every SEC` | `test` / `track`: repeat every SEC seconds until Ctrl+C | once |
| `--settle SEC` | `scan` / `track`: seconds to wait for ARP replies | 5 |
| `--iface NAME` | `scan` / `track`: adapter to use (e.g. `eth0`, `"Wi-Fi"`) | auto |
| `-f, --file PATH` | Use another devices/phones config file | – |
| `--log-dir DIR` | Where CSV logs go | `./netlogs` |

### Examples
```bash
netanalyzer init                          # create devices.conf + phones.conf
netanalyzer info
netanalyzer ping 8.8.8.8 -c 20
netanalyzer ping google.com -p 443        # TCP latency to port 443
netanalyzer ping gateway                  # "gateway" = your default router
netanalyzer test                          # test everything in devices.conf
netanalyzer test 1.1.1.1 example.com:443  # ad-hoc targets
netanalyzer test --every 60               # repeat each minute
netanalyzer scan
netanalyzer track --every 60
```

### Exit codes
`0` success · `1` usage/config error · `2` target(s) unreachable (`ping` got no replies, or `test` found DOWN/UNRESOLVED devices)

---

## The GUI

Tabs: **Overview · Ping · Devices · Scan · Phones · Logs**

| Tab | What it does |
|-----|--------------|
| **Overview** | Hostname, gateway, DNS, and a table of adapters. Refresh button. |
| **Ping** | Host, count, interval, optional TCP port. Shows a **live latency graph** plus a per-probe table and running summary. |
| **Devices** | Add/remove devices, run a test now, or auto-repeat (minimum 10 s). Rows are colour-coded by status. |
| **Scan** | Scans the network. Select a row, type a name, and click **Track selected as phone** to add it to the Phones tab. |
| **Phones** | Add/remove phones by MAC, check now, or auto-repeat (minimum 20 s). Colour-coded events. |
| **Logs** | Browse any of the CSV logs in a table, with a button to open the logs folder. |

Settings (`devices.conf`, `phones.conf`) and the `netlogs` folder live **next to the `.exe`**. You can start on a specific tab with `netanalyzer_gui.exe --tab 3`.

---

## Configuration files

### `devices.conf`
```
# name, host, [tcp_port]
Router, gateway
Cloudflare DNS, 1.1.1.1
Google (HTTPS), google.com, 443
```
- No port → ICMP ping latency.
- With a port → checks that the service accepts connections.
- `gateway` → your default router.
- Lines starting with `#` and blank lines are ignored.

### `phones.conf`
```
# name, MAC address
My Phone, aa:bb:cc:dd:ee:ff
```
Use the MAC your phone uses **for this Wi-Fi network** (Settings → Wi-Fi → network details → private/randomized MAC), not the factory MAC. Run `scan` to see what's on your network. MACs may use `:` or `-`.

---

## How it works

### Architecture

```
netanalyzer.cpp  ── engine ─────────────────────────────┐
  ├─ system info   (adapters, gateway, DNS)              │  used directly by the CLI (main)
  ├─ probes        (ICMP / TCP latency)                  │
  ├─ ARP discovery (subnet sweep + ARP table)            │  and #included by
  ├─ analysis      (stats, classification, trends)       │
  └─ CSV logging                                         │  netanalyzer_gui.cpp  ── Win32 UI
                                                         ┘  (defines NETANALYZER_NO_MAIN to
                                                             drop the CLI main())
```

Platform differences are isolated with `#ifdef _WIN32`, so every command behaves the same on both systems.

### 1. System info (`info`)
- **Windows:** `GetAdaptersAddresses` (adapters, IPs, DNS, MAC), `GetIfEntry2` (traffic counters), `GetBestRoute` toward `1.1.1.1` (default gateway).
- **Linux:** `getifaddrs`, plus `/sys/class/net/<if>/…` for MTU, speed, and byte counters; `/proc/net/route` for the gateway; `/etc/resolv.conf` for DNS.

### 2. Latency probing (`ping`)
A *series* sends N probes, one at a time, and records the round-trip time (RTT) of each.

- **ICMP** (default): Windows uses `IcmpSendEcho` (no special rights needed). Linux uses an *unprivileged* ICMP datagram socket (`SOCK_DGRAM + IPPROTO_ICMP`), building the echo packet and checksum by hand.
- **TCP fallback:** used when you pass `-p`/`--tcp`, or when Linux doesn't allow unprivileged ICMP. It times a non-blocking `connect()`. A *"connection refused"* reply still proves the host is alive, so it counts as a reply (reported as "port closed").
- Timing uses a monotonic clock (`steady_clock`), so values are in fractional milliseconds.

**Statistics computed**
- min / max / average
- **jitter** = mean absolute difference between consecutive RTTs
- standard deviation
- packet loss % = (sent − received) / sent

### 3. Device testing and analysis (`test`)
1. Every device runs its probe series **in parallel** (`std::async`).
2. Each result is classified:

| Status | Rule |
|--------|------|
| `UNRESOLVED` | Host name couldn't be resolved |
| `DOWN` | No replies at all |
| `PORT_CLOSED` | Host answers, but every reply was "connection refused" |
| `POOR` | Loss ≥ 20 % **or** avg ≥ 200 ms |
| `DEGRADED` | Any loss, **or** jitter > 30 ms, **or** avg ≥ 100 ms |
| `EXCELLENT` | avg < 20 ms **and** jitter < 5 ms |
| `GOOD` | Everything else |

3. **Trend:** the previous row for that device is read from `device_stats.csv` and the avg-latency difference is shown (e.g. `+3.2 ms`). A warning is added if latency jumped by more than 10 ms or 50 %.
4. Human-readable notes are added (packet loss, high jitter, closed port, error text) and one row per device is logged.

### 4. Network scan (`scan`)
No raw sockets or admin rights are required. The trick is to let the OS's own ARP do the work:

1. Pick the interface (the default-route adapter, or `--iface`) and compute the subnet. Subnets larger than /22 are limited to a /24, and /31–/32 are refused.
2. **Sweep:** send one tiny UDP packet to port 9 of every address in the subnet, twice (a second pass wakes sleeping phones). This forces the OS to ARP for each address.
3. Wait `--settle` seconds, then read the OS ARP table (`GetIpNetTable` on Windows, `/proc/net/arp` on Linux).
4. Filter to the right interface and subnet, dropping incomplete entries. On Windows each entry is re-verified with `SendARP`, because Windows keeps stale entries for a long time.
5. Reverse-DNS each host in parallel and flag **randomized MACs** (the "locally administered" bit, which phones use on Wi-Fi).

### 5. Phone tracking (`track`)
Phones change IP addresses (DHCP), but their MAC stays the same for a given Wi-Fi network. So the tracker:

1. Runs the same scan as above and builds a MAC → IP map.
2. Looks each phone's MAC up. Found = `ONLINE`, not found = `OFFLINE`.
3. Compares with the last logged state in `phone_tracking.csv` and emits an **event**:

| Event | Meaning |
|-------|---------|
| `FIRST_SEEN` / `NOT_FOUND_YET` | First check for this phone |
| `IP_CHANGED` | Online both times, but with a different IP |
| `BACK_ONLINE` / `BACK_ONLINE_NEW_IP` | Was offline, now online (same / different IP) |
| `WENT_OFFLINE` | Was online, now gone (last IP is remembered) |

4. For online phones it also does a quick 3-probe ping. "No reply" is normal because many sleeping phones ignore ping, while ARP still proves they're present.

### 6. Logging
`appendLog` creates `netlogs/` if needed, writes a header the first time a file is created, then appends one row per result. Commas and newlines in values are replaced with spaces to keep the CSV valid.

| File | Written by | Contents |
|------|-----------|----------|
| `interface_info.csv` | `info` | Adapter state, IP, MAC, gateway, rx/tx bytes |
| `latency_stats.csv` | `ping` | Loss, min/avg/max, jitter, stddev |
| `device_stats.csv` | `test` | Per-device stats, status, notes |
| `network_scan.csv` | `scan` | IP, MAC, hostname, randomized flag |
| `phone_tracking.csv` | `track` | Status, IP, previous IP, event, latency |

### 7. GUI internals
- **Win32 API only:** native tab control, list views, status bar, a custom-painted graph control, DPI scaling, and Common Controls v6 styling (a manifest is activated at runtime).
- **One background job at a time:** `beginJob` / `endJob` use an atomic flag so scans and tests never overlap. Work runs on a worker `std::thread`.
- **Thread safety:** worker threads never touch the UI directly. They call `ui(fn)`, which posts the closure to the main window as a `WM_UI_CALL` message, and it runs on the UI thread.
- **Stop button:** sets the shared `g_stop` flag that the engine checks between probes (the same flag Ctrl+C sets in the CLI).
- **Auto-repeat:** Windows timers (`SetTimer`) re-run the device test or phone check.
- **Layout:** each control stores its position in unscaled pixels (negative values anchor to the far edge) and is rescaled on resize or DPI change.
- **Enter key:** pressing Enter in a text box triggers the page's main action.

---

## Notes and limitations

- `scan` and `track` only see devices on the **same local subnet** (IPv4).
- Devices that block UDP/ARP, or are fully asleep, may not appear on a scan.
- Phone tracking relies on a stable MAC. If you forget the Wi-Fi network or change the private-address setting, the MAC changes and you must update `phones.conf`.
- Windows ICMP and ARP use the IP Helper API. Linux ICMP needs `net.ipv4.ping_group_range` to allow your user. Otherwise the tool automatically falls back to TCP timing.
- Only scan networks you own or have permission to test.
