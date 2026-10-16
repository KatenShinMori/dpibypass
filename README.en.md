# dpibypass — High-Performance Wire-Level DPI Bypass Engine for Windows

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6.svg)](https://microsoft.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Driver](https://img.shields.io/badge/Driver-WinDivert%202.2.2-green.svg)](https://reqcrypt.org/windivert.html)

**[English](README.en.md) | [Türkçe](README.md)**

**dpibypass** is a pure Go, wire-level Deep Packet Inspection (DPI) evasion engine and transparent DNS bridge designed for Windows x64. It operates at the kernel network layer via WinDivert to protect TCP (TLS/HTTP) and UDP traffic system-wide without requiring external proxies, VPNs, or browser extensions.

Specifically engineered to defeat stateful middlebox inspection (such as Türk Telekom / BTK throttling and censorship), **dpibypass** successfully bypasses blocks on Discord (native desktop app and voice gateways), Roblox, and web targets.

---

## Key Architectural Innovations

### 1. Pure Go Kernel Harness via WinDivert ABI (Zero CGO)
Unlike traditional tools that require C compilers or heavyweight third-party runtimes, `dpibypass` communicates directly with `WinDivert.dll` and `WinDivert64.sys` using pure Go standard library syscalls and structured ABI definitions. It features:
- **Pre-allocated 64 KiB buffer sizing** for Windows Large Send Offload (LSO/TSO) packet bursts.
- **Microsecond wire-level filtering** that passes non-target traffic straight through with zero overhead.

### 2. Post-Quantum TLS 1.3 Multi-Packet SNI Splitting
Modern Chromium-based applications (including Electron apps like the native Discord desktop client) send ~1,900-byte Post-Quantum (`X25519MLKEM768`) TLS 1.3 `ClientHello` records.
- **Pre-Segmented Packet 2 Continuation Tracking:** In large handshakes, the Windows TCP stack segments the payload before egress, placing the 1,216-byte key share in Packet 1 and the Server Name Indication (SNI) extension in Packet 2. `dpibypass` dynamically tracks TCP sequence continuations and intercepts Packet 2, desyncing and splitting right at the SNI boundary (`sni-mid`).
- **Out-of-Order Injection:** Transmits Segment 2 before Segment 1 onto the wire so middlebox reassembly engines fail to extract the target domain name.
- **MTU Safety Subsegmentation:** Automatically bounds injected chunks to `<= 1400` bytes to prevent Ethernet MTU drops.

### 3. Low-TTL Middlebox Poisoning (Fake Packet Injection)
- Synthesizes a valid TLS `ClientHello` with a benign SNI (e.g., `www.example.com`) sharing the exact 4-tuple and TCP sequence numbers.
- Transmits the fake packet with a low hop count (e.g., `TTL 3` or `TTL 4`) so it blinds the ISP middlebox at hop 3 and evaporates before reaching the destination server.
- Supports multi-hop TTL interleaving to resist ECMP routing shifts.

### 4. Zero-DNS DoH Bootstrap & Automated Windows `hosts` Sync
ISP DNS sinkholing (e.g. redirecting domains to `195.175.254.2`) poisons Windows `Dnscache` and Chromium's in-memory `net::HostCache`. `dpibypass` eliminates this:
- **Zero-DNS Bootstrap:** Directly dials Anycast IPs (`1.1.1.1`, `8.8.8.8`) over HTTPS, preventing bootstrap DNS deadlocks.
- **Automated `hosts` Sync:** Concurrently resolves live, clean IPv4 records for Discord and Roblox endpoints on startup and atomically manages the `# BEGIN DPIBYPASS MANAGED HOSTS` block in `C:\Windows\System32\drivers\etc\hosts`.
- **WFP Impostor Capture:** Captures UDP port 53 queries even when re-injected by third-party antivirus WFP filters (such as Kaspersky), synthesizing inbound RFC 768 software-checksummed responses.
- **Clean Recovery:** Automatically restores the original `hosts` file upon exit or recovery.

### 5. IPv6 Happy Eyeballs Fallback (RFC 8305)
Dual-stack ISP routers often route connections over IPv6 where packet manipulation is unconfigured. `dpibypass` suppresses outbound IPv6 TCP SYN packets on ports 80/443 and answers IPv6 DNS with clean `NODATA` responses, forcing client applications to fall back immediately within 1ms to protected IPv4 paths.

### 6. Embedded Loopback WebUI & Anti-Cheat Safe Mode
Runs an optional, zero-dependency dashboard on `127.0.0.1:8787`:
- Live metrics: packets intercepted, synthetic fake packets, split segments, and DoH resolutions.
- **Anti-Cheat Safe Mode (`Pause / Resume Driver`):** Temporarily closes kernel driver handles and unloads the driver service on demand so kernel anti-cheat engines (Easy Anti-Cheat, BattlEye, Vanguard) can launch without conflicts.

---

## Quick Start (1-Click Launchers)

All batch scripts auto-elevate to Administrator privileges on Windows:

| Script / Command | Purpose |
|---|---|
| **`launch-discord.bat`** | **Recommended for Discord.** Flushes DNS, validates clean domain resolution, starts the wire engine in the background, and launches Discord desktop client. |
| **`start-bypass.bat`** | Starts the packet engine with WebUI dashboard at `http://127.0.0.1:8787`. |
| **`stop-and-recover.bat`** | Stops the engine, unloads the WinDivert driver, cleans up `hosts` file entries, and flushes DNS cache. |
| **`test-live.ps1`** | **ISP Benchmark & Profile Tuner.** Automated 8-profile live ISP benchmark (`powershell -ExecutionPolicy Bypass -File .\test-live.ps1 -NoPause`) testing candidate fake modes and TTL hop counts (`TTL 3` to `TTL 6`, `multi-ttl`, `wrong-chksum`, and pure split) against live targets (`updates.discord.com`, `discord.com`, `gateway.discord.gg`, `www.roblox.com`) to benchmark and recommend the winning profile for your network. |

---

## ISP Compatibility & Multi-ISP Tuning (Turkey)

`dpibypass` is specifically hardened against Turkish ISP middleboxes (BTK / DPI filter architecture) and supports all major network providers:

| ISP / Provider | Status & Recommended Strategy | Technical Notes |
|---|---|---|
| **Türk Telekom** | **Verified 100% Out-of-the-Box** (`fake_ttl: 4`, `sni-mid`) | Middlebox is typically located at hop 3 or 4. `dpibypass` automatically traps and drops connections to Türk Telekom's sinkhole IP (`195.175.254.2`) with an instant inbound TCP `RST+ACK`, synchronizes clean Anycast IPs via DoH to `hosts`, and blinds middleboxes via `TTL 4` fake packets. |
| **Turkcell Superonline** | **Fully Supported** (Self-tuning `TTL 3`–`6` or `TTL 4`) | Superonline implements strict transparent UDP port 53 hijacking. `dpibypass` completely neutralizes this via direct IP DoH bootstrap (`1.1.1.1:443`) and local Windows `hosts` sync. Because DPI middlebox hop distances vary by city and fiber topology, run `.\test-live.ps1` or `dpibypass.exe tune --mode packet --domains discord.com,www.roblox.com --apply` to automatically select your optimal local hop count. |
| **Vodafone Net** | **Fully Supported** (Default profile / `AutoLearner`) | Defeats Vodafone DPI filters through QUIC suppression (`drop_quic: true`), IPv6 TCP SYN dropping to force Happy Eyeballs IPv4 fallback, and adaptive retransmission escalation (`TTL 4 -> 3 -> 5`). |
| **Türksat Kablonet** | **Fully Supported** (Default profile) | Clean bypass on Docsis / GPON infrastructure via out-of-order TLS record splitting and DoH-to-`hosts` sync. |
| **TurkNet** | **Fully Supported** (Default profile) | Works seamlessly across GigaFiber and VDSL networks with zero configuration changes. |

### Running the Live Multi-Profile Benchmark
To benchmark all 8 evasion profiles on your specific connection:
```powershell
powershell -ExecutionPolicy Bypass -File .\test-live.ps1 -NoPause
```

To run the automated packet tuner to find and apply the exact minimum working TTL for your network:
```powershell
.\dpibypass.exe tune --mode packet --domains discord.com,updates.discord.com,www.roblox.com --apply
```

---

## Configuration (`config.json`)

The default configuration is optimized for daily use:

```json
{
  "mode": "packet",
  "default_profile": "packet-default",
  "packet": {
    "fake_mode": "ttl",
    "fake_ttl": 4,
    "fake_sni": "www.example.com",
    "split_offset": "sni-mid",
    "drop_quic": true,
    "intercept_dns": true,
    "desync_http": true,
    "auto_learn": true
  },
  "doh": {
    "enabled": true,
    "endpoints": [
      { "url": "https://cloudflare-dns.com/dns-query" },
      { "url": "https://dns.google/dns-query" }
    ]
  }
}
```

---

## Building from Source

### Prerequisites
- **OS:** Windows 10/11 x64
- **Go:** Version 1.22 or higher
- **Privileges:** Administrator prompt (required for WinDivert driver interaction)
- **WinDivert 2.2.2 Driver Files:**
  `dpibypass` requires the official Microsoft-signed WinDivert 2.2.2 driver to capture packets:
  1. Download the official `WinDivert-2.2.2-A.zip` distribution package from [reqcrypt.org/windivert.html](https://reqcrypt.org/windivert.html) or [GitHub Divert Releases](https://github.com/basil00/Divert/releases/tag/v2.2.2).
  2. Extract `x64\WinDivert.dll` and `x64\WinDivert64.sys` into the repository root alongside the `dpibypass` project files.

### Build Commands
Run the PowerShell build automation script in the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

The script compiles `dpibypass.exe`, applies version and commit ldflags, performs binary smoke testing, and prints the SHA-256 artifact hash.

Alternatively, compile with standard Go:
```powershell
go build -o dpibypass.exe ./cmd/dpibypass
```

### Running Tests

```powershell
go test -count=1 ./...
```

---

## Command-Line Usage

```text
Usage: dpibypass <command> [options]

Commands:
  run [--mode packet|proxy] [--config <path>] [--webui 127.0.0.1:8787]
      Start the wire bypass engine (WinDivert packet mode or userspace proxy)

  recover [--check-only] [--status] [--force]
      Unified crash recovery: restores system proxy, cleans hosts file, unloads WinDivert driver

  tune --domains <d1,d2> [--apply]
      Auto-tune minimum working TTL hop count against target domains

  config validate [--config <path>]
      Validate configuration syntax, safety rules, and loopback limits

  version
      Print version and build metadata
```

---

## License

This project is licensed under the [MIT License](LICENSE).
WinDivert is licensed under the GNU Lesser General Public License (LGPL) v3 or GNU General Public License (GPL) v2.
