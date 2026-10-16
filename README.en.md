# dpibypass — Wire-Level DPI Bypass Engine for Windows

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6.svg)](https://microsoft.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Driver](https://img.shields.io/badge/Driver-WinDivert%202.2.2-green.svg)](https://reqcrypt.org/windivert.html)

**[English](README.en.md) | [Türkçe](README.md)**

**dpibypass** is a pure Go, wire-level Deep Packet Inspection (DPI) evasion tool and DNS bridge designed for Windows x64. It operates at the kernel network layer via WinDivert to capture and modify TCP (TLS/HTTP) and UDP packets without requiring external proxies, VPNs, or browser extensions.

Specifically designed to mitigate stateful middlebox inspection and SNI-based filtering, **dpibypass** provides packet manipulation techniques and DoH-based domain resolution for services experiencing DPI restrictions, such as Discord (desktop client and voice gateways) and Roblox.

---

## Limitations

- **SNI/DPI Blocks Only:** Only effective against domain-name (SNI) and packet inspection-based filtering. It cannot bypass IP-based blocks, BGP routing blackholes, or direct server-side blocks.
- **Windows 10/11 x64 Only:** Requires the WinDivert 2.2.2 x64 driver; 32-bit Windows, Linux, and macOS are not supported.
- **Administrator Privileges Required:** Must be run with Administrator privileges to open the WinDivert kernel driver handle and update the Windows `hosts` file.
- **Antivirus Flags (False Positives):** Because WinDivert is a low-level packet capture driver, some antivirus vendors may flag it as suspicious or unwanted software.
- **Kernel Anti-Cheat Conflicts:** Can conflict with kernel-level anti-cheat software (such as Easy Anti-Cheat, BattlEye, Vanguard). The driver should be paused or dpibypass exited before launching protected games.
- **ISP and Regional Variations:** Middlebox hardware, inspection rules, and network topology differ across ISPs, regions, and connection types. Settings working on one network may not work on another.

---

## What This Tool Changes on Your System

1. **WinDivert Kernel Driver:** Temporarily registers and starts the `WinDivert64.sys` driver service to capture and inject network packets.
2. **Windows `hosts` File:** Resolves clean IP addresses for configured domains (e.g. Discord, Roblox) via DoH and writes them between `# BEGIN DPIBYPASS MANAGED HOSTS` and `# END DPIBYPASS MANAGED HOSTS` markers in `C:\Windows\System32\drivers\etc\hosts`. Backs up the original file before modifying.
3. **Local Web UI:** Binds a lightweight HTTP server on loopback `127.0.0.1:8787` for metrics and status monitoring.

### How `recover` Undoes These Changes
Running `dpibypass recover` or `stop-and-recover.bat`:
- Removes the `# BEGIN DPIBYPASS MANAGED HOSTS` block from the `hosts` file (or restores the original backup).
- Stops and unloads the WinDivert driver service (`sc stop WinDivert` / service deletion).
- Restores any system proxy settings if proxy mode was previously enabled.
- Flushes the Windows DNS cache (`ipconfig /flushdns`).

---

## Responsible Use & Disclaimer

This tool is developed for educational, testing, and diagnostic purposes to analyze DPI behavior and network filtering mechanisms. Users are solely responsible for ensuring compliance with applicable local laws, regulations, and terms of service. The author provides no warranties and accepts no liability for misuse, downtime, or software conflicts.

---

## Key Architecture & Features

### 1. Pure Go Kernel Harness via WinDivert ABI (Zero CGO)
Communicates directly with `WinDivert.dll` and `WinDivert64.sys` using pure Go standard library syscalls and structured ABI definitions without C compiler toolchain dependencies:
- **Pre-allocated 64 KiB buffer sizing** for Windows Large Send Offload (LSO/TSO) packet bursts.
- **Wire-level filtering** that passes non-target traffic straight through.

### 2. Multi-Packet TLS 1.3 SNI Splitting
Modern Chromium-based applications (including Electron apps like Discord) can send large (~1,900-byte) TLS 1.3 `ClientHello` records due to post-quantum key shares (e.g., `X25519MLKEM768`).
- **Pre-Segmented Packet 2 Tracking:** When the Windows TCP stack segments the handshake before egress, the SNI extension often lands in Packet 2. `dpibypass` tracks sequence numbers, intercepts the packet with the SNI, and splits it at the SNI boundary (`sni-mid`).
- **Out-of-Order Injection:** Injects Segment 2 before Segment 1 onto the wire so simple middlebox reassembly engines fail to extract the plain SNI.
- **MTU Bounds:** Bounds injected fragments to `<= 1400` bytes to minimize Ethernet MTU fragmentation drops.

### 3. Low-TTL Middlebox Desync (Fake Packet Injection)
- Synthesizes a valid TLS `ClientHello` with a benign SNI (e.g., `www.example.com`) sharing the exact 4-tuple and TCP sequence numbers.
- Transmits the fake packet with a low hop count (e.g., `TTL 3` or `TTL 4`) so it reaches the ISP middlebox and drops before reaching the destination server.
- Supports multi-hop TTL interleaving against ECMP route shifts.

### 4. DoH Bootstrap & Windows `hosts` Sync
- **Zero-DNS Bootstrap:** Connects directly to Anycast IPs (`1.1.1.1`, `8.8.8.8`) over HTTPS to avoid local DNS poisoning.
- **Automated `hosts` Sync:** Resolves clean IPv4 addresses for configured domains and updates the managed block in `C:\Windows\System32\drivers\etc\hosts`.
- **UDP Port 53 Capture:** Intercepts local UDP DNS queries and responds with DoH-resolved records.
- **Clean Recovery:** Restores the hosts file cleanly upon exit or recovery.

### 5. IPv6 Happy Eyeballs Fallback (RFC 8305)
Suppresses outbound IPv6 TCP SYN packets on ports 80/443 and answers IPv6 DNS with `NODATA` responses to encourage dual-stack clients to fall back quickly to protected IPv4 paths.

### 6. Embedded Loopback WebUI & Anti-Cheat Safe Mode
Optional dashboard running on `127.0.0.1:8787`:
- Live metrics: packets intercepted, synthetic fake packets, split segments, and DoH resolutions.
- **Anti-Cheat Safe Mode (`Pause / Resume Driver`):** Temporarily unloads the WinDivert driver service on demand to minimize conflicts with kernel anti-cheat systems.

---

## Quick Start (1-Click Launchers)

All batch scripts auto-elevate to Administrator privileges on Windows:

| Script / Command | Purpose |
|---|---|
| **`launch-discord.bat`** | **Launcher for Discord.** Flushes DNS, validates clean domain resolution, starts the wire engine in the background, and launches Discord desktop client. |
| **`start-bypass.bat`** | Starts the packet engine with WebUI dashboard at `http://127.0.0.1:8787`. |
| **`stop-and-recover.bat`** | Stops the engine, unloads the WinDivert driver, cleans up `hosts` file entries, and flushes DNS cache. |
| **`test-live.ps1`** | **ISP Benchmark & Profile Tuner.** PowerShell test tool evaluating candidate fake modes and TTL hop counts against live target domains. |

---

## ISP Compatibility & Tuning (Turkey)

Network topologies and filtering rules differ across ISPs and regions:

| ISP / Provider | Status | Strategy / Technical Notes |
|---|---|---|
| **Türk Telekom** | Tested by the author | Tested with `fake_ttl: 4` and `sni-mid`. Middlebox is typically located at hop 3 or 4. `dpibypass` intercepts sinkhole redirects, resolves clean IPs via DoH to `hosts`, and uses low-TTL fake packets to bypass middlebox inspection. |
| **Turkcell Superonline** | Untested - feedback welcome | Transparent UDP port 53 redirection can be addressed via DoH and `hosts` sync. Hop distance may vary; can be tuned with `.\test-live.ps1` or `tune`. |
| **Vodafone Net** | Untested - feedback welcome | Uses QUIC drop (`drop_quic: true`), IPv6 TCP SYN suppression to encourage IPv4 fallback, and adaptive retransmissions. |
| **Türksat Kablonet** | Untested - feedback welcome | Out-of-order TLS record splitting and DoH-to-`hosts` sync. |
| **TurkNet** | Untested - feedback welcome | Standard default packet profile configuration. |

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
