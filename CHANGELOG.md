# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Configurable domain synchronization via `hosts_sync.domains` in `config.json`.
- Automatic hosts file backup before first modification (`hosts.dpibypass.bak`).
- Leftover managed block detection at startup and in `recover --check-only`.
- Windows console control handler for graceful cleanup on Ctrl+C, console close, user logoff, and system shutdown.
- GitHub Actions CI workflow for Windows test validation.
- GitHub Actions automated release pipeline with SHA256SUMS publication.

### Changed
- Clarified documentation: toned down marketing claims, added limitations, anti-cheat considerations, and system modification details.
- Updated ISP compatibility status: Türk Telekom tested by author; other Turkish ISPs marked as untested / feedback welcome.
- Moved testing configuration to `examples/config.phase2-test.json`.
- Hardened `.gitignore` to strictly exclude driver binaries, built executables, logs, and local configs.

### Fixed
- Hardened hosts file management: isolated strictly to managed block `# BEGIN/END DPIBYPASS MANAGED HOSTS`.
- Idempotent `recover` command for hosts file, sysproxy, and WinDivert service cleanup.

## [1.0.0] - 2026-10-15

### Added
- Initial release of pure Go wire-level DPI evasion engine using WinDivert 2.2.2 ABI.
- TCP TLS 1.3 ClientHello multi-packet tracking and out-of-order segment splitting (`sni-mid`).
- Synthetic low-TTL fake packet injection.
- Zero-DNS DoH bootstrap resolver (Cloudflare & Google Anycast IPs).
- Local web dashboard on `127.0.0.1:8787`.
- System proxy and WinDivert recovery commands.
