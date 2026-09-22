<div align="center">
  <img src="icon-veil.png" width="128" height="128" alt="Veil Logo">
  <h1>Veil Panel</h1>
  <p><strong>An all-in-one VPN control panel: 18 Xray & WireGuard protocols, Telegram MTProto proxy, DPI bypass, and subscriptions for all popular clients — from a single web UI.</strong></p>
  <p>
    <a href="README.md">🇬🇧 English</a> |
    <a href="README.ru.md">🇷🇺 Русский</a>
  </p>
  <p>
    <a href="https://github.com/GurovNA/Veil/releases/latest"><img src="https://img.shields.io/github/v/release/GurovNA/Veil?label=release&color=blue" alt="Release"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
    <a href="https://ubuntu.com/download/server"><img src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-orange.svg" alt="Ubuntu"></a>
  </p>
</div>

---

## Quick install

Deploy on Ubuntu with a single command:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/GurovNA/Veil/main/install.sh)
```

> The panel runs as `vpnpanel.service` (managed via `systemctl`),
> web UI available over HTTPS: `https://<server-ip>:8443`.
> Initial credentials are printed during installation (`FIRST-LOGIN.txt`).

---

## Features

### Protocols (18 out of the box)
- **VLESS**: Reality, XHTTP+Reality, WS, WS+TLS, TCP+TLS, gRPC+TLS, XHTTP+TLS
- **VMess** and **Trojan**: WS / TCP / gRPC + TLS
- **Shadowsocks** AEAD, **Hysteria2**
- **WireGuard** on the kernel module (`veilwg`) and **AmneziaWG** (`awg0`) — with PSK and personal `.conf` generation
- REALITY with SNI validation, configurable TLS fingerprints (Firefox/Chrome/Safari/iOS/Android)

### Subscriptions & clients
- A single `/sub/<token>` URL: base64 list for v2rayNG/NekoBox/Hiddify, sing-box JSON, and **INCY** link format — detected by User-Agent or `?format=`
- Public subscription page `/p/<token>`: status, traffic, QR codes, app catalog with deep links, `WireGuard.conf` / `AmneziaWG.conf` downloads
- `subscription-userinfo` headers (used/left/expiry) with per-client time units
- Traffic quotas and expiry with automatic blocking; online count and per-client traffic via the Xray Stats API

### Security
- 2FA (TOTP), login/password change, brute-force throttling
- Session management: list (IP, user-agent, last seen), revoke one or all others
- Built-in journals: API action audit and login history in the UI
- Native ACME client for Let's Encrypt with auto-renewal; dynv6 DDNS with DoH domain verification

### Censorship bypass & Telegram
- **Zapret2** (DPI bypass) toggled from the panel, Nginx-based web proxy, **decoy site** (bundled NES emulator) for obfuscation
- **Telegram bot**: create subscriptions with limits, list clients, restart, alerts
- **telemt**: MTProto proxy with web settings and version switching

### Diagnostics & administration
- Diagnostics tab: CPU/RAM/load metrics, service and port status, protocol-aware self-test (TCP/UDP), **Globalping** measurements from worldwide probes with Telegram alerts
- Update center: panel / Xray / telemt with rollback to previous version; state export/import (backup)
- PWA; themes, wallpapers and logo configurable from the UI; multi-node management (beta)

## Documentation

- Full version history — [`CHANGELOG.md`](CHANGELOG.md)
- Notes: [SNI vs FakeTLS](docs/SNI_vs_FakeTLS.md)
- Client subscription & deep-link formats: [INCY docs](https://incy.gitbook.io), [sing-box docs](https://sing-box.sagernet.org)

## License

Distributed under the MIT license ([`LICENSE`](LICENSE)). Some network fixes are borrowed from open MEKO tooling ([`LICENSE-MEKO`](LICENSE-MEKO)).
