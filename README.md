<div align="center">
  <img src="icon-veil.png" width="128" height="128" alt="Veil Logo">
  <h1>Veil — VPN Panel</h1>
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
- **Traffic reset cycles** (day / week / month / lifetime) with delta-accumulated counters that survive Xray restarts, plus **Telegram alerts** at 80 % of quota, on expiry and on auto-block
- **Per-client device limit**: devices are identified by a stable *install token* from the client User-Agent, not by IP — switching Wi‑Fi→4G merges into the same device instead of counting as a new one; sustained excess is auto-banned for 2 h via nftables (the youngest device only)
- **«What you use» stats**: per-subscriber breakdown of which protocols were used in the last 7 days (from the Xray access log) on `/p` and in the admin card
- **One-tap protocol provisioning**: a client created under one protocol can be added to all enabled protocols with one button ("All protocols") so WireGuard/AmneziaWG appear in the subscription; WG/AWG ship as single-line `wireguard://` and `amneziawg://` links importable by Shadowrocket/Happ/NekoBox
- **Self-service payments on `/p`**: plan top-up by card (ЮKassa), crypto (CryptoBot), your own HMAC-signed cash register or manually — receipts extend the client's quota/expiry without admin touch, the bot reports them
- **RU / IR split tunnel** pushed into client configs (direct-to-RU or proxy-only-IR), with the panel mirroring the upstream sing-box geoip/geosite rule sets nightly and serving them from `/rulesets/`
- Standalone full sing-box config per subscriber at `/sb/<token>` (TUN + mixed port, DNS and split-tunnel rules included)

### Interface & dashboard
- **New sidebar interface** (default) with a switch back to the classic layout in "Appearance"; the choice is stored server-side
- **Fully multilingual: RU / EN / FA (RTL) / ZH** — UI, subscription pages, and the Telegram bot; a beginner-friendly "explain it simply" guide under almost every section
- **Live dashboard widgets**: Xray status with uptime, "clients online" and "traffic today" KPIs (delta vs. yesterday), active protocol list, CPU/RAM/disk rings, a 30-day traffic chart, an events feed and quick actions
- Mobile layout: bottom tab bar, compact cards, responsive grids; fast repeat loads — page served gzipped with ETag revalidation

### Security
- **Passkey sign-in (Face ID / Touch ID / Windows Hello) — by default** — built-in WebAuthn with zero third-party services; when a passkey is linked the login screen leads with the big «🔑» button, password folds to a fallback
- **Operators with granular permissions**: give support staff access to only chosen tabs; the owner keeps full control
- 2FA (TOTP), login/password change, brute-force throttling
- **fail2ban-lite for the panel login**: repeat offenders banned into nftables timeout sets (`veil_bans`), never locking out your own session or private IPs; active-ban list with unban in the UI, bans survive restarts
- **Prometheus `/metrics`** (Bearer-protected): per-client traffic/limit/expiry/devices, bans, disk/mem, cert expiry and more — one-click token generation in settings
- Session management: list (IP, user-agent, last seen), revoke one or all others
- Built-in journals: API action audit and login history in the UI
- Native ACME client for Let's Encrypt with auto-renewal; dynv6 DDNS with DoH domain verification

### Censorship bypass & Telegram
- **Zapret2** (DPI bypass) toggled from the panel, Nginx-based web proxy, **decoy site** for obfuscation: a self-contained 8-bit NES arcade (accurate FCEUmm libretro core compiled to WebAssembly + two homebrew ROMs, gamepad/keyboard/touch, own-ROM loader, no CDN and no outbound requests)
- **Telegram bot**: admin ops plus a **subscriber mode** — a user links their subscription once and gets «➕ add proxy to Telegram» one-tap buttons, «💳 renew» wired to the payment plans (or a request to the admin), and personal 80 %/expiry reminders (RU/EN/FA/ZH)
- **telemt**: MTProto proxy with web settings and version switching; **per-link device limit** (`max_unique_ips`) configurable from the panel
- **🎭 Custom site-mask for MTProto (TLS-F)**: put your own front domain behind the proxy link (Cloudflare DNS → Let's Encrypt → decoy on :443 → telemt facade); old links keep working through front rotation, and the panel self-checks the facade handshake under VPN over IPv4/IPv6
- **📣 Address-change self-binding**: when the server host/IP changes (move, DDNS, hop switch), subscribers with Telegram get a push with the new address and the `/sub` links rebuild themselves — no reissuing needed

### Diagnostics & administration
- Diagnostics tab: CPU/RAM/load metrics, service and port status, protocol-aware self-test (TCP/UDP), **Globalping** measurements from worldwide probes with Telegram alerts
- **Logs tab**: browse service logs (Xray, telemt, nginx, panel, journald) right in the browser — no SSH needed; server-side housekeeping caps journal and syslog growth automatically
- Update center: panel / Xray / telemt with rollback to previous version; state export/import (backup)
- PWA; themes, wallpapers and logo configurable from the UI
- **Node federation**: accept other Veil panels' clients over a scoped Node API (`/api/ext/*`, rate-limited, audited, revocable tokens) and place your own clients on remote nodes — either a Veil panel or the standalone `agent.py` (vless+reality, traffic accounting, autoblock, same-uuid mirrors added to the subscription; TLS pin TOFU)
- **⚡ SSH node bootstrap**: enter IP/login/password of a clean VPS — the panel installs xray and `agent.py`, enables the systemd service, opens firewall ports and registers the node (password used once for key install, never stored). **Telegram DC coverage** in the Proxy tab: RTT, writers and coverage % via telemt API with an adjustable threshold
- **🚚 Automated VPS migration («Переезд»)**: enter the new host's SSH credentials on the old panel — it pre-checks every port it owns (showing *who* occupies each, never touching SSH), optionally takes them over on explicit confirm, ships the **entire state** (subscriber DB, Xray/Reality/HY2 keys, telemt secrets, nginx fronts, LE certs, avatars, rules) and reinstalls itself **port-for-port, so no subscriber link ever changes**; then self-verifies from outside, switches Cloudflare/dynv6 DNS (now or on a schedule, e.g. 3:00 MSK), and the old host is retired only on a separate explicit click. Every step is journaled to disk — an interrupted move resumes where it stopped, not from scratch. Owner-only tab.

## Documentation

- Full version history — [`CHANGELOG.md`](CHANGELOG.md)
- Notes: [SNI vs FakeTLS](docs/SNI_vs_FakeTLS.md)
- Client subscription & deep-link formats: [INCY docs](https://incy.gitbook.io), [sing-box docs](https://sing-box.sagernet.org)

## License

Distributed under the MIT license ([`LICENSE`](LICENSE)). Some network fixes are borrowed from open MEKO tooling ([`LICENSE-MEKO`](LICENSE-MEKO)).
