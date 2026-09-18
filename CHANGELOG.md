# Changelog

All notable changes to Veil Panel will be documented in this file.

## [2.2.3] - 2026-09-18
- **Bot: multi-step subscription creation** — `/addsub` now walks through 3 steps in chat: client name → traffic limit in GB (`0` = unlimited, decimals allowed) → expiry in days (`0` = no expiry). The flow validates input, supports `/cancel` at any step, and calls `_create_subscription(name, limit_gb, expiry_days)`, which persists the limit/expiry on the client.
- **Bot: Status and Statistics merged** — `/status` now shows Xray state + uptime, client count, node count, RU availability from Globalping, CPU/RAM and disk. `/stats` is kept as a synonym; the «📈 Статистика» menu button was removed.
- **Bot: low-availability alerts** — when the RU availability probe drops to ≤50% (state transition, not every poll), the bot notifies the admin chat (🚨/✅), deduplicated via `_GP_LOW_ALERT_ACTIVE`.
- **Panel: WireGuard `.conf` download** — public endpoint `GET /api/wgconf/<sub_token>` serves the WG config as an attachment (RFC 5987 `filename*`, ASCII fallback); `conf_url` is added to `/api/subs` and `/api/clients` for WG subscriptions and shown as a «⬇ WireGuard» button on the subscription card.
- **Panel: restart button** — «⟳ Панель» button next to the version pill triggers a delayed `systemctl restart vpnpanel` via POST `/api/restart` (graceful, session survives).
- **Panel: VPS IP list in Settings** — `/api/settings` returns `addrs` (IPv4/IPv6 of every interface via `_all_iface_ips()`), rendered in the Settings block.

## [2.2.2] - 2026-09-18
- **Telegram Bot fixes**: added missing `_main_menu_keyboard`, removed double admin check that used the bot's own id (all commands fell into "no rights"), commands now accept the `/cmd@BotName` suffix, logging includes tracebacks + error messages sent to the chat, messages are capped at 4000 chars, and client names in `/clients` are HTML-escaped.
- **Globalping RU availability fixed**: the frontend relied on a non-existent `result.success` field; HTTP probes now use `status === "finished"` + `statusCode`, RTT comes from `timings.total`. Added the previously missing POST `/api/globalping/history` (GET-only before), so results are actually persisted (atomic write, ISO UTC `created_at`, last 50 kept). Probe target is derived from the subscription URL (host/protocol/port/path instead of a hardcoded path that returned 404) and HTTP 429 is handled with `Retry-After`.
- **Panel HTML nesting fixes**: `tab-security` pane is now inside `#panel` (two stray `</div>` tags removed) so Security no longer stays visible after logout; closed an unclosed `<p>`.
- **Swipe between tabs**: horizontal swipe on the active tab content switches to the previous/next tab (book-like), ignoring taps on buttons/inputs and vertical scroll.
- **Auto-check every 15 minutes now always runs**: replaced the `visibilityState === "visible"` guard (which skipped the check whenever the browser tab wasn't focused) with an overlap-protected `gpAutoCheck()`.
- **Log noise reduction**: Telegram long-poll read timeouts are no longer logged as errors (HTTP timeout raised to 40s), and `BrokenPipe`/`ConnectionReset` tracebacks from port scanners are suppressed.

## [2.2.1] - 2026-09-17
- **UI & Pane Nesting Fixes**: Resolved broken HTML nesting that caused proxy, site, and settings tabs to appear empty.
- **Add-User Modal Fix**: Fixed user creation modal to render correctly and function from any tab (including subscriptions).
- **Server Metrics Unification**: Unified CPU and RAM into clean circular gauges in mini-stats, with real-time load average and port status tracking via `/api/metrics`.
- **Appearance Modernization**: Removed redundant app/retro OS theme presets and added new stylish presets (Sakura, Matcha, Sunset, Cosmos).
- **README Cleanup**: Removed MEKO top attribution, made version/license/Ubuntu badges clickable, and updated attribution phrasing.

## [2.2.0] - 2026-09-17
- **Universal per-user subscription**: one `sub_token` and one `uuid` per user across every protocol; a single `/sub/<token>` URL returns base64 links for all enabled protocols (v2rayNG / Hiddify / Streisand / NekoBox / Happ / Shadowrocket).
- **3x-ui style subscription headers**: added `/api/subs`, `profile-title` (base64), `profile-web-page-url` and `subscription-userinfo` (upload/download/total/expire) headers.
- **Unique per-protocol link names**: each link now carries `<user> · <protocol>`, fixing clients that collapsed all entries with the same name into one.
- **Hysteria2 uses the real Let's Encrypt certificate**: dropped the self-signed cert and `insecure=1` from share links; Hysteria2 now works in Xray-based clients (Happ) that no longer honour `insecure`.
- **VMess + gRPC share link**: `type` is emitted as `gun` (v2rayN convention) so clients resolve the gRPC service name correctly.
- **Removed Shadowsocks-2022 (aes-256-gcm / chacha20)**: it handshook but did not pass traffic reliably through Russian mobile DPI; removed from protocols, ports and subscriptions.
- Fixed `profile-title` being sent as a Python `repr` of bytes, and a `panel_port` NameError in the `/sub` handler.

## [2.0.5] - 2026-09-15
- **Fingerprint configuration**: Moved TLS fingerprint setting from General Settings into inbound settings dialog (⋯ menu on protocol cards).
- **SNI Validation**: Added DNS resolution and TCP port 443 availability check before applying SNI changes to prevent breaking REALITY handshakes.
- **Protocol Cards UI Refinement**: Balanced action buttons, collapsible Shadowsocks-2022 cards by default.
- **Web Proxy (nginx)**: One-click installation of nginx HTTPS reverse proxy for telemt web directly from the panel.
- **Telemt Management**: Added version switcher, pre-release support, and rollback backup management directly from the Telegram proxy tab.
- **Default Firefox Fingerprint**: Changed default TLS fingerprint to firefox for improved REALITY handshake stability across various clients.

## [2.0.4] - 2026-09-14
- Initial release of modular Xray + Telemt integration.
- Added dark theme, system status metrics, and user management UI.
