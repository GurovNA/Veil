# Security Policy

## Supported versions

We actively support the latest release of Veil on fresh Ubuntu 22.04 / 24.04 LTS servers.
Older releases receive fixes at the maintainer's discretion, usually limited to
authentication, TLS/Reality handling and subscription-token issues.

| Version | Supported |
|---------|-----------|
| latest  | ✅ |
| older   | ⚠️ best effort |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report vulnerabilities privately via
[GitHub security advisories](https://github.com/GurovNA/Veil/security/advisories/new)
or through the contact listed on the repository profile page.

Include, if possible:

- the panel version (shown on the dashboard header of the web UI);
- affected endpoint or component (web UI, subscriber page `/p/<token>`,
  `/api/*` routes, Telegram bot, MTProxy, Xray config writer);
- a minimal reproduction, redacted of any real keys, tokens, passwords or IPs.

A maintainer typically acknowledges private reports within 7 days.
Coordinated disclosure is welcome: we would prefer a fixed release to exist
before details become public.

## What counts as security-relevant

Examples we take seriously:

- authentication or session bypass in the admin web UI;
- subscriber page or API leaking another subscriber's links, keys or traffic data;
- SSRF, SQL/command injection or path traversal reachable through any web route;
- a configuration the panel writes that silently exposes a cleartext inbound
  on a public address;
- credential material (private keys, Reality secrets, MTProto secrets) ending up
  in logs, archives or API responses.

## Hardening already built into the panel

For reference, current defenses include:

- cleartext Xray inbounds are bound to loopback unless TLS/Reality protects them;
- optional fail2ban-style bans with an allow list, plus an SSH-port lockout guard;
- atomic file writes (`0600`) for state that contains subscriber identifiers;
- release archives ship with published `sha256` digests — verify before installing:

```bash
sha256sum -c veil.tar.gz.sha256
```

## Scope notes

Veil wraps third-party software (Xray-core, WireGuard/AmneziaWG, Cloudflare
`cloudflared`, Telegram client-proxy `telemt`). Vulnerabilities in those
upstreams belong to their own trackers first; we still accept reports if the
exposure is created or amplified by how the panel configures them.
