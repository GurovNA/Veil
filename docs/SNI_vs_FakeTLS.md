# SNI / dest vs FakeTLS Domain Analysis

## 1. SNI / dest in VLESS-REALITY
- **What it is**: Server Name Indication (SNI) is part of the TLS Client Hello handshake. In Xray REALITY, `dest` specifies the real destination website (e.g., `dl.google.com:443`), and `serverNames` specifies the domains accepted by the proxy inbound.
- **How it works**: When a client connects, it mimics a legitimate TLS connection to the target `dest` website. DPI systems see allowed traffic to a trusted domain (like Google), while the proxy server securely proxies the inner connection.
- **Validation**: Veil panel validates DNS resolution and TCP port 443 availability before applying SNI changes to prevent broken handshakes.

## 2. FakeTLS Domain
- **What it is**: Traditional obfuscation mechanism (used in older Shadowsocks/Trojan plugins) that prepends fake TLS handshake bytes to raw TCP streams.
- **Difference**: FakeTLS simulates a TLS handshake without establishing a real underlying TLS session to a target server, whereas REALITY actually transparently proxies TLS to a real website, making detection significantly harder for modern DPI.
