#!/usr/bin/env python3
import base64, json, os, subprocess, secrets, hashlib, uuid as uuidlib, re, ssl, time, threading, socket
import ssl, socketserver, http.server
import urllib.parse, urllib.request, urllib.error
import shutil, tarfile, tempfile, datetime
import zipfile

BASE = "/opt/vpnpanel"
CFG = f"{BASE}/config.json"
STATE = f"{BASE}/state.json"
THEME = f"{BASE}/theme.json"
WALL = f"{BASE}/wallpaper.bin"
HTML = f"{BASE}/index.html"
XRAY = "/usr/local/etc/xray/config.json"
XRAY_BIN = "/usr/local/bin/xray"
TOKEN_FILE = f"{BASE}/github.token"
TELEMT_API = "http://127.0.0.1:9091"
TELEMT_CONF = "/etc/telemt/telemt.toml"
REPO = "GurovNA/Veil"
VERSION = "2.1.1"


# ========== ENTERPRISE FEATURES (v2.1.0) ==========

import base64, hashlib, hmac, struct, time, os, json, socket

NODES_CONFIG_FILE = f"{BASE}/nodes.json"

def get_nodes():
    if os.path.exists(NODES_CONFIG_FILE):
        try:
            return json.load(open(NODES_CONFIG_FILE))
        except Exception:
            return []
    return []

def save_nodes(nodes):
    json.dump(nodes, open(NODES_CONFIG_FILE, "w"), indent=2)

def generate_totp(secret_key, interval=30):
    try:
        key = base64.b32decode(secret_key.upper() + "=" * ((8 - len(secret_key)) % 8))
    except Exception:
        key = secret_key.encode('utf-8')
    counter = int(time.time() // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    o = digest[19] & 15
    code_int = (struct.unpack(">I", digest[o:o+4])[0] & 0x7fffffff) % 1000000
    return f"{code_int:06d}"

def verify_totp(secret_key, code):
    if not secret_key:
        return True
    interval = 30
    for offset in [-interval, 0, interval]:
        if generate_totp(secret_key, interval) == str(code).strip():
            return True
    return False

def get_system_metrics():
    metrics = {"cpu_percent": 0.0, "ram_percent": 0.0, "net_rx": 0, "net_tx": 0}
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()
            parts = [int(x) for x in line.split()[1:]]
            idle = parts[3]
            total = sum(parts)
            metrics["cpu_percent"] = round(100.0 * (1.0 - idle / max(1, total)), 1)
    except Exception:
        pass
    try:
        meminfo = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    meminfo[parts[0].strip()] = int(parts[1].split()[0])
        total_mem = meminfo.get("MemTotal", 1)
        avail_mem = meminfo.get("MemAvailable", total_mem)
        metrics["ram_percent"] = round(100.0 * (1.0 - avail_mem / max(1, total_mem)), 1)
    except Exception:
        pass
    return metrics

def run_protocol_self_test():
    results = {}
    for port in [443, 8444, 7443]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.connect(("127.0.0.1", port))
            results[port] = "OK"
        except Exception as e:
            results[port] = f"FAIL: {e}"
        finally:
            s.close()
    return results

# ==================================================

LOGO_FILE = f"{BASE}/logo.bin"
_GROUP_ORDER = ("reality", "vless", "vmess", "trojan", "ss", "hy2", "wg")
_GROUP_LABELS = {"reality": "Reality", "vless": "VLESS", "vmess": "VMess",
                 "trojan": "Trojan", "ss": "Shadowsocks",
                 "hy2": "Hysteria2", "wg": "WireGuard"}
PROTOCOLS = [
    {"id": "reality",             "label": "VLESS + Reality",                         "group": "reality", "ui_group": "vless", "net": "tcp",       "tls": False},
    {"id": "vless-xhttp-reality", "label": "VLESS + XHTTP + Reality",                 "group": "reality", "ui_group": "vless", "net": "xhttp",     "tls": False},
    {"id": "vless-ws",            "label": "VLESS + WebSocket",                       "group": "vless",   "ui_group": "vless", "net": "ws",       "tls": False},
    {"id": "vless-ws-tls",        "label": "VLESS + WebSocket + TLS (self-signed)",   "group": "vless",   "ui_group": "vless", "net": "ws",       "tls": True},
    {"id": "vless-tcp-tls",       "label": "VLESS + TCP + TLS (self-signed)",         "group": "vless",   "ui_group": "vless", "net": "tcp",      "tls": True},
    {"id": "vless-grpc-tls",      "label": "VLESS + gRPC + TLS (self-signed)",        "group": "vless",   "ui_group": "vless", "net": "grpc",     "tls": True},
    {"id": "vless-xhttp-tls",     "label": "VLESS + XHTTP + TLS (self-signed)",       "group": "vless",   "ui_group": "vless", "net": "xhttp",    "tls": True},
    {"id": "vmess-ws",            "label": "VMess + WebSocket",                       "group": "vmess",   "net": "ws",       "tls": False},
    {"id": "vmess-ws-tls",        "label": "VMess + WebSocket + TLS (self-signed)",   "group": "vmess",   "net": "ws",       "tls": True},
    {"id": "vmess-tcp-tls",       "label": "VMess + TCP + TLS (self-signed)",         "group": "vmess",   "net": "tcp",      "tls": True},
    {"id": "vmess-grpc-tls",      "label": "VMess + gRPC + TLS (self-signed)",        "group": "vmess",   "net": "grpc",     "tls": True},
    {"id": "trojan-ws",           "label": "Trojan + WebSocket",                      "group": "trojan",  "net": "ws",       "tls": False},
    {"id": "trojan-ws-tls",       "label": "Trojan + WebSocket + TLS (self-signed)",  "group": "trojan",  "net": "ws",       "tls": True},
    {"id": "trojan-tcp-tls",      "label": "Trojan + TCP + TLS (self-signed)",        "group": "trojan",  "net": "tcp",      "tls": True},
    {"id": "trojan-grpc-tls",     "label": "Trojan + gRPC + TLS (self-signed)",       "group": "trojan",  "net": "grpc",     "tls": True},
    {"id": "shadowsocks",         "label": "Shadowsocks AEAD (aes-256-gcm)",          "group": "ss",      "net": "tcp",      "tls": False},
    {"id": "shadowsocks-2022",    "label": "Shadowsocks 2022 (aes-128-gcm)",          "group": "ss",      "net": "tcp",      "tls": False},
    {"id": "hysteria2",           "label": "Hysteria2",                               "group": "hy2",     "net": "udp",      "tls": False},
    {"id": "wireguard",           "label": "WireGuard",                               "group": "wg",      "net": "udp",      "tls": False},
]
for _p in PROTOCOLS:
    _p["group_label"] = _GROUP_LABELS.get(_p["group"], _p["group"])
    _p.setdefault("ui_group", _p["group"])
    _p["ui_group_label"] = _GROUP_LABELS.get(_p["ui_group"], _p["ui_group"])
_VALID_PROTOCOLS = tuple(p["id"] for p in PROTOCOLS)
_PROTO_MAP = {p["id"]: p for p in PROTOCOLS}
_PORTS = {"reality": 443, "vmess-ws": 10443, "vless-ws": 11443,
          "trojan-ws": 12443, "vless-ws-tls": 13443, "vmess-ws-tls": 14443,
          "trojan-ws-tls": 15443, "vless-tcp-tls": 16443, "vmess-tcp-tls": 17443,
          "trojan-tcp-tls": 18443, "vless-grpc-tls": 19443, "vmess-grpc-tls": 20443,
"trojan-grpc-tls": 21443, "shadowsocks": 22443,
           "vless-xhttp-tls": 23443, "vless-xhttp-reality": 24443,
           "shadowsocks-2022": 26443,
           "hysteria2": 27443, "wireguard": 28443}
# Порт 443/80 заняты nginx (webproxy/decoy и Let's Encrypt), 18080 — telemt web,
# 9091 — telemt API, 7443 — telemt MTProto. Панель не должна их занимать.
_RESERVED_PORTS = {80, 443, 8080, 18080, 9091, 7443}
CERT_DIR = f"{BASE}/certs"

def _proto_meta(proto):
    return _PROTO_MAP.get(proto, _PROTO_MAP["reality"])

SESSIONS = {}
SESSIONS_FILE = f"{BASE}/sessions.json"

def _save_sessions():
    _save(SESSIONS_FILE, dict(SESSIONS))

def _load_sessions():
    try:
        d = json.load(open(SESSIONS_FILE)) or {}
        now = time.time()
        keep = {k: v for k, v in d.items() if isinstance(v, (int, float)) and v > now}
        SESSIONS.update(keep)
    except Exception:
        pass

# ---------- helpers ----------

def _load(p, d=None):
    try:
        with open(p) as f: return json.load(f)
    except Exception: return d

def _save(p, o, mode=0o600):
    with open(p, "w") as f: json.dump(o, f, indent=2, ensure_ascii=False)
    os.chmod(p, mode)

def _hash(salt, pw):
    return hashlib.sha256((salt + pw).encode()).hexdigest()

def _free_port(pref=443):
    import socket
    def ok(p):
        s = socket.socket()
        try: s.bind(("", p)); s.close(); return True
        except OSError: s.close(); return False
    if pref and ok(pref): return pref
    s = socket.socket(); s.bind(("", 0)); p = s.getsockname()[1]; s.close(); return p

def _port_free(port):
    import socket
    if not (isinstance(port, int) and 0 < port < 65536):
        return False
    for typ in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        s = socket.socket(socket.AF_INET, typ)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", port))
        except OSError:
            s.close(); return False
        s.close()
    return True

def _sni_ok(host, timeout=5):
    import socket
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host or ""):
        return True
    try:
        addrs = [i[4][0] for i in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)]
    except Exception:
        return "SNI: домен '" + host + "' не найден в DNS — Reality перестанет работать. Укажи реальный сайт."
    for ip in addrs[:2]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, 443))
            s.close()
            return True
        except OSError:
            s.close()
            continue
    return "SNI: домен '" + host + "' не отвечает на 443 — Reality перестанет работать. Укажи реальный сайт (например www.samsung.com)."

def _last_line(out, *keys):
    for line in out.splitlines():
        low = line.lower()
        if any(k in low for k in keys):
            return re.split(r"[:=\s]+", line.strip())[-1]
    return None

def _gen_keys():
    out = subprocess.run(["xray", "x25519"], capture_output=True, text=True).stdout
    priv = _last_line(out, "private")
    pub = _last_line(out, "public", "password")
    if priv and pub: return priv.strip(), pub.strip()
    raise RuntimeError("не разобрал xray x25519: " + out)

def _reality_key_std(k):
    if not k: return k
    k = str(k).strip()
    pad = "=" * ((4 - len(k) % 4) % 4)
    try:
        raw = base64.b64decode(k + pad, altchars=b"-_")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    except Exception:
        return k

def _wg_key_std(k):
    if not k: return k
    k = str(k).strip()
    pad = "=" * ((4 - len(k) % 4) % 4)
    try:
        raw = base64.b64decode(k + pad, altchars=b"-_")
        return base64.b64encode(raw).decode()
    except Exception:
        return k

def _gen_wg_psk():
    return _wg_key_std(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())

def _wg_is_wireguard(inb):
    if str(inb.get("proto", "")) == "wireguard":
        return True
    if "public_key" in inb and any(c.get("client_public_key") for c in inb.get("clients", [])):
        return True
    return False

def _ensure_wg_psk(st):
    changed = False
    for inb in (st or {}).get("inbounds", {}).values():
        if inb.get("proto") == "wireguard" or "public_key" in inb:
            if not inb.get("psk"):
                inb["psk"] = _gen_wg_psk(); changed = True
    return changed

def _ensure_wg_std(st):
    changed = False
    for inb in (st or {}).get("inbounds", {}).values():
        if not _wg_is_wireguard(inb):
            continue
        for f in ("private_key", "public_key", "psk"):
            v = inb.get(f)
            if v:
                nv = _wg_key_std(v)
                if nv != v: inb[f] = nv; changed = True
        for c in inb.get("clients", []):
            for f in ("client_private_key", "client_public_key"):
                v = c.get(f)
                if v:
                    nv = _wg_key_std(v)
                    if nv != v: c[f] = nv; changed = True
    return changed

def _ensure_xray_keys_urlsafe(st):
    changed = False
    for inb in (st or {}).get("inbounds", {}).values():
        if "public_key" not in inb or _wg_is_wireguard(inb):
            continue
        for f in ("private_key", "public_key"):
            v = inb.get(f)
            if not v:
                continue
            pad = "=" * ((4 - len(v) % 4) % 4)
            try:
                raw = base64.b64decode(v + pad)
                nv = base64.urlsafe_b64encode(raw).decode().rstrip("=")
                if nv != v: inb[f] = nv; changed = True
            except Exception:
                pass
    return changed

def _ver_tuple(v):
    try: return tuple(int(x) for x in str(v).split("."))
    except Exception: return (0,)

# ---------- state / xray ----------

def _client_count(st):
    if not st: return 0
    return sum(len(inb.get("clients", [])) for inb in (st.get("inbounds") or {}).values())

def _find_client(st, uuid_):
    if not st: return None, None, None
    for proto, inb in (st.get("inbounds") or {}).items():
        for c in inb.get("clients", []):
            if c["uuid"] == uuid_:
                return proto, inb, c
    return None, None, None

def _migrate_state(st):
    if st is None: return False
    changed = False
    inbs = st.get("inbounds") or {}
    if isinstance(inbs, dict):
        for proto, inb in inbs.items():
            if proto in ("reality", "vless-xhttp-reality"):
                for k in ("private_key", "public_key"):
                    if inb.get(k):
                        fixed = _reality_key_std(inb[k])
                        if fixed != inb[k]:
                            inb[k] = fixed
                            changed = True
        for k in ("clients", "uuid", "proto", "port", "private_key",
                  "public_key", "sid", "sni", "dest", "password"):
            if st.pop(k, None) is not None:
                changed = True
        return changed
    clients = st.pop("clients", None) or []
    old = st.pop("uuid", None)
    if old and not any(c.get("uuid") == old for c in clients):
        clients.insert(0, {"uuid": old, "name": "Основной", "created": 0})
    proto = st.pop("proto", None) or "reality"
    if proto not in _VALID_PROTOCOLS: proto = "reality"
    inb = {"port": _find_free_port(_PORTS.get(proto)), "clients": list(clients)}
    for k in ("port", "private_key", "public_key", "sid", "sni", "dest", "password"):
        v = st.pop(k, None)
        if v is None: continue
        if k == "port": inb["port"] = v
        else: inb[k] = v
    st["inbounds"] = {proto: inb}
    return True

def _proto_of(st):
    if not st: return "reality"
    a = st.get("active")
    if a in _VALID_PROTOCOLS: return a
    inbs = st.get("inbounds") or {}
    for p in _PORTS:
        if p in inbs: return p
    for p in inbs:
        return p
    return "reality"

def _new_state(proto="reality"):
    if proto not in _VALID_PROTOCOLS: proto = "reality"
    return {"active": proto, "inbounds": {}, "favorites": []}

def _gen_selfsigned(proto):
    os.makedirs(CERT_DIR, exist_ok=True)
    crt = f"{CERT_DIR}/{proto}.crt"
    key = f"{CERT_DIR}/{proto}.key"
    if not (os.path.exists(crt) and os.path.exists(key)):
        r = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", crt, "-days", "3650",
             "-subj", "/CN=Veil", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
            capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("openssl: " + (r.stderr or r.stdout))
    os.chmod(crt, 0o644)
    os.chmod(key, 0o644)
    return crt, key

def _new_inbound(proto):
    if proto not in _VALID_PROTOCOLS: proto = "reality"
    inb = {"port": _find_free_port(_PORTS.get(proto)), "clients": []}
    if proto in ("reality", "vless-xhttp-reality"):
        priv, pub = _gen_keys()
        inb.update({"private_key": priv, "public_key": pub,
                    "sid": secrets.token_hex(4), "sni": "www.samsung.com",
                    "dest": "www.samsung.com:443"})
    if proto == "shadowsocks":
        inb["password"] = secrets.token_urlsafe(12)
    if proto == "shadowsocks-2022":
        inb["password"] = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode()
        inb["method"] = "2022-blake3-aes-128-gcm"
    if proto == "hysteria2":
        pass
    if proto == "wireguard":
        priv, pub = _gen_keys()
        inb.update({"private_key": priv, "public_key": pub,
                    "address": "10.10.0.1/32", "mtu": 1420, "next_address": 2,
                    "psk": _gen_wg_psk()})
    if _proto_meta(proto)["tls"]:
        cp = _cert_pathes()
        if cp["cert"] and cp["key"]:
            inb["cert"], inb["key"] = cp["cert"], cp["key"]
        else:
            inb["cert"], inb["key"] = _gen_selfsigned(proto)
    return inb

def _alloc_inbound(st, proto):
    inb = _new_inbound(proto)
    used = set()
    for ib in (st.get("inbounds") or {}).values():
        if ib.get("port"): used.add(ib["port"])
    if inb["port"] in used:
        inb["port"] = _find_free_port(_PORTS.get(proto), used)
    return inb

HY2_CERT = "/usr/local/etc/xray/hy2_cert.pem"
HY2_KEY = "/usr/local/etc/xray/hy2_key.pem"

def _ensure_hy2_cert(dom):
    if os.path.exists(HY2_CERT): return
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-nodes", "-days", "3650", "-newkey", "rsa:2048",
             "-keyout", HY2_KEY, "-out", HY2_CERT, "-subj", "/CN=" + dom,
             "-addext", "subjectAltName=DNS:" + dom],
            capture_output=True, timeout=30)
        os.chmod(HY2_CERT, 0o644)
        os.chmod(HY2_KEY, 0o600)
        try: shutil.chown(HY2_CERT, user="nobody", group="nogroup")
        except Exception: pass
        try: shutil.chown(HY2_KEY, user="nobody", group="nogroup")
        except Exception: pass
    except Exception as e:
        print(f"не удалось создать hy2 cert: {e}", flush=True)

def _stream_settings(proto, inb):
    meta = _proto_meta(proto)
    if proto == "hysteria2":
        dom = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
        _ensure_hy2_cert(dom)
        masq = {"type": "proxy", "url": "https://" + dom} if dom else {"type": "404"}
        return {"network": "hysteria",
                "security": "tls",
                "tlsSettings": {"serverName": dom, "alpn": ["h3"],
                                "certificates": [{"certificateFile": "/usr/local/etc/xray/hy2_cert.pem",
                                                   "keyFile": "/usr/local/etc/xray/hy2_key.pem"}]},
                "hysteriaSettings": {
                    "version": 2,
                    "udpIdleTimeout": 60,
                    "masquerade": masq}}
    if proto == "wireguard":
        return {}
    def _reality():
        return {"show": False, "dest": inb["dest"], "xver": 0,
                "serverNames": [inb["sni"]], "privateKey": inb["private_key"],
                "shortIds": [inb["sid"]]}
    if proto == "reality":
        return {"network": "tcp", "security": "reality", "realitySettings": _reality()}
    ss = {"network": meta["net"],
          "security": "tls" if meta["tls"] else "none"}
    if proto == "vless-xhttp-reality":
        ss["security"] = "reality"
        ss["realitySettings"] = _reality()
    if meta["net"] == "ws":
        ss["wsSettings"] = {"path": "/veil", "headers": {}}
    elif meta["net"] == "grpc":
        ss["grpcSettings"] = {"serviceName": "veil"}
    elif meta["net"] == "xhttp":
        ss["xhttpSettings"] = {"path": "/veil", "mode": "auto"}
    elif meta["net"] == "splithttp":
        ss["splithttpSettings"] = {"path": "/veil", "mode": "auto"}
    if meta["tls"]:
        ss["tlsSettings"] = {
            "alpn": ["h2", "http/1.1"] if meta["net"] in ("grpc", "xhttp", "splithttp") else ["http/1.1"],
            "certificates": [{"certificateFile": inb.get("cert"), "keyFile": inb.get("key")}]}
    return ss

def _inbound(proto, inb):
    meta = _proto_meta(proto)
    ib = {"listen": "0.0.0.0", "port": inb["port"], "tag": proto}
    if proto == "hysteria2":
        ib["protocol"] = "hysteria"
        ib["settings"] = {"version": 2, "clients": [
            {"auth": c.get("auth") or c["uuid"], "email": c["uuid"]}
            for c in inb["clients"]]}
        ib["sniffing"] = {"enabled": False}
        ib["streamSettings"] = _stream_settings(proto, inb)
        return ib
    if proto == "wireguard":
        ib["protocol"] = "wireguard"
        ib["settings"] = {
            "secretKey": inb["private_key"],
            "address": [inb.get("address", "10.10.0.1/32")],
            "noKernelTun": True,
            "mtu": inb.get("mtu", 1420),
            "peers": [{"publicKey": c["client_public_key"],
                       "preSharedKey": inb.get("psk", ""),
                       "allowedIPs": ["0.0.0.0/0", "::/0"],
                       "email": c["uuid"]}
                      for c in inb["clients"]]}
        ib["sniffing"] = {"enabled": False}
        return ib
    ib["sniffing"] = {"enabled": True, "destOverride": ["http", "tls", "quic"]}
    if proto.startswith("shadowsocks"):
        ib["protocol"] = "shadowsocks"
        ib["settings"] = {"method": inb.get("method") or "aes-256-gcm",
                          "password": inb.get("password") or "", "network": "tcp,udp"}
        return ib
    if proto.startswith("trojan"):
        ib["protocol"] = "trojan"
        ib["settings"] = {"clients": [
            {"password": c.get("password") or inb.get("password"), "flow": "",
             "email": c["uuid"]}
            for c in inb["clients"]], "decryption": "none"}
    elif proto.startswith("vmess"):
        ib["protocol"] = "vmess"
        ib["settings"] = {"clients": [
            {"id": c["uuid"], "alterId": 0, "email": c["uuid"]}
            for c in inb["clients"]]}
    else:
        ib["protocol"] = "vless"
        flow = "xtls-rprx-vision" if proto == "reality" else ""
        ib["settings"] = {"clients": [
            {"id": c["uuid"], "flow": flow, "email": c["uuid"]}
            for c in inb["clients"]],
            "decryption": "none"}
    ib["streamSettings"] = _stream_settings(proto, inb)
    return ib

_STATS_PORT = 10088

def _autoblock_limits(st, force=False):
    """Автоблокировка: лимит ГБ или истёк срок -> клиент убирается из конфига.
    Возвращает список {uuid, name, reason} только что заблокированных (пусто = без изменений)."""
    import urllib.parse as _up_  # не нужно — urllib уже в коде
    if not st: return []
    t = not force
    out = []
    now = time.time()
    for proto, inb in (st.get("inbounds") or {}).items():
        for c in inb.get("clients", []):
            if c.get("blocked"): continue
            why = None
            up = float(c.get("up") or 0); down = float(c.get("down") or 0)
            lim = float(c.get("limit_gb") or 0)
            if lim > 0 and (up + down) >= lim * 1024 ** 3 * 0.95:
                why = "limit"
            ex = int(c.get("expiry") or 0)
            if ex and now > ex:
                why = why or "expired"
            if not why: continue
            c["blocked"] = int(now)
            c["blocked_reason"] = why
            out.append({"uuid": c["uuid"], "name": c["name"], "reason": why})
    return out

def _write_xray(st):
    inbounds = []
    for proto, inb in (st.get("inbounds") or {}).items():
        if inb.get("clients"):
            inbounds.append(_inbound(proto, inb))
    inbounds.append({
        "listen": "127.0.0.1", "port": _STATS_PORT, "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1"}, "tag": "api"})
    
    routing_rules = [{"inboundTag": ["api"], "outboundTag": "api", "type": "field"}]
    outbounds = [{"protocol": "freedom", "tag": "direct"}]
    
    if CFG_CACHE.get("ru_bypass"):
        routing_rules.append({
            "type": "field",
            "outboundTag": "direct",
            "domain": ["geosite:category-ru"],
            "ip": ["geoip:ru"]
        })
    
    cfg = {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService"]},
        "stats": {},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": routing_rules},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True,
                             "statsUserOnline": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True}}}
    _save(XRAY, cfg, 0o644)

def _statsquery():
    try:
        r = subprocess.run(
            ["xray", "api", "statsquery", "--server", f"127.0.0.1:{_STATS_PORT}",
             "--pattern", "user>>>", "--reset", "false"],
            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return {}
        d = json.loads(r.stdout)
    except Exception:
        return {}
    arr = d.get("stat", d.get("stats", []))
    if not isinstance(arr, list):
        return {}
    out = {}
    for s in arr:
        parts = [x for x in str(s.get("name", "")).split(">>>") if x]
        # user>>>email>>>traffic>>>{uplink,downlink}
        if len(parts) < 4 or parts[0] != "user" or parts[2] != "traffic":
            continue
        email, direction = parts[1], parts[3]
        if direction not in ("uplink", "downlink"):
            continue
        out.setdefault(email, {"uplink": 0, "downlink": 0})
        out[email][direction] = int(s.get("value", 0) or 0)
    return out

_ONLINE_CACHE = {}

def _online_count(email):
    now = time.time()
    hit = _ONLINE_CACHE.get(email)
    if hit and now - hit[0] < 30:
        return hit[1]
    v = None
    if len(_ONLINE_CACHE) < 200:
        try:
            r = subprocess.run(
                ["xray", "api", "statsonline", "--server", f"127.0.0.1:{_STATS_PORT}",
                 "-email", email],
                capture_output=True, text=True, timeout=8)
            if r.returncode == 0:
                d = json.loads(r.stdout)
                st = d.get("stat") or {}
                if "value" in st:
                    v = int(st.get("value", 0))
                else:
                    v = 0
        except Exception:
            v = None
    _ONLINE_CACHE[email] = (now, v)
    if len(_ONLINE_CACHE) > 200:
        _ONLINE_CACHE.clear()
    return v

def _start_xray():
    subprocess.run(["systemctl", "start", "xray"], check=True, capture_output=True)

def _stop_xray():
    subprocess.run(["systemctl", "stop", "xray"], check=True, capture_output=True)

def _restart_xray():
    t = subprocess.run(["xray", "run", "-test", "-config", XRAY],
                       capture_output=True, text=True)
    if t.returncode:
        raise RuntimeError("конфиг Xray невалиден: " + (t.stderr or t.stdout))
    subprocess.run(["systemctl", "restart", "xray"], check=True, capture_output=True)

_FP_VALUES = {"firefox", "chrome", "safari", "ios", "android", "edge", "randomized", "random"}

def _fp():
    v = (CFG_CACHE.get("fp") or "").strip().lower()
    return v if v in _FP_VALUES else "firefox"

def _link(inb, host, client, proto):
    meta = _proto_meta(proto)
    fp = _fp()
    name = client.get("name") or "Veil"
    if proto == "hysteria2":
        dom = (CFG_CACHE.get("panel_domain") or "").strip() or host
        auth = client.get("auth") or client["uuid"]
        q = urllib.parse.urlencode({"sni": dom,
                                    "insecure": 1})
        return f"hy2://{auth}@{host}:{inb['port']}/?{q}#{urllib.parse.quote(name)}"
    if proto == "wireguard":
        psk = inb.get("psk") or ""
        return ("[Interface]\n"
                f"PrivateKey = {client['client_private_key']}\n"
                f"Address = {client['address']}\n"
                f"DNS = 1.1.1.1, 8.8.8.8\n"
                f"MTU = {inb.get('mtu', 1420)}\n\n"
                "[Peer]\n"
                f"PublicKey = {inb['public_key']}\n"
                + (f"PresharedKey = {psk}\n" if psk else "")
                + f"Endpoint = {host}:{inb['port']}\n"
                "AllowedIPs = 0.0.0.0/0, ::/0\n"
                "PersistentKeepalive = 25\n"
                "")
    if proto.startswith("shadowsocks"):
        cred = (inb.get("method") or "aes-256-gcm") + ":" + (inb.get("password") or "")
        raw = base64.urlsafe_b64encode(cred.encode()).decode().rstrip("=")
        return f"ss://{raw}@{host}:{inb['port']}#{urllib.parse.quote(name)}"
    if proto.startswith("vmess"):
        add = host.strip("[]")
        p = {"v": "2", "ps": name, "add": add, "port": inb["port"],
             "id": client["uuid"], "aid": "0", "scy": "auto",
             "net": meta["net"], "type": "none", "host": "",
             "path": "/veil" if meta["net"] == "ws" else "veil",
             "tls": "tls" if meta["tls"] else ""}
        if meta["tls"]:
            p["sni"] = host; p["allowInsecure"] = True; p["fp"] = fp
        return "vmess://" + base64.urlsafe_b64encode(json.dumps(p).encode()).decode()
    if proto.startswith("trojan"):
        scheme = "trojan://" + urllib.parse.quote(client.get("password") or inb.get("password") or "") + "@"
    else:
        scheme = f"vless://{client['uuid']}@"
    qparts = {"type": meta["net"]}
    if meta["net"] == "ws":
        qparts["path"] = "/veil"
    elif meta["net"] == "grpc":
        qparts["serviceName"] = "veil"; qparts["mode"] = "gun"
    elif meta["net"] in ("xhttp", "splithttp"):
        qparts["path"] = "/veil"
    if proto in ("reality", "vless-xhttp-reality"):
        qparts.update({"security": "reality", "pbk": inb["public_key"],
                       "fp": fp, "sni": inb["sni"], "sid": inb["sid"],
                       "spx": "/"})
        if proto == "reality":
            qparts["flow"] = "xtls-rprx-vision"
        else:
            qparts["host"] = inb["sni"]
    elif meta["tls"]:
        qparts.update({"security": "tls", "sni": host, "fp": fp,
                       "allowInsecure": "1"})
        if meta["net"] in ("xhttp", "splithttp"):
            qparts["alpn"] = "h2,http/1.1"
    else:
        qparts["security"] = "none"
    q = urllib.parse.urlencode(qparts)
    return f"{scheme}{host}:{inb['port']}?{q}#{urllib.parse.quote(name)}"

def _new_client(name, proto=None, inb=None, **kw):
    c = {"uuid": str(uuidlib.uuid4()),
         "name": (name or "").strip() or "Кент",
         "sub_token": secrets.token_urlsafe(16),
         "created": int(time.time())}
    # Лимиты трафика/срок (0 = без ограничений)
    c["limit_gb"] = float(kw.get("limit_gb") or 0)
    c["expiry"] = int(kw.get("expiry") or 0)
    if proto and proto.startswith("trojan"):
        c["password"] = secrets.token_urlsafe(12)
    if proto == "hysteria2":
        c["auth"] = secrets.token_hex(16)
    if proto == "wireguard" and inb is not None:
        priv, pub = _gen_keys()
        addr = inb.get("next_address", 2)
        inb["next_address"] = addr + 1
        c["client_private_key"] = priv
        c["client_public_key"] = pub
        c["address"] = f"10.10.0.{addr}/32"
    return c

# ---------- github / update ----------

def _gh_headers():
    h = {"Accept": "application/vnd.github+json", "User-Agent": "veil-panel"}
    try:
        with open(TOKEN_FILE) as f: tok = f.read().strip()
        if tok: h["Authorization"] = "Bearer " + tok
    except Exception: pass
    return h

def _gh_latest():
    url = f"https://api.github.com/repos/{REPO}/releases?per_page=1"
    print("[update] GET " + url, flush=True)
    req = urllib.request.Request(url, headers=_gh_headers())
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.load(r)
        print("[update] OK type=" + type(data).__name__, flush=True)
        if isinstance(data, list):
            if not data: raise RuntimeError("нет релизов")
            print("[update] tags=" + str([x.get("tag_name") for x in data]), flush=True)
            return data[0]
        return data
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode(errors="replace")[:500]
        except Exception: pass
        print("[update] HTTP " + str(e.code) + " " + body, flush=True)
        raise

def _dl(url, dest):
    h = _gh_headers()
    h["Accept"] = "application/octet-stream"
    print("[update] download " + url, flush=True)
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=90) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)
    print("[update] downloaded " + str(os.path.getsize(dest)) + " bytes", flush=True)

def _sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def _check_update():
    rel = _gh_latest()
    tag = rel.get("tag_name", "").lstrip("v")
    newer = False
    if tag and tag != VERSION:
        newer = _ver_tuple(tag) > _ver_tuple(VERSION)
    return {"current": VERSION, "latest": tag,
            "url": rel.get("html_url", ""),
            "update_available": newer}

def _install_update():
    rel = _gh_latest()
    tag = rel.get("tag_name", "").lstrip("v")
    if not tag: raise RuntimeError("в релизе нет tag_name")
    if not (_ver_tuple(tag) > _ver_tuple(VERSION)):
        raise RuntimeError("нет обновлений (текущая " + VERSION + ")")
    assets = {a["name"]: a["url"] for a in rel.get("assets", [])}
    for need in ("veil.tar.gz", "veil.tar.gz.sha256"):
        if need not in assets: raise RuntimeError("в релизе нет " + need)
    with tempfile.TemporaryDirectory(prefix="veil-up-") as tmp:
        arch = os.path.join(tmp, "veil.tar.gz"); shaf = os.path.join(tmp, "sha256")
        _dl(assets["veil.tar.gz"], arch); _dl(assets["veil.tar.gz.sha256"], shaf)
        with open(shaf) as f: expected = f.read().strip().split()[0]
        actual = _sha256_file(arch)
        if actual.lower() != expected.lower():
            raise RuntimeError("sha256 не совпал — обновление отклонено")
        exdir = os.path.join(tmp, "x"); os.makedirs(exdir, exist_ok=True)
        with tarfile.open(arch, "r:gz") as tar:
            for m in tar.getmembers():
                base = os.path.basename(m.name)
                if base not in ("panel.py", "index.html"): continue
                m.name = base
                tar.extract(m, exdir)
        for fn in ("panel.py", "index.html"):
            if not os.path.exists(os.path.join(exdir, fn)):
                raise RuntimeError("в архиве нет " + fn)
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
        bdir = f"{BASE}/backup-v{VERSION}-{ts}"
        os.makedirs(bdir, exist_ok=True)
        for fn in ("panel.py", "index.html"):
            src = os.path.join(BASE, fn)
            if os.path.exists(src): shutil.copy2(src, os.path.join(bdir, fn))
        for fn in ("panel.py", "index.html"):
            shutil.copy2(os.path.join(exdir, fn), os.path.join(BASE, fn))
        os.chmod(os.path.join(BASE, "panel.py"), 0o755)
    subprocess.Popen(["bash", "-c", "sleep 1 && systemctl restart vpnpanel"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    return {"ok": True, "from": VERSION, "to": tag, "restarting": True}

# ---------- HTTP ----------

CFG_CACHE = _load(CFG, {}) or {}

def _cookie(self):
    m = re.search(r"sid=([^;]+)", self.headers.get("Cookie", "") or "")
    return m.group(1) if m else None

def _authed(self):
    t = _cookie(self)
    if t is None:
        t = (self.headers.get("X-Sid") or "").strip() or None
    e = SESSIONS.get(t) if t else None
    return bool(e and e > time.time())


# ---------- telemt / telegram proxy ----------


def verify_api_token(environ):
    auth_header = environ.get("HTTP_AUTHORIZATION", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        tokens = CFG_CACHE.get("api_tokens", [])
        if token in tokens:
            return True
    return False


def _tg_api(method, path, body=None):
    import urllib.request, urllib.error
    url = TELEMT_API + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}

def _tg_available():
    try:
        _tg_api("GET", "/v1/users")
        return True
    except Exception:
        return False

def _tg_status():
    try:
        d = _tg_api("GET", "/v1/users")
    except Exception:
        return {"installed": False, "users": []}
    web = _tg_web_get()
    web_links = {u: _tg_web_link(u) for u in (web["profiles"] if web else [])}
    users = []
    for u in d.get("data", []):
        links = (u.get("links") or {}).get("tls") or []
        # Первая ссылка обычно IPv4 — предпочтём её
        link = ""
        for l in links:
            if "server=" in l and ":" not in l.split("server=")[1].split("&")[0]:
                link = l; break
        if not link and links:
            link = links[0]
        users.append({
            "username": u.get("username", ""),
            "enabled": bool(u.get("enabled")),
            "link": link,
            "web_link": web_links.get(u.get("username", ""), ""),
            "connections": u.get("active_unique_ips", 1 if u.get("current_connections", 0) else 0),
            "total_octets": u.get("total_octets", 0),
        })
    for u in users:
        u["link"] = _tg_host_ok(u.get("link") or "")
    res = {"installed": True, "users": users}
    if web:
        res["web"] = web
    return res


def _tg_host_ok(link):
    host = (CFG_CACHE.get("panel_domain") or "").strip()
    if not host or not link:
        return link
    return re.sub(r"(?i)(server=)[^&:]+", lambda m: m.group(1)+host, link)

def _tg_add(username):
    name = (username or "").strip().replace(" ", "_")
    if not name:
        raise RuntimeError("имя пустое")
    if not re.match(r"^[a-zA-Z0-9_.-]{1,32}$", name):
        raise RuntimeError("только латиница, цифры, _ . - (до 32 символов)")
    d = _tg_api("POST", "/v1/users", {"username": name})
    secret = d.get("secret", "")
    links = ((d.get("data") or {}).get("user") or {}).get("links", {})
    tls = links.get("tls") or []
    link = ""
    for l in tls:
        if "server=" in l and ":" not in l.split("server=")[1].split("&")[0]:
            link = l; break
    if not link and tls:
        link = tls[0]
    web_link = ""
    w = _tg_web_get()
    if w and w.get("enabled") and w.get("host"):
        users = list(w["profiles"])
        if name not in users:
            users.append(name)
            try:
                _tg_web_set_profiles(users)
                w = _tg_web_get()
            except Exception:
                w = None
        if w and name in w["profiles"]:
            s = secret or _tg_web_secret(name)
            web_link = "tg://webproxy?server=%s&secret=dd%s" % (w["host"], s) if s else ""
    return {"username": name, "secret": secret, "link": _tg_host_ok(link), "web_link": web_link}

def _tg_remove(username):
    if not username:
        raise RuntimeError("имя пустое")
    w = _tg_web_get()
    if w and username in w["profiles"]:
        try:
            _tg_web_set_profiles([u for u in w["profiles"] if u != username])
        except Exception:
            pass
    _tg_api("DELETE", "/v1/users/" + urllib.parse.quote(username))
    return {"ok": True}

def _tg_web_get():
    """WEB-конфиг telemt: enabled, carrier, vhosts-профили, host."""
    try:
        d = _tg_api("GET", "/v1/config").get("data", {})
    except Exception:
        return None
    w = d.get("web") or {}
    vhosts = w.get("vhosts") or []
    out = {
        "enabled": bool(w.get("enabled")),
        "carrier": w.get("carrier"),
        "host": "",
        "public_addr": "",
        "profiles": [],
    }
    if vhosts:
        v = vhosts[0]
        out["host"] = v.get("host", "")
        out["public_addr"] = v.get("public_addr", "")
        out["profiles"] = [p.get("user") for p in (v.get("profiles") or [])]
    return out

def _tg_web_secret(username):
    """Секрет пользователя из telemt.toml [access.users]."""
    try:
        with open(TELEMT_CONF, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception:
        return ""
    m = re.search(r"(?ms)^\s*\[access\.users\]\s*$(.+?)(?=^\s*\[|\Z)", text)
    if not m:
        return ""
    for line in m.group(1).splitlines():
        line = line.strip()
        mm = re.match(r'^"?([^"=\s]+)"?\s*=\s*"([0-9a-fA-F]+)"', line)
        if mm and mm.group(1) == username:
            return mm.group(2)
    return ""

def _tg_web_link(username):
    """tg://webproxy?server=HOST&secret=dd<secret> для пользователя."""
    w = _tg_web_get()
    if not (w and w.get("enabled") and w.get("host")):
        return ""
    if username not in w["profiles"]:
        return ""
    secret = _tg_web_secret(username)
    if not secret:
        return ""
    return "tg://webproxy?server=%s&secret=dd%s" % (w["host"], secret)

def _tg_web_set_profiles(users):
    """PATCH [web].vhosts[].profiles целиком (hot-reload, без перезапуска)."""
    d = _tg_api("GET", "/v1/config").get("data", {})
    w = d.get("web") or {}
    vhosts = list(w.get("vhosts") or [])
    if not vhosts:
        return
    v = dict(vhosts[0])
    existing = {}
    for p in (v.get("profiles") or []):
        existing[p.get("user")] = dict(p)
    new_profiles = []
    for u in users:
        p = existing.get(u) or {"user": u, "secret_mode": "dd",
                                 "max_sessions": 8, "max_streams": 512,
                                 "max_streams_per_session": 64}
        p["user"] = u
        if "secret_mode" not in p:
            p["secret_mode"] = "dd"
        new_profiles.append(p)
    v["profiles"] = new_profiles
    vhosts[0] = v
    _tg_api("PATCH", "/v1/config", {"web": {"vhosts": vhosts}})

_WEB_CARRIERS = ("https", "https-lanes", "websocket", "websocket-lanes")

def _tg_web_set(carrier=None, enabled=None):
    """Сменить [web] carrier / включить-выключить WEB (hot-reload, без перезапуска)."""
    patch = {}
    if enabled is not None:
        patch["enabled"] = bool(enabled)
    if carrier is not None:
        carrier = (carrier or "").strip().lower()
        if carrier not in _WEB_CARRIERS:
            raise RuntimeError("carrier: https, https-lanes, websocket, websocket-lanes")
        patch["carrier"] = carrier
    d = _tg_api("GET", "/v1/config").get("data", {})
    w = d.get("web") or {}
    if (patch.get("enabled", w.get("enabled")) and
            (carrier or w.get("carrier")) == "https-lanes"):
        mh = (w.get("limits") or {}).get("max_http_handlers", 512)
        if isinstance(mh, int) and mh < 4:
            raise RuntimeError("https-lanes требует max_http_handlers >= 4")
    _tg_api("PATCH", "/v1/config", {"web": patch})
    return _tg_web_get()

_NG_WEBPROXY_TEMPLATE = """map $http_upgrade $telemt_connection_upgrade {
    default upgrade;
    ''      '';
}

map $uri $cache_control {
    default                 "public, max-age=300";
    "~^/$"                  "no-store, no-cache";
    "~^/index\\.html$"     "no-store, no-cache";
    "~^/manifest\\.json$"  "no-store, no-cache";
    "~*\\.(png|jpg|jpeg|ico)$" "no-store, no-cache";
}

upstream telemt_web {
    server 127.0.0.1:18080;
    keepalive 64;
}

server {
    listen 443 ssl;
    http2 on;
    server_name {domain};
    access_log /var/log/nginx/decoy-access.log;

    ssl_certificate     {cert};
    ssl_certificate_key {key};

    client_max_body_size 2m;

    location = /manifest.json {
        proxy_pass http://telemt_web;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $telemt_connection_upgrade;

        proxy_hide_header Content-Type;
        proxy_hide_header Cache-Control;
        add_header Content-Type "application/manifest+json; charset=utf-8" always;
        add_header Cache-Control "no-store, no-cache" always;
    }

    location / {
        proxy_pass http://telemt_web;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $telemt_connection_upgrade;

        proxy_hide_header Cache-Control;
        add_header Cache-Control $cache_control always;

        proxy_connect_timeout 5s;
        proxy_send_timeout 65s;
        proxy_read_timeout 65s;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_next_upstream off;
    }
}
"""

_NG_CONF = "/etc/nginx/conf.d/webproxy.conf"

def _ng_certs(domain):
    live = f"{CERT_DIR}/live/veil-{domain}"
    cp = _cert_pathes()
    if cp["cert"] and os.path.exists(cp["cert"]) and cp["key"] and os.path.exists(cp["key"]):
        return cp["cert"], cp["key"]
    if os.path.exists(f"{live}/fullchain.pem") and os.path.exists(f"{live}/privkey.pem"):
        return f"{live}/fullchain.pem", f"{live}/privkey.pem"
    crt = f"{CERT_DIR}/webproxy-{domain}.crt"; key = f"{CERT_DIR}/webproxy-{domain}.key"
    if not (os.path.exists(crt) and os.path.exists(key)):
        os.makedirs(CERT_DIR, exist_ok=True)
        r = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", crt, "-days", "3650",
             "-subj", "/CN=" + domain, "-addext", "subjectAltName=DNS:" + domain],
            capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("openssl: " + (r.stderr or r.stdout))
    return crt, key

def _webproxy_status():
    nginx_bin = shutil.which("nginx")
    ng_conf = os.path.exists(_NG_CONF)
    ng_active = False
    if nginx_bin:
        r = subprocess.run(["systemctl", "is-active", "--quiet", "nginx"])
        ng_active = r.returncode == 0
    installed = bool(nginx_bin and ng_conf and ng_active)
    free80 = _port_free(80)
    free443 = _port_free(443)
    domain = (CFG_CACHE.get("panel_domain") or "").strip()
    domain_set = bool(domain and not re.fullmatch(r"[0-9.]+", domain)
                      and ":" not in domain and "//" not in domain)
    busy = []
    if not free80: busy.append(80)
    if not free443: busy.append(443)
    return {"installed": installed, "nginx": bool(nginx_bin), "config": ng_conf,
            "active": ng_active, "port80": free80, "port443": free443,
            "busy": busy, "domain": domain, "domain_set": domain_set,
            "can_install": (not installed) and (not busy) and domain_set}

def _webproxy_install():
    st = _webproxy_status()
    if st["installed"]:
        return {"ok": True, "status": st, "message": "Web Proxy уже установлен и работает"}
    if st["busy"]:
        raise RuntimeError("порт %s занят — освободи его, после этого кнопка установки появится" %
                           "/".join(map(str, st["busy"])))
    if not st["domain_set"]:
        raise RuntimeError("нет домена или DDNS — внеси его во вкладке Сайт (раздел DDNS)")
    domain = st["domain"]
    if not st["nginx"]:
        r = subprocess.run(["apt-get", "install", "-y", "-qq", "nginx"],
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            raise RuntimeError("apt nginx: " + (r.stderr or r.stdout)[-300:])
    cert, key = _ng_certs(domain)
    conf = _NG_WEBPROXY_TEMPLATE.format(domain=domain, cert=cert, key=key)
    os.makedirs(os.path.dirname(_NG_CONF), exist_ok=True)
    with open(_NG_CONF, "w") as f:
        f.write(conf)
    t = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=20)
    if t.returncode != 0:
        raise RuntimeError("nginx -t: " + (t.stderr or t.stdout)[-400:])
    subprocess.run(["systemctl", "enable", "nginx"], capture_output=True)
    subprocess.run(["systemctl", "restart", "nginx"], check=True, capture_output=True, timeout=60)
    return {"ok": True, "status": _webproxy_status()}

def _find_free_port(pref=None, avoid=()):
    import socket
    avoid = set(avoid or ())
    avoided = _RESERVED_PORTS | avoid
    if pref is None:
        prefs = (7443, 2443, 8843, 6443, 9443)
    elif isinstance(pref, int):
        prefs = (pref,)
    else:
        prefs = tuple(pref) or (7443, 2443, 8843, 6443, 9443)
    for port in prefs:
        if port in avoided: continue
        s = socket.socket()
        try:
            s.bind(("", port)); s.close(); return port
        except OSError:
            s.close()
    for _ in range(200):
        s = socket.socket()
        try:
            s.bind(("", 0)); port = s.getsockname()[1]; s.close()
        except OSError:
            s.close(); continue
        if port not in avoided:
            return port
    raise RuntimeError("нет свободного порта")


_IPV6_CACHE = {"t": 0, "v": None}

_IPV4_CACHE = {"t": 0, "v": None}

def _my_ip():
    if time.time() - _IPV4_CACHE["t"] < 300:
        return _IPV4_CACHE["v"]
    v = None
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "scope", "global"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            toks = line.split()
            idx = toks.index("inet") if "inet" in toks else -1
            if idx != -1 and idx + 1 < len(toks):
                v = toks[idx + 1].split("/")[0]
                break
    except Exception:
        pass
    _IPV4_CACHE["t"] = time.time(); _IPV4_CACHE["v"] = v
    return v


def _my_ipv6():
    if time.time() - _IPV6_CACHE["t"] < 300:
        return _IPV6_CACHE["v"]
    v = None
    try:
        out = subprocess.run(["ip", "-6", "-o", "addr", "show", "scope", "global"],
                             capture_output=True, text=True, timeout=5).stdout
        addrs = []
        for line in out.splitlines():
            parts = line.split()
            if "inet6" not in parts:
                continue
            addr = parts[parts.index("inet6") + 1].split("/")[0]
            if addr and addr not in ("::1",) and "::1" != addr:
                addrs.append(addr)
        for a in addrs:
            low = a.lower()
            if not low.startswith(("fd", "fc", "fe")) and "." not in a:
                v = a; break
        if not v and addrs:
            v = addrs[0]
    except Exception:
        pass
    _IPV6_CACHE.update(t=time.time(), v=v)
    return v

_LOGIN_FAILS = {}

def _login_throttle(client_ip):
    now = time.time()
    a = [x for x in _LOGIN_FAILS.get(client_ip, []) if x > now - 600]
    _LOGIN_FAILS[client_ip] = a
    return len(a) >= 5

def _login_fail(client_ip):
    _LOGIN_FAILS.setdefault(client_ip, []).append(time.time())

def _login_ok(client_ip):
    _LOGIN_FAILS.pop(client_ip, None)

# ---------- veil-zapret2 fix ----------

import subprocess as _sp

def _fix_status():
    try:
        r = _sp.run(["systemctl", "is-active", "veil-zapret2"],
                    capture_output=True, text=True, timeout=5)
        active = r.stdout.strip() == "active"
    except Exception:
        active = False
    installed = __import__("os").path.exists("/opt/veil-zapret2/bin/nfqws2")
    return {"installed": installed, "active": active}

def _fix_enable():
    # Если не установлен — отдаём ошибку с подсказкой
    import os
    if not os.path.exists("/usr/local/sbin/veil-zapret2-start.sh"):
        raise RuntimeError("veil-zapret2 не установлен на этом сервере")
    _sp.run(["systemctl", "enable", "--now", "veil-zapret2"],
            capture_output=True, text=True, timeout=15, check=True)
    return _fix_status()

def _fix_disable():
    _sp.run(["systemctl", "disable", "--now", "veil-zapret2"],
            capture_output=True, text=True, timeout=15)
    return _fix_status()

# ---------- statistics ----------

def _service_active_since(unit):
    try:
        out = subprocess.run(
            ["systemctl", "show", unit, "-p", "ActiveEnterTimestamp"],
            capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return None
    if "=" not in out:
        return None
    v = out.split("=", 1)[1].strip()
    return v or None

def _xray_current_version():
    try:
        out = subprocess.run([XRAY_BIN, "version"], capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", out)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"

def _xray_versions():
    req = urllib.request.Request(
        "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=100",
        headers=_gh_headers())
    with urllib.request.urlopen(req, timeout=20) as r:
        rels = json.load(r)
    vers = []
    pre = []
    for rel in rels:
        if rel.get("draft"):
            continue
        tag = str(rel.get("tag_name") or "").lstrip("v")
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", tag) and tag not in vers:
            vers.append(tag)
            if rel.get("prerelease"):
                pre.append(tag)
    return {"versions": vers, "pre": pre}

def _xray_min_req():
    try:
        with open(XRAY, "r", encoding="utf-8") as f:
            txt = f.read()
    except Exception:
        txt = ""
    if '"xhttp"' in txt:
        return (24, 9, 0)
    return (1, 8, 0)

def _xray_switch(version):
    version = version.strip().lstrip("v")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise RuntimeError("неверный формат версии")
    cur = _xray_current_version()
    if cur == version:
        raise RuntimeError("эта версия уже установлена (" + cur + ")")
    mreq = _xray_min_req()
    if _ver_tuple(version) < mreq:
        need = "v24.9" if mreq[0] == 24 else "v1.8"
        raise RuntimeError("слишком старая версия — конфиг требует xray >= " + need)
    with tempfile.TemporaryDirectory(prefix="xray-sw-") as tmp:
        z = os.path.join(tmp, "x.zip")
        url = "https://github.com/XTLS/Xray-core/releases/download/v" + version + "/Xray-linux-64.zip"
        _dl(url, z)
        with zipfile.ZipFile(z) as arc:
            arc.extract("xray", tmp)
        newbin = os.path.join(tmp, "xray")
        if not os.path.exists(newbin):
            raise RuntimeError("в архиве нет бинаря xray")
        os.chmod(newbin, 0o755)
        t = subprocess.run([newbin, "run", "-test", "-config", XRAY],
                           capture_output=True, text=True, timeout=90)
        if t.returncode:
            raise RuntimeError("новая версия не прошла проверку конфига: " + (t.stderr or t.stdout)[-300:])
        bdir = os.path.join(BASE, "backups", "xray", cur)
        os.makedirs(bdir, exist_ok=True)
        shutil.copy2(XRAY_BIN, os.path.join(bdir, "xray"))
        tmpbin = XRAY_BIN + ".new"
        shutil.copy2(newbin, tmpbin)
        os.chmod(tmpbin, 0o755)
        os.replace(tmpbin, XRAY_BIN)
        subprocess.run(["systemctl", "restart", "xray"], check=True, capture_output=True, timeout=60)
    return {"ok": True, "from": cur, "to": version}

def _panel_backups():
    res = []
    try:
        entries = sorted(os.listdir(BASE), reverse=True)
    except Exception:
        return res
    for d in entries:
        dd = os.path.join(BASE, d)
        m = re.fullmatch(r"backup-v([0-9]+\.[0-9]+\.[0-9]+)-.*", d)
        if m and os.path.isdir(dd) and os.path.isfile(os.path.join(dd, "panel.py")):
            res.append({"version": m.group(1), "dir": d})
    return res

def _xray_backups():
    res = []
    base = os.path.join(BASE, "backups", "xray")
    if not os.path.isdir(base):
        return res
    for d in sorted(os.listdir(base), reverse=True):
        if os.path.isfile(os.path.join(base, d, "xray")):
            res.append({"version": d})
    return res

def _panel_restore(version):
    for b in _panel_backups():
        if b["version"] == version:
            dd = os.path.join(BASE, b["dir"])
            shutil.copy2(os.path.join(dd, "panel.py"), os.path.join(BASE, "panel.py"))
            os.chmod(os.path.join(BASE, "panel.py"), 0o755)
            if os.path.exists(os.path.join(dd, "index.html")):
                shutil.copy2(os.path.join(dd, "index.html"), os.path.join(BASE, "index.html"))
            subprocess.Popen(["bash", "-c", "sleep 1 && systemctl restart vpnpanel"])
            return {"ok": True, "type": "panel", "version": version}
    raise RuntimeError("бэкап панели v" + version + " не найден")

def _xray_restore(version):
    src = os.path.join(BASE, "backups", "xray", version, "xray")
    if not os.path.isfile(src):
        raise RuntimeError("бэкап xray v" + version + " не найден")
    cur = _xray_current_version()
    if cur == version:
        raise RuntimeError("эта версия уже стоит")
    t = subprocess.run([src, "run", "-test", "-config", XRAY],
                       capture_output=True, text=True, timeout=90)
    if t.returncode:
        raise RuntimeError("бэкап не прошёл проверку конфига: " + (t.stderr or t.stdout)[-300:])
    bdir = os.path.join(BASE, "backups", "xray", cur)
    os.makedirs(bdir, exist_ok=True)
    shutil.copy2(XRAY_BIN, os.path.join(bdir, "xray"))
    tmpbin = XRAY_BIN + ".new"
    shutil.copy2(src, tmpbin)
    os.chmod(tmpbin, 0o755)
    os.replace(tmpbin, XRAY_BIN)
    subprocess.run(["systemctl", "restart", "xray"], check=True, capture_output=True, timeout=60)
    return {"ok": True, "type": "xray", "version": version}

# ---------- telemt version / update / rollback ----------

def _tg_current_version():
    try:
        out = subprocess.run(["/usr/bin/telemt", "--version"],
                             capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", out)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"

def _tg_versions():
    req = urllib.request.Request(
        "https://api.github.com/repos/telemt/telemt/releases?per_page=100",
        headers=_gh_headers())
    with urllib.request.urlopen(req, timeout=20) as r:
        rels = json.load(r)
    vers = []
    pre = []
    for rel in rels:
        if rel.get("draft"):
            continue
        tag = str(rel.get("tag_name") or "").lstrip("v")
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", tag) and tag not in vers:
            vers.append(tag)
            if rel.get("prerelease"):
                pre.append(tag)
    return {"versions": vers, "pre": pre}

def _tg_switch(version):
    version = version.strip().lstrip("v")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise RuntimeError("неверный формат версии")
    cur = _tg_current_version()
    if cur == version:
        raise RuntimeError("эта версия уже установлена (" + cur + ")")
    if (_tg_versions()["versions"] and version not in _tg_versions()["versions"]):
        raise RuntimeError("версия v" + version + " не найдена в релизах telemt")
    with tempfile.TemporaryDirectory(prefix="telemt-sw-") as tmp:
        z = os.path.join(tmp, "t.tar.gz")
        url = ("https://github.com/telemt/telemt/releases/download/" + version +
               "/telemt-x86_64-linux-gnu.tar.gz")
        _dl(url, z)
        with tarfile.open(z, "r:gz") as arc:
            arc.extract("telemt", tmp)
        newbin = os.path.join(tmp, "telemt")
        if not os.path.exists(newbin):
            raise RuntimeError("в архиве нет бинаря telemt")
        os.chmod(newbin, 0o755)
        t = subprocess.run([newbin, "--version"], capture_output=True, text=True, timeout=20)
        if t.returncode:
            raise RuntimeError("бинар не запускается: " + (t.stderr or t.stdout)[-300:])
        bdir = os.path.join(BASE, "backups", "telemt", cur)
        os.makedirs(bdir, exist_ok=True)
        shutil.copy2("/usr/bin/telemt", os.path.join(bdir, "telemt"))
        tmpbin = "/usr/bin/telemt.new"
        shutil.copy2(newbin, tmpbin)
        os.chmod(tmpbin, 0o755)
        os.replace(tmpbin, "/usr/bin/telemt")
        subprocess.run(["systemctl", "restart", "telemt"], check=True, capture_output=True, timeout=60)
    return {"ok": True, "from": cur, "to": version}

def _tg_backups():
    res = []
    base = os.path.join(BASE, "backups", "telemt")
    if not os.path.isdir(base):
        return res
    for d in sorted(os.listdir(base), reverse=True):
        if os.path.isfile(os.path.join(base, d, "telemt")):
            res.append({"version": d})
    return res

def _tg_restore(version):
    src = os.path.join(BASE, "backups", "telemt", version, "telemt")
    if not os.path.isfile(src):
        raise RuntimeError("бэкап telemt v" + version + " не найден")
    cur = _tg_current_version()
    if cur == version:
        raise RuntimeError("эта версия уже стоит")
    t = subprocess.run([src, "--version"], capture_output=True, text=True, timeout=20)
    if t.returncode:
        raise RuntimeError("бэкап не запускается: " + (t.stderr or t.stdout)[-300:])
    bdir = os.path.join(BASE, "backups", "telemt", cur)
    os.makedirs(bdir, exist_ok=True)
    shutil.copy2("/usr/bin/telemt", os.path.join(bdir, "telemt"))
    tmpbin = "/usr/bin/telemt.new"
    shutil.copy2(src, tmpbin)
    os.chmod(tmpbin, 0o755)
    os.replace(tmpbin, "/usr/bin/telemt")
    subprocess.run(["systemctl", "restart", "telemt"], check=True, capture_output=True, timeout=60)
    return {"ok": True, "type": "telemt", "version": version}

_DDNS = {"configured": False, "host": "", "updated": None, "error": "", "response": "", "ipv4": None, "ipv6": None}
CERT_DIR = f"{BASE}/certs"
_CERT_STATE = {"domain": "", "issued": None, "expire": None, "cert": "", "key": "", "error": "", "busy": False,
               "email": "", "auto": True}

def _dynv6_conf():
    c = CFG_CACHE or {}
    return {"host": (c.get("dynv6_host") or "").strip(),
            "token": (c.get("dynv6_token") or "").strip()}

def _pub_ip4():
    for u in ("https://ipv4.icanhazip.com", "https://api.ipify.org"):
        try:
            with urllib.request.urlopen(u, timeout=8) as r:
                ip = r.read().decode().strip()
            if re.fullmatch(r"[0-9.]+", ip):
                return ip
        except Exception:
            pass
    v = _my_ip()
    return v if v and re.fullmatch(r"[0-9.]+", v) else None

def _pub_ip6():
    for u in ("https://v6.ident.me", "https://ipv6.icanhazip.com"):
        try:
            with urllib.request.urlopen(u, timeout=8) as r:
                ip = r.read().decode().strip()
            if ":" in ip:
                return ip
        except Exception:
            pass
    return _my_ipv6()

def _dynv6_create_zone(name, account_token):
    """Создание зоны через dynv6 REST v2 API (нужен Bearer account-token)."""
    name = (name or "").strip().lower()
    account_token = (account_token or "").strip()
    if not name or not account_token:
        raise RuntimeError("нужны имя зоны и account-token dynv6")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,31}", name):
        raise RuntimeError("имя зоны: латиница/цифры/- (2–32 символа)")
    body = json.dumps({"name": name}).encode()
    req = urllib.request.Request("https://dynv6.com/api/v2/zones", data=body,
                                 method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + account_token})
    with urllib.request.urlopen(req, timeout=30) as r:
        d = json.loads(r.read().decode("utf-8", "replace"))
    host = (d.get("name") or "").strip()
    token = (d.get("token") or "").strip()
    if not host or not token:
        raise RuntimeError("dynv6: ответ API не содержит name/token: " + json.dumps(d, ensure_ascii=False)[:200])
    # сохраняем новую зону как текущую dynv6-configured
    CFG_CACHE["dynv6_host"] = host
    CFG_CACHE["dynv6_token"] = token
    _save(CFG, CFG_CACHE)
    if not (CFG_CACHE.get("panel_domain") or "").strip():
        CFG_CACHE["panel_domain"] = host
        CFG_CACHE["dynv6_host"] = host
        _save(CFG, CFG_CACHE)
    up = None
    try:
        up = _dynv6_update()
    except Exception as e:
        up = {"ok": False, "error": str(e)}
    return {"ok": True, "host": host, "zone_created": True, "update": up}

def _dynv6_update():
    conf = _dynv6_conf()
    host, token = conf["host"], conf["token"]
    if not host or not token:
        raise RuntimeError("dynv6 не настроен (нужны host и token)")
    if not re.fullmatch(r"(?i)[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", host):
        raise RuntimeError("некорректный dynv6-host")
    ip4, ip6 = _pub_ip4(), _pub_ip6()
    p = [("hostname", host)]
    if ip4: p.append(("ipv4", ip4))
    if ip6: p.append(("ipv6", ip6))
    p.append(("token", token))
    url = "https://dynv6.com/api/update?" + urllib.parse.urlencode(p)
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=25) as r:
        body = r.read().decode("utf-8", "replace").strip()
    ok = body.lower().startswith("addresses updated")
    _DDNS.update(configured=True, host=host, ipv4=ip4, ipv6=ip6,
                 response=body, error="" if ok else body)
    if ok:
        _DDNS["updated"] = time.time()
        if not CFG_CACHE.get("panel_domain"):
            CFG_CACHE["panel_domain"] = host
            _save(CFG, CFG_CACHE)
    else:
        _DDNS["error"] = "dynv6: " + body
        raise RuntimeError("dynv6: " + body[:200])
    return {"ok": True, "host": host, "ipv4": ip4, "ipv6": ip6, "response": body}

_WEB_CTX = None

def _web_tls_ctx():
    """SSLContext из сохранённого серта (или None). Вызывать при старте и после перевыпуска."""
    global _WEB_CTX
    cert = (CFG_CACHE.get("panel_cert_path") or "").strip()
    key = (CFG_CACHE.get("panel_key_path") or "").strip()
    if not (cert and key and os.path.exists(cert) and os.path.exists(key)):
        cert = (CFG_CACHE.get("cert") or "").strip()
        key = (CFG_CACHE.get("cert_key") or "").strip()
    if not (cert and key and os.path.exists(cert) and os.path.exists(key)):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.load_cert_chain(cert, key)
    except Exception:
        return None
    _WEB_CTX = ctx
    return ctx

def _cert_pathes():
    c = CFG_CACHE or {}
    return {"cert": (c.get("cert") or "").strip(),
            "key": (c.get("cert_key") or "").strip(),
            "domain": (c.get("cert_domain") or "").strip()}

def _cert_expire(path):
    try:
        out = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-in", path],
                             capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"notAfter=(.+)", out)
        if not m: return None
        t = re.sub(r"\s*GMT\s*$", " UTC", m.group(1))
        return datetime.datetime.strptime(t, "%b %d %H:%M:%S %Y %Z").timestamp()
    except Exception:
        return None

def _cert_status():
    _CERT_STATE["email"] = (CFG_CACHE.get("cert_email") or "").strip()
    _CERT_STATE["auto"] = bool(CFG_CACHE.get("cert_auto", True))
    cp = _cert_pathes()
    if cp["cert"] and os.path.exists(cp["cert"]):
        _CERT_STATE.update(domain=cp["domain"] or "", cert=cp["cert"], key=cp["key"],
                           issued=os.path.getmtime(cp["cert"]),
                           expire=_cert_expire(cp["cert"]))
    return dict(_CERT_STATE)

def _domain_points(domain, cands):
    """True, если домен из вне (DoH Cloudflare/Google) резолвится в один из cands."""
    def _doh(url):
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=12) as r:
                d = json.load(r)
            return {x.get("data") for x in (d.get("Answer") or []) if x.get("type") == 1}
        except Exception:
            return set()
    ips = set()
    for a in range(6):
        ips = _doh("https://cloudflare-dns.com/dns-query?name=" + urllib.parse.quote(domain) + "&type=A") | \
              _doh("https://dns.google/resolve?name=" + urllib.parse.quote(domain) + "&type=A")
        if any(ip in cands for ip in ips):
            return True
        time.sleep(12)
    return False

def _cert_issue(email=None):
    if _CERT_STATE.get("busy"):
        raise RuntimeError("выпуск сертификата уже идёт")
    domain = (CFG_CACHE.get("panel_domain") or "").strip()
    if not domain or re.fullmatch(r"[0-9.]+", domain) or ":" in domain or "//" in domain:
        raise RuntimeError("сначала задай домен (не IP) — в поле ниже или через DDNS")
    cur = _pub_ip4()
    if cur:
        ok = False
        last = set()
        point = _domain_points(domain, {cur})
        ok = point
        last = set()
        if not ok:
            raise RuntimeError("домен " + domain + " сейчас не указывает на этот сервер (" +
                               cur + ") — сначала DDNS / A-запись (DoH: " +
                               ",".join(sorted(last)) + ")")
    if not _port_free(80):
        raise RuntimeError("порт 80 занят — Let's Encrypt (HTTP-01) невозможен")
    os.makedirs(CERT_DIR, exist_ok=True)
    live = f"{CERT_DIR}/live/veil-{domain}"
    certp = f"{live}/fullchain.pem"; keyp = f"{live}/privkey.pem"
    _CERT_STATE["busy"] = True
    try:
        email = (email or CFG_CACHE.get("cert_email") or "").strip()
        args = ["certbot", "certonly", "--standalone", "--preferred-challenges", "http",
                "-d", domain, "--non-interactive", "--agree-tos"]
        if email:
            args += ["--email", email]
        else:
            args += ["--register-unsafely-without-email"]
        args += ["--config-dir", CERT_DIR, "--work-dir", CERT_DIR + "/work",
                 "--logs-dir", CERT_DIR + "/logs", "--cert-name", "veil-" + domain]
        r = subprocess.run(args, capture_output=True, text=True, timeout=280)
        if r.returncode != 0:
            raise RuntimeError("certbot: " + (r.stderr or r.stdout)[-400:])
        if not (os.path.exists(certp) and os.path.exists(keyp)):
            raise RuntimeError("certbot завершился, но no fullchain/privkey")
        if email:
            CFG_CACHE["cert_email"] = email
        CFG_CACHE["cert"] = certp; CFG_CACHE["cert_key"] = keyp
        CFG_CACHE["cert_domain"] = domain
        _save(CFG, CFG_CACHE)
        _CERT_STATE.update(domain=domain, cert=certp, key=keyp,
                           issued=os.path.getmtime(certp), expire=_cert_expire(certp), error="")
        _attach_cert_to_tls()
        return {"ok": True, "domain": domain, "cert": certp, "key": keyp}
    finally:
        _CERT_STATE["busy"] = False

def _attach_cert_to_tls():
    cp = _cert_pathes()
    if not (cp["cert"] and cp["key"]): return
    st = _load(STATE, {}) or {}
    changed = False
    for proto, inb in (st.get("inbounds") or {}).items():
        if (_proto_meta(proto).get("tls") or False) and inb.get("port"):
            inb["cert"], inb["key"] = cp["cert"], cp["key"]
            changed = True
    if changed:
        _save(STATE, st)
        try:
            _write_xray(st)
            _restart_xray()
        except Exception:
            pass

def _reload_cert_runtime():
    """После перевыпуска/изменения сертификата: обновить TLS-контекст панели и рестартовать Xray."""
    try:
        _web_tls_ctx()
    except Exception:
        pass
    try:
        _write_xray(_load(STATE, {}) or {})
        _restart_xray()
    except Exception:
        pass

def _cert_maybe_renew():
    if not CFG_CACHE.get("cert_auto", True):
        return
    cp = _cert_pathes()
    if not (cp["cert"] and os.path.exists(cp["cert"])):
        return
    exp = _cert_expire(cp["cert"])
    if exp and exp > time.time() + 30 * 86400:
        return
    if not _port_free(80):
        _CERT_STATE["error"] = "порт 80 занят — автопродление сейчас невозможно"
        return
    r = subprocess.run(["certbot", "renew", "--config-dir", CERT_DIR,
                        "--work-dir", CERT_DIR + "/work", "--logs-dir", CERT_DIR + "/logs",
                        "--non-interactive"], capture_output=True, text=True, timeout=280)
    if r.returncode == 0:
        _cert_status()
        _reload_cert_runtime()
    else:
        _CERT_STATE["error"] = "автопродление: " + (r.stderr or r.stdout)[-300:]

def _cert_renew_now():
    cp = _cert_pathes()
    if not (cp["cert"] and os.path.exists(cp["cert"])):
        raise RuntimeError("нет выпущенного сертификата — сначала выпусти")
    if _CERT_STATE.get("busy"):
        raise RuntimeError("операция с сертификатом уже идёт")
    if not _port_free(80):
        raise RuntimeError("порт 80 занят — продление (HTTP-01) невозможно")
    _CERT_STATE["busy"] = True
    try:
        r = subprocess.run(["certbot", "renew", "--force-renewal",
                            "--config-dir", CERT_DIR,
                            "--work-dir", CERT_DIR + "/work", "--logs-dir", CERT_DIR + "/logs",
                            "--non-interactive"], capture_output=True, text=True, timeout=280)
        if r.returncode != 0:
            raise RuntimeError("certbot: " + (r.stderr or r.stdout)[-400:])
        _cert_status()
        _reload_cert_runtime()
        return dict(_CERT_STATE)
    finally:
        _CERT_STATE["busy"] = False

def _ddns_loop():
    time.sleep(6)
    try:
        if _dynv6_conf()["host"]:
            _dynv6_update()
    except Exception as e:
        _DDNS.update(configured=bool(_dynv6_conf()["host"]), error=str(e))
    last_day = ""
    while True:
        time.sleep(600)
        try:
            if _dynv6_conf()["host"]:
                _dynv6_update()
        except Exception as e:
            _DDNS["error"] = str(e)
        day = datetime.date.today().isoformat()
        if day != last_day:
            last_day = day
            try:
                _cert_maybe_renew()
            except Exception as e:
                _CERT_STATE["error"] = str(e)


def _limits_loop():
    while True:
        try:
            st = _load(STATE)
            if st:
                bl = _autoblock_limits(st)
                if bl:
                    _save(STATE, st)
                    try:
                        _write_xray(st); _restart_xray()
                    except Exception:
                        pass
                    print("[limits] автоблок: " +
                          ", ".join(f"{b['name']}({b['reason']})" for b in bl), flush=True)
        except Exception as e:
            print("[limits] " + str(e), flush=True)
        time.sleep(60)

threading.Thread(target=_ddns_loop, daemon=True).start()
threading.Thread(target=_limits_loop, daemon=True).start()

def _stats():
    st = _load(STATE) or {}
    clients_count = _client_count(st)

    disk_usage = None
    try:
        out = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=5).stdout
        line = out.splitlines()[1]
        parts = line.split()
        disk_usage = {
            "total": parts[1], "used": parts[2], "avail": parts[3],
            "percent": int(parts[4].rstrip("%")),
        }
    except Exception:
        pass

    memory_usage = None
    try:
        out = subprocess.run(["free", "-m"], capture_output=True, text=True, timeout=5).stdout
        line = [l for l in out.splitlines() if l.startswith("Mem:")][0]
        parts = line.split()
        total = int(parts[1]); used = int(parts[2]); avail = int(parts[6])
        memory_usage = {
            "total_mb": total, "used_mb": used, "avail_mb": avail,
            "percent": round(used * 100 / total) if total else 0,
        }
    except Exception:
        pass

    return {
        "uptime_xray": _service_active_since("xray"),
        "uptime_telemt": _service_active_since("telemt"),
        "clients_count": clients_count,
        "disk_usage": disk_usage,
        "memory_usage": memory_usage,
    }

# ---------- backup / restore ----------

def _backup():
    data = {
        "meta": {"version": VERSION, "created": int(time.time()), "app": "Veil"},
        "panel_config": _load(CFG, {}),
        "state": _load(STATE),
        "theme": _load(THEME, {}),
        "xray_config": _load(XRAY),
        "wallpaper": None,
        "certs": {},
    }
    if os.path.exists(WALL):
        with open(WALL, "rb") as f:
            data["wallpaper"] = base64.b64encode(f.read()).decode()
    for proto in _VALID_PROTOCOLS:
        if not _PROTO_MAP[proto]["tls"] and proto not in ("reality", "vless-xhttp-reality"):
            continue
        for ext in ("crt", "key"):
            p = f"{CERT_DIR}/{proto}.{ext}"
            if os.path.exists(p):
                with open(p, "rb") as f:
                    data["certs"][f"{proto}.{ext}"] = base64.b64encode(f.read()).decode()
    return data

def _restore(data):
    if not isinstance(data, dict) or "state" not in data:
        raise RuntimeError("это не файл резервной копии Veil")
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    bdir = f"{BASE}/restore-backup-{ts}"
    os.makedirs(bdir, exist_ok=True)
    for src, name in ((CFG, "panel_config.json"), (STATE, "state.json"), (XRAY, "xray_config.json")):
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(bdir, name))
    if isinstance(data.get("panel_config"), dict):
        _save(CFG, data["panel_config"], 0o600)
    st = data.get("state")
    if isinstance(st, dict):
        _save(STATE, st, 0o600)
        _write_xray(st)
    if isinstance(data.get("theme"), dict):
        _save(THEME, data["theme"], 0o644)
    if data.get("wallpaper"):
        try:
            with open(WALL, "wb") as f:
                f.write(base64.b64decode(data["wallpaper"]))
        except Exception:
            pass
    for fname, b64 in (data.get("certs") or {}).items():
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.(crt|key)", fname or ""):
            continue
        try:
            p = os.path.join(CERT_DIR, fname)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(base64.b64decode(b64))
            os.chmod(p, 0o644)
        except Exception:
            pass
    global CFG_CACHE
    CFG_CACHE = _load(CFG, {}) or {}
    try:
        _restart_xray()
    except Exception:
        pass
    return {"ok": True, "restored_at": ts, "clients": _client_count(st)}

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, obj, ctype="application/json"):
        b = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        for c in getattr(self, "_cookies", []):
            self.send_header("Set-Cookie", c)
        self.end_headers(); self.wfile.write(b)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _is_cur_pw(self, cur):
        return _hash(CFG_CACHE.get("salt", ""), cur) == CFG_CACHE.get("pass_hash")

    # ---- GET ----
    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        
        if p.startswith("/sub/") or p in ("/sub", "/sub/"):
            # Универсальная подписка (/sub) или личная подписка клиента (/sub/<token>): base64-список ссылок.
            try:
                import base64
                sub_path = p[5:].strip("/") if p.startswith("/sub/") else ""
                links = []
                st = _load(STATE) or {}
                host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
                host = host if "://" not in host else urllib.parse.urlparse(host).netloc
                
                found_client = False
                state_changed = False
                
                for proto, inb in (st.get("inbounds") or {}).items():
                    for c in inb.get("clients", []):
                        if not c.get("sub_token"):
                            c["sub_token"] = secrets.token_urlsafe(16)
                            state_changed = True
                        
                        if sub_path:
                            if c.get("sub_token") == sub_path:
                                try:
                                    links.append(_link(inb, host, c, proto))
                                    found_client = True
                                except Exception:
                                    pass
                        else:
                            try:
                                links.append(_link(inb, host, c, proto))
                            except Exception:
                                continue
                                
                if state_changed:
                    _save(STATE, st)
                    
                if sub_path and not found_client:
                    return self._send(404, {"error": "клиент не найден"})
                if not links:
                    return self._send(404, {"error": "нет клиентов"})
                    
                payload = base64.b64encode("\n".join(links).encode()).decode()
                b = payload.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(b)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers(); self.wfile.write(b)
                return None
            except Exception as e:
                return self._send(500, {"error": str(e)})


        if p == "/api/metrics":
            return self._send(200, get_system_metrics())
        if p == "/api/selftest":
            return self._send(200, run_protocol_self_test())
        if p == "/api/nodes":
            return self._send(200, get_nodes())

        if p in ("/", "/index.html"):
            with open(HTML, "rb") as f: return self._send(200, f.read(), "text/html; charset=utf-8")
        if p == "/api/state":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            st = _load(STATE)
            running = subprocess.run(["systemctl", "is-active", "--quiet", "xray"]).returncode == 0
            out = {"version": VERSION, "running": running, "login": CFG_CACHE.get("login", ""),
                   "configured": _client_count(st) > 0,
                   "proto": _proto_of(st),
                   "panel_port": CFG_CACHE.get("panel_port", 8443),
                   "ipv6": _my_ipv6(),
                   "favorites": st.get("favorites", []) if st else []}
            return self._send(200, out)
        if p == "/api/vpn/protocols":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            st = _load(STATE) or {}
            return self._send(200, {"current": _proto_of(st),
                                    "configured": _client_count(st) > 0,
                                    "protocols": PROTOCOLS})
        if p == "/api/clients":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            st = _load(STATE)
            if not st: return self._send(200, {"clients": [], "configured": False})
            if _migrate_state(st): _save(STATE, st)
            host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
            host = host if "://" not in host else urllib.parse.urlparse(host).netloc
            panel_port = CFG_CACHE.get("panel_port", 8444)
            ipv6 = _my_ipv6()
            tr = _statsquery()
            out = []
            state_changed = False
            for proto, inb in (st.get("inbounds") or {}).items():
                for c in inb.get("clients", []):
                    if not c.get("sub_token"):
                        c["sub_token"] = secrets.token_urlsafe(16)
                        state_changed = True
                    sub_token = c["sub_token"]
                    sub_url = f"https://{host}:{panel_port}/sub/{sub_token}"
                    t = tr.get(c["uuid"], {})
                    item = {"uuid": c["uuid"], "name": c["name"],
                            "link": _link(inb, host, c, proto),
                            "sub_token": sub_token,
                            "sub_url": sub_url,
                            "up": t.get("uplink", 0), "down": t.get("downlink", 0),
                            "limit_gb": float(c.get("limit_gb") or 0),
                            "expiry": int(c.get("expiry") or 0),
                            "used_gb": round((t.get("uplink", 0) + t.get("downlink", 0)) / (1024**3), 3),
                            "ipv6": ipv6,
                            "proto": proto, "port": inb["port"],
                            "proto_label": _proto_meta(proto)["label"],
                            "created": c.get("created", 0)}
                    if ipv6:
                        item["link6"] = _link(inb, f"[{ipv6}]", c, proto)
                    if proto == "wireguard" and c.get("address"):
                        item["address"] = c["address"]
                        item["link6"] = ""
                    if len(out) < 16:
                        item["online"] = _online_count(c["uuid"])
                    out.append(item)
            if state_changed:
                _save(STATE, st)
            return self._send(200, {"clients": out,
                                    "configured": bool(out),
                                    "active": _proto_of(st),
                                    "ipv6": ipv6})
        if p == "/api/update":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            try:
                return self._send(200, _check_update())
            except urllib.error.HTTPError as e:
                return self._send(502, {"error": f"GitHub API: HTTP {e.code}"})
            except Exception as e:
                return self._send(502, {"error": str(e)})
        if p == "/api/theme":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(json.dumps(_load(THEME, {})).encode())
            return
        if p == "/api/port/check":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            port = int((qs.get("port") or ["0"])[0] or "0")
            st = _load(STATE, {}) or {}
            taken_by = None
            for pr, inb in (st.get("inbounds") or {}).items():
                if inb.get("port") == port and pr != (qs.get("proto") or [""])[0]:
                    taken_by = pr; break
            free = _port_free(port) and taken_by is None
            return self._send(200, {"port": port, "free": free,
                                    "taken_by": taken_by,
                                    "current": (st.get("inbounds") or {}).get((qs.get("proto") or [""])[0], {}).get("port")})
        if p == "/api/xray/info":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            try:
                vp = _xray_versions()
                return self._send(200, {"current": _xray_current_version(),
                                        "versions": vp["versions"], "pre": vp["pre"]})
            except Exception as e:
                return self._send(502, {"error": str(e)})
        if p == "/api/tg/versions":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            try:
                vp = _tg_versions()
                return self._send(200, {"current": _tg_current_version(),
                                        "versions": vp["versions"], "pre": vp["pre"]})
            except Exception as e:
                return self._send(502, {"error": str(e)})
        if p == "/api/versions":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, {"panel": _panel_backups(), "xray": _xray_backups(), "telemt": _tg_backups()})
        if p == "/api/dynv6/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            conf = _dynv6_conf()
            return self._send(200, {"host": conf["host"], "configured": bool(conf["host"] and conf["token"]),
                                    "updated": _DDNS.get("updated"), "error": _DDNS.get("error"),
                                    "response": _DDNS.get("response"), "ipv4": _DDNS.get("ipv4"),
                                    "ipv6": _DDNS.get("ipv6")})
        if p == "/api/cert/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _cert_status())
        if p == "/api/cert/search":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            found = []
            roots = [os.path.join(CERT_DIR, "live"), "/etc/letsencrypt/live"]
            for root in roots:
                if not os.path.isdir(root): continue
                try: doms = sorted(os.listdir(root))
                except Exception: continue
                for dom in doms:
                    if "readme" in dom.lower(): continue
                    cert = os.path.join(root, dom, "fullchain.pem")
                    key = os.path.join(root, dom, "privkey.pem")
                    if os.path.isfile(cert) and os.path.isfile(key):
                        exp = _cert_expire(cert)
                        found.append({
                            "domain": dom,
                            "cert": cert, "key": key,
                            "expire": exp - time.time() if exp else None,
                            "days": int((exp - time.time()) / 86400) if exp else None,
                            "current": (os.path.realpath(cert) == os.path.realpath((CFG_CACHE.get("panel_cert_path") or CFG_CACHE.get("cert") or "").strip())
                                        and os.path.realpath(key) == os.path.realpath((CFG_CACHE.get("panel_key_path") or CFG_CACHE.get("cert_key") or "").strip()))})
            return self._send(200, {"found": found})
        if p == "/api/settings":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            st = _load(STATE, {}) or {}
            sni = ""
            sni_list = []
            ports = []
            for proto, inb in (st.get("inbounds") or {}).items():
                ports.append({"proto": proto, "label": _proto_meta(proto)["label"], "port": inb.get("port")})
                if "sni" in inb:
                    if not sni: sni = inb["sni"]
                    sni_list.append({"proto": proto, "label": _proto_meta(proto)["label"], "sni": inb["sni"]})
            if not sni: sni = "www.samsung.com"
            domain = (CFG_CACHE.get("panel_domain") or "").strip()
            out = {"sni": sni, "sni_list": sni_list, "ports": ports, "domain": domain,
                   "fp": _fp(), "fp_values": sorted(_FP_VALUES),
                   "ipv4": _my_ip(), "ipv6": _my_ipv6(),
                   "a": [], "aaaa": [], "match4": None, "match6": None}
            try:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                d = (qs.get("dns") or [""])[0].strip()
                if d:
                    import socket as _s
                    infos = _s.getaddrinfo(d, None, _s.AF_UNSPEC, _s.SOCK_STREAM)
                    for fi in infos:
                        ip_ = fi[4][0]
                        if ":" in ip_:
                            if ip_ not in out["aaaa"]: out["aaaa"].append(ip_)
                        else:
                            if ip_ not in out["a"]: out["a"].append(ip_)
                    out["match4"] = out["ipv4"] in out["a"] if out["ipv4"] else None
                    out["match6"] = out["ipv6"] in out["aaaa"] if out["ipv6"] else None
            except Exception:
                pass
            return self._send(200, out)
        if p == "/api/network/settings":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, {
                "ru_bypass": bool(CFG_CACHE.get("ru_bypass")),
                "bind": CFG_CACHE.get("panel_bind", ""),
                "cert_path": CFG_CACHE.get("panel_cert_path", ""),
                "key_path": CFG_CACHE.get("panel_key_path", ""),
            })
        if p == "/wallpaper":
            if os.path.exists(WALL):
                t = _load(THEME, {}) or {}
                mime = t.get("wall_mime", "image/jpeg")
                with open(WALL, "rb") as f: data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404); self.end_headers()
            return
        if p == "/logo":
            if os.path.exists(LOGO_FILE):
                t = _load(THEME, {}) or {}
                mime = t.get("logo_mime", "image/png")
                with open(LOGO_FILE, "rb") as f: data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404); self.end_headers()
            return
        if p == "/api/fix/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _fix_status())
        if p == "/api/tg/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _tg_status())
        if p == "/api/webproxy/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _webproxy_status())
        if p == "/api/stats":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _stats())
        if p == "/api/backup":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _backup())
        if p in ("/icon-1024.png", "/icon-512.png", "/icon-192.png", "/icon-veil.png",
                 "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png",
                 "/apple-touch-icon-180x180.png", "/apple-touch-icon-167x167.png",
                 "/apple-touch-icon-152x152.png", "/apple-touch-icon-144x144.png",
                 "/apple-touch-icon-120x120.png", "/apple-touch-icon-87x87.png",
                 "/apple-touch-icon-80x80.png", "/apple-touch-icon-76x76.png",
                 "/apple-touch-icon-58x58.png", "/logo.jpg", "/manifest.json"):
            try:
                with open(os.path.join(BASE, os.path.basename(p)), "rb") as f: data = f.read()
                if p.endswith(".json"):
                    ctype = "application/manifest+json; charset=utf-8"
                elif p.endswith(".jpg"):
                    ctype = "image/jpeg"
                else:
                    ctype = "image/png"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store, no-cache")
                self.end_headers()
                self.wfile.write(data)
                return
            except FileNotFoundError:
                return self._send(404, {"error": "not found"}, "application/json")
        return self._send(404, {"error": "not found"})

    # ---- POST ----
    def do_POST(self):
        try:
            p = urllib.parse.urlparse(self.path).path
            if p == "/api/login":
                b = self._body()
                cip = self.client_address[0]
                if _login_throttle(cip):
                    return self._send(429, {"error": "слишком много попыток. подожди 10 минут"})
                if not (b.get("login") == CFG_CACHE.get("login") and
                        self._is_cur_pw(b.get("password", ""))):
                    _login_fail(cip)
                    return self._send(401, {"error": "неверный логин или пароль"})
                _login_ok(cip)
                t = secrets.token_hex(32)
                rem = bool(b.get("remember"))
                SESSIONS[t] = time.time() + (30 * 86400 if rem else 72 * 3600)
                _save_sessions()
                ma = 2592000 if rem else 259200
                self._cookies = ["sid=" + t + "; Path=/; HttpOnly; Max-Age=" + str(ma) + "; SameSite=Lax"]
                return self._send(200, {"ok": True, "sid": t, "remember": rem})
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            if p == "/api/logout":
                t = _cookie(self)
                if t is None:
                    t = (self.headers.get("X-Sid") or "").strip() or None
                if t:
                    SESSIONS.pop(t, None); _save_sessions()
                self._cookies = ["sid=; Path=/; Max-Age=0"]
                return self._send(200, {"ok": True})

            # ---- vpn setup / новый клиент (старые ссылки никогда не трогаются) ----
            if p == "/api/vpn":
                b = self._body()
                want = b.get("proto") or None
                if want and want not in _VALID_PROTOCOLS:
                    return self._send(400, {"error": "неизвестный протокол"})
                st = _load(STATE)
                if st is None:
                    st = _new_state(want or "reality")
                _migrate_state(st)
                 proto = want or _proto_of(st)
                 inb = (st.get("inbounds") or {}).get(proto)
                 if not inb:
                     inb = _alloc_inbound(st, proto)
                     st.setdefault("inbounds", {})[proto] = inb
                 name = "Основной" if _client_count(st) == 0 else f"Клиент {_client_count(st) + 1}"
                c = _new_client(name, proto, inb)
                inb["clients"].append(c)
                st["active"] = proto
                _write_xray(st); _save(STATE, st)
                _restart_xray()
                host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
                return self._send(200, {"ok": True, "link": _link(inb, host, c, proto),
                                        "port": inb["port"], "proto": proto,
                                        "name": c["name"], "uuid": c["uuid"]})

            # ---- clients ----
            if p == "/api/nodes/add":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                b = self._body()
                name = (b.get("name") or "").strip() or "Нода"
                host = (b.get("host") or "").strip()
                port = int((b.get("port") or 0) or 0)
                token = (b.get("token") or "").strip()
                if not host:
                    return self._send(400, {"error": "укажи адрес ноды"})
                if host in ("0.0.0.0", "::", "localhost"):
                    return self._send(400, {"error": "этот адрес — не внешняя нода"})
                if not (1 <= port <= 65535):
                    return self._send(400, {"error": "порт должен быть от 1 до 65535"})
                nodes = get_nodes()
                for n in nodes:
                    if (n.get("host") or "").strip().lower() == host.lower():
                        return self._send(400, {"error": "такая нода уже добавлена"})
                nodes.append({"name": name, "host": host, "port": port,
                              "token": token, "online": False, "added": int(time.time())})
                save_nodes(nodes)
                return self._send(200, {"ok": True, "nodes": get_nodes()})
            if p == "/api/nodes/delete":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                b = self._body()
                host = (b.get("host") or "").strip()
                nodes = get_nodes()
                out = [n for n in nodes
                       if (n.get("host") or "").strip().lower() != host.lower()]
                if len(out) == len(nodes):
                    return self._send(404, {"error": "нода не найдена"})
                save_nodes(out)
                return self._send(200, {"ok": True, "nodes": get_nodes()})
            if p == "/api/clients/add":
                b = self._body()
                name = (b.get("name") or "").strip() or "Клиент"
                want_proto = (b.get("proto") or "").strip()
                st = _load(STATE)
                if st is None:
                    st = _new_state(want_proto or "reality")
                _migrate_state(st)
                 if want_proto:
                     if want_proto not in _VALID_PROTOCOLS:
                         return self._send(400, {"error": "неизвестный протокол"})
                     proto = want_proto
                 else:
                     proto = _proto_of(st)
                 inb = (st.get("inbounds") or {}).get(proto)
                 if not inb:
                     inb = _alloc_inbound(st, proto)
                     st.setdefault("inbounds", {})[proto] = inb
                 c = _new_client(name, proto, inb,
                          limit_gb=(float(b.get("limit_gb") or 0) or None),
                          expiry=(int(b.get("expiry_days") or 0) or None))
                inb["clients"].append(c)
                _write_xray(st); _save(STATE, st)
                _restart_xray()
                host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
                return self._send(200, {"ok": True, "client": {
                    "uuid": c["uuid"], "name": c["name"],
                    "link": _link(inb, host, c, proto), "proto": proto}})

            if p == "/api/clients/delete":
                b = self._body()
                u = b.get("uuid")
                st = _load(STATE)
                if not st or _client_count(st) == 0:
                    return self._send(400, {"error": "нет клиентов"})
                if _client_count(st) <= 1:
                    return self._send(400, {"error": "нельзя удалить последнего клиента"})
                proto, inb, _ = _find_client(st, u)
                if not inb:
                    return self._send(404, {"error": "клиент не найден"})
                inb["clients"] = [c for c in inb["clients"] if c["uuid"] != u]
                if not inb["clients"]:
                    del st["inbounds"][proto]
                    if st.get("active") == proto:
                        st["active"] = _proto_of(st)
                _write_xray(st); _save(STATE, st)
                _restart_xray()
                return self._send(200, {"ok": True})

            if p == "/api/clients/rename":
                b = self._body()
                u = b.get("uuid"); name = (b.get("name") or "").strip()
                if not name: return self._send(400, {"error": "имя пустое"})
                st = _load(STATE)
                proto, inb, c = _find_client(st, u)
                if not inb: return self._send(404, {"error": "клиент не найден"})
                c["name"] = name
                _save(STATE, st)
                return self._send(200, {"ok": True})

            if p == "/api/favorite":
                b = self._body()
                proto = (b.get("proto") or "").strip()
                if proto not in _VALID_PROTOCOLS:
                    return self._send(400, {"error": "неизвестный протокол"})
                st = _load(STATE) or _new_state()
                fav = set(st.get("favorites", []))
                if proto in fav:
                    fav.remove(proto)
                else:
                    fav.add(proto)
                st["favorites"] = list(fav)
                _save(STATE, st)
                return self._send(200, {"ok": True, "favorites": list(fav)})

            if p == "/api/xray/switch":
                try:
                    b = self._body()
                    return self._send(200, _xray_switch((b.get("version") or "").strip()))
                except urllib.error.HTTPError as e:
                    return self._send(502, {"error": f"скачивание: HTTP {e.code}"})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/tg/switch":
                try:
                    b = self._body()
                    return self._send(200, _tg_switch((b.get("version") or "").strip()))
                except urllib.error.HTTPError as e:
                    return self._send(502, {"error": f"скачивание: HTTP {e.code}"})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/versions/restore":
                try:
                    b = self._body()
                    typ = (b.get("type") or "").strip()
                    ver = (b.get("version") or "").strip()
                    if typ == "panel":
                        return self._send(200, _panel_restore(ver))
                    if typ == "xray":
                        return self._send(200, _xray_restore(ver))
                    if typ == "telemt":
                        return self._send(200, _tg_restore(ver))
                    return self._send(400, {"error": "неизвестный тип"})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/dynv6/save":
                try:
                    b = self._body()
                    host = (b.get("host") or "").strip()
                    token = (b.get("token") or "").strip()
                    if not host or not token:
                        return self._send(400, {"error": "нужны host и token"})
                    if not re.fullmatch(r"(?i)[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", host):
                        return self._send(400, {"error": "некорректный host"})
                    CFG_CACHE["dynv6_host"] = host
                    CFG_CACHE["dynv6_token"] = token
                    _save(CFG, CFG_CACHE)
                    try:
                        return self._send(200, _dynv6_update())
                    except Exception as e:
                        return self._send(200, {"ok": False, "error": str(e), "saved": True})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/dynv6/create-zone":
                try:
                    b2 = self._body()
                    name = (b2.get("name") or "").strip()
                    atok = (b2.get("account_token") or "").strip()
                    return self._send(200, _dynv6_create_zone(name, atok))
                except urllib.error.HTTPError as e:
                    try:
                        err = e.read().decode("utf-8", "replace")[:300]
                    except Exception:
                        err = ""
                    return self._send(502, {"error": f"dynv6 HTTP {e.code}" + ((": " + err) if err else "")})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/dynv6/update":
                try:
                    return self._send(200, _dynv6_update())
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/cert/issue":
                try:
                    b = self._body()
                    return self._send(200, _cert_issue((b or {}).get("email") or CFG_CACHE.get("cert_email")))
                except urllib.error.HTTPError as e:
                    return self._send(502, {"error": f"HTTP {e.code}"})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/cert/config":
                try:
                    b = self._body() or {}
                    email = (b.get("email") or "").strip()
                    if email:
                        CFG_CACHE["cert_email"] = email
                    elif "email" in b:
                        CFG_CACHE.pop("cert_email", None)
                    if "auto" in b:
                        CFG_CACHE["cert_auto"] = bool(b.get("auto"))
                    _save(CFG, CFG_CACHE)
                    return self._send(200, _cert_status())
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/cert/renew":
                try:
                    return self._send(200, _cert_renew_now())
                except urllib.error.HTTPError as e:
                    return self._send(502, {"error": f"HTTP {e.code}"})
                except Exception as e:
                    return self._send(400, {"error": str(e)})

            # ---- security ----
            if p == "/api/security":
                b = self._body()
                if not self._is_cur_pw(b.get("current_password", "")):
                    return self._send(401, {"error": "неверный текущий пароль"})
                changed = False
                nl = (b.get("login") or "").strip()
                np_ = b.get("password") or ""
                if nl and nl != CFG_CACHE.get("login"):
                    CFG_CACHE["login"] = nl; changed = True
                if np_:
                    if len(np_) < 8:
                        return self._send(400, {"error": "пароль короче 8 символов"})
                    CFG_CACHE["salt"] = secrets.token_hex(16)
                    CFG_CACHE["pass_hash"] = _hash(CFG_CACHE["salt"], np_)
                    changed = True
                if not changed: return self._send(400, {"error": "нечего менять"})
                _save(CFG, CFG_CACHE)
                SESSIONS.clear(); _save_sessions()
                self._cookies = ["sid=; Path=/; Max-Age=0"]
                return self._send(200, {"ok": True, "relogin": True})

            if p == "/api/panel/port":
                b = self._body()
                port = b.get("port")
                try: port = int(port)
                except (TypeError, ValueError):
                    return self._send(400, {"error": "Порт: 1-65535"})
                if not (0 < port < 65536):
                    return self._send(400, {"error": "Порт: 1-65535"})
                cur = CFG_CACHE.get("panel_port", 8443)
                if port == int(cur):
                    return self._send(200, {"ok": True, "port": cur, "restarting": False})
                if port in _RESERVED_PORTS:
                    return self._send(400, {"error": f"Порт {port} зарезервирован под nginx/webproxy/telemt"})
                if not _port_free(port):
                    return self._send(400, {"error": f"Порт {port} занят"})
                CFG_CACHE["panel_port"] = port
                _save(CFG, CFG_CACHE)
                subprocess.Popen(["bash", "-c", "sleep 1 && systemctl restart vpnpanel"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
                return self._send(200, {"ok": True, "port": port, "restarting": True})

            # ---- update ----
            if p == "/api/settings":
                n = int(self.headers.get("Content-Length", "0") or 0)
                raw = b""; rem = n
                while rem > 0:
                    ch = self.rfile.read(min(rem, 65536))
                    if not ch: break
                    raw += ch; rem -= len(ch)
                try: body = json.loads(raw.decode("utf-8", "replace") or "{}")
                except Exception: body = {}
                sni = (body.get("sni") or "").strip()
                proto = (body.get("proto") or "").strip()
                domain = (body.get("domain") or "").strip()
                port = body.get("port")
                if port is not None:
                    try: port = int(port)
                    except (TypeError, ValueError):
                        port = None
                if sni and not re.fullmatch(r"[A-Za-z0-9.-]+", sni):
                    return self._send(400, {"error": "SNI: только буквы/цифры/точки/дефисы"})
                if sni and body.get("proto"):
                    _sni_check = _sni_ok(sni)
                    if _sni_check is not True:
                        return self._send(400, {"error": _sni_check})
                if domain and (domain.startswith("http") or "/" in domain or " " in domain):
                    return self._send(400, {"error": "Домен: только имя хоста (без http:// и пути)"})
                if port is not None and not (0 < port < 65536):
                    return self._send(400, {"error": "Порт: 1-65535"})
                st = _load(STATE, {}) or {}
                changed = False
                inb = None
                if sni:
                    if proto:
                        inb = (st.get("inbounds") or {}).get(proto)
                        if not inb or "sni" not in inb:
                            return self._send(400, {"error": "Такой протокол не настроен или не использует SNI"})
                        inb["sni"] = sni
                        if inb.get("dest"): inb["dest"] = sni + ":443"
                        changed = True
                    else:
                        for inb in (st.get("inbounds") or {}).values():
                            if "sni" in inb:
                                inb["sni"] = sni
                                if inb.get("dest"): inb["dest"] = sni + ":443"
                        changed = True
                if port is not None:
                    if not proto:
                        return self._send(400, {"error": "Укажи proto для смены порта"})
                    inb = (st.get("inbounds") or {}).get(proto)
                    if not inb:
                        return self._send(400, {"error": "Такой протокол не настроен"})
                    if inb.get("port") == port:
                        pass
                    else:
                        if not _port_free(port):
                            return self._send(400, {"error": f"Порт {port} занят"})
                        for pr, ib2 in (st.get("inbounds") or {}).items():
                            if pr != proto and ib2.get("port") == port:
                                return self._send(400, {"error": f"Порт {port} уже используется протоколом {pr}"})
                        inb["port"] = port
                        changed = True
                if changed:
                    _save(STATE, st)
                    try: _write_xray(st)
                    except Exception as e: return self._send(500, {"error": f"xray: {e}"})
                    try: _restart_xray()
                    except Exception as e: return self._send(500, {"error": f"рестарт: {e}"})
                if "domain" in body:
                    if domain:
                        CFG_CACHE["panel_domain"] = domain
                    else:
                        CFG_CACHE.pop("panel_domain", None)
                    _save(CFG, CFG_CACHE)
                if "fp" in body:
                    fp = (str(body["fp"] or "")).strip().lower()
                    if fp:
                        if fp not in _FP_VALUES:
                            return self._send(400, {"error": "Неизвестный отпечаток: " + fp})
                        CFG_CACHE["fp"] = fp
                    else:
                        CFG_CACHE.pop("fp", None)
                    _save(CFG, CFG_CACHE)
                out = {"ok": True, "sni": sni or "", "proto": proto or "", "domain": domain,
                       "fp": _fp(),
                       "port": (inb.get("port") if inb else None) if port is not None else None}
                if changed: out["restarted"] = True
                return self._send(200, out)
            if p == "/api/theme":
                n = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(n) if n else b""
                try: body = json.loads(raw.decode() or "{}")
                except Exception: body = {}
                t = _load(THEME, {}) or {}
                for k in ("bg","bg2","card","card2","fg","mut","br","acc","acc2","font","layout"):
                    if k in body: t[k] = body[k]
                _save(THEME, t)
                self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
                self.wfile.write(b'{"ok":true}'); return
            if p == "/api/wallpaper":
                n = int(self.headers.get("Content-Length", "0") or 0)
                data = b""; rem = n
                while rem > 0:
                    ch = self.rfile.read(min(rem, 65536))
                    if not ch: break
                    data += ch; rem -= len(ch)
                try: body = json.loads(data.decode() or "{}")
                except Exception: body = {}
                b64 = body.get("data","")
                mime = body.get("mime","image/jpeg")
                if mime not in ("image/jpeg","image/png","image/webp","image/gif"):
                    mime = "image/jpeg"
                import base64 as _b64
                try: blob = _b64.b64decode(b64)
                except Exception: blob = b""
                if not blob:
                    self.send_response(400); self.send_header("Content-Type","application/json"); self.end_headers()
                    self.wfile.write(b'{"error":"empty"}'); return
                with open(WALL, "wb") as f: f.write(blob)
                t = _load(THEME, {}) or {}; t["wall_mime"] = mime; _save(THEME, t)
                self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
                self.wfile.write(b'{"ok":true}'); return
            if p == "/api/wallpaper/delete":
                try: os.remove(WALL)
                except FileNotFoundError: pass
                t = _load(THEME, {}) or {}; t.pop("wall_mime", None); _save(THEME, t)
                self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
                self.wfile.write(b'{"ok":true}'); return
            if p == "/api/logo":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                n = int(self.headers.get("Content-Length", "0") or 0)
                data = b""; rem = n
                while rem > 0:
                    ch = self.rfile.read(min(rem, 65536))
                    if not ch: break
                    data += ch; rem -= len(ch)
                try: body = json.loads(data.decode() or "{}")
                except Exception: body = {}
                b64 = body.get("data","")
                mime = body.get("mime","image/png")
                if mime not in ("image/png","image/jpeg","image/webp","image/gif"):
                    mime = "image/png"
                import base64 as _b64
                try: blob = _b64.b64decode(b64)
                except Exception: blob = b""
                if not blob:
                    self.send_response(400); self.send_header("Content-Type","application/json"); self.end_headers()
                    self.wfile.write(b'{"error":"empty"}'); return
                with open(LOGO_FILE, "wb") as f: f.write(blob)
                t = _load(THEME, {}) or {}; t["logo_mime"] = mime; _save(THEME, t)
                self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
                self.wfile.write(b'{"ok":true}'); return
            if p == "/api/logo/delete":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                try: os.remove(LOGO_FILE)
                except FileNotFoundError: pass
                t = _load(THEME, {}) or {}; t.pop("logo_mime", None); _save(THEME, t)
                self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
                self.wfile.write(b'{"ok":true}'); return
            if p == "/api/network/settings":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                n = int(self.headers.get("Content-Length", "0") or 0)
                data = b""; rem = n
                while rem > 0:
                    ch = self.rfile.read(min(rem, 65536))
                    if not ch: break
                    data += ch; rem -= len(ch)
                try: body = json.loads(data.decode() or "{}")
                except Exception: body = {}
                xray_changed = False
                panel_changed = False
                if "ru_bypass" in body:
                    CFG_CACHE["ru_bypass"] = bool(body["ru_bypass"])
                    xray_changed = True
                if "bind" in body:
                    bind = (body["bind"] or "").strip()
                    if bind:
                        CFG_CACHE["panel_bind"] = bind
                    else:
                        CFG_CACHE.pop("panel_bind", None)
                    panel_changed = True
                if "cert_path" in body:
                    cert_path = (body["cert_path"] or "").strip()
                    if cert_path:
                        CFG_CACHE["panel_cert_path"] = cert_path
                    else:
                        CFG_CACHE.pop("panel_cert_path", None)
                    panel_changed = True
                if "key_path" in body:
                    key_path = (body["key_path"] or "").strip()
                    if key_path:
                        CFG_CACHE["panel_key_path"] = key_path
                    else:
                        CFG_CACHE.pop("panel_key_path", None)
                    panel_changed = True
                if xray_changed or panel_changed:
                    _save(CFG, CFG_CACHE)
                if xray_changed and not panel_changed:
                    try:
                        st = _load(STATE)
                        _write_xray(st)
                        _restart_xray()
                        return self._send(200, {"ok": True, "restarting": False, "xray_restarted": True})
                    except Exception as e:
                        return self._send(500, {"error": "Xray: " + str(e)})
                if panel_changed:
                    subprocess.Popen(["bash", "-c", "sleep 1 && systemctl restart vpnpanel"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     start_new_session=True)
                return self._send(200, {"ok": True, "restarting": panel_changed})
            if p == "/api/xray/start":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                try:
                    _start_xray()
                    return self._send(200, {"ok": True})
                except Exception as e:
                    return self._send(500, {"error": str(e)})
            if p == "/api/xray/stop":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                try:
                    _stop_xray()
                    return self._send(200, {"ok": True})
                except Exception as e:
                    return self._send(500, {"error": str(e)})
            if p == "/api/xray/restart":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                try:
                    _restart_xray()
                    return self._send(200, {"ok": True})
                except Exception as e:
                    return self._send(500, {"error": str(e)})
            if p == "/api/update/install":
                try:
                    return self._send(200, _install_update())
                except urllib.error.HTTPError as e:
                    return self._send(502, {"error": f"GitHub API: HTTP {e.code}"})
                except Exception as e:
                    return self._send(500, {"error": str(e)})
            # ---- veil-zapret2 fix ----
            if p == "/api/fix/enable":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                try:
                    return self._send(200, _fix_enable())
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/fix/disable":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                try:
                    return self._send(200, _fix_disable())
                except Exception as e:
                    return self._send(400, {"error": str(e)})

            # ---- telegram proxy ----
            if p == "/api/tg/user/add":
                b = self._body()
                try:
                    res = _tg_add(b.get("name", ""))
                    return self._send(200, {"ok": True, "user": res})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/tg/user/remove":
                b = self._body()
                try:
                    _tg_remove(b.get("username", ""))
                    return self._send(200, {"ok": True})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/tg/web/set":
                b = self._body()
                try:
                    return self._send(200, {"ok": True, "web": _tg_web_set(
                        b.get("carrier"), b.get("enabled"))})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/webproxy/install":
                try:
                    return self._send(200, _webproxy_install())
                except Exception as e:
                    return self._send(400, {"error": str(e)})

            if p == "/api/backup":
                try:
                    return self._send(200, _restore(self._body()))
                except Exception as e:
                    return self._send(400, {"error": str(e)})

            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(500, {"error": str(e)})

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def get_request(self):
        sock, addr = super().get_request()
        if _WEB_CTX is not None:
            sock.settimeout(5)
            try:
                first = sock.recv(1, socket.MSG_PEEK)
            except Exception:
                try: sock.close()
                except Exception: pass
                raise
            if first == b"\x16":
                try:
                    sock = _WEB_CTX.wrap_socket(sock, server_side=True)
                except Exception:
                    try: sock.close()
                    except Exception: pass
                    raise
            else:
                # plain-HTTP запрос на HTTPS-порт → 301 на https
                host = (CFG_CACHE.get("panel_domain") or "127.0.0.1").strip()
                port = CFG_CACHE.get("panel_port", 8443)
                try:
                    sock.sendall(("HTTP/1.1 301 Moved Permanently\r\n"
                                  "Location: https://%s:%d/\r\n"
                                  "Content-Length: 0\r\n"
                                  "Connection: close\r\n\r\n" % (host, int(port))).encode())
                except Exception: pass
                try: sock.close()
                except Exception: pass
                raise ConnectionRefusedError("plain http -> https")
        return sock, addr

if __name__ == "__main__":
    port = CFG_CACHE.get("panel_port", 8443)
    bind = (CFG_CACHE.get("panel_bind") or "0.0.0.0").strip()
    print("Veil " + VERSION + " слушает " + bind + ":" + str(port), flush=True)
    _load_sessions()
    try:
        st = _load(STATE)
        xc = _load(XRAY)
        chg = _ensure_wg_psk(st) or _ensure_wg_std(st)
        chg = _ensure_xray_keys_urlsafe(st) or chg
        if chg:
            _save(STATE, st)
        need_rewrite = _client_count(st) > 0 and (not xc or "api" not in (xc.get("api") or {}) or not any(
                (ib or {}).get("tag") == "api" for ib in (xc.get("inbounds") or [])))
        has_wg = any(("public_key" in ib) for ib in (st or {}).get("inbounds", {}).values()) if st else False
        if (st and _client_count(st) > 0 and (need_rewrite or has_wg)):
            _write_xray(st)
            new_xc = _load(XRAY)
            if json.dumps(new_xc, sort_keys=True) != json.dumps(xc, sort_keys=True):
                print("migrate: обновил конфиг Xray, перезапускаю", flush=True)
                _restart_xray()
    except Exception as e:
        print("migrate error: " + str(e), flush=True)
    _web_tls_ctx()
    with S((bind, port), H) as srv:
        srv.serve_forever()
