#!/usr/bin/env python3
import base64, json, os, subprocess, secrets, hashlib, uuid as uuidlib, re, time
import socketserver, http.server
import urllib.parse, urllib.request, urllib.error
import shutil, tarfile, tempfile, datetime

BASE = "/opt/vpnpanel"
CFG = f"{BASE}/config.json"
STATE = f"{BASE}/state.json"
THEME = f"{BASE}/theme.json"
WALL = f"{BASE}/wallpaper.bin"
HTML = f"{BASE}/index.html"
XRAY = "/usr/local/etc/xray/config.json"
TOKEN_FILE = f"{BASE}/github.token"
TELEMT_API = "http://127.0.0.1:9091"
REPO = "GurovNA/Veil"
VERSION = "1.4.1"
PROTOCOLS = [
    {"id": "reality",        "label": "VLESS + Reality",                        "net": "tcp",  "tls": False},
    {"id": "vmess-ws",       "label": "VMess + WebSocket",                      "net": "ws",   "tls": False},
    {"id": "vless-ws",       "label": "VLESS + WebSocket",                      "net": "ws",   "tls": False},
    {"id": "trojan-ws",      "label": "Trojan + WebSocket",                     "net": "ws",   "tls": False},
    {"id": "vless-ws-tls",   "label": "VLESS + WebSocket + TLS (self-signed)",  "net": "ws",   "tls": True},
    {"id": "vmess-ws-tls",   "label": "VMess + WebSocket + TLS (self-signed)",  "net": "ws",   "tls": True},
    {"id": "trojan-ws-tls",  "label": "Trojan + WebSocket + TLS (self-signed)", "net": "ws",   "tls": True},
    {"id": "vless-tcp-tls",  "label": "VLESS + TCP + TLS (self-signed)",        "net": "tcp",  "tls": True},
    {"id": "vmess-tcp-tls",  "label": "VMess + TCP + TLS (self-signed)",        "net": "tcp",  "tls": True},
    {"id": "trojan-tcp-tls", "label": "Trojan + TCP + TLS (self-signed)",       "net": "tcp",  "tls": True},
    {"id": "vless-grpc-tls", "label": "VLESS + gRPC + TLS (self-signed)",       "net": "grpc", "tls": True},
    {"id": "vmess-grpc-tls", "label": "VMess + gRPC + TLS (self-signed)",       "net": "grpc", "tls": True},
    {"id": "trojan-grpc-tls", "label": "Trojan + gRPC + TLS (self-signed)",     "net": "grpc", "tls": True},
    {"id": "shadowsocks",    "label": "Shadowsocks AEAD (aes-256-gcm)",         "net": "tcp",  "tls": False},
]
_VALID_PROTOCOLS = tuple(p["id"] for p in PROTOCOLS)
_PROTO_MAP = {p["id"]: p for p in PROTOCOLS}
_PORTS = {"reality": 443, "vmess-ws": 10443, "vless-ws": 11443,
          "trojan-ws": 12443, "vless-ws-tls": 13443, "vmess-ws-tls": 14443,
          "trojan-ws-tls": 15443, "vless-tcp-tls": 16443, "vmess-tcp-tls": 17443,
          "trojan-tcp-tls": 18443, "vless-grpc-tls": 19443, "vmess-grpc-tls": 20443,
          "trojan-grpc-tls": 21443, "shadowsocks": 22443}
CERT_DIR = f"{BASE}/certs"

def _proto_meta(proto):
    return _PROTO_MAP.get(proto, _PROTO_MAP["reality"])

SESSIONS = {}

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
    if priv and pub: return priv, pub
    raise RuntimeError("не разобрал xray x25519: " + out)

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
    if isinstance(st.get("inbounds"), dict):
        for k in ("clients", "uuid", "proto", "port", "private_key",
                  "public_key", "sid", "sni", "dest", "password"):
            st.pop(k, None)
        return False
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
    return {"active": proto, "inbounds": {}}

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
    if proto == "reality":
        priv, pub = _gen_keys()
        inb.update({"private_key": priv, "public_key": pub,
                    "sid": secrets.token_hex(4), "sni": "www.samsung.com",
                    "dest": "www.samsung.com:443"})
    if proto == "shadowsocks":
        inb["password"] = secrets.token_urlsafe(12)
    if _proto_meta(proto)["tls"]:
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

def _stream_settings(proto, inb):
    meta = _proto_meta(proto)
    if proto == "reality":
        return {"network": "tcp", "security": "reality", "realitySettings": {
            "show": False, "dest": inb["dest"], "xver": 0,
            "serverNames": [inb["sni"]], "privateKey": inb["private_key"],
            "shortIds": [inb["sid"]]}}
    ss = {"network": meta["net"],
          "security": "tls" if meta["tls"] else "none"}
    if meta["net"] == "ws":
        ss["wsSettings"] = {"path": "/veil", "headers": {}}
    elif meta["net"] == "grpc":
        ss["grpcSettings"] = {"serviceName": "veil"}
    if meta["tls"]:
        ss["tlsSettings"] = {
            "alpn": ["h2", "http/1.1"] if meta["net"] == "grpc" else ["http/1.1"],
            "certificates": [{"certificateFile": inb.get("cert"), "keyFile": inb.get("key")}]}
    return ss

def _inbound(proto, inb):
    meta = _proto_meta(proto)
    ib = {"listen": "0.0.0.0", "port": inb["port"],
          "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}}
    if proto == "shadowsocks":
        ib["protocol"] = "shadowsocks"
        ib["settings"] = {"method": "aes-256-gcm",
                          "password": inb.get("password") or "", "network": "tcp,udp"}
        return ib
    if proto.startswith("trojan"):
        ib["protocol"] = "trojan"
        ib["settings"] = {"clients": [
            {"password": c.get("password") or inb.get("password"), "flow": ""}
            for c in inb["clients"]], "decryption": "none"}
    elif proto.startswith("vmess"):
        ib["protocol"] = "vmess"
        ib["settings"] = {"clients": [
            {"id": c["uuid"], "alterId": 0} for c in inb["clients"]]}
    else:
        ib["protocol"] = "vless"
        flow = "xtls-rprx-vision" if proto == "reality" else ""
        ib["settings"] = {"clients": [
            {"id": c["uuid"], "flow": flow} for c in inb["clients"]],
            "decryption": "none"}
    ib["streamSettings"] = _stream_settings(proto, inb)
    return ib

def _write_xray(st):
    inbounds = []
    for proto, inb in (st.get("inbounds") or {}).items():
        if inb.get("clients"):
            inbounds.append(_inbound(proto, inb))
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom"}]
    }
    _save(XRAY, cfg, 0o644)

def _restart_xray():
    t = subprocess.run(["xray", "run", "-test", "-config", XRAY],
                       capture_output=True, text=True)
    if t.returncode:
        raise RuntimeError("конфиг Xray невалиден: " + (t.stderr or t.stdout))
    subprocess.run(["systemctl", "restart", "xray"], check=True, capture_output=True)

def _link(inb, host, client, proto):
    meta = _proto_meta(proto)
    name = client.get("name") or "Veil"
    if proto == "shadowsocks":
        cred = "aes-256-gcm:" + (inb.get("password") or "")
        raw = base64.urlsafe_b64encode(cred.encode()).decode().rstrip("=")
        return f"ss://{raw}@{host}:{inb['port']}#{urllib.parse.quote(name)}"
    if proto.startswith("vmess"):
        p = {"v": "2", "ps": name, "add": host, "port": inb["port"],
             "id": client["uuid"], "aid": "0", "scy": "auto",
             "net": meta["net"], "type": "none", "host": "",
             "path": "/veil" if meta["net"] == "ws" else "veil",
             "tls": "tls" if meta["tls"] else ""}
        if meta["tls"]:
            p["sni"] = host; p["allowInsecure"] = True; p["fp"] = "chrome"
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
    if proto == "reality":
        qparts.update({"security": "reality", "pbk": inb["public_key"],
                       "fp": "chrome", "sni": inb["sni"], "sid": inb["sid"],
                       "spx": "/", "flow": "xtls-rprx-vision"})
    elif meta["tls"]:
        qparts.update({"security": "tls", "sni": host, "fp": "chrome",
                       "allowInsecure": "1"})
    else:
        qparts["security"] = "none"
    q = urllib.parse.urlencode(qparts)
    return f"{scheme}{host}:{inb['port']}?{q}#{urllib.parse.quote(name)}"

def _new_client(name, proto=None):
    c = {"uuid": str(uuidlib.uuid4()),
         "name": (name or "").strip() or "Клиент",
         "created": int(time.time())}
    if proto and proto.startswith("trojan"):
        c["password"] = secrets.token_urlsafe(12)
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
    e = SESSIONS.get(t) if t else None
    return bool(e and e > time.time())


# ---------- telemt / telegram proxy ----------

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
            "connections": u.get("current_connections", 0),
            "total_octets": u.get("total_octets", 0),
        })
    return {"installed": True, "users": users}

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
    return {"username": name, "secret": secret, "link": link}

def _tg_remove(username):
    if not username:
        raise RuntimeError("имя пустое")
    _tg_api("DELETE", "/v1/users/" + urllib.parse.quote(username))
    return {"ok": True}

def _find_free_port(pref=None, avoid=()):
    import socket
    avoid = set(avoid or ())
    if pref is None:
        prefs = (7443, 2443, 8843, 6443, 9443)
    elif isinstance(pref, int):
        prefs = (pref,)
    else:
        prefs = tuple(pref) or (7443, 2443, 8843, 6443, 9443)
    for port in prefs:
        if port in avoid: continue
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
        if port not in avoid:
            return port
    raise RuntimeError("нет свободного порта")


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

def _stats():
    xc = _load(XRAY) or {}
    clients_count = 0
    for ib in (xc.get("inbounds") or []):
        clients_count += len((ib.get("settings") or {}).get("clients") or [])

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
        if p in ("/", "/index.html"):
            with open(HTML, "rb") as f: return self._send(200, f.read(), "text/html; charset=utf-8")
        if p == "/api/state":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            st = _load(STATE)
            running = subprocess.run(["systemctl", "is-active", "--quiet", "xray"]).returncode == 0
            out = {"version": VERSION, "running": running, "login": CFG_CACHE.get("login", ""),
                   "configured": _client_count(st) > 0,
                   "proto": _proto_of(st)}
            return self._send(200, out)
        if p == "/api/vpn/protocols":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            st = _load(STATE) or {}
            return self._send(200, {"current": _proto_of(st),
                                    "configured": bool(st and st.get("clients")),
                                    "protocols": PROTOCOLS})
        if p == "/api/clients":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            st = _load(STATE)
            if not st: return self._send(200, {"clients": [], "configured": False})
            if _migrate_state(st): _save(STATE, st)
            host = self.headers.get("Host", "").split(":")[0]
            out = []
            for proto, inb in (st.get("inbounds") or {}).items():
                for c in inb.get("clients", []):
                    out.append({"uuid": c["uuid"], "name": c["name"],
                                "link": _link(inb, host, c, proto),
                                "proto": proto, "port": inb["port"],
                                "proto_label": _proto_meta(proto)["label"],
                                "created": c.get("created", 0)})
            return self._send(200, {"clients": out,
                                    "configured": bool(out),
                                    "active": _proto_of(st)})
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
        if p == "/api/fix/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _fix_status())
        if p == "/api/tg/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _tg_status())
        if p == "/api/stats":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _stats())
        return self._send(404, {"error": "not found"})

    # ---- POST ----
    def do_POST(self):
        try:
            p = urllib.parse.urlparse(self.path).path
            if p == "/api/login":
                b = self._body()
                if not (b.get("login") == CFG_CACHE.get("login") and
                        self._is_cur_pw(b.get("password", ""))):
                    return self._send(401, {"error": "неверный логин или пароль"})
                t = secrets.token_hex(32); SESSIONS[t] = time.time() + 72 * 3600
                self._cookies = ["sid=" + t + "; Path=/; HttpOnly; Max-Age=259200; SameSite=Lax"]
                return self._send(200, {"ok": True})
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            if p == "/api/logout":
                t = _cookie(self)
                if t: SESSIONS.pop(t, None)
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
                inb = _alloc_inbound(st, proto)
                st["inbounds"][proto] = inb
                name = "Основной" if _client_count(st) == 0 else f"Клиент {_client_count(st) + 1}"
                c = _new_client(name, proto)
                inb["clients"].append(c)
                st["active"] = proto
                _write_xray(st); _save(STATE, st)
                _restart_xray()
                host = self.headers.get("Host", "").split(":")[0]
                return self._send(200, {"ok": True, "link": _link(inb, host, c, proto),
                                        "port": inb["port"], "proto": proto,
                                        "name": c["name"], "uuid": c["uuid"]})

            # ---- clients ----
            if p == "/api/clients/add":
                b = self._body()
                name = (b.get("name") or "").strip() or "Клиент"
                st = _load(STATE)
                if st is None:
                    st = _new_state("reality")
                _migrate_state(st)
                proto = _proto_of(st)
                inb = _alloc_inbound(st, proto)
                st["inbounds"][proto] = inb
                c = _new_client(name, proto)
                inb["clients"].append(c)
                _write_xray(st); _save(STATE, st)
                _restart_xray()
                host = self.headers.get("Host", "").split(":")[0]
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
                SESSIONS.clear()
                self._cookies = ["sid=; Path=/; Max-Age=0"]
                return self._send(200, {"ok": True, "relogin": True})

            # ---- update ----
            if p == "/api/theme":
                n = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(n) if n else b""
                try: body = json.loads(raw.decode() or "{}")
                except Exception: body = {}
                t = _load(THEME, {}) or {}
                for k in ("bg","card","fg","mut","acc","font"):
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


            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(500, {"error": str(e)})

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    port = CFG_CACHE.get("panel_port", 8443)
    print("Veil " + VERSION + " слушает :" + str(port), flush=True)
    with S(("0.0.0.0", port), H) as srv:
        srv.serve_forever()
