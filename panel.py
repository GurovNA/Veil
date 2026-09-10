#!/usr/bin/env python3
import json, os, subprocess, secrets, hashlib, uuid as uuidlib, re, time
import socketserver, http.server
import urllib.parse, urllib.request, urllib.error
import shutil, tarfile, tempfile, datetime

BASE = "/opt/vpnpanel"
CFG = f"{BASE}/config.json"
STATE = f"{BASE}/state.json"
HTML = f"{BASE}/index.html"
XRAY = "/usr/local/etc/xray/config.json"
TOKEN_FILE = f"{BASE}/github.token"
TELEMT_API = "http://127.0.0.1:9091"
REPO = "GurovNA/Veil"
VERSION = "0.6.0"
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

def _migrate_state(st):
    if st is None: return False
    if "clients" in st: return False
    old = st.pop("uuid", None)
    st["clients"] = []
    if old:
        st["clients"].append({"uuid": old, "name": "Основной", "created": 0})
    return True

def _write_xray(st):
    clients = [{"id": c["uuid"], "flow": "xtls-rprx-vision"} for c in st.get("clients", [])]
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "0.0.0.0", "port": st["port"], "protocol": "vless",
            "settings": {"clients": clients, "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "show": False, "dest": st["dest"], "xver": 0,
                "serverNames": [st["sni"]], "privateKey": st["private_key"],
                "shortIds": [st["sid"]]}},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}
        }],
        "outbounds": [{"protocol": "freedom"}]
    }
    _save(XRAY, cfg, 0o644)

def _restart_xray():
    t = subprocess.run(["xray", "run", "-test", "-config", XRAY],
                       capture_output=True, text=True)
    if t.returncode:
        raise RuntimeError("конфиг Xray невалиден: " + (t.stderr or t.stdout))
    subprocess.run(["systemctl", "restart", "xray"], check=True, capture_output=True)

def _link(st, host, client):
    q = urllib.parse.urlencode({
        "type": "tcp", "security": "reality", "pbk": st["public_key"],
        "fp": "firefox", "sni": st["sni"], "sid": st["sid"],
        "spx": "/", "flow": "xtls-rprx-vision"})
    name = urllib.parse.quote(client.get("name") or "Veil")
    return f"vless://{client['uuid']}@{host}:{st['port']}?{q}#{name}"

def _new_client(name):
    return {"uuid": str(uuidlib.uuid4()),
            "name": (name or "").strip() or "Клиент",
            "created": int(time.time())}

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

def _find_free_port(candidates=(7443, 2443, 8843, 6443, 9443)):
    import socket
    for port in candidates:
        s = socket.socket()
        try:
            s.bind(("", port)); s.close(); return port
        except OSError:
            s.close()
    s = socket.socket(); s.bind(("", 0)); port = s.getsockname()[1]; s.close()
    return port

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
                   "configured": bool(st and st.get("clients"))}
            if st: out["port"] = st["port"]
            return self._send(200, out)
        if p == "/api/clients":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            st = _load(STATE)
            if not st: return self._send(200, {"clients": [], "configured": False})
            if _migrate_state(st): _save(STATE, st)
            host = self.headers.get("Host", "").split(":")[0]
            out = [{"uuid": c["uuid"], "name": c["name"],
                    "link": _link(st, host, c),
                    "created": c.get("created", 0)} for c in st.get("clients", [])]
            return self._send(200, {"clients": out, "port": st["port"],
                                    "configured": bool(out)})
        if p == "/api/update":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            try:
                return self._send(200, _check_update())
            except urllib.error.HTTPError as e:
                return self._send(502, {"error": f"GitHub API: HTTP {e.code}"})
            except Exception as e:
                return self._send(502, {"error": str(e)})
        if p == "/api/tg/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _tg_status())
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

            # ---- vpn init ----
            if p == "/api/vpn":
                st = _load(STATE)
                if st is None:
                    port = _free_port(443); priv, pub = _gen_keys()
                    st = {"port": port, "private_key": priv, "public_key": pub,
                          "sid": secrets.token_hex(4),
                          "sni": "www.samsung.com", "dest": "www.samsung.com:443",
                          "clients": []}
                _migrate_state(st)
                if not st["clients"]:
                    st["clients"].append(_new_client("Основной"))
                _write_xray(st); _save(STATE, st)
                _restart_xray()
                host = self.headers.get("Host", "").split(":")[0]
                first = st["clients"][0]
                return self._send(200, {"ok": True, "link": _link(st, host, first),
                                        "port": st["port"]})

            # ---- clients ----
            if p == "/api/clients/add":
                b = self._body()
                name = (b.get("name") or "").strip() or "Клиент"
                st = _load(STATE)
                if st is None:
                    port = _free_port(443); priv, pub = _gen_keys()
                    st = {"port": port, "private_key": priv, "public_key": pub,
                          "sid": secrets.token_hex(4),
                          "sni": "www.samsung.com", "dest": "www.samsung.com:443",
                          "clients": []}
                _migrate_state(st)
                c = _new_client(name)
                st["clients"].append(c)
                _write_xray(st); _save(STATE, st)
                _restart_xray()
                host = self.headers.get("Host", "").split(":")[0]
                return self._send(200, {"ok": True, "client": {
                    "uuid": c["uuid"], "name": c["name"], "link": _link(st, host, c)}})

            if p == "/api/clients/delete":
                b = self._body()
                u = b.get("uuid")
                st = _load(STATE)
                if not st or not st.get("clients"):
                    return self._send(400, {"error": "нет клиентов"})
                nlist = [c for c in st["clients"] if c["uuid"] != u]
                if len(nlist) == len(st["clients"]):
                    return self._send(404, {"error": "клиент не найден"})
                if not nlist:
                    return self._send(400, {"error": "нельзя удалить последнего клиента"})
                st["clients"] = nlist
                _write_xray(st); _save(STATE, st)
                _restart_xray()
                return self._send(200, {"ok": True})

            if p == "/api/clients/rename":
                b = self._body()
                u = b.get("uuid"); name = (b.get("name") or "").strip()
                if not name: return self._send(400, {"error": "имя пустое"})
                st = _load(STATE)
                found = False
                for c in st.get("clients", []):
                    if c["uuid"] == u: c["name"] = name; found = True
                if not found: return self._send(404, {"error": "клиент не найден"})
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
            if p == "/api/update/install":
                try:
                    return self._send(200, _install_update())
                except urllib.error.HTTPError as e:
                    return self._send(502, {"error": f"GitHub API: HTTP {e.code}"})
                except Exception as e:
                    return self._send(500, {"error": str(e)})
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
