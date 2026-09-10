#!/usr/bin/env python3
import json, os, subprocess, secrets, hashlib, uuid, re, time, socketserver, http.server
import urllib.parse, urllib.request

BASE="/opt/vpnpanel"; CFG=f"{BASE}/config.json"; STATE=f"{BASE}/state.json"
HTML=f"{BASE}/index.html"; XRAY="/usr/local/etc/xray/config.json"
VERSION="0.3.0"; SESSIONS={}

def _load(p, d=None):
    try:
        with open(p) as f: return json.load(f)
    except Exception: return d

def _save(p, o, mode=0o600):
    with open(p,"w") as f: json.dump(o, f, indent=2, ensure_ascii=False)
    os.chmod(p, mode)

def _hash(salt, pw):
    return hashlib.sha256((salt+pw).encode()).hexdigest()

def _free_port(pref=443):
    import socket
    def ok(p):
        s=socket.socket()
        try: s.bind(("",p)); s.close(); return True
        except OSError: s.close(); return False
    if pref and ok(pref): return pref
    s=socket.socket(); s.bind(("",0)); p=s.getsockname()[1]; s.close(); return p

def _last_line(out, *keys):
    for line in out.splitlines():
        low=line.lower()
        if any(k in low for k in keys):
            return re.split(r"[:=\s]+", line.strip())[-1]
    return None

def _gen_keys():
    out = subprocess.run(["xray","x25519"], capture_output=True, text=True).stdout
    priv = _last_line(out, "private")
    pub  = _last_line(out, "public", "password")
    if priv and pub: return priv, pub
    raise RuntimeError("не разобрал xray x25519: "+out)

def _write_xray(st):
    cfg = {
      "log":{"loglevel":"warning"},
      "inbounds":[{
        "listen":"0.0.0.0","port":st["port"],"protocol":"vless",
        "settings":{"clients":[{"id":st["uuid"],"flow":"xtls-rprx-vision"}],"decryption":"none"},
        "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
            "show":False,"dest":st["dest"],"xver":0,
            "serverNames":[st["sni"]],"privateKey":st["private_key"],"shortIds":[st["sid"]]}},
        "sniffing":{"enabled":True,"destOverride":["http","tls","quic"]}
      }],
      "outbounds":[{"protocol":"freedom"}]
    }
    _save(XRAY, cfg, 0o644)

def _restart_xray():
    t = subprocess.run(["xray","run","-test","-config",XRAY], capture_output=True, text=True)
    if t.returncode:
        raise RuntimeError("конфиг Xray невалиден: "+(t.stderr or t.stdout))
    subprocess.run(["systemctl","restart","xray"], check=True, capture_output=True)

def _link(st, host):
    q = urllib.parse.urlencode({
        "type":"tcp","security":"reality","pbk":st["public_key"],
        "fp":"firefox","sni":st["sni"],"sid":st["sid"],
        "spx":"/","flow":"xtls-rprx-vision"})
    return f"vless://{st['uuid']}@{host}:{st['port']}?{q}#VPN"

CFG_CACHE = _load(CFG, {}) or {}

def _cookie(self):
    m = re.search(r"sid=([^;]+)", self.headers.get("Cookie","") or "")
    return m.group(1) if m else None

def _authed(self):
    t = _cookie(self)
    e = SESSIONS.get(t) if t else None
    return bool(e and e > time.time())

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass

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

    def _is_current_password(self, cur):
        return _hash(CFG_CACHE.get("salt",""), cur) == CFG_CACHE.get("pass_hash")

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        if p in ("/","/index.html"):
            with open(HTML,"rb") as f: html = f.read()
            return self._send(200, html, "text/html; charset=utf-8")
        if p == "/api/state":
            if _authed(self) == False: return self._send(401, {"error":"unauthorized"})
            st = _load(STATE)
            running = subprocess.run(["systemctl","is-active","--quiet","xray"]).returncode == 0
            out = {"version":VERSION,"running":running,"configured":bool(st),
                   "login":CFG_CACHE.get("login","")}
            if st:
                host = self.headers.get("Host","").split(":")[0]
                out["port"] = st["port"]; out["link"] = _link(st, host)
            return self._send(200, out)
        if p == "/api/update":
            if _authed(self) == False: return self._send(401, {"error":"unauthorized"})
            repo = CFG_CACHE.get("repo") or ""
            if repo == "": return self._send(400, {"error":"repo не задан (VPNPANEL_REPO)"})
            try:
                req = urllib.request.Request(
                    "https://api.github.com/repos/"+repo+"/releases/latest",
                    headers={"User-Agent":"vpnpanel"})
                rel = json.load(urllib.request.urlopen(req, timeout=8))
                latest = rel["tag_name"].lstrip("v")
                return self._send(200, {"current":VERSION,"latest":latest,
                                        "url":rel["html_url"],
                                        "update_available": not (latest == VERSION)})
            except Exception as e:
                return self._send(502, {"error":str(e)})
        return self._send(404, {"error":"not found"})

    def do_POST(self):
        try:
            p = urllib.parse.urlparse(self.path).path
            if p == "/api/login":
                b = self._body()
                good = (b.get("login") == CFG_CACHE.get("login") and
                        self._is_current_password(b.get("password","")))
                if good == False:
                    return self._send(401, {"error":"неверный логин или пароль"})
                t = secrets.token_hex(32); SESSIONS[t] = time.time() + 72*3600
                self._cookies = ["sid="+t+"; Path=/; HttpOnly; Max-Age=259200; SameSite=Lax"]
                return self._send(200, {"ok": True})
            if _authed(self) == False:
                return self._send(401, {"error":"unauthorized"})
            if p == "/api/logout":
                t = _cookie(self)
                if t: SESSIONS.pop(t, None)
                self._cookies = ["sid=; Path=/; Max-Age=0"]
                return self._send(200, {"ok": True})
            if p == "/api/vpn":
                st = _load(STATE)
                if st is None:
                    port = _free_port(443); priv, pub = _gen_keys()
                    st = {"port":port,"uuid":str(uuid.uuid4()),
                          "private_key":priv,"public_key":pub,
                          "sid":secrets.token_hex(4),
                          "sni":"www.samsung.com","dest":"www.samsung.com:443"}
                    _write_xray(st); _save(STATE, st)
                _restart_xray()
                host = self.headers.get("Host","").split(":")[0]
                return self._send(200, {"ok":True,"link":_link(st,host),"port":st["port"]})
            if p == "/api/security":
                b = self._body()
                if self._is_current_password(b.get("current_password","")) == False:
                    return self._send(401, {"error":"неверный текущий пароль"})
                changed = False
                nl = (b.get("login") or "").strip()
                np_ = b.get("password") or ""
                if nl and (nl == CFG_CACHE.get("login")) == False:
                    CFG_CACHE["login"] = nl; changed = True
                if np_:
                    if len(np_) < 8:
                        return self._send(400, {"error":"пароль короче 8 символов"})
                    CFG_CACHE["salt"] = secrets.token_hex(16)
                    CFG_CACHE["pass_hash"] = _hash(CFG_CACHE["salt"], np_)
                    changed = True
                if changed == False:
                    return self._send(400, {"error":"нечего менять"})
                _save(CFG, CFG_CACHE)
                SESSIONS.clear()
                self._cookies = ["sid=; Path=/; Max-Age=0"]
                return self._send(200, {"ok": True, "relogin": True})
            return self._send(404, {"error":"not found"})
        except Exception as e:
            return self._send(500, {"error": str(e)})

class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True; daemon_threads = True

if __name__ == "__main__":
    port = CFG_CACHE.get("panel_port", 8443)
    print("Veil "+VERSION+" слушает :"+str(port), flush=True)
    with S(("0.0.0.0", port), H) as srv:
        srv.serve_forever()
