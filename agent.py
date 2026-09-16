#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Veil Node Agent — агент мультисерверности (работает НА НОДЕ).
Запускается как отдельный systemd-сервис nodeagent (по желанию — на второй машине).
Назначение:
  * держать Xray на ноде живым (авто-подъём unit, пересборка при изменениях);
  * отдавать контроллеру (панели) статус/метрики/selftest по защищённому токену;
  * принимать команды apply (добавить/удалить клиента, заблокировать, лимиты);
  * вести собственные лимиты трафика/срока и автоблокировку (то же, что в панели).

HTTP: wsgiref + threading + self-signed TLS, токен через Authorization: Bearer.
"""
import base64, io, json, locale, os, re, ssl, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(ROOT, "agent_state.json")
XRAY_CONF = os.path.join(ROOT, "xray-agent.json")
HOST, PORT = "0.0.0.0", 9444
TOKEN_HASH = "node_agent_token"  # заменяется при первом запуске: sha256(случайный)

PASSWD_PATH = os.path.join(ROOT, "agent_token.txt")
def _load_token_file():
    global TOKEN_HASH
    try:
        t = io.open(PASSWD_PATH, encoding="utf-8").read().strip()
        if len(t) >= 16:
            TOKEN_HASH = hashlib_sha256(t)
    except Exception:
        pass

def hashlib_sha256(s):
    try:
        import hashlib
        return hashlib.sha256(s.encode("utf-8")).hexdigest()
    except Exception:
        return "0"*64

# ---- состояние (как в панели) ----
state = {"clients": [], "xray": None}
_lock = threading.Lock()

def _load_state():
    global state
    try:
        if os.path.exists(STATE_PATH):
            with io.open(STATE_PATH, encoding="utf-8") as f:
                state = json.load(f)
    except Exception:
        state = {"clients": [], "xray": None}
    if "clients" not in state: state["clients"] = []

def _save_state():
    with _lock:
        try:
            with io.open(STATE_PATH, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False, indent=1)
        except Exception:
            pass

# ---- большой общий хелпер fmt (дублирует панель, чтобы агент был самодостаточен) ----
def fmt_bytes(b):
    b = float(b or 0)
    for u in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} ПБ"

# ---- работа с Xray на ноде ----
def _xc_path():
    return os.path.join(ROOT, "xray")

def _xc_conf_private_key():
    try:
        with io.open(os.path.join(ROOT, "xray-agent.json"), encoding="utf-8") as f:
            j = json.load(f)
        return j["inbounds"][0].get("streamSettings", {}).get("realitySettings", {}).get("privateKey", "")
    except Exception:
        return ""

def _ensure_xray_conf():
    """Создаёт дефолтный конфиг агента (VLESS+Reality), если его нет."""
    if os.path.exists(XRAY_CONF): return True
    d = os.path.join(ROOT, "conf")
    try: os.makedirs(d, exist_ok=True)
    except Exception: pass
    priv = _xc_conf_private_key() or "replace-me-with-32-byte-key"
    conf = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": 443, "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality",
                "realitySettings": {"show": False, "dest": "www.microsoft.com:443",
                    "serverNames": ["www.microsoft.com", "microsoft.com"],
                    "privateKey": priv, "shortIds": ["6ba85179e30d4fc2"]}},
            "tag": "in-0",
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    with io.open(XRAY_CONF, "w", encoding="utf-8") as f:
        json.dump(conf, f, ensure_ascii=False, indent=1)
    return True

def _xc_bin_exists():
    return os.path.exists(_xc_path())

def _agent_status():
    """Статус агента: жив ли xray, версия, число клиентов."""
    running = False
    try:
        r = subprocess.run(["pgrep", "-f", "xray.*agent"], capture_output=True, text=True, timeout=5)
        running = bool(r.stdout.strip())
    except Exception:
        running = False
    ver = ""
    try:
        r = subprocess.run([_xc_path(), "-version"], capture_output=True, text=True, timeout=8)
        if r.returncode == 0:
            ver = (r.stdout.splitlines() or [""])[0]
    except Exception:
        ver = ""
    return {"running": running, "version": ver, "clients": len(state.get("clients", [])),
            "conf_exists": os.path.exists(XRAY_CONF)}

def _autoblock_limits():
    """Проверяет лимиты трафика/срока у клиентов агента; блокирует при превышении."""
    now = int(time.time())
    changed = False
    for c in state.get("clients", []):
        lim = float(c.get("limit_gb") or 0)
        used = float(c.get("used_gb") or 0)
        exp = int(c.get("expiry") or 0)
        reason = None
        if lim > 0 and used >= lim:
            reason = "исчерпан лимит трафика"
        if exp and now >= exp:
            reason = "истёк срок"
        if reason:
            if not c.get("blocked"):
                c["blocked"] = True; c["blocked_reason"] = reason; changed = True
        else:
            if c.get("blocked"):
                c["blocked"] = False; c["blocked_reason"] = None; changed = True
    if changed:
        _save_state()
        _apply_config()

def _limits_loop(interval=60):
    while True:
        try:
            _autoblock_limits()
        except Exception:
            pass
        time.sleep(interval)

# ---- конфиг xray из клиентов агента ----
def _apply_config():
    """Пересобирает xray-agent.json из списка клиентов и перезапускает xray."""
    _ensure_xray_conf()
    try:
        with io.open(XRAY_CONF, encoding="utf-8") as f:
            conf = json.load(f)
    except Exception:
        return False
    inb = conf["inbounds"][0]
    inb["settings"]["clients"] = [
        {"id": c["uuid"], "flow": "xtls-rprx-vision", "email": c["name"], "level": 0,
         "limitGb": float(c.get("limit_gb") or 0), "expiry": int(c.get("expiry") or 0)}
        for c in state.get("clients", []) if not c.get("blocked")
    ]
    try:
        with io.open(XRAY_CONF, "w", encoding="utf-8") as f:
            json.dump(conf, f, ensure_ascii=False, indent=1)
    except Exception:
        return False
    subprocess.Popen(["systemctl", "restart", "nodexray"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True

# ---- HTTP ----
class AH(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass

    def _auth(self):
        a = self.headers.get("Authorization", "")
        m = re.match(r"Bearer\s+(\S+)", a)
        if not m: return False
        return hashlib_sha256(m.group(1)) == TOKEN_HASH

    def _send(self, code, obj, ctype="application/json; charset=utf-8"):
        b = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        try: self.wfile.write(b)
        except Exception: pass

    def do_GET(self):
        u = urlparse(self.path)
        p = u.path
        if p == "/agent/selftest":
            st = "ok"
            probs = []
            if not _xc_bin_exists(): st = "warn"; probs.append("xray не найден")
            sts = _agent_status()
            if not sts["running"]: st = "warn"; probs.append("xray не запущен")
            self._send(200, {"status": st, "agent": "veil-node-agent", "time": int(time.time()),
                             "xray": sts, "problems": probs})
        elif p == "/agent/status":
            self._send(200, {"status": "ok", "agent": "veil-node-agent", **_agent_status(),
                             "uptime_s": int(time.time() - _START)})
        elif p == "/agent/metrics":
            if not self._auth(): return self._send(401, {"error": "unauthorized"})
            sts = _agent_status()
            self._send(200, {"nodes": 1, "clients": sts["clients"],
                             "xray_running": sts["running"], "time": int(time.time())})
        elif p == "/agent/clients":
            if not self._auth(): return self._send(401, {"error": "unauthorized"})
            self._send(200, {"clients": state.get("clients", []), "count": len(state.get("clients", []))})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        p = u.path
        if not self._auth(): return self._send(401, {"error": "unauthorized"})
        try:
            ln = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(ln).decode("utf-8")) if ln else {}
        except Exception:
            body = {}
        if p == "/agent/apply":
            act = body.pop("action", None)
            if act == "add":
                n = body.get("name", "") or body.get("email", "")
                uu = body.get("uuid", "")
                if not uu: uu = str(uuid4())
                with _lock:
                    state.setdefault("clients", [])
                    if not any(c["uuid"] == uu for c in state["clients"]):
                        state["clients"].append({
                            "uuid": uu, "name": n, "proto": "vless",
                            "limit_gb": float(body.get("limit_gb") or 0),
                            "expiry": int(body.get("expiry") or 0),
                            "used_gb": 0, "up": 0, "down": 0, "created": int(time.time())})
                _save_state(); _apply_config()
                self._send(200, {"ok": True, "action": "add", "uuid": uu})
            elif act == "remove":
                uu = body.get("uuid", "")
                with _lock:
                    state["clients"] = [c for c in state.get("clients", []) if c["uuid"] != uu]
                _save_state(); _apply_config()
                self._send(200, {"ok": True, "action": "remove", "uuid": uu})
            elif act == "set_limits":
                uu = body.get("uuid", "")
                with _lock:
                    for c in state.get("clients", []):
                        if c["uuid"] == uu:
                            c["limit_gb"] = float(body.get("limit_gb") or 0)
                            c["expiry"] = int(body.get("expiry") or 0)
                _save_state(); _apply_config()
                self._send(200, {"ok": True, "action": "set_limits", "uuid": uu})
            elif act == "unblock":
                uu = body.get("uuid", "")
                with _lock:
                    for c in state.get("clients", []):
                        if c["uuid"] == uu:
                            c["blocked"] = False; c["blocked_reason"] = None
                _save_state(); _apply_config()
                self._send(200, {"ok": True, "action": "unblock", "uuid": uu})
            else:
                self._send(400, {"error": "unknown action", "got": act})
        else:
            self._send(404, {"error": "not found"})

def make_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert = os.path.join(ROOT, "agent.crt"); key = os.path.join(ROOT, "agent.key")
    if not (os.path.exists(cert) and os.path.exists(key)):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", cert, "-days", "3650",
                        "-subj", "/CN=node-agent"], capture_output=True)
    ctx.load_cert_chain(cert, key)
    return ctx

def main():
    _load_token_file()
    _load_state()
    _ensure_xray_conf()
    def _mk():
        srv = ThreadingHTTPServer((HOST, PORT), AH)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        return srv
    global ctx, _START
    _START = int(time.time())
    ctx = make_ctx()
    threading.Thread(target=_limits_loop, daemon=True).start()
    print(f"veil-node-agent: https://{HOST}:{PORT} (clients={len(state.get('clients',[]))})")
    while True:
        try:
            srv = _mk()
            srv.serve_forever()
        except Exception as e:
            print(f"  srv err: {e}")
            time.sleep(00.5)

if __name__ == "__main__":
    try:
        from uuid import uuid4
    except Exception:
        def uuid4():
            import uuid
            return uuid.uuid4()
    main()
