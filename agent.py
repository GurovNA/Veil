#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Veil Node Agent — автономная нода для панели Veil (только stdlib + xray + openssl).

Запуск на сервере-ноде:
    python3 agent.py                 # поднимет API и xray, сохранит всё рядом с файлом
    python3 agent.py --token         # показать токен для мастера
    python3 agent.py --version

Мастер-панель подключается по адресу https://HOST:api_port и общается через
/agent/hello (публичные параметры), /agent/status, /agent/clients и POST /agent/apply.
Транспорт — HTTPS с self-signed сертификатом; мастер закрепляет отпечаток (TOFU),
поэтому токен не уходит на MITM.

Файлы агента (лежат в каталоге самого agent.py):
  agent.conf.json   — настройки (порты, имя, sni)
  agent_token.txt   — токен доступа (0600), генерируется при первом запуске
  agent_state.json  — ключи reality и клиенты с трафиком
  agent.crt / agent.key — self-signed сертификат API
  xray-agent.json   — конфиг xray (перезаписывается агентом)
  logs/             — stdout/stderr xray и агента
"""
import datetime
import hashlib
import json
import os
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid as uuidlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0"
BASE = os.path.dirname(os.path.abspath(__file__))
CONF_FILE = f"{BASE}/agent.conf.json"
STATE_FILE = f"{BASE}/agent_state.json"
TOKEN_FILE = f"{BASE}/agent_token.txt"
CRT_FILE = f"{BASE}/agent.crt"
KEY_FILE = f"{BASE}/agent.key"
XCFG_FILE = f"{BASE}/xray-agent.json"
LOG_DIR = f"{BASE}/logs"
XRAY_LOG = f"{LOG_DIR}/xray.log"
AGENT_LOG = f"{LOG_DIR}/agent.err"
STARTED_AT = time.time()

DEFAULT_CONF = {
    "api_port": 9444,      # HTTPS API агента (мастер стучится сюда)
    "xport": 8444,         # порт входящего vless+reality для клиентов
    "stats_port": 10090,   # локальный stats-API xray (127.0.0.1)
    "xray_bin": "xray",
    "name": "Veil node",
    "sni": "www.samsung.com",
}

STATE_LOCK = threading.RLock()
CONF = None
STATE = None
_XP = None            # Popen процесса xray
_XAPPLIED = ""        # sha256 применённого конфига xray — не рестартуем без причины


# ---------------- низкий уровень ----------------

def _load(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def _save(path, data, mode=0o600):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def _log(msg):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(AGENT_LOG, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass


def _conf():
    global CONF
    if CONF is None:
        c = _load(CONF_FILE)
        if not isinstance(c, dict):
            c = {}
            _save(CONF_FILE, {**DEFAULT_CONF}, 0o644)
        merged = {**DEFAULT_CONF, **c}
        CONF = merged
    return CONF


def _state():
    global STATE
    if STATE is None:
        s = _load(STATE_FILE)
        if not isinstance(s, dict):
            s = {"clients": {}, "keys": {}}
        s.setdefault("clients", {})
        s.setdefault("keys", {})
        STATE = s
    return STATE


def _save_state():
    _save(STATE_FILE, _state())


def ensure_token():
    tok = ""
    try:
        with open(TOKEN_FILE) as f:
            tok = f.read().strip()
    except Exception:
        tok = ""
    if not tok:
        tok = secrets.token_urlsafe(24)
        with open(TOKEN_FILE, "w") as f:
            f.write(tok)
        os.chmod(TOKEN_FILE, 0o600)
    return tok


def _public_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ensure_cert():
    if os.path.exists(CRT_FILE) and os.path.exists(KEY_FILE):
        return
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", KEY_FILE, "-out", CRT_FILE, "-days", "3650",
         "-subj", "/CN=veil-agent",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("openssl: " + (r.stderr or r.stdout))
    os.chmod(KEY_FILE, 0o600)
    os.chmod(CRT_FILE, 0o644)


def ensure_keys():
    st = _state()
    k = st.get("keys") or {}
    if k.get("private_key") and k.get("public_key") and k.get("sid"):
        return k
    out = subprocess.run([_conf()["xray_bin"], "x25519"],
                         capture_output=True, text=True).stdout
    priv = pub = ""
    for line in out.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        label, val = line.split(":", 1)
        label = label.lower()
        val = val.strip()
        if "private" in label:
            priv = val
        elif "public" in label or "password" in label:
            pub = val
    if not (priv and pub):
        raise RuntimeError("не разобрал xray x25519: " + out)
    k = {"private_key": priv, "public_key": pub, "sid": secrets.token_hex(4)}
    st["keys"] = k
    _save_state()
    return k


# ---------------- конфиг и процесс xray ----------------

def _active_uuids(st):
    return [u for u, c in (st.get("clients") or {}).items() if not c.get("blocked")]


def _xray_cfg():
    c = _conf()
    st = _state()
    keys = st.get("keys") or {}
    clients = [{"id": u, "flow": "xtls-rprx-vision", "email": u}
               for u in _active_uuids(st)]
    inbound = {
        "listen": "0.0.0.0", "port": int(c["xport"]), "tag": "reality",
        "protocol": "vless",
        "settings": {"clients": clients, "decryption": "none"},
        "streamSettings": {
            "network": "tcp", "security": "reality",
            "realitySettings": {
                "show": False, "dest": c["sni"] + ":443", "xver": 0,
                "serverNames": [c["sni"]],
                "privateKey": keys.get("private_key", ""),
                "shortIds": [keys.get("sid", "")]}},
        "sniffing": {"enabled": True,
                     "destOverride": ["http", "tls", "quic"]}}
    api_in = {"listen": "127.0.0.1", "port": int(c["stats_port"]),
              "protocol": "dokodemo-door",
              "settings": {"address": "127.0.0.1"}, "tag": "api"}
    return {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api",
                "services": ["HandlerService", "LoggerService", "StatsService"]},
        "stats": {},
        "inbounds": [inbound, api_in],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": [{"inboundTag": ["api"], "outboundTag": "api",
                               "type": "field"}]},
        "policy": {"levels": {"0": {"statsUserUplink": True,
                                    "statsUserDownlink": True,
                                    "statsUserOnline": True}},
                   "system": {"statsInboundUplink": True,
                              "statsInboundDownlink": True}}}


def _xray_stop():
    global _XP
    if _XP is not None and _XP.poll() is None:
        try:
            os.killpg(os.getpgid(_XP.pid), signal.SIGTERM)
        except Exception:
            try:
                _XP.terminate()
            except Exception:
                pass
    _XP = None


def _xray_start():
    global _XP
    c = _conf()
    _xray_stop()
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(XRAY_LOG, "ab") as lf:
        _XP = subprocess.Popen([c["xray_bin"], "run", "-config", XCFG_FILE],
                               stdout=lf, stderr=subprocess.STDOUT,
                               start_new_session=True)
    time.sleep(0.5)
    if _XP.poll() is not None:
        _log("xray стартовал и сразу умер — см. " + XRAY_LOG)


def _xray_alive():
    return _XP is not None and _XP.poll() is None


def xray_apply(force=False):
    """Перезаписать конфиг xray; рестарт только если содержимое реально изменилось."""
    global _XAPPLIED
    cfg = _xray_cfg()
    blob = json.dumps(cfg, sort_keys=True)
    h = hashlib.sha256(blob.encode()).hexdigest()
    if not force and h == _XAPPLIED and _xray_alive():
        return False
    _save(XCFG_FILE, cfg, 0o644)
    _xray_start()
    _XAPPLIED = h
    return True


# ---------------- учёт трафика ----------------

def _cycle_key(kind, ts=None):
    if kind not in ("day", "week", "month"):
        return "lifetime"
    d = datetime.datetime.fromtimestamp(
        ts if ts is not None else time.time(), datetime.timezone.utc)
    if kind == "day":
        return d.strftime("%Y-%m-%d")
    if kind == "week":
        return d.strftime("%G-W%V")
    return d.strftime("%Y-%m")


def _statsquery():
    c = _conf()
    try:
        r = subprocess.run(
            [c["xray_bin"], "api", "statsquery",
             "--server", f"127.0.0.1:{c['stats_port']}",
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
        if len(parts) < 4 or parts[0] != "user" or parts[2] != "traffic":
            continue
        email, direction = parts[1], parts[3]
        if direction not in ("uplink", "downlink"):
            continue
        out.setdefault(email, {"uplink": 0, "downlink": 0})
        out[email][direction] = int(s.get("value", 0) or 0)
    return out


def _statsreset(u):
    c = _conf()
    try:
        subprocess.run(
            [c["xray_bin"], "api", "statsreset",
             "--server", f"127.0.0.1:{c['stats_port']}",
             "--pattern", f"user>>>{u}>>>"],
            capture_output=True, text=True, timeout=8)
    except Exception:
        pass


def _autoblock(st):
    """Лимит >=95% или истёкший срок -> blocked. Меняет конфиг, если есть активные."""
    structural = False
    now = time.time()
    for u, c in (st.get("clients") or {}).items():
        if c.get("blocked"):
            continue
        why = None
        used = float(c.get("up") or 0) + float(c.get("down") or 0)
        lim = float(c.get("limit_gb") or 0)
        if lim > 0 and used >= lim * 1024 ** 3 * 0.95:
            why = "limit"
        ex = int(c.get("expiry") or 0)
        if ex and now > ex:
            why = why or "expired"
        if not why:
            continue
        c["blocked"] = int(now)
        c["blocked_reason"] = why
        if u in _active_uuids(st):
            structural = True
    return structural


def _traffic_tick():
    tr = _statsquery()
    if not tr:
        return False
    st = _state()
    changed = False
    structural = False
    for u, c in (st.get("clients") or {}).items():
        ck = _cycle_key(c.get("reset_cycle"))
        if c.get("cycle") != ck:
            c["cycle"] = ck
            c["up"] = 0
            c["down"] = 0
            c["last_up"] = 0
            c["last_down"] = 0
            _statsreset(u)
            if c.get("blocked") and c.get("blocked_reason") == "limit":
                c.pop("blocked", None)
                c.pop("blocked_reason", None)
                structural = True
            changed = True
            continue
        t = tr.get(u) or {}
        cu = int(t.get("uplink", 0) or 0)
        cd = int(t.get("downlink", 0) or 0)
        lu = int(c.get("last_up") or 0)
        ld = int(c.get("last_down") or 0)
        du = cu - lu
        dd = cd - ld
        if du < 0:
            du = cu   # xray перезапустился — считаем с нуля
        if dd < 0:
            dd = cd
        if du or dd:
            c["up"] = int(c.get("up") or 0) + du
            c["down"] = int(c.get("down") or 0) + dd
            changed = True
        if lu != cu or ld != cd:
            c["last_up"] = cu
            c["last_down"] = cd
            changed = True
    if _autoblock(st):
        structural = True
        changed = True
    if changed:
        _save_state()
    if structural:
        xray_apply()
    return changed


def _tick_loop():
    while True:
        try:
            if not _xray_alive():
                _log("xray упал — поднимаю заново")
                xray_apply(force=True)
            _traffic_tick()
        except Exception as e:
            import traceback
            _log("tick: " + traceback.format_exc())
        time.sleep(60)


# ---------------- HTTP API ----------------

class H(BaseHTTPRequestHandler):
    server_version = "VeilAgent/" + VERSION

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        raw = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except Exception:
            pass

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > 1_000_000:
                return {}
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def _authed(self):
        tok = ensure_token()
        got = ""
        hdr = self.headers.get("Authorization") or ""
        if hdr.lower().startswith("bearer "):
            got = hdr[7:].strip()
        if not got:
            got = (self.headers.get("X-Agent-Token") or "").strip()
        return bool(got) and secrets.compare_digest(got, tok)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        if p == "/agent/hello":
            c = _conf()
            st = _state()
            keys = st.get("keys") or {}
            return self._send(200, {
                "ok": True, "role": "veil-agent", "version": VERSION,
                "name": c.get("name") or "Veil node",
                "proto": "reality", "port": int(c["xport"]),
                "api_port": int(c["api_port"]),
                "public_key": keys.get("public_key", ""),
                "sni": c.get("sni") or "", "sid": keys.get("sid") or "",
                "fp": "firefox", "flow": "xtls-rprx-vision",
                "host_hint": _public_ip(),
                "clients": len(_active_uuids(st))})
        if p == "/agent/status":
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            c = _conf()
            st = _state()
            allc = st.get("clients") or {}
            used = sum(float(x.get("up") or 0) + float(x.get("down") or 0)
                       for x in allc.values())
            return self._send(200, {
                "ok": True, "version": VERSION, "role": "veil-agent",
                "name": c.get("name"), "xray": _xray_alive(),
                "clients": len(allc), "blocked": sum(1 for x in allc.values()
                                                     if x.get("blocked")),
                "used_gb": round(used / 1024 ** 3, 3),
                "port": int(c["xport"]), "api_port": int(c["api_port"]),
                "uptime": int(time.time() - STARTED_AT)})
        if p == "/agent/clients":
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            st = _state()
            items = [{"uuid": u, "name": c.get("name") or "",
                      "up": int(c.get("up") or 0),
                      "down": int(c.get("down") or 0),
                      "limit_gb": float(c.get("limit_gb") or 0),
                      "expiry": int(c.get("expiry") or 0),
                      "reset_cycle": c.get("reset_cycle") or "",
                      "cycle": c.get("cycle") or "",
                      "blocked": int(c.get("blocked") or 0),
                      "blocked_reason": c.get("blocked_reason") or ""}
                     for u, c in (st.get("clients") or {}).items()]
            return self._send(200, {"ok": True, "clients": items})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        if p != "/agent/apply":
            return self._send(404, {"error": "not found"})
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        b = self._body()
        action = (b.get("action") or "").strip().lower()
        st = _state()
        with STATE_LOCK:
            if action == "add":
                u = (b.get("uuid") or "").strip() or str(uuidlib.uuid4())
                if not _looks_uuid(u):
                    return self._send(400, {"error": "bad uuid"})
                if u in (st.get("clients") or {}):
                    return self._send(400, {"error": "клиент уже есть на ноде"})
                days = int(b.get("expiry_days") or 0)
                expiry = int(b.get("expiry") or 0)
                if not expiry and days > 0:
                    expiry = int(time.time()) + days * 86400
                name = (b.get("name") or "Клиент").strip()[:64] or "Клиент"
                try:
                    limit_gb = max(0.0, float(b.get("limit_gb") or 0))
                except Exception:
                    limit_gb = 0.0
                rc = (b.get("reset_cycle") or "").strip().lower()
                st.setdefault("clients", {})[u] = {
                    "name": name, "limit_gb": limit_gb, "expiry": expiry,
                    "reset_cycle": rc if rc in ("day", "week", "month") else "",
                    "cycle": _cycle_key(rc), "up": 0, "down": 0,
                    "last_up": 0, "last_down": 0,
                    "added": int(time.time())}
                _save_state()
                xray_apply()
                return self._send(200, {"ok": True, "uuid": u})
            if action in ("remove", "set_limits", "unblock"):
                u = (b.get("uuid") or "").strip()
                c = (st.get("clients") or {}).get(u)
                if not c:
                    return self._send(404, {"error": "клиент не найден"})
                if action == "remove":
                    st["clients"].pop(u, None)
                    _save_state()
                    xray_apply()
                    return self._send(200, {"ok": True})
                if action == "set_limits":
                    try:
                        c["limit_gb"] = max(0.0, float(b.get("limit_gb") or 0))
                    except Exception:
                        pass
                    days = int(b.get("expiry_days") or 0)
                    if days > 0:
                        c["expiry"] = int(time.time()) + days * 86400
                        if c.get("blocked_reason") == "expired":
                            c.pop("blocked", None)
                            c.pop("blocked_reason", None)
                    rc = (b.get("reset_cycle") or "").strip().lower()
                    if rc in ("day", "week", "month", ""):
                        c["reset_cycle"] = rc
                    _save_state()
                    return self._send(200, {"ok": True})
                # unblock
                was = bool(c.get("blocked"))
                by_limit = c.get("blocked_reason") == "limit"
                c.pop("blocked", None)
                c.pop("blocked_reason", None)
                if by_limit:
                    # без обнуления счётчика автоблок вернулся бы через минуту
                    c["up"] = 0
                    c["down"] = 0
                    c["last_up"] = 0
                    c["last_down"] = 0
                    _statsreset(u)
                _save_state()
                if was:
                    xray_apply()
                return self._send(200, {"ok": True})
            return self._send(400, {"error": "action: add|remove|set_limits|unblock"})


def _looks_uuid(u):
    try:
        uuidlib.UUID(u)
        return True
    except Exception:
        return False


# ---------------- запуск ----------------

def _on_term(signo, frame):
    raise KeyboardInterrupt

def serve():
    os.makedirs(LOG_DIR, exist_ok=True)
    c = _conf()
    _state()
    ensure_keys()
    ensure_cert()
    ensure_token()
    xray_apply(force=True)
    # SIGTERM -> KeyboardInterrupt: штатный finally гасит xray, без процессов-сирот
    signal.signal(signal.SIGTERM, _on_term)
    threading.Thread(target=_tick_loop, daemon=True).start()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CRT_FILE, KEY_FILE)
    srv = ThreadingHTTPServer(("0.0.0.0", int(c["api_port"])), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"Veil Agent {VERSION}: API https://0.0.0.0:{c['api_port']}  "
          f"vless+reality :{c['xport']}  токен в {TOKEN_FILE}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _xray_stop()


def main():
    args = [a.lower() for a in sys.argv[1:]]
    if "--version" in args or "-v" in args:
        print(VERSION)
        return
    if "--token" in args or "--print-token" in args:
        print(ensure_token())
        return
    serve()


if __name__ == "__main__":
    main()
