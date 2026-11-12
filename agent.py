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

Действия /agent/apply: add, block, unblock, remove, set_limits, restart.
Слово хозяина 11.11, измерено прибором: панель на агент-нодах зовёт только
add / set_limits / remove / restart — block и unblock агент держит для ручного
хода, живой мастер к ним не обращается.

Любое решение — пущено, отказ ворот, отказ по полю, беда применения, собственная
блокировка, недоступный счёт — записано ОДНОЙ строкой в logs/agent.err (без адресов,
токенов и ключей). До 1.1.1 `_log` звался только на смерти xray и на обрыве тика:
нода ОТКАЗЫВАЛА молча, и по журналу коробки нельзя было узнать, приходила ли команда
вообще (тот же класс дефекта, что #13 R43 на переключении ноги).

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

VERSION = "1.1.1"
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

AGENT_CAPS = ["clients_add", "limits", "unblock", "block", "restart", "autoblock"]

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


_NOTES = {"stats": None}


def _note(what, outcome, who="", why=""):
    """Свидетель решения: ОДНА строка журнала на любое слово агента — начало хода,
    отказ ворот, отказ по полю, беда применения, собственная блокировка. До 1.1.1
    `_log` звался только на смерти xray и на обрыве тика, поэтому на ноде нельзя
    было узнать, что она ОТКАЗАЛА: мастер видел «error: unauthorized» или обрыв
    транспорта, а журнал коробки молчал. Адресов, токенов и ключей в строке нет."""
    text = str(why or "")[:160].replace("\n", " ").replace("\r", " ")
    line = "%s: %s" % (what, outcome)
    if who:
        line += " " + str(who)[:40]
    if text:
        line += " — " + text
    _log(line)


def _txt(v):
    """Слово или None: цифра/список вместо строки не роняет ручку, а называется отказом."""
    return v if isinstance(v, str) else None


def _int(v, default=0):
    """Целое из числа или из слова; несъедобное — None, чтобы ручка отказала словом."""
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return None
    try:
        return int(str(v).strip())
    except Exception:
        return None


def _gb(v):
    """Гигабайты из числа или из слова; несъедобное — None (не молчаливый ноль лимита)."""
    if v is None or v == "":
        return 0.0
    if isinstance(v, bool):
        return None
    try:
        return max(0.0, float(str(v).strip()))
    except Exception:
        return None


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


def xray_apply(force=False, why=""):
    """Перезаписать конфиг xray; рестарт только если содержимое реально изменилось."""
    global _XAPPLIED
    cfg = _xray_cfg()
    blob = json.dumps(cfg, sort_keys=True)
    h = hashlib.sha256(blob.encode()).hexdigest()
    if not force and h == _XAPPLIED and _xray_alive():
        return False
    _log("xray: перезапуск (%s)" % (why or "без причины"))
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
    """Лимит >=95% или истёкший срок -> blocked. Меняет конфиг, если есть активные.

    Множество активных снимается ДО записи флага: преженный вид спрашивал
    `_active_uuids(st)` уже после того, как клиента пометили заблокированным, —
    он там оказаться не мог, и ход возвращал False ВСЕГДА. Замер 11.11 на ноге
    E4/E6: просроченный или лимитный клиент записывался в состояние и продолжал
    стоять в живом конфиге xray, пока какое-то чужое действие не пнуло apply.
    """
    structural = False
    now = time.time()
    active_before = set(_active_uuids(st))
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
        _note("tick", "блокировка", u, why)
        if u in active_before:
            structural = True
    return structural


def _traffic_tick():
    """Шаг учёта. Счётчик трафика — гость: если xray его не отдал, сроки и лимиты
    всё равно судятся, а отказ оракула называется ОДНОЙ строкой на смену состояния,
    а не молчанием и не потоком одинаковых строк каждую минуту."""
    tr = _statsquery()
    st = _state()
    if bool(tr) != _NOTES["stats"]:
        _NOTES["stats"] = bool(tr)
        if not tr:
            _note("tick", "счёт недоступен", why="statsquery не вернул счётчиков")
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
        if not tr:
            continue   # оракул молчит: счётчик не трогаем, иначе следующая проба
                       # досчитала бы жизнь клиента заново поверх уже учтённого
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
    # apply зовётся всегда, а не только при structural: хеш-защита внутри xray_apply
    # сама решает, нужен ли рестарт. Этим же закрывается пропуск, который оставлял
    # отказ записи конфига или отказа apply в ходе: состояние уже говорит «заблокирован»,
    # а живой конфиг держал клиента до следующего действия мастера.
    xray_apply(why="tick")
    return changed


def _tick_loop():
    while True:
        try:
            if not _xray_alive():
                _note("tick", "xray упал — поднимаю заново")
                xray_apply(force=True, why="подъём")
            _traffic_tick()
        except Exception as e:
            import traceback
            _note("tick", "беда", why=traceback.format_exc().replace("\n", " "))
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

    def _auth_why(self):
        """Пустое слово — пущено, иначе — почему нет. До 1.1.1 ворота ПЕРЕВАЛИВАЛИСЬ
        на токене с не-ASCII: `secrets.compare_digest` отказывается сравнивать строки
        с не-ASCII и бросает TypeError, поэтому чужое слово с кириллицей рвало соединение
        без ответа вместо честного отказа. Сравниваются байты UTF-8 — то же самое
        время, но без падения. Слова отказа идут только в журнал, наружу — всегда
        одно и то же «unauthorized»."""
        got = ""
        hdr = self.headers.get("Authorization") or ""
        if hdr.lower().startswith("bearer "):
            got = hdr[7:].strip()
        if not got:
            x = self.headers.get("X-Agent-Token")
            got = x.strip() if isinstance(x, str) else ""
        if not got:
            return "токена в запросе нет"
        return "" if secrets.compare_digest(got.encode("utf-8"),
                                            ensure_token().encode("utf-8")) else "токен не совпал"

    def _authed(self):
        return not self._auth_why()

    def _gate(self, what):
        """Ворота прав ручки + свидетель отказа в журнале (до починки — ноль строк)."""
        why = self._auth_why()
        if why:
            _note("api %s" % what, "отказ ворот", why=why)
        return why

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
                "clients": len(_active_uuids(st)), "caps": AGENT_CAPS})
        if p == "/agent/status":
            if self._gate("status"):
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
                "uptime": int(time.time() - STARTED_AT), "caps": AGENT_CAPS})
        if p == "/agent/clients":
            if self._gate("clients"):
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
        _note("api get", "отказ", urllib.parse.urlparse(self.path).path[:40],
              "ручки нет")
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        if p != "/agent/apply":
            _note("api post", "отказ", p[:40], "ручки нет")
            return self._send(404, {"error": "not found"})
        if self._gate("apply"):
            return self._send(401, {"error": "unauthorized"})
        b = self._body()
        if not isinstance(b, dict):
            b = {}
        try:
            code, obj = self._apply(b)
        except Exception as e:
            _note("api apply", "беда", _txt(b.get("action")) or "?",
                  "%s: %s" % (type(e).__name__, e))
            return self._send(500, {"error": "сбой применения: %s" % type(e).__name__})
        _note("api %s" % (_txt(b.get("action")) or "?"),
              "отказ" if code >= 400 else ("исполнено" if obj.get("ok") else "не исполнено"),
              _txt(b.get("uuid")) or "",
              _txt(obj.get("error")) or _txt(obj.get("warning")) or
              ("перезапуск xray" if obj.get("restarted") or obj.get("restarting") else ""))
        return self._send(code, obj)

    def _apply(self, b):
        """Тело команды -> (код, ответ). Мутирует состояние ТОЛЬКО после того,
        как все поля названы съедобными. До починки `int(b.get('expiry_days'))`
        на слове бросало исключение и рвало соединение посреди хода, а гнилой
        `limit_gb` молча становился нулём — то есть БЕЗЛИМИТИЕМ."""
        st = _state()
        with STATE_LOCK:
            if b.get("action") is not None and not isinstance(b.get("action"), str):
                return 400, {"error": "action — слово"}
            action = (_txt(b.get("action")) or "").strip().lower()
            for key in ("name", "reset_cycle"):
                if b.get(key) is not None and not isinstance(b[key], str):
                    return 400, {"error": "%s — слово" % key}
            for key in ("expiry_days", "expiry"):
                if b.get(key) is not None and _int(b[key]) is None:
                    return 400, {"error": "%s — число" % key}
            if b.get("limit_gb") is not None and _gb(b["limit_gb"]) is None:
                return 400, {"error": "limit_gb — число"}
            raw_u = b.get("uuid")
            if raw_u is not None and not isinstance(raw_u, str):
                return 400, {"error": "uuid — слово"}
            u = (raw_u or "").strip()
            if action == "add" and not u:
                u = str(uuidlib.uuid4())
            name = (_txt(b.get("name")) or "").strip()[:64] or "Клиент"
            why = "%s: %s" % (action, name)

            if action == "add":
                if not _looks_uuid(u):
                    return 400, {"error": "bad uuid"}
                if u in (st.get("clients") or {}):
                    return 400, {"error": "клиент уже есть на ноде"}
                days = _int(b.get("expiry_days")) or 0
                expiry = _int(b.get("expiry")) or 0
                if not expiry and days > 0:
                    expiry = int(time.time()) + days * 86400
                limit_gb = _gb(b.get("limit_gb")) or 0.0
                rc = (_txt(b.get("reset_cycle")) or "").strip().lower()
                st.setdefault("clients", {})[u] = {
                    "name": name, "limit_gb": max(0.0, float(limit_gb)),
                    "expiry": int(expiry),
                    "reset_cycle": rc if rc in ("day", "week", "month") else "",
                    "cycle": _cycle_key(rc), "up": 0, "down": 0,
                    "last_up": 0, "last_down": 0,
                    "added": int(time.time())}
                _save_state()
                xray_apply(why=why)
                return 200, {"ok": True, "uuid": u}
            if action == "restart":
                changed = xray_apply(force=True, why="restart")
                return 200, {"ok": True, "restarted": bool(changed)}
            if action in ("remove", "set_limits", "unblock", "block"):
                c = (st.get("clients") or {}).get(u)
                if not c:
                    return 404, {"error": "клиент не найден"}
                if action == "block":
                    if c.get("blocked"):
                        return 200, {"ok": True}
                    c["blocked"] = int(time.time())
                    c["blocked_reason"] = "manual"
                    _save_state()
                    xray_apply(why=why)
                    return 200, {"ok": True}
                if action == "remove":
                    st["clients"].pop(u, None)
                    _save_state()
                    xray_apply(why=why)
                    return 200, {"ok": True}
                if action == "set_limits":
                    limit_gb = _gb(b.get("limit_gb"))
                    days = _int(b.get("expiry_days")) or 0
                    expiry = _int(b.get("expiry")) or 0
                    rc = _txt(b.get("reset_cycle"))
                    c["limit_gb"] = max(0.0, float(limit_gb or 0.0))
                    if days > 0 or expiry > 0:
                        c["expiry"] = int(expiry or
                                          (int(time.time()) + days * 86400))
                        if c.get("blocked_reason") == "expired":
                            c.pop("blocked", None)
                            c.pop("blocked_reason", None)
                    if rc is not None and rc.strip().lower() in ("day", "week", "month", ""):
                        c["reset_cycle"] = rc.strip().lower()
                    _save_state()
                    return 200, {"ok": True}
                # unblock
                was = bool(c.get("blocked"))
                by_limit = c.get("blocked_reason") == "limit"
                expired = int(c.get("expiry") or 0) and time.time() > int(c["expiry"])
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
                restart = False
                if was and not expired:
                    restart = xray_apply(why=why)
                if expired:
                    # до починки ручка отвечала «ок, разблокирован», а тик через
                    # минуту молча ставил блок на место — мастер видел противоречие
                    _note("api unblock", "не исполнено", u,
                          "срок истёк: блокировка вернётся на первом же тике")
                    return 200, {"ok": True, "restarting": bool(restart),
                                 "warning": "срок истёк — блокировка вернётся на первом же тике"}
                return 200, {"ok": True, "restarting": bool(restart)}
            return 400, {"error": "action: add|remove|set_limits|unblock|block|restart"}


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
