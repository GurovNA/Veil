#!/usr/bin/env python3
import base64, json, os, subprocess, secrets, hashlib, uuid as uuidlib, re, ssl, time, threading, socket, hmac, struct
import ssl, socketserver, http.server
import urllib.parse, urllib.request, urllib.error
import shutil, tarfile, tempfile, datetime
import html as _html
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
VERSION = "2.7.4"
# 2.5.0: Фаза 1 — циклы сброса трафика (день/неделя/месяц) + TG-алерты 80%/истечение,
#        лимит устройств на клиента (по access-логу Xray, автобан лишних IP),
#        fail2ban-lite для входа в панель (nft-таблица inet veil_bans),
#        Prometheus /metrics (veil_* метрики, Bearer-токен), split-tunnel RU/IR
#        в подписках и /sb-конфигах sing-box + ночное зеркало geoip/geosite-правил
#        с выдачи sing-box, /sub userinfo-заголовки, одно кликовый откат релиза.
# 2.4.4: заглушка на 443 полностью переписана — «8BIT HAVEN»: рабочий эмулятор JSNES
#        (корректный blit кадров, плавающий аудиобуфер, CRT-фильтр), две легально
#        распространяемые домашние ROM (RoboRun GPL-3.0, Falling MIT) вместо битого
#        nestest.nes, мультитач-геймпад/клавиатура/Gamepad API и загрузка своих .nes;
#        install.sh перезапускает telemt после переустановки (telemt кэширует decoy при старте).
# 2.4.3: исправлен формат wireguard:// ссылок для INCY (publickey/address плейнтекстом,
#        address без префикса /32, без mtu; secretKey в userinfo остаётся percent-encoded —
#        Incy декодирует только userinfo); decoy-каталог дополнен jsnes.min.js и nestest.nes.
# 2.4.2: вкладка «Диагностика» (Master Plan §6): GET /api/metrics и GET /api/selftest,
#        протокол-осознанные проверки портов (TCP-connect / UDP-bound), сетка бейджей статусов.
# 2.4.1: фикды: поле ok в ответах бэкенда, ошибка revoke сессий, адаптивность таблиц на
#        мобильных, secretKey в Xray WireGuard outbound для INCY.
# 2.4.0: добавлены read-only GET /api/audit и GET /api/login/history (журналы безопасности в UI);


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
    # содержит токены нод — только 0600
    _save(NODES_CONFIG_FILE, nodes)

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
    try:
        metrics["load1"] = round(os.getloadavg()[0], 2)
    except Exception:
        pass
    try:
        du = shutil.disk_usage("/")
        metrics["disk_used_percent"] = round(100.0 * du.used / du.total, 1)
        metrics["disk_free_gb"] = round(du.free / (1024**3), 1)
    except Exception:
        pass
    try:
        metrics["xray_running"] = subprocess.run(["systemctl", "is-active", "--quiet", "xray"]).returncode == 0
    except Exception:
        metrics["xray_running"] = False
    try:
        st = _load(STATE, {}) or {}
        ps = {}
        for proto, inb in (st.get("inbounds") or {}).items():
            port = inb.get("port")
            if isinstance(port, int):
                ps[str(port)] = not _port_free(port)
        metrics["ports_status"] = ps
    except Exception:
        metrics["ports_status"] = {}
    return metrics

def run_protocol_self_test():
    results = {}
    checks = [(8443, "Панель (TCP)")]
    try:
        st = _load(STATE, {}) or {}
        for proto, inb in (st.get("inbounds") or {}).items():
            p = inb.get("port")
            if isinstance(p, int):
                is_udp = proto in ("wireguard", "amneziawg", "hysteria2") or inb.get("net") == "udp"
                checks.append((p, f"{proto} ({'UDP' if is_udp else 'TCP'})"))
    except Exception:
        pass

    for port, label in checks:
        is_udp = "UDP" in label
        if is_udp:
            bound = not _port_free(port)
            results[str(port)] = {"label": label, "status": "OK (слушает)" if bound else "FAIL: свободен"}
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            try:
                s.connect(("127.0.0.1", port))
                results[str(port)] = {"label": label, "status": "OK"}
            except Exception:
                if not _port_free(port):
                    results[str(port)] = {"label": label, "status": "OK (занят)"}
                else:
                    results[str(port)] = {"label": label, "status": "FAIL: закрыт"}
            finally:
                s.close()
    return results

# ==================================================

LOGO_FILE = f"{BASE}/logo.bin"
_GROUP_ORDER = ("reality", "vless", "vmess", "trojan", "ss", "hy2", "wg", "awg")
_GROUP_LABELS = {"reality": "Reality", "vless": "VLESS", "vmess": "VMess",
                 "trojan": "Trojan", "ss": "Shadowsocks",
                 "hy2": "Hysteria2", "wg": "WireGuard", "awg": "AmneziaWG"}
PROTOCOLS = [
    {"id": "reality",             "label": "VLESS + Reality",                         "group": "reality", "ui_group": "vless", "net": "tcp",       "tls": False},
    {"id": "vless-xhttp-reality", "label": "VLESS + XHTTP + Reality",                 "group": "reality", "ui_group": "vless", "net": "xhttp",     "tls": False},
    {"id": "vless-ws",            "label": "VLESS + WebSocket",                       "group": "vless",   "ui_group": "vless", "net": "ws",       "tls": False},
    {"id": "vless-ws-tls",        "label": "VLESS + WebSocket + TLS",   "group": "vless",   "ui_group": "vless", "net": "ws",       "tls": True},
    {"id": "vless-tcp-tls",       "label": "VLESS + TCP + TLS",         "group": "vless",   "ui_group": "vless", "net": "tcp",      "tls": True},
    {"id": "vless-grpc-tls",      "label": "VLESS + gRPC + TLS",        "group": "vless",   "ui_group": "vless", "net": "grpc",     "tls": True},
    {"id": "vless-xhttp-tls",     "label": "VLESS + XHTTP + TLS",       "group": "vless",   "ui_group": "vless", "net": "xhttp",    "tls": True},
    {"id": "vmess-ws",            "label": "VMess + WebSocket",                       "group": "vmess",   "net": "ws",       "tls": False},
    {"id": "vmess-ws-tls",        "label": "VMess + WebSocket + TLS",   "group": "vmess",   "net": "ws",       "tls": True},
    {"id": "vmess-tcp-tls",       "label": "VMess + TCP + TLS",         "group": "vmess",   "net": "tcp",      "tls": True},
    {"id": "vmess-grpc-tls",      "label": "VMess + gRPC + TLS",        "group": "vmess",   "net": "grpc",     "tls": True},
    {"id": "trojan-ws-tls",       "label": "Trojan + WebSocket + TLS",             "group": "trojan",  "net": "ws",       "tls": True},
    {"id": "trojan-tcp-tls",      "label": "Trojan + TCP + TLS",        "group": "trojan",  "net": "tcp",      "tls": True},
    {"id": "trojan-grpc-tls",     "label": "Trojan + gRPC + TLS",       "group": "trojan",  "net": "grpc",     "tls": True},
    {"id": "shadowsocks",         "label": "Shadowsocks AEAD (aes-256-gcm)",          "group": "ss",      "net": "tcp",      "tls": False},
    {"id": "hysteria2",           "label": "Hysteria2",                               "group": "hy2",     "net": "udp",      "tls": False},
    {"id": "wireguard",           "label": "WireGuard",                               "group": "wg",      "net": "udp",      "tls": False},
    {"id": "amneziawg",           "label": "AmneziaWG",                               "group": "awg",     "net": "udp",      "tls": False},
]
for _p in PROTOCOLS:
    _p["group_label"] = _GROUP_LABELS.get(_p["group"], _p["group"])
    _p.setdefault("ui_group", _p["group"])
    _p["ui_group_label"] = _GROUP_LABELS.get(_p["ui_group"], _p["ui_group"])
_VALID_PROTOCOLS = tuple(p["id"] for p in PROTOCOLS)
_PROTO_MAP = {p["id"]: p for p in PROTOCOLS}

# Proto labels for bot messages
PROTO_LABELS = {p["id"]: p["label"] for p in PROTOCOLS}
_PORTS = {"reality": 443, "vmess-ws": 10443, "vless-ws": 11443,
          "trojan-ws": 12443, "vless-ws-tls": 13443, "vmess-ws-tls": 14443,
          "trojan-ws-tls": 15443, "vless-tcp-tls": 16443, "vmess-tcp-tls": 17443,
          "trojan-tcp-tls": 18443, "vless-grpc-tls": 19443, "vmess-grpc-tls": 20443,
"trojan-grpc-tls": 21443, "shadowsocks": 22443,
           "vless-xhttp-tls": 23443, "vless-xhttp-reality": 24443,
           "hysteria2": 27443, "wireguard": 28443, "amneziawg": 28444}
# Порт 80 занят nginx/Let's Encrypt, 18080 — telemt web, 9091 — telemt API,
# 7443 — telemt MTProto. 443 намеренно НЕ зарезервирован: на чистом хосте Reality
# должен занять его (см. _find_free_port — bind-тест), а если его держит nginx —
# bind упадёт и порт выделяется резервный. Панель не должна брать 80/telemt-порты.
_RESERVED_PORTS = {80, 8080, 18080, 9091, 7443}
CERT_DIR = f"{BASE}/certs"

def _proto_meta(proto):
    return _PROTO_MAP.get(proto, _PROTO_MAP["reality"])

SESSIONS = {}
SESSIONS_FILE = f"{BASE}/sessions.json"

# Метаданные сессий (IP/UA/время) — хранится параллельно в отдельном файле,
# чтобы не менять формат sessions.json (там {token: expiry_float}).
SESSIONS_META = {}
SESSIONS_META_FILE = f"{BASE}/sessions_meta.json"

def _save_sessions():
    _save(SESSIONS_FILE, dict(SESSIONS))
    try:
        _save(SESSIONS_META_FILE, SESSIONS_META)
    except Exception:
        pass

def _load_sessions():
    try:
        d = json.load(open(SESSIONS_FILE)) or {}
        now = time.time()
        keep = {k: v for k, v in d.items() if isinstance(v, (int, float)) and v > now}
        SESSIONS.update(keep)
    except Exception:
        pass
    try:
        m = json.load(open(SESSIONS_META_FILE)) or {}
        if isinstance(m, dict):
            SESSIONS_META.update(m)
    except Exception:
        pass

AUDIT = []
AUDIT_FILE = f"{BASE}/audit.json"
AUDIT_LIMIT = 2000
_LOGIN_HIST = []
LOGIN_HIST_FILE = f"{BASE}/login_history.json"
LOGIN_HIST_LIMIT = 500

def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

def _load_audit():
    global AUDIT
    try:
        d = json.load(open(AUDIT_FILE)) or []
        if isinstance(d, list):
            AUDIT = d[-AUDIT_LIMIT:]
    except Exception:
        AUDIT = []

def _save_audit():
    try:
        _save(AUDIT_FILE, AUDIT[-AUDIT_LIMIT:])
    except Exception:
        pass

def _audit(ev, **kw):
    """Запись в аудит-журнал. ev — событие, kw — детали (имя клиента, uuid, ip и т.п.)."""
    entry = {"ts": _now_iso(), "ev": ev}
    entry.update({k: v for k, v in kw.items() if v is not None})
    AUDIT.append(entry)
    if len(AUDIT) > AUDIT_LIMIT + 64:
        del AUDIT[: len(AUDIT) - AUDIT_LIMIT]
    try:
        _save_audit()
    except Exception:
        pass

def _login_history(ev, ip=None, ua=None, user=None, ok=True, err=None):
    entry = {"ts": _now_iso(), "ev": ev, "ip": ip, "ua": (ua or "")[:256],
             "user": user, "ok": bool(ok), "err": err}
    _LOGIN_HIST.append(entry)
    if len(_LOGIN_HIST) > LOGIN_HIST_LIMIT + 32:
        del _LOGIN_HIST[: len(_LOGIN_HIST) - LOGIN_HIST_LIMIT]
    try:
        _save(LOGIN_HIST_FILE, _LOGIN_HIST[-LOGIN_HIST_LIMIT:])
    except Exception:
        pass
    _audit("login_" + ev, ip=ip, ua=(ua or "")[:256], user=user, **({"err": err} if err else {}))

# ---------- УСТРОЙСТВА И КЛИЕНТЫ ПОДПИСЧИКОВ (User-Agent + IP с /sub) ----------
_SUBDEV_FILE = f"{BASE}/sub_devices.json"
_SUBPREF_FILE = f"{BASE}/sub_prefs.json"
_SUBDEV_LOCK = threading.Lock()
_SUBDEV = None    # {sub_token: [ {ip,ua,client,version,os,type,old,n,first_ts,last_ts} ]}
_SUBPREF = None   # {sub_token: {"fmt": "auto|base64|singbox"}}
_SUBDEV_MAX_IPS = 24
_UA_CLIENTS = [
    ("v2rayng", "v2rayNG"), ("sing-box", "sing-box"), ("xray-core", "Xray"),
    ("hiddify", "Hiddify"), ("nekobox", "NekoBox"), ("someka", "NekoBox"),
    ("nekocap", "Neko"), ("nekoray", "NekoRay"), ("neko", "Neko"),
    ("streisand", "Streisand"), ("shadowrocket", "Shadowrocket"),
    ("foxray", "FoXray"), ("fock", "FoXray"), ("v2box", "v2Box"),
    ("quantumult", "Quantumult X"), ("stash", "Stash"), ("kitsunebi", "Kitsunebi"),
    ("surfboard", "Surfboard"), ("loon", "Loon"), ("potatso", "Potatso"),
    ("happ", "Happ"), ("flclash", "FlClash"), ("clash-verge", "Clash Verge"),
    ("clashverge", "Clash Verge"), ("v2rayn", "v2rayN"), ("clash", "Clash"),
    ("incy", "INCY"), ("okhttp", "Android-клиент"), ("dalvik", "Android-клиент"),
    ("curl", "curl"), ("python", "скрипт"), ("mozilla", "Браузер"),
]
_OLD_MIN = {"v2rayNG": (1, 8, 0), "v2rayN": (5, 0, 0), "sing-box": (1, 8, 0),
            "NekoBox": (0, 4, 0), "Hiddify": (0, 4, 0), "Happ": (3, 0, 0), "INCY": (1, 0, 0)}
# Коды моделей по префиксу (сначала проверяются, когда UA несёт модель)
_ANDROID_CODES = [
    ("sm-", "Samsung"), ("sgt-", "Samsung"), ("sph-", "Samsung"), ("gt-", "Samsung"),
    ("m0", "Xiaomi"), ("m1", "Xiaomi"), ("m2", "Xiaomi"), ("2109", "Xiaomi"),
    ("2201", "Xiaomi"), ("2307", "Xiaomi"), ("redmi", "Xiaomi"), ("poco", "POCO"),
    ("kb2", "OnePlus"), ("kb5", "OnePlus"), ("hd1", "OnePlus"), ("hd2", "OnePlus"),
    ("rmx", "realme"), ("cph", "OPPO"), ("v20", "vivo"), ("v21", "vivo"), ("v22", "vivo"),
    ("xt2", "Motorola"), ("lnb", "Lenovo"),
]
# Узнаваемые имена брендов (подстрока в UA)
_ANDROID_NAMES = [
    ("samsung", "Samsung"), ("xiaomi", "Xiaomi"), ("redmi", "Redmi"), ("poco", "POCO"),
    ("pixel", "Google Pixel"), ("oneplus", "OnePlus"), ("huawei", "Huawei"), ("honor", "Honor"),
    ("motorola", "Motorola"), ("asus", "ASUS"), ("zenfone", "ASUS"), ("oppo", "OPPO"),
    ("vivo", "vivo"), ("realme", "realme"), ("nokia", "Nokia"), ("lenovo", "Lenovo"),
    ("tecno", "Tecno"), ("infinix", "Infinix"), ("sony", "Sony"), ("lg-", "LG"),
]

def _device_type(u, os_, ua=""):
    """Человекочитаемый тип/бренд устройства из User-Agent (когда он его содержит)."""
    if "iphone" in u: return "📱 iPhone"
    if "ipad" in u:   return "📱 iPad"
    if "ipod" in u:  return "📱 iPod touch"
    if os_ == "iOS": return "📱 iOS-устройство"
    if os_ == "macOS": return "💻 Mac"
    if "windows" in u: return "🖥 Windows"
    if os_ == "Linux": return "🖥 Linux"
    if os_ != "Android": return ""
    src = ua or u
    m = re.search(r"Android[\s\d._]*;\s*([^;)]+)", src)
    model = (m.group(1).strip()[:26] if m else "")
    ml = model.lower()
    if ml:
        for pref, name in _ANDROID_CODES:
            if ml.startswith(pref): return "📱 " + name
    for key, name in _ANDROID_NAMES:
        if key in u: return "📱 " + name
    return "📱 Android" + ((" " + model) if model else "")

def _subdev_load():
    global _SUBDEV, _SUBPREF
    if _SUBDEV is None:
        try:
            d = json.load(open(_SUBDEV_FILE))
            _SUBDEV = d if isinstance(d, dict) else {}
        except Exception:
            _SUBDEV = {}
    if _SUBPREF is None:
        try:
            d = json.load(open(_SUBPREF_FILE))
            _SUBPREF = d if isinstance(d, dict) else {}
        except Exception:
            _SUBPREF = {}

def _parse_client(ua, xclient=""):
    u = (ua or "").lower()
    name = ""
    for needle, pretty in _UA_CLIENTS:
        if needle in u:
            name = pretty
            break
    if not name and (xclient or "").lower() == "incy":
        name = "INCY"
    ver = ""
    if name:
        m = re.search(re.escape(name.lower()) + r"[\s/]*v?(\d+\.\d+(?:\.\d+)?)", u)
        if not m:
            m = re.search(r"(\d+\.\d+(?:\.\d+)?)", u)
        if m:
            ver = m.group(1)
    os_ = ""
    for hay, lab in (("android", "Android"), ("iphone", "iOS"), ("ios", "iOS"),
                     ("mac os", "macOS"), ("macos", "macOS"), ("darwin", "macOS"),
                     ("windows", "Windows"), ("linux", "Linux")):
        if hay in u:
            os_ = lab
            break
    old = False
    if name and ver and name in _OLD_MIN:
        try:
            vt = tuple(int(x) for x in ver.split(".")[:3])
        except Exception:
            vt = ()
        if vt and vt < _OLD_MIN[name]:
            old = True
    dtype = _device_type(u, os_, ua)
    return name, ver, os_, old, dtype

def _subdev_note(token, ip, ua, xclient=""):
    if not token:
        return
    name, ver, os_, old, dtype = _parse_client(ua, xclient)
    ts = _now_iso()
    with _SUBDEV_LOCK:
        _subdev_load()
        lst = _SUBDEV.get(token) or []
        dev = next((d for d in lst if d.get("ip") == ip), None)
        if dev:
            dev["last_ts"] = ts
            dev["n"] = int(dev.get("n", 0)) + 1
            if ua:
                dev["ua"] = (ua or "")[:200]
            if name:
                dev["client"] = name
            if ver:
                dev["version"] = ver
            if os_:
                dev["os"] = os_
            if dtype:
                dev["type"] = dtype
            dev["old"] = bool(old)
        else:
            lst.append({"ip": ip, "ua": (ua or "")[:200], "client": name,
                        "version": ver, "os": os_, "type": dtype, "old": bool(old),
                        "n": 1, "first_ts": ts, "last_ts": ts})
        lst.sort(key=lambda d: d.get("last_ts", ""), reverse=True)
        _SUBDEV[token] = lst[:_SUBDEV_MAX_IPS]
        _save(_SUBDEV_FILE, _SUBDEV)

def _subdev_list(token):
    with _SUBDEV_LOCK:
        _subdev_load()
        return [dict(d) for d in (_SUBDEV.get(token) or [])]

def _subdev_remove(token, ip):
    with _SUBDEV_LOCK:
        _subdev_load()
        _SUBDEV[token] = [d for d in (_SUBDEV.get(token) or []) if d.get("ip") != ip]
        _save(_SUBDEV_FILE, _SUBDEV)

def _subdev_pref(token):
    with _SUBDEV_LOCK:
        _subdev_load()
        return (_SUBPREF.get(token) or {}).get("fmt", "auto")

def _subdev_set_pref(token, fmt):
    if fmt not in ("auto", "base64", "singbox"):
        return False
    with _SUBDEV_LOCK:
        _subdev_load()
        p = _SUBPREF.get(token) or {}
        p["fmt"] = fmt
        _SUBPREF[token] = p
        _save(_SUBPREF_FILE, _SUBPREF)
    return True

def _subdev_prune(valid_tokens):
    with _SUBDEV_LOCK:
        _subdev_load()
        changed = False
        for src in (_SUBDEV, _SUBPREF):
            for k in list(src):
                if k not in valid_tokens:
                    src.pop(k, None)
                    changed = True
        if changed:
            _save(_SUBDEV_FILE, _SUBDEV)
            _save(_SUBPREF_FILE, _SUBPREF)

# ---------- helpers ----------

def _load(p, d=None):
    try:
        with open(p) as f: return json.load(f)
    except Exception: return d

def _save(p, o, mode=0o600):
    os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
    with open(p, "w") as f: json.dump(o, f, indent=2, ensure_ascii=False)
    os.chmod(p, mode)

def _hash(salt, pw):
    return hashlib.sha256((salt + pw).encode()).hexdigest()

def _totp_verify(secret_base32, code, window=1):
    try:
        secret = base64.b32decode(secret_base32.upper().replace(" ", "") + '=' * (-len(secret_base32) % 8))
        counter = int(time.time() // 30)
        for i in range(-window, window + 1):
            c = counter + i
            msg = struct.pack(">Q", c)
            digest = hmac.new(secret, msg, hashlib.sha1).digest()
            o = digest[19] & 15
            token = (struct.unpack(">I", digest[o:o+4])[0] & 0x7fffffff) % 1000000
            if f"{token:06d}" == str(code).strip().zfill(6):
                return True
    except Exception:
        pass
    return False

def _totp_generate_secret():
    import secrets
    return base64.b32encode(secrets.token_bytes(10)).decode('utf-8').rstrip('=')

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

# ---------- AmneziaWG (системный kernel-интерфейс awg0) ----------
AWG_IFACE = "awg0"
AWG_CONF = "/etc/amnezia/amneziawg/awg0.conf"
AWG_ADDR = "10.20.0.1/24"

WG_IFACE = "veilwg"
WG_CONF = "/etc/wireguard/veilwg.conf"
WG_ADDR = "10.10.0.1/24"
AWG_POOL = "10.20.0."
# Параметры обфускации AmneziaWG. S1-S4 — размеры padding (числа 15-150), H1-H4 — уникальные
# номера типов пакетов. ВАЖНО: S1/S2/H1-H4 должны совпадать на сервере и клиенте (server-side).
AWG_JUNK = {
    "Jc": 6, "Jmin": 50, "Jmax": 500,
    "S1": 40, "S2": 90, "S3": 0, "S4": 0,
    "H1": 1, "H2": 2, "H3": 3, "H4": 4
}

def _awg_pubof(priv):
    try:
        r = subprocess.run(["/usr/bin/awg", "pubkey"], input=str(priv).strip(),
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception as e:
        print("awg pubkey err: " + str(e), flush=True)
    return ""

def _awg_read_conf():
    try:
        with open(AWG_CONF) as f:
            text = f.read()
    except Exception:
        return {}
    m = re.search(r"^\s*PrivateKey\s*=\s*(\S+)", text, re.M)
    p = re.search(r"^\s*ListenPort\s*=\s*(\d+)", text, re.M)
    a = re.search(r"^\s*Address\s*=\s*(\S+)", text, re.M)
    mt = re.search(r"^\s*MTU\s*=\s*(\d+)", text, re.M)
    return {"private_key": m.group(1) if m else None,
            "port": int(p.group(1)) if p else None,
            "address": a.group(1) if a else None,
            "mtu": int(mt.group(1)) if mt else 1420}

def _awg_write_conf(inb):
    os.makedirs(os.path.dirname(AWG_CONF), exist_ok=True)
    jk = AWG_JUNK
    with open(AWG_CONF, "w") as f:
        f.write("[Interface]\n"
                f"Address = {inb.get('address') or AWG_ADDR}\n"
                f"ListenPort = {inb['port']}\n"
                f"PrivateKey = {inb['private_key']}\n"
                f"MTU = {inb.get('mtu', 1420)}\n"
                f"Jc = {jk['Jc']}\n"
                f"Jmin = {jk['Jmin']}\n"
                f"Jmax = {jk['Jmax']}\n"
                f"S1 = {jk['S1']}\n"
                f"S2 = {jk['S2']}\n"
                f"H1 = {jk['H1']}\n"
                f"H2 = {jk['H2']}\n"
                f"H3 = {jk['H3']}\n"
                f"H4 = {jk['H4']}\n")
        for c in inb.get("clients", []):
            if c.get("blocked"):
                continue
            if not (c.get("client_public_key") and c.get("address")):
                continue
            f.write("\n[Peer]\n"
                    f"PublicKey = {c['client_public_key']}\n"
                    f"AllowedIPs = {c['address']}\n"
                    "PersistentKeepalive = 25\n")
    os.chmod(AWG_CONF, 0o600)

def _awg_iface_synced(inb):
    try:
        cur = _awg_read_conf()
        if not cur.get("private_key"):
            return False
        if cur.get("private_key") != inb.get("private_key"):
            return False
        if cur.get("port") != inb.get("port"):
            return False
        r = subprocess.run(["ip", "link", "show", AWG_IFACE], capture_output=True, text=True)
        if r.returncode != 0:
            return False
        return True
    except Exception:
        return False

def _awg_restart_iface(st):
    try:
        _awg_write_conf(st["inbounds"]["amneziawg"])
        r = subprocess.run(["systemctl", "restart", "awg-quick@" + AWG_IFACE],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            print("awg restart err: " + (r.stderr or r.stdout), flush=True)
        return r.returncode == 0
    except Exception as e:
        print("awg restart exc: " + str(e), flush=True)
        return False

def _awg_sync(st, force=False):
    """Синхронизирует панель с системой: ключи интерфейса awg0 и список peers."""
    if not st:
        return False
    inbounds = st.setdefault("inbounds", {})
    inb = inbounds.get("amneziawg")
    if inb is None:
        inb = _alloc_inbound(st, "amneziawg")
        inbounds["amneziawg"] = inb
    if not inb.get("private_key"):
        conf = _awg_read_conf()
        if conf.get("private_key") and conf.get("port"):
            inb["private_key"] = conf["private_key"]
            inb["public_key"] = _awg_pubof(conf["private_key"])
            inb["port"] = conf["port"]
            inb.setdefault("address", conf.get("address") or AWG_ADDR)
            inb.setdefault("mtu", int(conf.get("mtu") or 1420))
            inb.setdefault("next_address", 2)
    if not inb.get("public_key"):
        inb["public_key"] = _awg_pubof(inb.get("private_key", ""))
    if not _awg_iface_synced(inb) or force:
        if not inb.get("public_key"):
            inb["public_key"] = _awg_pubof(inb.get("private_key", ""))
        _awg_restart_iface(st)
    # Применяем peers
    try:
        cur = subprocess.run(["/usr/bin/awg", "show", AWG_IFACE, "peers"],
                             capture_output=True, text=True, timeout=10).stdout.split()
    except Exception:
        cur = []
    want = {}
    for c in inb.get("clients", []):
        if c.get("blocked"):
            continue
        if c.get("client_public_key") and c.get("address"):
            want[c["client_public_key"]] = c["address"]
    for pub in cur:
        if pub not in want:
            try:
                subprocess.run(["/usr/bin/awg", "set", AWG_IFACE, "peer", pub, "remove"],
                               capture_output=True, text=True, timeout=10)
            except Exception:
                pass
    for pub, addr in want.items():
        if pub not in cur:
            try:
                subprocess.run(["/usr/bin/awg", "set", AWG_IFACE, "peer", pub,
                                "allowed-ips", addr, "persistent-keepalive", "25"],
                               capture_output=True, text=True, timeout=10)
            except Exception as e:
                print("awg set peer err: " + str(e), flush=True)
    return True

def _wg_pubof(priv):
    try:
        r = subprocess.run(["/usr/bin/wg", "pubkey"], input=str(priv).strip(),
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception as e:
        print("wg pubkey err: " + str(e), flush=True)
    return ""

def _wg_listen_port():
    try:
        r = subprocess.run(["/usr/bin/wg", "show", WG_IFACE, "listen-port"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            try:
                return int(r.stdout.split()[0])
            except Exception:
                pass
    except Exception:
        pass
    return None

def _wg_conf_text(inb):
    parts = ["[Interface]\n",
             f"Address = {inb.get('address') or WG_ADDR}\n",
             f"ListenPort = {inb['port']}\n",
             f"PrivateKey = {inb['private_key']}\n",
             f"MTU = {inb.get('mtu', 1420)}\n"]
    for c in inb.get("clients", []):
        if c.get("blocked"):
            continue
        if not (c.get("client_public_key") and c.get("address")):
            continue
        parts += ["\n[Peer]\n",
                  f"PublicKey = {c['client_public_key']}\n",
                  f"AllowedIPs = {c['address']}\n",
                  "PersistentKeepalive = 25\n"]
    return "".join(parts)

def _wg_iface_synced(inb):
    try:
        r = subprocess.run(["ip", "link", "show", WG_IFACE], capture_output=True, text=True)
        with open(WG_CONF) as f:
            live = f.read()
        return r.returncode == 0 and live == _wg_conf_text(inb) and _wg_listen_port() == inb.get("port")
    except Exception:
        return False

def _wg_write_conf(inb):
    os.makedirs("/etc/wireguard", exist_ok=True)
    with open(WG_CONF, "w") as f:
        f.write(_wg_conf_text(inb))
    os.chmod(WG_CONF, 0o600)

def _wg_restart_iface(st):
    try:
        _wg_write_conf(st["inbounds"]["wireguard"])
        subprocess.run(["systemctl", "stop", "wg-quick@" + WG_IFACE],
                       capture_output=True, text=True, timeout=30)
        r = subprocess.run(["systemctl", "start", "wg-quick@" + WG_IFACE],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            print("wg restart err: " + (r.stderr or r.stdout), flush=True)
        return r.returncode == 0
    except Exception as e:
        print("wg restart exc: " + str(e), flush=True)
        return False

def _wg_sync(st, force=False):
    """Синхронизирует kernel-wireguard интерфейс veilwg: ключи, порт и список peers.
    WireGuard работает на штатном kernel-модуле (через wg-quick@veilwg), а не в Xray:
    userspace-tun Xray пакеты в интернет не маршрутизирует.
    wg-quick сам регистрирует маршруты /32 каждого клиента; при любом изменении
    конфиг переписывается и интерфейс перезапускается."""
    if not st:
        return False
    _ensure_wg_net()
    inbounds = st.setdefault("inbounds", {})
    inb = inbounds.get("wireguard")
    if inb is None:
        inb = _alloc_inbound(st, "wireguard")
        inbounds["wireguard"] = inb
    if not inb.get("private_key"):
        return False
    if not inb.get("public_key"):
        inb["public_key"] = _wg_pubof(inb.get("private_key", ""))
    if not _wg_iface_synced(inb) or force:
        _wg_restart_iface(st)
    return True

def _ensure_wg_net():
    """IPv4-forwarding + NAT masquerade для туннельных подсетей
    (wireguard 10.10.0.0/24 и amneziawg 10.20.0.0/24).
    Идемпотентно; повторно применяется при каждом старте панели."""
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                       capture_output=True, text=True, timeout=10)
        with open("/etc/sysctl.d/99-veil-wg.conf", "w") as f:
            f.write("net.ipv4.ip_forward = 1\n")
    except Exception:
        pass
    try:
        subprocess.run(["nft", "create", "table", "ip", "veil_wg"],
                       capture_output=True, text=True, timeout=10)
        subprocess.run(["nft", "create", "chain", "ip", "veil_wg", "post",
                        "{ type nat hook postrouting priority srcnat; policy accept; }"],
                       capture_output=True, text=True, timeout=10)
    except Exception:
        pass
    try:
        subprocess.run(["nft", "flush", "table", "ip", "veil_wg"],
                       capture_output=True, text=True, timeout=10)
        subprocess.run(["nft", "add", "rule", "ip", "veil_wg", "post",
                        "ip", "saddr", "10.10.0.0/24", "masquerade"],
                       capture_output=True, text=True, timeout=10)
        subprocess.run(["nft", "add", "rule", "ip", "veil_wg", "post",
                        "ip", "saddr", "10.20.0.0/24", "masquerade"],
                       capture_output=True, text=True, timeout=10)
    except Exception as e:
        print("nft err: " + str(e), flush=True)

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

def _ensure_all_protos(st):
    """Гарантирует, что в state созданы ВСЕ поддерживаемые inbounds и каждый
    подписчик присутствует во всех протоколах (по одному клиенту на inbound).
    Требуется для универсальной подписки со всеми протоколами/транспортами."""
    if not st:
        return False
    changed = False
    inbounds = st.setdefault("inbounds", {})
    for proto in _VALID_PROTOCOLS:
        if proto not in inbounds:
            try:
                inbounds[proto] = _alloc_inbound(st, proto)
                changed = True
            except Exception as e:
                print(f"ensure_all: {proto} -> {e}", flush=True)
    # Сгруппируем подписчиков по sub_token (эталонные атрибуты берём из первого вхождения)
    refs = {}
    for inb in inbounds.values():
        for c in inb.get("clients", []):
            key = c.get("sub_token") or c["uuid"]
            if key not in refs:
                refs[key] = {"uuid": c["uuid"], "name": c.get("name") or "Клиент",
                             "sub_token": c.get("sub_token"),
                             "limit_gb": c.get("limit_gb", 0),
                             "expiry": c.get("expiry", 0),
                             "created": c.get("created", 0)}
    # Раскидаем каждого подписчика по всем inbounds (без потери уже существующих клиентов)
    for ref in refs.values():
        for proto, inb in inbounds.items():
            if not inb.get("clients"):
                inb["clients"] = []
            if any(c.get("sub_token") == ref["sub_token"] or c["uuid"] == ref["uuid"]
                   for c in inb["clients"]):
                continue
            c = _new_client(ref["name"], proto, inb)
            c["uuid"] = ref["uuid"]
            if ref["sub_token"]:
                c["sub_token"] = ref["sub_token"]
            for k in ("limit_gb", "expiry", "created"):
                if ref.get(k):
                    c[k] = ref[k]
            inb["clients"].append(c)
            changed = True
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
                raw = base64.b64decode(v + pad, altchars=b"-_")
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
    if proto == "hysteria2":
        cp = _cert_pathes()
        if cp["cert"] and cp["key"]:
            inb["cert"], inb["key"] = cp["cert"], cp["key"]
    if proto == "wireguard":
        priv, pub = _gen_keys()
        inb.update({"private_key": _wg_key_std(priv), "public_key": _wg_key_std(pub),
                    "address": "10.10.0.1/24", "mtu": 1420, "next_address": 2})
    if proto == "amneziawg":
        priv, pub = _gen_keys()
        inb.update({"private_key": _wg_key_std(priv), "public_key": _wg_key_std(pub),
                    "address": AWG_ADDR, "mtu": 1420, "next_address": 2})
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
            capture_output=True, timeout=60)
        os.chmod(HY2_CERT, 0o644)
        os.chmod(HY2_KEY, 0o600)
        try: shutil.chown(HY2_CERT, user="nobody", group="nogroup")
        except Exception: pass
        try: shutil.chown(HY2_KEY, user="nobody", group="nogroup")
        except Exception: pass
    except Exception as e:
        print(f"не удалось создать hy2 cert: {e}", flush=True)

def _deep_merge(base, over):
    """Рекурсивно врезает over в base (словари сливаются, остальное заменяется).
        base не мутируется; пустой/не-словарь over -> копия base без изменений."""
    if not isinstance(over, dict) or not over:
        return dict(base) if isinstance(base, dict) else base
    out = dict(base) if isinstance(base, dict) else {}
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out

def _as_list(v):
    if isinstance(v, list):
        return [x for x in v if str(x).strip()]
    if v is None or str(v).strip() == "":
        return None
    return [x.strip() for x in re.split(r"[,\n;]+", str(v)) if x.strip()]

def _stream_settings(proto, inb):
    meta = _proto_meta(proto)
    adv = inb.get("_adv")
    if proto == "hysteria2":
        dom = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
        cert, key = inb.get("cert"), inb.get("key")
        if not (cert and os.path.exists(cert) and key and os.path.exists(key)):
            _ensure_hy2_cert(dom)
            cert, key = HY2_CERT, HY2_KEY
        masq = {"type": "proxy", "url": "https://" + dom} if dom else {"type": "404"}
        base = {"network": "hysteria",
                "security": "tls",
                "tlsSettings": {"serverName": dom, "alpn": ["h3"],
                                "certificates": [{"certificateFile": cert,
                                                  "keyFile": key}]},
                "hysteriaSettings": {
                    "version": 2,
                    "udpIdleTimeout": 60,
                    "masquerade": masq}}
        return _deep_merge(base, adv)
    if proto == "wireguard":
        return {}
    snis = _as_list(inb.get("snis")) or [inb.get("sni") or "www.samsung.com"]
    sids = _as_list(inb.get("sids")) or ([inb.get("sid")] if inb.get("sid") else [])
    def _reality():
        return {"show": False, "dest": inb.get("dest") or "www.samsung.com:443", "xver": 0,
                "serverNames": snis, "privateKey": inb["private_key"],
                "shortIds": sids}
    if proto == "reality":
        return _deep_merge({"network": "tcp", "security": "reality",
                            "realitySettings": _reality()}, adv)
    path = inb.get("path") or "/veil"
    alpn = _as_list(inb.get("alpn"))
    ss = {"network": meta["net"],
          "security": "tls" if meta["tls"] else "none"}
    if proto == "vless-xhttp-reality":
        ss["security"] = "reality"
        ss["realitySettings"] = _reality()
    if meta["net"] == "ws":
        hdrs = {}
        if inb.get("host"): hdrs["Host"] = inb["host"]
        ss["wsSettings"] = {"path": path, "headers": hdrs}
    elif meta["net"] == "grpc":
        ss["grpcSettings"] = {"serviceName": inb.get("service") or "veil"}
        if inb.get("host"): ss["grpcSettings"]["authority"] = inb["host"]
        if inb.get("mode"): ss["grpcSettings"]["mode"] = inb["mode"]
    elif meta["net"] == "xhttp":
        ss["xhttpSettings"] = {"path": path, "mode": inb.get("mode") or "auto"}
    elif meta["net"] == "splithttp":
        ss["splithttpSettings"] = {"path": path, "mode": inb.get("mode") or "auto"}
    if meta["tls"]:
        ss["tlsSettings"] = {
            "alpn": alpn or (["h2", "http/1.1"] if meta["net"] in ("grpc", "xhttp", "splithttp") else ["http/1.1"]),
            "certificates": [{"certificateFile": inb.get("cert"), "keyFile": inb.get("key")}]}
    return _deep_merge(ss, adv)

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
    sn = inb.get("sniff")
    if sn is False:
        ib["sniffing"] = {"enabled": False}
    elif isinstance(sn, dict) and sn:
        ib["sniffing"] = sn
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
        if "flow" in inb:
            flow = inb.get("flow") or ""
        else:
            flow = "xtls-rprx-vision" if proto == "reality" else ""
        ib["settings"] = {"clients": [
            {"id": c["uuid"], "flow": flow, "email": c["uuid"]}
            for c in inb["clients"]],
            "decryption": "none"}
    ib["streamSettings"] = _stream_settings(proto, inb)
    return _deep_merge(ib, inb.get("_adv_ib"))

_INBOUND_EDIT_KEYS = ("sni", "snis", "dest", "sid", "sids", "path", "host",
                      "service", "mode", "alpn", "sniff", "flow", "mtu",
                      "_adv", "_adv_ib")

def _inbound_public(proto, inb):
    """Безопасное для UI представление точечных настроек inbound (без приватных ключей)."""
    meta = _proto_meta(proto)
    out = {"proto": proto, "port": inb.get("port"),
           "net": meta.get("net", ""), "tls": bool(meta.get("tls")),
           "reality": ("reality" in proto)}
    for k in _INBOUND_EDIT_KEYS:
        if k in inb: out[k] = inb[k]
    return out

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

def _build_xray_cfg(st, force_proto=None):
    inbounds = []
    for proto, inb in (st.get("inbounds") or {}).items():
        if proto in ("amneziawg", "wireguard"):
            continue
        if inb.get("clients") or proto == force_proto:
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

    return {
        "log": {"loglevel": "warning", "access": _XRAY_ACCESS},
        "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService"]},
        "stats": {},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": routing_rules},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True,
                             "statsUserOnline": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True}}}

def _write_xray(st):
    try:
        os.makedirs(os.path.dirname(_XRAY_ACCESS), exist_ok=True)
    except Exception:
        pass
    _save(XRAY, _build_xray_cfg(st), 0o644)

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

def _cycle_key(kind, ts=None):
    """Ключ текущего цикла трафика (UTC). '' = lifetime (без сброса)."""
    if kind not in ("day", "week", "month"):
        return "lifetime"
    d = datetime.datetime.fromtimestamp(
        ts if ts is not None else time.time(), datetime.timezone.utc)
    if kind == "day":  return d.strftime("%Y-%m-%d")
    if kind == "week": return d.strftime("%G-W%V")
    return d.strftime("%Y-%m")

def _traffic_tick(st):
    """Накапливает дельты счётчиков Xray в cycle-полях клиента (up/down).
    Счётчики Xray живут в памяти и обнуляются при рестарте — поэтому ведём
    last_up/last_down и копим дельты. На границе цикла обнуляем накопленное
    и делаем xray api statsreset. Значения зеркалятся во ВСЕ записи одного
    uuid (клиент может быть в нескольких инбаундах с одним uuid). True = изменения."""
    tr = _statsquery()
    if not tr:
        return False
    groups = {}
    for proto, inb in (st.get("inbounds") or {}).items():
        for c in inb.get("clients", []):
            groups.setdefault(c["uuid"], []).append(c)
    changed = False
    for key, cs in groups.items():
        c0 = cs[0]
        ck = _cycle_key(c0.get("reset_cycle"))
        if c0.get("cycle") != ck:
            for c in cs:
                c["cycle"] = ck
                c["up"] = 0; c["down"] = 0
                c["last_up"] = 0; c["last_down"] = 0
                c["warned_80"] = False
            try:
                subprocess.run(
                    ["xray", "api", "statsreset", "--server", f"127.0.0.1:{_STATS_PORT}",
                     "--pattern", f"user>>>{key}>>>"],
                    capture_output=True, text=True, timeout=8)
            except Exception:
                pass
            changed = True
            continue
        t = tr.get(key) or {}
        cu = int(t.get("uplink", 0) or 0); cd = int(t.get("downlink", 0) or 0)
        lu = int(c0.get("last_up") or 0); ld = int(c0.get("last_down") or 0)
        du = cu - lu; dd = cd - ld
        if du < 0: du = cu   # Xray перезапустился — считаем текущее значение с нуля
        if dd < 0: dd = cd
        if du or dd:
            for c in cs:
                c["up"] = int(c.get("up") or 0) + du
                c["down"] = int(c.get("down") or 0) + dd
            _traffic_days_add(du + dd)
            changed = True
        if lu != cu or ld != cd:
            for c in cs:
                c["last_up"] = cu; c["last_down"] = cd
            changed = True
    return changed

# Общесерверная дневная история трафика (для дашборда): {дата: байты}, до 120 дней.
_TRAFFIC_DAYS_FILE = f"{BASE}/logs/traffic_days.json"
_TRAFFIC_DAYS = _load(_TRAFFIC_DAYS_FILE, {}) or {}

def _traffic_days_add(nb):
    if nb <= 0:
        return
    k = time.strftime("%Y-%m-%d", time.gmtime())
    _TRAFFIC_DAYS[k] = int(_TRAFFIC_DAYS.get(k) or 0) + int(nb)
    if len(_TRAFFIC_DAYS) > 120:
        for old in sorted(_TRAFFIC_DAYS)[:len(_TRAFFIC_DAYS) - 120]:
            _TRAFFIC_DAYS.pop(old, None)
    _save(_TRAFFIC_DAYS_FILE, _TRAFFIC_DAYS)

_GB = 1024 ** 3

def _user_traffic(c):
    return int(c.get("up") or 0) + int(c.get("down") or 0)

def _maybe_traffic_alerts(st):
    """TG-предупреждения: 80% лимита, скорая блокировка (3/1 день), сброс цикла.
    Возвращает True, если выставили новые флаги (state надо сохранять)."""
    ids = CFG_CACHE.get("bot_chat_ids") or []
    if not ids:
        return False
    now = time.time()
    changed = False
    seen = set()
    for proto, inb in (st.get("inbounds") or {}).items():
        for c in inb.get("clients", []):
            if c["uuid"] in seen or c.get("blocked"):
                continue
            seen.add(c["uuid"])
            group = []
            for p2, i2 in (st.get("inbounds") or {}).items():
                for c2 in i2.get("clients", []):
                    if c2["uuid"] == c["uuid"]:
                        group.append(c2)
            msgs = []
            lim = float(c.get("limit_gb") or 0)
            if lim > 0 and not c.get("warned_80"):
                if _user_traffic(c) >= lim * _GB * 0.8:
                    msgs.append(
                        f"⚠️ <b>80% лимита</b>\nКлиент: {c.get('name')}\n"
                        f"Использовано: {_user_traffic(c) / _GB:.2f} из {lim:g} ГБ")
                    for g in group: g["warned_80"] = True
                    changed = True
            ex = int(c.get("expiry") or 0)
            if ex > now:
                days_left = int((ex - now) / 86400) + 1
                warned = list(c.get("warned_days") or [])
                for d in (3, 1):
                    if days_left <= d and d not in warned:
                        msgs.append(
                            f"⏳ <b>Срок истекает</b>\nКлиент: {c.get('name')}\n"
                            f"Осталось дней: {days_left}")
                        warned.append(d)
                        for g in group: g["warned_days"] = warned
                        changed = True
                        break
            if msgs:
                try:
                    _bot_send_message(ids[0], "\n".join(msgs), "HTML")
                except Exception as e:
                    print("[alert] " + str(e), flush=True)
    return changed

def _notify_blocked(bl):
    """TG-уведомление о сработавшей автоблокировке."""
    try:
        ids = CFG_CACHE.get("bot_chat_ids") or []
        if not ids or not bl: return
        reason_ru = {"limit": "лимит трафика", "expired": "срок истёк"}
        lines = [f"⛔ <b>Клиент заблокирован:</b> {b['name']} ({reason_ru.get(b['reason'], b['reason'])})"
                 for b in bl]
        _bot_send_message(ids[0], "\n".join(lines), "HTML")
    except Exception as e:
        print("[alert] " + str(e), flush=True)

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

def _subs_summary(st, for_display=False):
    """Агрегированный список подписчиков (как в 3x-ui): по одному на sub_token/uuid,
    со ссылками на ВСЕ протоколы и суммарным трафиком."""
    if not st: return []
    host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
    host = host if "://" not in host else urllib.parse.urlparse(host).netloc
    panel_port = CFG_CACHE.get("panel_port", 8444)
    ipv6 = _my_ipv6()
    users = {}
    state_changed = False
    for proto, inb in (st.get("inbounds") or {}).items():
        for c in inb.get("clients", []):
            if not c.get("sub_token"):
                c["sub_token"] = secrets.token_urlsafe(16)
                state_changed = True
            key = c["sub_token"]
            u = users.get(key)
            if u is None:
                u = {"uuid": c["uuid"], "name": c["name"], "sub_token": key,
                     "created": c.get("created", 0),
                     "limit_gb": float(c.get("limit_gb") or 0),
                     "expiry": int(c.get("expiry") or 0),
                     "reset_cycle": c.get("reset_cycle") or "",
                     "cycle": c.get("cycle") or "lifetime",
                     "max_devices": int(c.get("max_devices") or 0),
                     "blocked": bool(c.get("blocked")),
                     "blocked_reason": c.get("blocked_reason", "") or "",
                     "links": {}, "protos": [], "up": 0, "down": 0}
                users[key] = u
            try:
                u["links"][proto] = _link(inb, host, c, proto)
            except Exception:
                pass
            if proto == "wireguard":
                u["conf_url"] = f"{_pb(host, panel_port)}/api/wgconf/{key}"
            if proto == "amneziawg":
                u["conf_url"] = f"{_pb(host, panel_port)}/api/awgconf/{key}"
            if proto not in [x["proto"] for x in u["protos"]]:
                u["protos"].append({"proto": proto, "label": _proto_meta(proto)["label"],
                                    "port": inb.get("port", 0)})
            if not u.get("_tr_taken"):
                u["_tr_taken"] = True
                u["up"] = int(c.get("up") or 0)
                u["down"] = int(c.get("down") or 0)
    if state_changed:
        _save(STATE, st)
    out = []
    for u in users.values():
        u.pop("_tr_taken", None)
        u["used_gb"] = round((u["up"] + u["down"]) / (1024 ** 3), 3)
        u["sub_url"] = f"{_pb(host, panel_port)}/sub/{u['sub_token']}"
        u["sb_url"] = f"{_pb(host, panel_port)}/sb/{u['sub_token']}"
        u["online"] = int(_online_count(u["uuid"]) or 0)
        out.append(u)
    return out

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

def _validate_and_apply(st, force_proto=None):
    """Проверяет candidate-конфиг через `xray run -test` на временном файле.
    Если валиден — коммитит config.json и state.json и перезапускает xray.
    Если нет — ничего не трогает (STATE на диске остаётся прежним). Возвращает (ok, err)."""
    tmp = os.path.join(os.path.dirname(XRAY), "panel.validate.json")
    try:
        cfg = _build_xray_cfg(st, force_proto=force_proto)
        _save(tmp, cfg, 0o644)
        t = subprocess.run(["xray", "run", "-test", "-config", tmp],
                           capture_output=True, text=True, timeout=30)
        if t.returncode:
            return False, ("конфиг Xray невалиден: "
                           + (t.stderr or t.stdout or "").strip()[:600])
        _save(XRAY, cfg, 0o644)
        _save(STATE, st)
        try:
            subprocess.run(["systemctl", "restart", "xray"], check=True, capture_output=True)
        except Exception as e:
            return False, "xray не перезапустился: " + str(e)
        return True, None
    except subprocess.TimeoutExpired:
        return False, "xray -test: таймаут проверки конфига"
    except Exception as e:
        return False, str(e)
    finally:
        try: os.remove(tmp)
        except Exception: pass

_FP_VALUES = {"firefox", "chrome", "safari", "ios", "android", "edge", "randomized", "random"}

def _fp():
    v = (CFG_CACHE.get("fp") or "").strip().lower()
    return v if v in _FP_VALUES else "firefox"

def _link(inb, host, client, proto):
    meta = _proto_meta(proto)
    fp = _fp()
    _base = client.get("name") or "Veil"
    name = f"{_base} · {meta['label']}"
    if proto == "hysteria2":
        dom = (CFG_CACHE.get("panel_domain") or "").strip() or host
        auth = client.get("auth") or client["uuid"]
        q = urllib.parse.urlencode({"sni": dom})
        return f"hy2://{auth}@{host}:{inb['port']}/?{q}#{urllib.parse.quote(name)}"
    if proto == "amneziawg":
        jk = AWG_JUNK
        cli_junk = ("\n"
                    f"Jc = {jk['Jc']}\n"
                    f"Jmin = {jk['Jmin']}\n"
                    f"Jmax = {jk['Jmax']}\n"
                    f"S1 = {jk['S1']}\n"
                    f"S2 = {jk['S2']}\n"
                    f"H1 = {jk['H1']}\n"
                    f"H2 = {jk['H2']}\n"
                    f"H3 = {jk['H3']}\n"
                    f"H4 = {jk['H4']}\n")
        return ("[Interface]\n"
                f"PrivateKey = {client['client_private_key']}\n"
                f"Address = {client['address']}\n"
                f"DNS = 1.1.1.1, 8.8.8.8\n"
                f"MTU = {inb.get('mtu', 1420)}\n"
                + cli_junk
                + "[Peer]\n"
                f"PublicKey = {inb['public_key']}\n"
                f"Endpoint = {host}:{inb['port']}\n"
                "AllowedIPs = 0.0.0.0/0, ::/0\n"
                "PersistentKeepalive = 25\n"
                "")
    if proto == "wireguard":
        return ("[Interface]\n"
                f"PrivateKey = {client['client_private_key']}\n"
                f"Address = {client['address']}\n"
                f"DNS = 1.1.1.1, 8.8.8.8\n"
                f"MTU = {inb.get('mtu', 1420)}\n\n"
                "[Peer]\n"
                f"PublicKey = {inb['public_key']}\n"
                f"Endpoint = {host}:{inb['port']}\n"
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
             "net": meta["net"], "type": "gun" if meta["net"] == "grpc" else "none", "host": "",
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

# ---------- экспорт / импорт подписчиков (B2) ----------
# Два формата обмена между панелями:
#   json  — внутренний снимок Veil→Veil (identичность + лимиты на каждый протокол),
#           восстанавливается без потерь; хост/порты/ключи сервера берёт приёмник.
#   links — текст ссылок vless/trojan/vmess/ss/hy2 (+ URL подписки) — для 3x-ui,
#           marzban, Hiddify, Remnawave; на импорте пересоздаём клиентов с той же
#           идентичностью/транспортом против СВОЕГО сервера Veil.

def _subs_export_json(st):
    """Внутренний снимок подписчиков (Veil→Veil). Группировка по sub_token."""
    subs = {}
    for proto, inb in (st.get("inbounds") or {}).items():
        if proto not in _VALID_PROTOCOLS:
            continue
        for c in inb.get("clients", []):
            tok = c.get("sub_token") or ""
            if not tok:
                continue
            s = subs.get(tok)
            if s is None:
                s = {"name": c.get("name") or "Клиент", "sub_token": tok,
                     "limit_gb": float(c.get("limit_gb") or 0),
                     "expiry": int(c.get("expiry") or 0),
                     "reset_cycle": c.get("reset_cycle") or "",
                     "max_devices": int(c.get("max_devices") or 0),
                     "tg_proxy": c.get("tg_proxy") or "",
                     "tg_user": c.get("tg_user") or "",
                     "blocked": bool(c.get("blocked")),
                     "blocked_reason": c.get("blocked_reason", "") or "",
                     "created": int(c.get("created") or 0),
                     "clients": []}
                subs[tok] = s
            cc = {"proto": proto}
            for k in ("uuid", "password", "auth", "flow",
                      "client_private_key", "client_public_key", "address"):
                if c.get(k) is not None:
                    cc[k] = c[k]
            s["clients"].append(cc)
    return {"format": "veil-subs-v1", "exported": int(time.time()),
            "panel_version": VERSION, "count": len(subs),
            "subs": list(subs.values())}

def _subs_export_links(st):
    """Текст ссылок для переноса/распространения: по блоку на подписчика."""
    host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
    host = host if "://" not in host else urllib.parse.urlparse(host).netloc
    panel_port = CFG_CACHE.get("panel_port", 8444)
    out = ["# Veil — экспорт подписчиков " + time.strftime("%Y-%m-%d %H:%M"), ""]
    for u in _subs_summary(st):
        protos = [x["proto"] for x in u.get("protos", [])]
        labels = ", ".join(_proto_meta(pr).get("label", pr) for pr in protos)
        out.append("# ==== " + (u.get("name") or "Клиент") + " (" + labels + ") ====")
        for pr in protos:
            ln = (u.get("links") or {}).get(pr)
            if ln and "\n" not in ln:
                out.append(ln)
        if u.get("sub_url"):
            out.append(u["sub_url"])
        if u.get("conf_url"):
            out.append(u["conf_url"])
        out.append("")
    return "\n".join(out).rstrip() + "\n"

def _split_hostport(s):
    s = (s or "").strip()
    if s.startswith("["):
        j = s.find("]")
        host = s[:j + 1]
        rest = s[j + 1:]
        if rest.startswith(":"):
            return host, rest[1:]
        return host, ""
    if s.count(":") == 1:
        a, b = s.split(":", 1)
        return a, b
    return s, ""

def _sub_base_name(name):
    name = (name or "").strip()
    if " · " in name:
        name = name.rsplit(" · ", 1)[0].strip()
    return (name[:40] or "Клиент")

def _map_vless_proto(sec, typ):
    typ = {"splithttp": "xhttp", "tcp": "tcp", "ws": "ws", "grpc": "grpc"}.get(typ, typ)
    if sec == "reality":
        return "vless-xhttp-reality" if typ == "xhttp" else "reality"
    if sec == "tls":
        return {"ws": "vless-ws-tls", "grpc": "vless-grpc-tls",
                "xhttp": "vless-xhttp-tls", "tcp": "vless-tcp-tls"}.get(typ)
    if sec in ("", "none"):
        return "vless-ws" if typ == "ws" else None
    return None

def _map_trojan_proto(typ):
    typ = {"splithttp": "xhttp", "ws": "ws", "grpc": "grpc", "tcp": "tcp"}.get(typ, "tcp")
    return {"ws": "trojan-ws-tls", "grpc": "trojan-grpc-tls", "tcp": "trojan-tcp-tls"}.get(typ)

def _map_vmess_proto(net, tls):
    net = {"splithttp": "xhttp", "h2": "xhttp", "ws": "ws", "grpc": "grpc", "tcp": "tcp"}.get((net or "").lower(), (net or "").lower())
    if net == "ws":   return "vmess-ws-tls" if tls else "vmess-ws"
    if net == "tcp":  return "vmess-tcp-tls" if tls else None
    if net == "grpc": return "vmess-grpc-tls" if tls else None
    return None

def _parse_link_line(line):
    """Одна строка ссылки → dict идентичности + целевой proto Veil, либо None."""
    line = (line or "").strip()
    if not line or line[0] == "#":
        return None
    low = line.lower()
    try:
        if low.startswith("vless://"):
            body = line[8:]
            frag = ""
            if "#" in body: body, frag = body.split("#", 1)
            q = ""
            if "?" in body: body, q = body.split("?", 1)
            params = urllib.parse.parse_qs(q)
            if "@" not in body: return None
            uid, hp = body.rsplit("@", 1)
            sec = (params.get("security") or [""])[0].strip().lower()
            typ = (params.get("type") or [""])[0].strip().lower()
            proto = _map_vless_proto(sec, typ)
            return {"scheme": "vless", "proto": proto, "uuid": uid.strip(),
                    "name": urllib.parse.unquote(frag), "host": _split_hostport(hp)[0]}
        if low.startswith("trojan://"):
            body = line[9:]
            frag = ""
            if "#" in body: body, frag = body.split("#", 1)
            q = ""
            if "?" in body: body, q = body.split("?", 1)
            params = urllib.parse.parse_qs(q)
            if "@" not in body: return None
            pw, hp = body.rsplit("@", 1)
            typ = (params.get("type") or [""])[0].strip().lower()
            return {"scheme": "trojan", "proto": _map_trojan_proto(typ),
                    "password": urllib.parse.unquote(pw),
                    "name": urllib.parse.unquote(frag), "host": _split_hostport(hp)[0]}
        if low.startswith("vmess://"):
            b64 = line[8:].strip()
            pad = "=" * ((4 - len(b64) % 4) % 4)
            try:
                obj = json.loads(base64.b64decode(b64 + pad).decode("utf-8", "replace"))
            except Exception:
                return None
            net = (obj.get("net") or obj.get("type") or "").lower()
            tls = (obj.get("tls") or "").lower() in ("tls", "1", "true")
            return {"scheme": "vmess", "proto": _map_vmess_proto(net, tls),
                    "uuid": (obj.get("id") or "").strip(),
                    "name": urllib.parse.unquote(obj.get("ps") or "")}
        if low.startswith("ss://"):
            body = line[5:]
            frag = ""
            if "#" in body: body, frag = body.split("#", 1)
            if "@" in body:
                cred, hp = body.rsplit("@", 1)
            else:
                cred, hp = body, ""
            method = password = ""
            if ":" in cred:
                method, password = cred.split(":", 1)
            else:
                try:
                    pad = "=" * ((4 - len(cred) % 4) % 4)
                    dec = base64.urlsafe_b64decode(cred + pad).decode("utf-8", "replace")
                    if ":" in dec: method, password = dec.split(":", 1)
                except Exception:
                    password = cred
            return {"scheme": "ss", "proto": "shadowsocks", "ss_method": method or "aes-256-gcm",
                    "password": password, "name": urllib.parse.unquote(frag)}
        if low.startswith("hy2://"):
            body = line[6:]
            frag = ""
            if "#" in body: body, frag = body.split("#", 1)
            if "@" not in body: return None
            auth, hp = body.rsplit("@", 1)
            return {"scheme": "hy2", "proto": "hysteria2", "auth": auth,
                    "name": urllib.parse.unquote(frag)}
    except Exception:
        return None
    return None

def _parse_subscription_blob(blob):
    """Тело подписки (base64-строка ссылок или plain text) → список items без дублей."""
    blob = (blob or "").strip()
    if not blob:
        return []
    cand = [blob]
    try:
        b = blob.replace("-","+").replace("_","/")
        pad = "=" * ((4 - len(b) % 4) % 4)
        dec = base64.b64decode(b + pad).decode("utf-8", "replace")
        if "://" in dec:
            cand.append(dec)
    except Exception:
        pass
    out, seen = [], set()
    for src in cand:
        for ln in src.splitlines():
            it = _parse_link_line(ln)
            if not it:
                continue
            key = (it.get("scheme"), it.get("uuid") or it.get("password") or it.get("auth"),
                   it.get("ss_method"), it.get("proto"))
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
    return out

def _fetch_subscription(url):
    """Бounded server-side GET подписки по URL администратора (для импорта ссылок)."""
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("http", "https"):
        raise ValueError("только http/https")
    ctx = None
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "veil-panel-import"})
    with urllib.request.urlopen(req, timeout=12, context=ctx) as r:
        raw = r.read(2 * 1024 * 1024)
    return raw.decode("utf-8", "replace")

def _import_from_links(st, text):
    """Разбираем вставленный текст ссылок (+URL подписки) и пересоздаём подписчиков
    против этого сервера. Возвращаем (imported_subs, warnings)."""
    warnings = []
    items = []
    fetch_targets = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line[0] == "#":
            continue
        low = line.lower()
        if low.startswith(("http://", "https://")):
            fetch_targets.append(line)
            continue
        it = _parse_link_line(line)
        if it:
            items.append(it)
        else:
            warnings.append("не распознана строка: " + line[:48])
    for url in fetch_targets:
        try:
            items.extend(_parse_subscription_blob(_fetch_subscription(url)))
        except Exception as e:
            warnings.append("не удалось получить подписку " + url[:56] + ": " + str(e)[:70])
    groups = {}
    for it in items:
        groups.setdefault(_sub_base_name(it.get("name")), []).append(it)
    imported = 0
    for base, its in groups.items():
        sub_token = secrets.token_urlsafe(16)
        made = 0
        for it in its:
            proto = it.get("proto")
            if not proto:
                warnings.append(base + ": нет подходящего inbound для " + it.get("scheme", "?") + " — пропущено")
                continue
            inb = (st.get("inbounds") or {}).get(proto)
            if inb is None:
                try:
                    inb = _alloc_inbound(st, proto)
                    st.setdefault("inbounds", {})[proto] = inb
                except Exception as e:
                    warnings.append(base + ": не создал inbound " + proto + ": " + str(e)[:70])
                    continue
            if proto == "shadowsocks":
                if it.get("ss_method"): inb["method"] = it["ss_method"]
                if it.get("password"): inb["password"] = it["password"]
            c = _new_client(base, proto, inb)
            c["sub_token"] = sub_token
            if it.get("uuid") and not any(x.get("uuid") == it["uuid"] for x in inb.get("clients", [])):
                c["uuid"] = it["uuid"]
            elif it.get("uuid"):
                warnings.append(base + ": uuid занят на " + proto + ", назначен новый")
            if proto.startswith("trojan") and it.get("password"):
                c["password"] = it["password"]
            if proto == "hysteria2" and it.get("auth"):
                c["auth"] = it["auth"]
            inb.setdefault("clients", []).append(c)
            made += 1
        if made:
            imported += 1
        else:
            warnings.append(base + ": ни один протокол не импортирован")
    return imported, warnings

def _import_from_json(st, data):
    """Восстанавливаем снимок Veil→Veil без потерь (identичность + лимиты)."""
    warnings = []
    subs = data.get("subs") if isinstance(data, dict) else None
    if not isinstance(subs, list):
        raise ValueError("нет массива subs (ожидаю внутренний формат veil-subs-v1)")
    existing_toks = {c.get("sub_token") for inb in (st.get("inbounds") or {}).values()
                     for c in inb.get("clients", [])}
    imported = 0
    for s in subs:
        if not isinstance(s, dict):
            continue
        name = (s.get("name") or "Клиент").strip()[:40] or "Клиент"
        tok = s.get("sub_token") or ""
        if not tok or tok in existing_toks:
            tok = secrets.token_urlsafe(16)
        else:
            existing_toks.add(tok)
        try: limit_gb = float(s.get("limit_gb") or 0)
        except Exception: limit_gb = 0
        try: expiry = int(s.get("expiry") or 0)
        except Exception: expiry = 0
        try: max_devices = int(s.get("max_devices") or 0)
        except Exception: max_devices = 0
        reset_cycle = (s.get("reset_cycle") or "").strip().lower()
        tg_mode = (s.get("tg_proxy") or "").strip().lower()
        if tg_mode not in ("off", "shared", "personal"):
            tg_mode = ""
        made = 0
        for cc in (s.get("clients") or []):
            proto = (cc or {}).get("proto")
            if proto not in _VALID_PROTOCOLS:
                warnings.append(name + ": неизвестный протокол " + str(proto))
                continue
            inb = (st.get("inbounds") or {}).get(proto)
            if inb is None:
                try:
                    inb = _alloc_inbound(st, proto)
                    st.setdefault("inbounds", {})[proto] = inb
                except Exception as e:
                    warnings.append(name + ": inbound " + proto + ": " + str(e)[:70])
                    continue
            c = _new_client(name, proto, inb, limit_gb=limit_gb or None, expiry=expiry,
                            reset_cycle=reset_cycle, max_devices=max_devices)
            c["sub_token"] = tok
            u = cc.get("uuid")
            if u and not any(x.get("uuid") == u for x in inb.get("clients", [])):
                c["uuid"] = u
            if proto.startswith("trojan") and cc.get("password") is not None:
                c["password"] = cc["password"]
            if proto == "hysteria2" and cc.get("auth"):
                c["auth"] = cc["auth"]
            if tg_mode:
                c["tg_proxy"] = tg_mode
                if s.get("tg_user"):
                    c["tg_user"] = s["tg_user"]
            if s.get("blocked"):
                c["blocked"] = True
                c["blocked_reason"] = s.get("blocked_reason", "") or ""
            inb.setdefault("clients", []).append(c)
            made += 1
        if made:
            imported += 1
        else:
            warnings.append(name + ": ни один клиент не импортирован")
    return imported, warnings

# ---------- sing-box JSON-подписка ----------
# INCY, Happ+, Streisand, SFI/SFA/SFM и другие sing-box клиенты импортируют
# подписку как JSON-массив outbound'ов; многострочные WG-блоки в base64-подписке
# у них не разбираются (показывается только первый vless+reality).

_SB_UA_HINTS = ("incy", "happ", "streisand", "sing-box", "singbox", "sfi", "sfa",
                "sfm", "stray", "nekobox", "foxray", "hiddify", "mysterium",
                "metacube", "v2box", "flutter")

def _need_singbox_sub(ua="", fmt=""):
    fmt = (fmt or "").lower()
    if fmt in ("sing-box", "singbox", "sbox", "json"):
        return True
    if fmt in ("v2ray", "base64", "text", ""):
        return fmt in ("v2ray", "base64", "text")  # явный выбор наоборот
    return False

def _is_singbox_client(ua=""):
    u = (ua or "").lower()
    if not u:
        return False
    for hint in _SB_UA_HINTS:
        if hint in u:
            return True
    return False

def _is_incy_client(ua="", xclient=""):
    # INCY — Xray-клиент (UA: INCY/<version>/<platform>, x-client: INCY).
    # Его подписка — открытые ссылки/база, НЕ sing-box outbound'ы.
    return "incy" in (ua or "").lower() or (xclient or "").lower() == "incy"

def _expire_seconds_client(ua="", xclient=""):
    # subscription-userinfo.expire: по умолчанию миллисекунды (v2rayNG, NekoBox,
    # Hiddify, Clash-клиенты), но INCY (по докам — Unix-секунды), Happ Plus и
    # Shadowrocket (иначе дата искажается) ждут секунды.
    u = (ua or "").lower()
    return ("shadowrocket" in u or "incy" in u or "happ" in u
            or (xclient or "").lower() == "incy")

def _incy_link(proto, inb, c, host):
    """Ссылка в формате INCY: по одной в строке, WG/AmneziaWG — однострочными схемами."""
    meta = _proto_meta(proto)
    base = c.get("name") or "Veil"
    name = f"{base} · {meta['label']}"
    if proto == "amneziawg":
        conf = _link(inb, host, c, proto)
        b64 = base64.urlsafe_b64encode(conf.encode("utf-8")).decode().rstrip("=")
        return f"amneziawg://{b64}#{urllib.parse.quote(name)}"
    if proto == "wireguard":
        # INCY: userinfo (secretKey) он percent-декодирует, а query-параметры — НЕТ
        # (в его конфиг уезжали "N%2FrePA...%3D" и "10.10.0.2%2F32/32").
        # Поэтому: ключ в userinfo кодируем, publickey/address — плейнтекстом,
        # address без префикса /32. Формат: wireguard://secretKey@host:port?publickey=K&address=IP#name
        addr = (c.get("address") or "10.10.0.2/32").split("/")[0]
        key = urllib.parse.quote(c.get("client_private_key") or "", safe="")
        q = "publickey=" + (inb.get("public_key") or "") + "&address=" + addr
        return (f"wireguard://{key}@{host}:{inb['port']}?{q}#{urllib.parse.quote(name)}")
    return _link(inb, host, c, proto)

def _singbox_outbound(proto, inb, c, host):
    meta = _proto_meta(proto)
    fp = _fp()
    base = c.get("name") or "Veil"
    tag = f"{base} · {meta['label']}"
    port = int(inb["port"])
    def _tls():
        if not meta["tls"]:
            return {"enabled": False}
        return {"enabled": True, "server_name": host,
                "utls": {"enabled": True, "fingerprint": fp}}
    def _transport():
        if meta["net"] == "ws":
            return {"type": "ws", "path": "/veil"}
        if meta["net"] == "grpc":
            return {"type": "grpc", "service_name": "veil"}
        if meta["net"] in ("xhttp", "splithttp"):
            return {"type": "xhttp", "path": "/veil"}
        return None
    if proto in ("amneziawg", "wireguard"):
        raw_priv = c.get("client_private_key") or ""
        priv = urllib.parse.unquote(raw_priv).replace("%2F", "/").replace("%2B", "+").replace("%3D", "=")
        raw_pub = inb.get("public_key") or ""
        pub = urllib.parse.unquote(raw_pub).replace("%2F", "/").replace("%2B", "+").replace("%3D", "=")
        raw_addr = c.get("address") or "10.10.0.2/32"
        addr = urllib.parse.unquote(raw_addr).replace("%2F", "/")
        if not addr.endswith("/32") and not "/" in addr:
            addr += "/32"
        elif "/32/32" in addr:
            addr = "10.10.0.2/32"
        ob = {"type": "wireguard", "tag": tag,
              "secretKey": priv,
              "address": [addr],
              "peers": [{
                  "publicKey": pub,
                  "endpoint": f"{host}:{port}",
                  "preSharedKey": inb.get("psk", "")
              }],
              "mtu": int(inb.get("mtu", 1420))}
        return ob
    if proto.startswith("shadowsocks"):
        return {"type": "shadowsocks", "tag": tag, "server": host, "server_port": port,
                "method": inb.get("method") or "aes-256-gcm",
                "password": inb.get("password") or ""}
    if proto == "hysteria2":
        return {"type": "hysteria2", "tag": tag, "server": host, "server_port": port,
                "password": c.get("auth") or c["uuid"],
                "tls": {"enabled": True,
                        "server_name": (CFG_CACHE.get("panel_domain") or "").strip() or host}}
    if proto.startswith("vmess"):
        ob = {"type": "vmess", "tag": tag, "server": host, "server_port": port,
              "uuid": c["uuid"], "security": "auto"}
    elif proto.startswith("trojan"):
        ob = {"type": "trojan", "tag": tag, "server": host, "server_port": port,
              "password": c.get("password") or inb.get("password") or ""}
    else:  # vless family
        ob = {"type": "vless", "tag": tag, "server": host, "server_port": port,
              "uuid": c["uuid"]}
    if proto in ("reality", "vless-xhttp-reality"):
        ob["flow"] = "xtls-rprx-vision"
        ob["tls"] = {"enabled": True, "server_name": inb.get("sni") or host,
                     "reality": {"enabled": True, "public_key": inb.get("public_key") or "",
                                 "short_id": inb.get("sid", "")},
                     "utls": {"enabled": True, "fingerprint": fp}}
    else:
        ob["tls"] = _tls()
    tr = _transport()
    if tr:
        ob["transport"] = tr
    return ob

def _singbox_subscription(st, sub_path, host, tr):
    """JSON-массив sing-box outbound'ов для всех протоколов подписчика.
    tr — результат _statsquery(). Возвращает (outbounds, up, down, total, expiry, sub_name)."""
    outbounds = []
    up = down = total = 0
    expiry = 0
    sub_name = ""
    seen = set()
    for proto, inb in (st.get("inbounds") or {}).items():
        for c in inb.get("clients", []):
            match = (not sub_path) or (c.get("sub_token") == sub_path) or (c["uuid"] == sub_path)
            if not match:
                continue
            sub_name = c.get("name") or sub_name
            key = c["uuid"]
            if key not in seen:
                seen.add(key)
                up += int(c.get("up") or 0)
                down += int(c.get("down") or 0)
                lim = float(c.get("limit_gb") or 0)
                if lim > 0:
                    total = max(total, int(lim * 1024 ** 3))
                ex = int(c.get("expiry") or 0)
                if ex:
                    expiry = max(expiry, ex)
            try:
                outbounds.append(_singbox_outbound(proto, inb, c, host))
            except Exception:
                continue
    return outbounds, up, down, total, expiry, sub_name

# Логотип проекта (файл icon-veil.png из поставки) — отдаётся странице /p/<token>.
_LOGO_PNG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon-veil.png")
if not os.path.exists(_LOGO_PNG):
    _LOGO_PNG = ""

# Каталог приложений для страницы подписки (/p/<token>).
# "link" — deep-link шаблон; плейсхолдеры: {sub} (URL-энкод), {rawsub} (как есть),
#   {b64} (base64 подписки), {wgconf} (base64 личного конфига WireGuard).
# "pay": платное приложение — в списке помещается ниже бесплатных, помечается «платно».
# "wg"/"awg": карточка показывается только если у подписчика есть этот протокол.
# Для WireGuard/AmneziaWG — импорт личного конфига (wgconf:// или скачивание .conf),
# а не подписки.
_SUB_APP_CATALOG = {
    "ios": [
        {"name": "INCY", "ic": "I", "col": "#4f46e5", "col2": "#06b6d4", "store": "https://apps.apple.com/app/incy/id6756943388", "link": "incy://import/{rawsub}#{name}"},
        {"name": "Happ", "ic": "H", "col": "#059669", "col2": "#84cc16", "store": "https://apps.apple.com/app/happ-proxy-utility/id6504287215", "link": ""},
        {"name": "sing-box (SFI)", "ic": "S", "col": "#e11d48", "col2": "#fb7185", "store": "https://apps.apple.com/app/sing-box-mt/id6785326793", "link": "sing-box://import-remote-profile?url={sub}#{name}"},
        {"name": "Streisand", "ic": "S", "col": "#9333ea", "col2": "#d946ef", "store": "https://apps.apple.com/app/streisand/id6450534064", "link": ""},
        {"name": "Foxray", "ic": "F", "col": "#ea580c", "col2": "#f59e0b", "store": "https://apps.apple.com/app/foxray-vpn-fast-secure/id6770070697", "link": ""},
        {"name": "WireGuard", "ic": "W", "col": "#2563eb", "col2": "#22d3ee", "store": "https://apps.apple.com/app/wireguard/id1441195209", "link": "wgconf://{wgconf}", "wg": True},
        {"name": "AmneziaWG", "ic": "A", "col": "#06b6d4", "col2": "#6366f1", "store": "https://apps.apple.com/app/amneziawg/id6478942365", "link": "wgconf://{awgconf}", "awg": True},
        {"name": "Shadowrocket", "ic": "S", "col": "#334155", "col2": "#64748b", "store": "https://apps.apple.com/app/shadowrocket/id932747118", "link": "shadowrocket://add/sub://{b64}?remark={name}", "pay": True},
        {"name": "Stash", "ic": "S", "col": "#7c3aed", "col2": "#a78bfa", "store": "https://apps.apple.com/app/stash-rule-based-proxy/id1596063349", "link": "stash://install-config?url={sub}#{name}", "pay": True},
        {"name": "Loon", "ic": "L", "col": "#e11d48", "col2": "#f43f5e", "store": "https://apps.apple.com/app/loon/id1373567447", "link": "", "pay": True},
    ],
    "android": [
        {"name": "v2rayNG", "ic": "V", "col": "#f59e0b", "col2": "#f97316", "store": "https://github.com/2dust/v2rayNG/releases", "link": "v2rayng://install-sub/?url={sub}#{name}"},
        {"name": "INCY", "ic": "I", "col": "#4f46e5", "col2": "#06b6d4", "store": "https://play.google.com/store/apps/details?id=llc.itdev.incy", "link": "incy://import/{rawsub}#{name}"},
        {"name": "Hiddify", "ic": "H", "col": "#0d9488", "col2": "#2dd4bf", "store": "https://play.google.com/store/apps/details?id=app.hiddify.com", "link": "hiddify://import/{rawsub}#{name}"},
        {"name": "Happ", "ic": "H", "col": "#059669", "col2": "#84cc16", "store": "https://play.google.com/store/apps/details?id=com.happproxy", "link": ""},
        {"name": "Karing", "ic": "K", "col": "#7c3aed", "col2": "#c084fc", "store": "https://karing.app/en/download", "link": ""},
        {"name": "NekoBox", "ic": "N", "col": "#65a30d", "col2": "#a3e635", "store": "https://github.com/MatsuriDayo/NekoBoxForAndroid/releases", "link": "sn://subscription/?url={sub}&name={name}"},
        {"name": "FlClash", "ic": "F", "col": "#06b6d4", "col2": "#22d3ee", "store": "https://github.com/chen08209/FlClash/releases", "link": ""},
        {"name": "sing-box (SFA)", "ic": "S", "col": "#e11d48", "col2": "#fb7185", "store": "https://github.com/SagerNet/sing-box/releases", "link": "sing-box://import-remote-profile?url={sub}#{name}"},
        {"name": "Hysteria2", "ic": "H", "col": "#e11d48", "col2": "#f97316", "store": "https://github.com/apernet/hysteria/releases", "link": "", "hy2": True},
        {"name": "WireGuard", "ic": "W", "col": "#2563eb", "col2": "#22d3ee", "store": "https://play.google.com/store/apps/details?id=com.wireguard.android", "link": "wgconf://{wgconf}", "wg": True},
        {"name": "AmneziaWG", "ic": "A", "col": "#06b6d4", "col2": "#6366f1", "store": "https://play.google.com/store/apps/details?id=org.amnezia.awg", "link": "wgconf://{awgconf}", "awg": True},
        {"name": "Amnezia VPN", "ic": "A", "col": "#0ea5e9", "col2": "#818cf8", "store": "https://play.google.com/store/apps/details?id=org.amnezia.vpn", "link": "", "awg": True},
    ],
    "windows": [
        {"name": "v2rayN", "ic": "V", "col": "#f59e0b", "col2": "#f97316", "store": "https://github.com/2dust/v2rayN/releases", "link": ""},
        {"name": "Hiddify", "ic": "H", "col": "#0d9488", "col2": "#2dd4bf", "store": "https://github.com/hiddify/hiddify-next/releases", "link": "hiddify://import/{rawsub}#{name}"},
        {"name": "Clash Verge Rev", "ic": "C", "col": "#2563eb", "col2": "#3b82f6", "store": "https://github.com/clash-verge-rev/clash-verge-rev/releases", "link": "clash://install-config?url={sub}#{name}"},
        {"name": "FlClash", "ic": "F", "col": "#06b6d4", "col2": "#22d3ee", "store": "https://github.com/chen08209/FlClash/releases", "link": ""},
        {"name": "sing-box (GUI)", "ic": "S", "col": "#e11d48", "col2": "#fb7185", "store": "https://github.com/GUI-for-Cores/GUI.for.SingBox/releases", "link": ""},
        {"name": "Nekoray", "ic": "N", "col": "#65a30d", "col2": "#84cc16", "store": "https://github.com/MatsuriDayo/nekoray/releases", "link": "nekoray://install-config?url={sub}"},
        {"name": "WireGuard", "ic": "W", "col": "#2563eb", "col2": "#22d3ee", "store": "https://www.wireguard.com/install/", "link": "", "wg": True},
        {"name": "AmneziaWG", "ic": "A", "col": "#06b6d4", "col2": "#6366f1", "store": "https://github.com/amnezia-vpn/amneziawg-windows-client/releases/latest", "link": "wgconf://{awgconf}", "awg": True},
    ],
    "macos": [
        {"name": "sing-box (SFM)", "ic": "S", "col": "#e11d48", "col2": "#fb7185", "store": "https://apps.apple.com/app/sing-box-mt/id6785326793", "link": "sing-box://import-remote-profile?url={sub}#{name}"},
        {"name": "Streisand", "ic": "S", "col": "#9333ea", "col2": "#d946ef", "store": "https://apps.apple.com/app/streisand/id6450534064", "link": ""},
        {"name": "FlClash", "ic": "F", "col": "#06b6d4", "col2": "#22d3ee", "store": "https://github.com/chen08209/FlClash/releases", "link": ""},
        {"name": "WireGuard", "ic": "W", "col": "#2563eb", "col2": "#22d3ee", "store": "https://apps.apple.com/app/wireguard/id1451685025", "link": "wgconf://{wgconf}", "wg": True},
        {"name": "Stash", "ic": "S", "col": "#7c3aed", "col2": "#a78bfa", "store": "https://apps.apple.com/app/stash-rule-based-proxy/id1596063349", "link": "stash://install-config?url={sub}#{name}", "pay": True},
    ],
    "apple_tv": [
        {"name": "sing-box (SFT)", "ic": "S", "col": "#e11d48", "col2": "#fb7185", "store": "https://apps.apple.com/app/sing-box-mt/id6785326793", "link": "sing-box://import-remote-profile?url={sub}#{name}"},
        {"name": "WireGuard", "ic": "W", "col": "#2563eb", "col2": "#22d3ee", "store": "https://www.wireguard.com/install/", "link": "wgconf://{wgconf}", "wg": True},
        {"name": "Stash", "ic": "S", "col": "#7c3aed", "col2": "#a78bfa", "store": "https://apps.apple.com/app/stash-rule-based-proxy/id1596063349", "link": "stash://install-config?url={sub}#{name}", "pay": True},
    ],
    "android_tv": [
        {"name": "v2rayNG", "ic": "V", "col": "#f59e0b", "col2": "#f97316", "store": "https://github.com/2dust/v2rayNG/releases", "link": "v2rayng://install-sub/?url={sub}#{name}"},
        {"name": "INCY", "ic": "I", "col": "#4f46e5", "col2": "#06b6d4", "store": "https://play.google.com/store/apps/details?id=llc.itdev.incy", "link": "incy://import/{rawsub}#{name}"},
        {"name": "sing-box (SFA)", "ic": "S", "col": "#e11d48", "col2": "#fb7185", "store": "https://github.com/SagerNet/sing-box/releases", "link": "sing-box://import-remote-profile?url={sub}#{name}"},
        {"name": "NekoBox", "ic": "N", "col": "#65a30d", "col2": "#a3e635", "store": "https://github.com/MatsuriDayo/NekoBoxForAndroid/releases", "link": "sn://subscription/?url={sub}&name={name}"},
        {"name": "Hiddify", "ic": "H", "col": "#0d9488", "col2": "#2dd4bf", "store": "https://play.google.com/store/apps/details?id=app.hiddify.com", "link": "hiddify://import/{rawsub}#{name}"},
        {"name": "WireGuard", "ic": "W", "col": "#2563eb", "col2": "#22d3ee", "store": "https://play.google.com/store/apps/details?id=com.wireguard.android", "link": "wgconf://{wgconf}", "wg": True},
    ],
    "linux": [
        {"name": "FlClash", "ic": "F", "col": "#06b6d4", "col2": "#22d3ee", "store": "https://github.com/chen08209/FlClash/releases", "link": ""},
        {"name": "Clash Verge Rev", "ic": "C", "col": "#2563eb", "col2": "#3b82f6", "store": "https://github.com/clash-verge-rev/clash-verge-rev/releases", "link": "clash://install-config?url={sub}#{name}"},
        {"name": "Nekoray", "ic": "N", "col": "#65a30d", "col2": "#84cc16", "store": "https://github.com/MatsuriDayo/nekoray/releases", "link": "nekoray://install-config?url={sub}"},
        {"name": "Hiddify", "ic": "H", "col": "#0d9488", "col2": "#2dd4bf", "store": "https://github.com/hiddify/hiddify-next/releases", "link": "hiddify://import/{rawsub}#{name}"},
        {"name": "WireGuard", "ic": "W", "col": "#2563eb", "col2": "#22d3ee", "store": "https://www.wireguard.com/install/", "link": "", "wg": True},
    ],
}
_SUB_PLATFORM_LABELS = {
    "ios": "iOS", "android": "Android", "windows": "Windows", "macos": "macOS",
    "apple_tv": "Apple TV", "android_tv": "Android TV", "linux": "Linux",
}

def _sub_status(u, now=None):
    now = now or time.time()
    if u.get("blocked"):
        reason = u.get("blocked_reason") or ""
        why = {"limit": "исчерпан лимит трафика", "expired": "подписка истекла"}.get(reason, "заблокирован")
        return "disabled", f"Отключена — {why}"
    ex = int(u.get("expiry") or 0)
    if ex and now > ex:
        return "disabled", "Отключена — срок действия истёк"
    lim = float(u.get("limit_gb") or 0)
    used = float(u.get("used_gb") or 0)
    if lim > 0 and used >= lim * 0.95:
        return "disabled", "Отключена — исчерпан лимит трафика"
    return "active", "Активна"

def _sub_ua_platform(ua=""):
    u = (ua or "").lower()
    if "appletv" in u or "tvos" in u:
        return "apple_tv"
    if "android" in u and "tv" in u:
        return "android_tv"
    if "android" in u:
        return "android"
    if "windows" in u or "win" in u:
        return "windows"
    if "linux" in u:
        return "linux"
    if "iphone" in u or "ipod" in u or "ipad" in u or "ios" in u:
        return "ios"
    if "macintosh" in u or "mac os" in u:
        return "macos"
    return "ios"

def _sub_page_html(u, sub_url, host, panel_port, ua="", devs=None):
    status, status_txt = _sub_status(u)
    now = time.time()
    ex = int(u.get("expiry") or 0)
    if ex:
        exp_txt = time.strftime("%d.%m.%Y", time.localtime(ex))
        dl = int(ex - now)
        if dl < 0:
            exp_sub = "срок истёк"
        elif dl < 86400:
            exp_sub = "осталось меньше суток"
        else:
            days = int(dl // 86400)
            exp_sub = (f"остался 1 день" if days == 1
                       else f"осталось {days} дня" if days < 5
                       else f"осталось {days} дней")
    else:
        exp_txt = "Без ограничения"
        exp_sub = "срок не задан"
    lim = float(u.get("limit_gb") or 0)
    used = float(u.get("used_gb") or 0)
    if lim > 0:
        pct = min(100.0, used / lim * 100)
        trf_txt = f"{used:.2f} / {lim:.1f} GB"
        pct_txt = "лимит исчерпан" if pct >= 100 else f"{pct:.1f}%"
    else:
        pct = 0.0
        trf_txt = f"{used:.2f} GB · безлимит"
        pct_txt = "безлимит"
    name_plain = str(u.get("name") or "Подписка")
    name_html = name_plain.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    onl = int(u.get("online") or 0)
    conns = len(u.get("protos") or [])
    tok = u["sub_token"]
    page_url = f"{_pb(host, panel_port)}/p/{tok}"
    cls = "ok" if status == "active" else "off"
    sub64 = base64.urlsafe_b64encode(sub_url.encode("utf-8")).decode().rstrip("=")
    avatar = (name_plain[:1] or "V").upper()
    links = u.get("links") or {}
    wg_conf = links.get("wireguard") or ""
    awg_conf = links.get("amneziawg") or ""
    def _b64(s):
        return base64.urlsafe_b64encode(s.encode("utf-8")).decode().rstrip("=") if s else ""
    wg_b64, awg_b64 = _b64(wg_conf), _b64(awg_conf)
    wg_url = f"{_pb(host, panel_port)}/api/wgconf/{tok}"
    awg_url = f"{_pb(host, panel_port)}/api/awgconf/{tok}"
    conf_blocks = []
    if wg_conf:
        conf_blocks.append('<a class="btn-conf" href="' + wg_url + '" download>'
                           '<svg viewBox="0 0 24 24"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>'
                           'WireGuard · .conf</a>')
    if awg_conf:
        conf_blocks.append('<a class="btn-conf" href="' + awg_url + '" download>'
                           '<svg viewBox="0 0 24 24"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>'
                           'AmneziaWG · .conf</a>')
    if u.get("sb_url"):
        conf_blocks.append('<a class="btn-conf" href="' + u["sb_url"] + '">'
                           '<svg viewBox="0 0 24 24"><path d="M4 4h16v16H4z"/><path d="M9 9h6v6H9z"/></svg>'
                           'sing-box · полный конфиг</a>')
    confs_html = "<div class='confs'>" + "".join(conf_blocks) + "</div>" if conf_blocks else ""
    # Строка под именем: лимиты вместо дубля окончания срока (он есть в карточках).
    cyc_label = {"day": "ежедневно", "week": "еженедельно",
                 "month": "ежемесячно"}.get(u.get("reset_cycle") or "", "")
    try: mdev = int(u.get("max_devices") or 0)
    except Exception: mdev = 0
    segs = []
    if cyc_label:
        segs.append("сброс " + cyc_label)
    if mdev:
        segs.append(f"до {mdev} устр.")
    if segs:
        head_line = "<b>" + " · ".join(segs) + "</b> · " + exp_sub
    else:
        head_line = ("Подписка <b>до " + exp_txt + "</b> · " if ex else "Подписка <b>бессрочная</b> · ") + exp_sub
    split = (CFG_CACHE.get("split_tunnel") or "off").strip().lower()
    rt_html = ""
    if split == "ru":
        rt_html = ("<div class='sec'><h2>Маршрутизация</h2><div class='rt'>"
                   "<b>Российские сайты и приложения идут напрямую</b>, остальное — через туннель.<br>"
                   "Готовые правила — в кнопке «sing-box · полный конфиг» выше (подходит для Happ, SFI/SFA, Streisand, NekoBox, Hiddify). "
                   "Клиентам, которые импортируют ссылки, правило нужно включить в самом приложении:"
                   "<ul>"
                   "<li><b>Shadowrocket</b>: Настройки → Маршрутизация → добавить правила <code>GEOSITE,category-ru,DIRECT</code> и <code>GEOIP,ru,DIRECT</code>.</li>"
                   "<li><b>v2rayNG</b>: Настройки маршрутизации → «Пользовательские» → правило <code>geosite:category-ru</code> → Direct.</li>"
                   "<li><b>INCY</b>: своих гео-правил нет — вместо ссылки подписки возьмите «sing-box · полный конфиг».</li>"
                   "</ul></div></div>")
    elif split == "ir":
        rt_html = ("<div class='sec'><h2>Маршрутизация</h2><div class='rt'>"
                   "<b>Через туннель идут только иранские сервисы</b>, остальной трафик — напрямую.<br>"
                   "Готовые правила — в кнопке «sing-box · полный конфиг» выше. В ссылочных клиентах правило настраивается в самом приложении:"
                   "<ul>"
                   "<li><b>Shadowrocket</b>: Настройки → Маршрутизация → <code>GEOIP,ir,PROXY</code> и <code>GEOSITE,ir,PROXY</code>, финальное правило — DIRECT.</li>"
                   "<li><b>v2rayNG</b>: «Пользовательские» → <code>geoip:ir</code> / <code>geosite:ir</code> → Proxy, остальные правила → Direct.</li>"
                   "<li><b>INCY</b>: своих гео-правил нет — возьмите «sing-box · полный конфиг».</li>"
                   "</ul></div></div>")
    hy2_conf = links.get("hysteria2") or ""
    cat = {k: [dict(a) for a in v
               if not (a.get("wg") and not wg_conf)
               and not (a.get("awg") and not awg_conf)
               and not (a.get("hy2") and not hy2_conf)]
           for k, v in _SUB_APP_CATALOG.items()}
    catalog_json = json.dumps(cat, ensure_ascii=False)
    plat_default = _sub_ua_platform(ua)
    if plat_default not in cat:
        plat_default = next(iter(cat), "")
    def _esc(s):
        return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))
    def _ago_txt(iso):
        try:
            dt = datetime.datetime.fromisoformat(iso).timestamp()
        except Exception:
            return ""
        s = max(0, int(now - dt))
        if s < 120: return "только что"
        if s < 3600: return "%d мин назад" % (s // 60)
        if s < 86400: return "%d ч назад" % (s // 3600)
        return "%d дн назад" % (s // 86400)
    drows = []
    for d in (devs or [])[:10]:
        cli = _esc(d.get("client") or "Клиент")
        ver = _esc(d.get("version") or "")
        typ = _esc(d.get("type") or "")
        osl = _esc(d.get("os") or "")
        ip = _esc(d.get("ip") or "")
        ago = _esc(_ago_txt(d.get("last_ts") or ""))
        try: n = int(d.get("n") or 1)
        except Exception: n = 1
        who = cli + ((" " + ver) if ver else "")
        sub = " · ".join(x for x in (typ or osl, ip,
                     (ago + ((" ×%d" % n) if n > 1 else "")) if ago else "") if x)
        drows.append('<div class="devr"><div class="devi"><b>' + who +
                     '</b><span>' + sub + '</span></div>'
                     '<button class="devx" data-ip="' + ip + '">Забыть</button></div>')
    if drows:
        devs_html = ('<div class="sec"><h2>Мои устройства</h2><div class="devlist">'
                     + "".join(drows) + '</div><div class="devnote">Устройства, '
                     'которые запрашивали вашу подписку. «Забыть» уберёт запись, '
                     'пока клиент снова не обновит подписку с этого адреса.</div></div>')
    else:
        devs_html = ''
    plats_json = json.dumps([[k, _SUB_PLATFORM_LABELS.get(k, k)] for k in cat], ensure_ascii=False)
    tpl = """<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/png" href="/logo.png">
<meta name="theme-color" content="#0a122a">
<title>__NAMEHT__ · подписка</title><style>
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0}
body{min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#e8ecf7;
  background:#0a122a;display:flex;justify-content:center;padding:28px 14px 56px;position:relative}
.bg{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.blob{position:absolute;border-radius:50%;filter:blur(90px);opacity:.45;animation:drift 18s ease-in-out infinite}
.b1{width:52vmax;height:52vmax;left:-18vmax;top:-20vmax;background:radial-gradient(circle,#24407f,transparent 65%)}
.b2{width:46vmax;height:46vmax;right:-16vmax;top:20%;background:radial-gradient(circle,#0e6f8f,transparent 65%);animation-delay:-6s}
.b3{width:40vmax;height:40vmax;left:12%;bottom:-22vmax;background:radial-gradient(circle,#143f5e,transparent 65%);animation-delay:-11s}
@keyframes drift{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(4vmax,-3vmax) scale(1.06)}66%{transform:translate(-3vmax,3vmax) scale(.96)}}
.ray{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.3;
  background:radial-gradient(900px 600px at 50% -12%,rgba(56,189,248,.10),transparent 60%)}
.page{width:100%;max-width:460px;position:relative;z-index:1}
.hbar{display:flex;align-items:center;gap:11px;margin-bottom:18px;padding:0 2px}
.hbar .lg{width:40px;height:40px;border-radius:12px;object-fit:cover;box-shadow:0 8px 20px -6px rgba(34,211,238,.5)}
.hbar .br{min-width:0;display:flex;flex-direction:column;justify-content:center}
.hbar .br b{font-size:15px;font-weight:800;letter-spacing:3px;line-height:1}
.hbar .br span{font-size:10.5px;color:#8b94b5;letter-spacing:.3px;margin-top:3px}
.hbar .pill{margin-left:auto;display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:999px;
  font-size:12px;font-weight:700;white-space:nowrap}
.pill.ok{background:rgba(74,222,128,.1);color:#4ade80;border:1px solid rgba(74,222,128,.35)}
.pill.off{background:rgba(251,113,133,.1);color:#fb7185;border:1px solid rgba(251,113,133,.35)}
.pill i{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}
.pill.ok i{animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.card{background:rgba(18,23,42,.72);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border:1px solid rgba(66,84,130,.45);border-radius:24px;overflow:hidden;
  box-shadow:0 30px 80px -24px rgba(0,0,0,.8)}
.head{display:flex;align-items:center;gap:14px;padding:20px 20px 16px;
  background:linear-gradient(180deg,rgba(59,130,246,.16),rgba(34,211,238,.04) 60%,transparent)}
.ava{width:64px;height:64px;border-radius:20px;flex:0 0 auto;display:flex;align-items:center;justify-content:center;
  font-size:30px;font-weight:800;color:#04101f;position:relative;
  background:linear-gradient(135deg,#3b82f6,#22d3ee);box-shadow:0 14px 30px -8px rgba(34,211,238,.5)}
.ava .ring{position:absolute;inset:-3px;border-radius:23px;border:2px solid transparent;pointer-events:none;
  border-top-color:rgba(125,211,252,.9);animation:spin 7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.meta{min-width:0}
.meta .name{font-size:22px;font-weight:800;color:#f2f5ff;margin:0;line-height:1.2;word-break:break-word}
.meta .sub{font-size:12.5px;color:#8b94b5;margin-top:6px;word-break:break-word}
.meta .sub b{color:#a5b4fc;font-weight:600}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:16px 20px 0}
.stat{position:relative;border-radius:16px;padding:12px 13px 14px;background:rgba(22,29,52,.85);
  border:1px solid rgba(66,84,130,.4);overflow:hidden}
.stat::before{content:'';position:absolute;inset:auto 0 0 0;height:2px;
  background:linear-gradient(90deg,#3b82f6,#22d3ee);opacity:.6}
.stat svg{width:14px;height:14px;stroke:#60a5fa;stroke-width:2;fill:none;stroke-linecap:round;stroke-linejoin:round;margin-bottom:8px}
.stat .lb{font-size:10px;color:#8b94b5;text-transform:uppercase;letter-spacing:.8px;font-weight:600}
.stat b{display:block;font-size:14px;font-weight:700;color:#eef2ff;margin-top:5px;line-height:1.35;word-break:break-word}
.stat b .dim{color:#8b94b5;font-weight:400;font-size:11px}
.barwrap{padding:14px 20px 16px}
.track{height:10px;border-radius:99px;background:rgba(10,15,33,.8);box-shadow:inset 0 2px 6px rgba(0,0,0,.5);
  overflow:hidden;position:relative}
.track i{display:block;height:100%;border-radius:99px;transition:width .6s cubic-bezier(.4,0,.2,1);position:relative;
  background:linear-gradient(90deg,#2563eb,#22d3ee,#34d399);background-size:200% 100%;animation:flows 3.5s linear infinite}
@keyframes flows{to{background-position:200% 0}}
.tl{display:flex;justify-content:space-between;align-items:baseline;margin-top:8px}
.tl span{font-size:11.5px;color:#8b94b5}
.tl b{font-size:12px;color:#cbd5f1;font-weight:600}
.confs{display:flex;gap:9px;padding:0 20px 6px;flex-wrap:wrap}
.confs:empty{display:none}
.btn-conf{flex:1;min-width:150px;display:inline-flex;align-items:center;justify-content:center;gap:7px;
  padding:11px 10px;border-radius:13px;text-decoration:none;font-size:12.5px;font-weight:600;color:#bfe3ff;
  background:rgba(30,58,138,.5);border:1px solid rgba(59,130,246,.45);transition:.15s}
.btn-conf:hover{border-color:#3b82f6;background:rgba(30,58,138,.85)}
.btn-conf svg{width:14px;height:14px;stroke:currentColor;stroke-width:2;fill:none;stroke-linecap:round;stroke-linejoin:round}
.rt{font-size:12.5px;color:#9aa6c8;line-height:1.65;background:rgba(22,29,52,.75);
  border:1px solid rgba(66,84,130,.4);border-radius:14px;padding:12px 14px}
.rt b{color:#cbd5f1}
.rt ul{margin:8px 0 0;padding-left:18px}
.rt li{margin:5px 0}
.rt code{color:#7dd3fc;font-size:11px;background:rgba(10,15,33,.6);padding:1px 5px;border-radius:5px}
.devlist{display:flex;flex-direction:column;gap:8px}
.devr{display:flex;align-items:center;gap:10px;background:rgba(22,29,52,.75);
  border:1px solid rgba(66,84,130,.4);border-radius:14px;padding:10px 12px}
.devi{min-width:0;flex:1;display:flex;flex-direction:column;gap:3px}
.devi b{font-size:13px;font-weight:700;color:#edf2fb;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.devi span{font-size:11px;color:#8b94b5;overflow-wrap:anywhere}
.devx{flex:0 0 auto;font:inherit;font-size:11.5px;font-weight:600;cursor:pointer;color:#fca5a5;
  background:rgba(251,113,133,.1);border:1px solid rgba(251,113,133,.35);border-radius:10px;padding:7px 12px;transition:.15s}
.devx:hover{background:rgba(251,113,133,.2)}
.devx:disabled{opacity:.5;cursor:default}
.devnote{font-size:11px;color:#58618a;margin-top:10px;line-height:1.55}
.sec{padding:18px 20px 20px}
h2{font-size:13px;color:#94a3c4;text-transform:uppercase;letter-spacing:.8px;margin:0 0 12px;font-weight:700;
  display:flex;align-items:center}
h2::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,rgba(66,84,130,.5),transparent);margin-left:12px}
.chips{display:flex;gap:8px;overflow-x:auto;padding-bottom:6px;margin-bottom:14px;scrollbar-width:none}
.chips::-webkit-scrollbar{display:none}
.chip-p{flex:0 0 auto;display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:999px;cursor:pointer;
  font-size:12.5px;font-weight:600;color:#9aa6c8;border:1px solid rgba(66,84,130,.5);background:rgba(22,29,52,.6);transition:.15s}
.chip-p:hover{color:#e8ecf7;border-color:#3b82f6}
.chip-p.sel{color:#04101f;background:linear-gradient(90deg,#3b82f6,#22d3ee);border-color:transparent;font-weight:700;
  box-shadow:0 8px 20px -8px rgba(34,211,238,.6)}
.apps{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media (max-width:420px){.apps{grid-template-columns:1fr}}
.app{display:flex;align-items:center;gap:11px;padding:11px;border-radius:16px;cursor:pointer;
  background:rgba(22,29,52,.75);border:1px solid rgba(66,84,130,.4);transition:.15s;min-width:0}
.app:hover{border-color:#3b82f6;transform:translateY(-1px)}
.app.sel{border-color:#22d3ee;background:rgba(19,33,58,.92);
  box-shadow:0 0 0 1px #22d3ee inset,0 10px 24px -12px rgba(34,211,238,.5)}
.ic{width:38px;height:38px;border-radius:11px;flex:0 0 auto;display:flex;align-items:center;justify-content:center;
  font-size:17px;font-weight:800;color:#fff;text-shadow:0 1px 2px rgba(0,0,0,.3);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.25),0 6px 14px -6px rgba(0,0,0,.6)}
.inf{min-width:0;flex:1}
.inf b{display:block;font-size:13px;font-weight:700;color:#edf2fb;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tags{display:flex;align-items:center;gap:5px;margin-top:5px;flex-wrap:wrap}
.tags a.store{font-size:10.5px;color:#60a5fa;text-decoration:none;font-weight:600}
.tags a.store:active{opacity:.7}
.tag{font-size:9px;font-weight:700;letter-spacing:.4px;padding:2px 7px;border-radius:999px;text-transform:uppercase}
.tag.pay{color:#fbbf24;border:1px solid rgba(251,191,36,.45);background:rgba(251,191,36,.1)}
.tag.cfg{color:#7dd3fc;border:1px solid rgba(125,211,252,.4);background:rgba(125,211,252,.08)}
.ck{width:21px;height:21px;border-radius:50%;flex:0 0 auto;display:flex;align-items:center;justify-content:center;
  font-size:11px;font-weight:800;color:transparent;border:1px solid rgba(94,109,166,.6);background:rgba(10,15,33,.5);transition:.15s}
.app.sel .ck{color:#04101f;background:#22d3ee;border-color:#22d3ee;box-shadow:0 0 12px rgba(34,211,238,.7)}
.btn{width:100%;padding:15px;border-radius:15px;border:0;cursor:pointer;font-size:15px;font-weight:800;letter-spacing:.2px;
  display:inline-flex;align-items:center;justify-content:center;gap:9px;transition:.15s;font-family:inherit}
.btn svg{width:16px;height:16px;stroke:currentColor;stroke-width:2.2;fill:none;stroke-linecap:round;stroke-linejoin:round}
.btn-add{background:linear-gradient(90deg,#2563eb,#22d3ee);color:#04101f;position:relative;overflow:hidden;
  box-shadow:0 14px 34px -10px rgba(34,211,238,.6)}
.btn-add::after{content:'';position:absolute;top:0;bottom:0;width:40%;left:-60%;transform:skewX(-20deg);
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.4),transparent);animation:sheen 3.4s ease-in-out infinite}
@keyframes sheen{0%,60%{left:-60%}100%{left:130%}}
.btn-add:active{transform:scale(.985)}
.btn-row{display:flex;gap:10px;margin-top:10px}
.btn-row .btn-copy{flex:1;background:rgba(26,34,64,.8);color:#c7d0ea;border:1px solid rgba(66,84,130,.5)}
.btn-row .btn-copy:hover{border-color:#3b82f6;color:#eef2ff}
.action{max-width:460px;padding-top:18px;position:relative;z-index:1;width:100%}
.hint{font-size:12px;color:#8b94b5;margin-top:12px;line-height:1.55;text-align:center;min-height:18px}
.footer{font-size:11px;color:#58618a;margin:18px 4px 0;text-align:center;line-height:1.9;word-break:break-all;position:relative;z-index:1}
.footer b{font-weight:600;color:#7b85ab}
.footer code{color:#5d6a94;font-size:10px}
.fade{animation:rise .5s ease both}
@keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@media (min-width:760px){
.page{max-width:680px}
.action{max-width:680px}
.apps{grid-template-columns:repeat(3,1fr)}
@media (max-width:900px){.apps{grid-template-columns:1fr 1fr}}
.stats{grid-template-columns:repeat(4,1fr)}
.head{padding:24px 26px 18px}
.stats,.barwrap,.confs{padding-left:26px;padding-right:26px}
.sec{padding:20px 26px 24px}
.meta .name{font-size:24px}
}
</style></head><body>
<div class="bg"><div class="blob b1"></div><div class="blob b2"></div><div class="blob b3"></div></div>
<div class="ray"></div>
<div class="page">
 <header class="hbar fade">
  <img src="/logo.png" class="lg" alt="Veil" width="40" height="40">
  <div class="br"><b>VEIL</b><span>личный кабинет подписки</span></div>
  <span class="pill __CLS__"><i></i>__STATUS__</span>
 </header>
 <main class="card fade" style="animation-delay:.08s">
  <div class="head">
   <div class="ava"><span class="ring"></span>__AVA__</div>
   <div class="meta">
    <div class="name">__NAMEHT__</div>
    <div class="sub">__HEADLINE__</div>
   </div>
  </div>
  <div class="stats">
   <div class="stat"><svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg><div class="lb">Окончание</div><b>__EXP__<span class="dim"> · __EXPSUB__</span></b></div>
   <div class="stat"><svg viewBox="0 0 24 24"><circle cx="12" cy="15" r="8"/><path d="M12 15l3.5-3.5M5 5l4 4"/></svg><div class="lb">Трафик</div><b>__TRF__</b></div>
   <div class="stat"><svg viewBox="0 0 24 24"><path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z"/></svg><div class="lb">Онлайн</div><b>__ONL__</b></div>
   <div class="stat"><svg viewBox="0 0 24 24"><path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/></svg><div class="lb">Протоколов</div><b>__CONNS__</b></div>
  </div>
  <div class="barwrap">
   <div class="track"><i style="width:__PCT__%"></i></div>
   <div class="tl"><span>использовано трафика</span><b>__PCTLBL__</b></div>
  </div>
  __CONFS__
  <div class="sec">
   <h2>Устройство</h2>
   <div class="chips" id="chips"></div>
   <div id="apps" class="apps"></div>
  </div>
  __DEVS__
  __RT__
 </main>
 <div class="action">
  <button class="btn btn-add fade" style="animation-delay:.16s" id="addBtn"><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg><span id="addLbl">Добавить / Импортировать</span></button>
  <div class="btn-row fade" style="animation-delay:.22s">
   <button class="btn btn-copy" id="copyBtn"><svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54 0l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54 0l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>Скопировать подписку</button>
   <button class="btn btn-copy" id="shareBtn"><svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="M8.6 13.5l6.8 4M15.4 6.5l-6.8 4"/></svg>Поделиться</button>
  </div>
  <div class="hint" id="hint" style="animation:none">Выберите приложение и нажмите «Добавить / Импортировать».</div>
 </div>
 <div class="footer"><b>Подписка:</b> <code>__SUB__</code><br><b>Ваша страница:</b> <code>__PAGE__</code></div>
</div>
<script>
const CATALOG=__CAT__;
const SUB=__SUBJS__;
const B64=__B64JS__;
const NAME=__NAMEJS__;
const WGCONF=__WGCONF__;
const AWGCONF=__AWGCONF__;
const WGDOWN=__WGDOWN__;
const AWGDOWN=__AWGDOWN__;
const PLATS=__PLATS__;
const TOK=__TOK__;
let cur=null;
let lastK=__PLATDEFAULT__;
const HP=document.getElementById.bind(document);
function hint(m,c){const h=HP('hint');h.textContent=m;h.style.color=c||'#8b94b5';}
function buildLink(a){return (a.link||'')
  .replace('{b64}',B64).replace('{rawsub}',SUB).replace('{sub}',encodeURIComponent(SUB))
  .replace('{name}',encodeURIComponent(NAME)).replace('{wgconf}',WGCONF).replace('{awgconf}',AWGCONF);}
function selHint(){
  if(!cur){hint('Сначала выберите приложение из списка.','#fbbf24');return false;}
  if(cur.wg||cur.awg){
    if(cur.link){hint((cur.wg?'WireGuard':'AmneziaWG')+': откроется импорт или скачается .conf.','#7dd3fc');}
    else{hint((cur.wg?'WireGuard':'AmneziaWG')+': конфиг будет скачан как .conf.','#7dd3fc');}
  }else if(cur.link){
    hint('Открываем «'+cur.name+'…». Если не открылось — скопируйте подписку кнопкой ниже.');
  }else{
    hint('«'+cur.name+'» — внешний клиент: установите из магазина (ссылка «Скачать») и импортируйте подписку через «Скопировать подписку».','#fbbf24');
  }
  return true;
}
function app(a){
  const d=document.createElement('div');d.className='app fade';
  d.style.animationDelay=Math.min((CATALOG[lastK]||[]).indexOf(a)*.03,.3)+'s';
  const ic=document.createElement('span');ic.className='ic';
  ic.textContent=String(a.ic||(a.name||'?')[0]).toUpperCase();
  ic.style.background='linear-gradient(135deg,'+(a.col||'#3b82f6')+' 0%,'+(a.col2||'#22d3ee')+' 100%)';
  const inf=document.createElement('div');inf.className='inf';
  const b=document.createElement('b');b.textContent=a.name;
  const tg=document.createElement('div');tg.className='tags';
  if(a.pay){const p=document.createElement('span');p.className='tag pay';p.textContent='платно';tg.appendChild(p);}
  else if(a.wg||a.awg){const p=document.createElement('span');p.className='tag cfg';p.textContent='.conf';tg.appendChild(p);}
  if(a.store){const x=document.createElement('a');x.href=a.store;x.target='_blank';x.rel='noopener';x.className='store';x.textContent='Скачать ↗';
    x.addEventListener('click',function(e){e.stopPropagation();});tg.appendChild(x);}
  inf.appendChild(b);inf.appendChild(tg);
  const ck=document.createElement('span');ck.className='ck';ck.textContent='✓';
  d.appendChild(ic);d.appendChild(inf);d.appendChild(ck);
  d.addEventListener('click',function(){
    cur=a;
    Array.prototype.forEach.call(d.parentNode.children,function(e){e.classList.remove('sel');});
    d.classList.add('sel');selHint();
  });
  return d;
}
function render(){
  const box=HP('apps');box.innerHTML='';
  const arr=CATALOG[lastK]||[];
  arr.forEach(a=>box.appendChild(app(a)));
  if(arr.indexOf(cur)<0)cur=arr[0]||null;
  if(cur){const el=box.children[arr.indexOf(cur)];if(el)el.classList.add('sel');}
  selHint();
  const lbl=HP('addLbl');
  if(cur&&cur.link)lbl.textContent='Добавить / Импортировать';
  else if(cur&&(cur.wg||cur.awg))lbl.textContent='Установить конфиг';
  else if(cur)lbl.textContent='Как подключиться';
  else lbl.textContent='Добавить / Импортировать';
}
function renderChips(){
  const box=HP('chips');box.innerHTML='';
  for(const e of PLATS){
    const k=e[0],lb=e[1];
    const c=document.createElement('div');c.className='chip-p'+(k===lastK?' sel':'');c.textContent=lb;
    c.addEventListener('click',function(){lastK=k;cur=null;renderChips();render();});
    box.appendChild(c);
  }
}
document.addEventListener('DOMContentLoaded',function(){
  renderChips();
  render();
  HP('addBtn').addEventListener('click',function(){
    if(!selHint())return;
    if(cur.wg||cur.awg){
      location.href=cur.link?buildLink(cur):(cur.wg?WGDOWN:AWGDOWN);
      return;
    }
    if(cur.link){location.href=buildLink(cur);return;}
    if(navigator.clipboard){
      navigator.clipboard.writeText(SUB).then(function(){
        hint('Ссылка подписки скопирована. Откройте «'+cur.name+'» и импортируйте её.','#4ade80');
      }).catch(function(){hint('Не удалось скопировать автоматически.');});
    }else{hint('Не удалось скопировать автоматически.');}
  });
  HP('copyBtn').addEventListener('click',function(){
    if(navigator.clipboard){
      navigator.clipboard.writeText(SUB).then(function(){hint('Ссылка подписки скопирована.','#4ade80');})
        .catch(function(){hint('Не удалось скопировать автоматически.');});
    }else{hint('Не удалось скопировать автоматически.');}
  });
  HP('shareBtn').addEventListener('click',function(){
    if(navigator.share){
      navigator.share({title:NAME,text:NAME,url:SUB}).catch(function(){hint('Копируйте ссылку вручную кнопкой выше.');});
    }else if(navigator.clipboard){
      navigator.clipboard.writeText(SUB).then(function(){hint('Ссылка подписки скопирована.','#4ade80');})
        .catch(function(){hint('Не удалось скопировать автоматически.');});
    }else{hint('Не удалось скопировать автоматически.');}
  });
  Array.prototype.forEach.call(document.querySelectorAll('.devx'),function(btn){
    btn.addEventListener('click',function(){
      var ip=btn.getAttribute('data-ip');
      if(!confirm('Забыть это устройство?'))return;
      btn.disabled=true;
      fetch('/p/'+encodeURIComponent(TOK)+'/forget',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})})
        .then(function(r){return r.json();})
        .then(function(j){ if(j&&j.ok){var row=btn.closest('.devr'); if(row) row.remove(); hint('Устройство забыто.','#4ade80');} else {hint('Не удалось забыть устройство: '+((j&&j.error)||'ошибка'),'#fb7185'); btn.disabled=false;} })
        .catch(function(){hint('Сеть недоступна.','#fb7185'); btn.disabled=false;});
    });
  });
});
</script></body></html>"""
    return (tpl.replace("__AVA__", avatar)
                .replace("__NAMEHT__", name_html)
                .replace("__CLS__", cls).replace("__STATUS__", status_txt)
                .replace("__EXP__", exp_txt).replace("__EXPSUB__", exp_sub)
                .replace("__TRF__", trf_txt).replace("__PCT__", f"{pct:.2f}")
                .replace("__PCTLBL__", pct_txt)
                .replace("__ONL__", str(onl)).replace("__CONNS__", str(conns))
                .replace("__SUB__", sub_url).replace("__PAGE__", page_url)
                .replace("__CONFS__", confs_html)
                .replace("__HEADLINE__", head_line)
                .replace("__DEVS__", devs_html)
                .replace("__RT__", rt_html)
                .replace("__SUBJS__", json.dumps(sub_url))
                .replace("__B64JS__", json.dumps(sub64))
                .replace("__NAMEJS__", json.dumps(name_plain, ensure_ascii=False))
                .replace("__WGCONF__", json.dumps(wg_b64))
                .replace("__AWGCONF__", json.dumps(awg_b64))
                .replace("__WGDOWN__", json.dumps(wg_url))
                .replace("__AWGDOWN__", json.dumps(awg_url))
                .replace("__CAT__", catalog_json)
                .replace("__PLATS__", plats_json)
                .replace("__TOK__", json.dumps(u["sub_token"]))
                .replace("__PLATDEFAULT__", json.dumps(plat_default)))

def _new_client(name, proto=None, inb=None, **kw):
    c = {"uuid": str(uuidlib.uuid4()),
         "name": (name or "").strip() or "Кент",
         "sub_token": secrets.token_urlsafe(16),
         "created": int(time.time())}
    # Лимиты трафика/срок (0 = без ограничений)
    c["limit_gb"] = float(kw.get("limit_gb") or 0)
    c["expiry"] = int(kw.get("expiry") or 0)
    rc = (kw.get("reset_cycle") or "").strip().lower()
    c["reset_cycle"] = rc if rc in ("day", "week", "month") else ""
    c["cycle"] = _cycle_key(c["reset_cycle"])
    c["up"] = 0; c["down"] = 0
    try: c["max_devices"] = max(0, int(kw.get("max_devices") or 0))
    except Exception: c["max_devices"] = 0
    if proto and proto.startswith("trojan"):
        c["password"] = secrets.token_urlsafe(12)
    if proto == "hysteria2":
        c["auth"] = secrets.token_hex(16)
    if proto == "wireguard" and inb is not None:
        priv, pub = _gen_keys()
        addr = inb.get("next_address", 2)
        inb["next_address"] = addr + 1
        c["client_private_key"] = _wg_key_std(priv)
        c["client_public_key"] = _wg_key_std(pub)
        c["address"] = f"10.10.0.{addr}/32"
    if proto == "amneziawg" and inb is not None:
        priv, pub = _gen_keys()
        addr = inb.get("next_address", 2)
        inb["next_address"] = addr + 1
        c["client_private_key"] = _wg_key_std(priv)
        c["client_public_key"] = _wg_key_std(pub)
        c["address"] = f"{AWG_POOL}{addr}/32"
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

# ---------- Telegram Bot Processing ----------

def _is_admin(chat_id):
    admin_ids = CFG_CACHE.get("bot_chat_ids", [])
    return str(chat_id) in [str(x) for x in admin_ids]

def _main_menu_keyboard():
    return {"inline_keyboard": [
        [{"text": "📊 Статус", "callback_data": "cmd_status"},
         {"text": "👥 Клиенты", "callback_data": "cmd_clients"}],
        [{"text": "➕ Добавить подписку", "callback_data": "cmd_addsub"},
         {"text": "🔄 Перезапустить Xray", "callback_data": "cmd_restart"}],
        [{"text": "🔐 2FA", "callback_data": "cmd_2fa"},
         {"text": "❓ Помощь", "callback_data": "cmd_help"}],
    ]}

# Многошаговое добавление подписки: chat_id -> {"step": "name"|"limit"|"days", ...}
BOT_NEW_SUB = {}
# Флаг активного «низкого» статуса доступности из РФ (для дедупликации оповещений)
_GP_LOW_ALERT_ACTIVE = False

def _gp_maybe_alert(entry):
    global _GP_LOW_ALERT_ACTIVE
    try:
        total = int(entry.get("total_count") or 0)
        ok = int(entry.get("success_count") or 0)
        if total <= 0:
            return
        pct = ok * 100.0 / total
        ids = (CFG_CACHE.get("bot_chat_ids") or [])
        if not ids:
            return
        if pct <= 50.0 and not _GP_LOW_ALERT_ACTIVE:
            _GP_LOW_ALERT_ACTIVE = True
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%d.%m %H:%M")
            _bot_send_message(ids[0],
                f"🚨 <b>Доступность из РФ упала ниже 50%!</b>\n"
                f"Зонды: {ok}/{total} ({pct:.0f}%)\n"
                f"Время: {ts} UTC\n"
                f"Подробности проведи проверку в панели или нажми 📊 Статус",
                "HTML")
        elif pct > 50.0 and _GP_LOW_ALERT_ACTIVE:
            _GP_LOW_ALERT_ACTIVE = False
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%d.%m %H:%M")
            _bot_send_message(ids[0],
                f"✅ Доступность из РФ восстановилась: {ok}/{total} ({pct:.0f}%) · {ts} UTC",
                "HTML")
    except Exception:
        pass

def _gp_last_history():
    try:
        with open(f"{BASE}/globalping_history.json", "r") as f:
            h = json.load(f)
    except Exception:
        return None
    if not isinstance(h, list) or not h:
        return None
    last = h[-1]
    total = int(last.get("total_count") or 0)
    ok = int(last.get("success_count") or 0)
    if total <= 0:
        return None
    pct = ok * 100.0 / total
    ts = str(last.get("created_at") or "")[:16].replace("T", " ")
    return ok, total, pct, ts

def _create_subscription(name, limit_gb=0, expiry_days=0):
    st = _load(STATE)
    if st is None:
        st = _new_state("reality")
    _migrate_state(st)
    sub_token = secrets.token_urlsafe(16)
    client_uuid = str(uuidlib.uuid4())
    expiry = (int(time.time()) + int(expiry_days) * 86400) if int(expiry_days) > 0 else 0
    host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
    host = host if "://" not in host else urllib.parse.urlparse(host).netloc
    panel_port = CFG_CACHE.get("panel_port", 8444)
    inbounds = st.setdefault("inbounds", {})
    for proto in _VALID_PROTOCOLS:
        if proto not in inbounds:
            try:
                inbounds[proto] = _alloc_inbound(st, proto)
            except Exception as e:
                print(f"create_sub alloc {proto} -> {e}", flush=True)
    if not inbounds:
        inbounds["reality"] = _alloc_inbound(st, "reality")
    first_link = None
    for proto, inb in inbounds.items():
        c = _new_client(name, proto, inb, limit_gb=float(limit_gb) or 0, expiry=expiry)
        c["uuid"] = client_uuid
        c["sub_token"] = sub_token
        inb.setdefault("clients", []).append(c)
        lnk = _link(inb, host, c, proto)
        if not first_link:
            first_link = lnk
    _awg_sync(st)
    _wg_sync(st)
    _write_xray(st)
    _save(STATE, st)
    _restart_xray()
    sub_url = f"{_pb(host, panel_port)}/sub/{sub_token}"
    return {"name": name, "sub_token": sub_token, "sub_url": sub_url,
            "link": first_link or "", "limit_gb": float(limit_gb) or 0,
            "expiry_days": int(expiry_days)}

def _bot_send_message(chat_id, text, parse_mode=None, reply_markup=None):
    token = CFG_CACHE.get("bot_token", "")
    if not token:
        return
    if len(text) > 4000:
        text = text[:4000] + "\n… (обрезано)"
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = {"chat_id": chat_id, "text": text}
        if parse_mode:
            data["parse_mode"] = parse_mode
        if reply_markup:
            data["reply_markup"] = json.dumps(reply_markup)
        data = json.dumps(data).encode()
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10):
            pass
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        print(f"[bot] sendMessage HTTP {e.code}: {body}", flush=True)
    except Exception as e:
        print("[bot] sendMessage error: " + str(e), flush=True)

def _bot_answer_callback(callback_query_id, text=None, show_alert=False):
    token = CFG_CACHE.get("bot_token", "")
    if not token:
        return
    try:
        url = f"https://api.telegram.org/bot{token}/answerCallbackQuery"
        data = {"callback_query_id": callback_query_id}
        if text:
            data["text"] = text
        if show_alert:
            data["show_alert"] = True
        data = json.dumps(data).encode()
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception as e:
        print("[bot] answerCallbackQuery error: " + str(e), flush=True)

def _process_bot_update(update):
    message = update.get("message") or update.get("edited_message")
    callback_query = update.get("callback_query")
    
    if callback_query:
        callback_query_id = callback_query["id"]
        message = callback_query.get("message")
        if not message:
            # Answer callback query even if no message (shouldn't happen but safety)
            _bot_answer_callback(callback_query_id, "Ошибка: нет сообщения", show_alert=True)
            return
        chat_id = message["chat"]["id"]
        from_id = callback_query["from"]["id"]
        data = callback_query["data"]
        if not _is_admin(from_id):
            _bot_send_message(chat_id, f"⛔ Нет прав доступа. Ваш ID: {from_id}. Админ ID: {CFG_CACHE.get('bot_chat_ids', [])}")
            _bot_answer_callback(callback_query_id, "⛔ Нет прав доступа", show_alert=True)
            return
        # Answer callback query first (required by Telegram)
        _bot_answer_callback(callback_query_id)
        if data == "cmd_status":
            cmd = "/status"
        elif data == "cmd_clients":
            cmd = "/clients"
        elif data == "cmd_restart":
            cmd = "/restart"
        elif data == "cmd_addsub":
            cmd = "/addsub"
        elif data == "cmd_help":
            cmd = "/help"
        elif data == "cmd_stats":
            cmd = "/stats"
        elif data == "cmd_2fa":
            cmd = "/2fa"
        else:
            return
        # Simulate command processing
        text = cmd
    else:
        message = update.get("message") or update.get("edited_message")
        if not message:
            return
        chat_id = message.get("chat", {}).get("id")
        from_id = message.get("from", {}).get("id")
        text = message.get("text", "").strip()
        if not text.startswith("/"):
            stp = BOT_NEW_SUB.get(chat_id)
            if stp and stp.get("step") and _is_admin(from_id):
                step = stp["step"]
                if step == "name":
                    name = text.strip()
                    if not name:
                        _bot_send_message(chat_id, "Имя не может быть пустым. Напиши имя ещё раз или /cancel", "HTML")
                        return
                    stp["name"] = name[:40]
                    stp["step"] = "limit"
                    BOT_NEW_SUB[chat_id] = stp
                    _bot_send_message(chat_id,
                        "👤 Имя: <b>" + _html.escape(stp["name"]) + "</b>\n"
                        "Теперь <b>лимит</b> трафика в ГБ (число, <code>0</code> = безлимит, можно дробное: 12.5):\n"
                        "Отмена: /cancel", "HTML")
                elif step == "limit":
                    try:
                        limit_gb = float(text.replace(",", ".").strip())
                        if limit_gb < 0:
                            raise ValueError
                    except ValueError:
                        _bot_send_message(chat_id, "Нужно число. Повтори лимит (0 = безлимит) или /cancel", "HTML")
                        return
                    stp["limit_gb"] = limit_gb
                    stp["step"] = "days"
                    BOT_NEW_SUB[chat_id] = stp
                    _bot_send_message(chat_id,
                        "Лимит: <b>" + str(limit_gb) + "</b> ГБ\nТеперь <b>срок</b> в днях (число, <code>0</code> = бессрочно):\n"
                        "Отмена: /cancel", "HTML")
                elif step == "days":
                    try:
                        days = int(text.strip())
                        if days < 0:
                            raise ValueError
                    except ValueError:
                        _bot_send_message(chat_id, "Нужно целое число дней. Повтори (0 = бессрочно) или /cancel", "HTML")
                        return
                    stp["days"] = days
                    BOT_NEW_SUB.pop(chat_id, None)
                    name = stp.get("name") or "Клиент"
                    try:
                        r = _create_subscription(name, limit_gb=stp.get("limit_gb", 0), expiry_days=days)
                    except Exception as e:
                        _bot_send_message(chat_id, f"❌ Ошибка создания: {e}")
                        return
                    lim = "безлимит" if r["limit_gb"] <= 0 else (str(r["limit_gb"]) + " ГБ")
                    day = "бессрочно" if r["expiry_days"] <= 0 else (str(r["expiry_days"]) + " дн.")
                    _bot_send_message(chat_id,
                        f"✅ <b>Подписка создана</b>\nИмя: <code>{_html.escape(name)}</code>\n"
                        f"Лимит: {lim} · Срок: {day}\n"
                        f"Подписка: <code>{r['sub_url']}</code>\n"
                        f"Скопируй ссылку в приложение (v2rayNG / Hiddify / Streisand / NekoBox / Happ / Shadowrocket).",
                        "HTML", _main_menu_keyboard())
            return
    
    if not _is_admin(from_id):
        _bot_send_message(chat_id, "⛔ Нет прав доступа")
        return
    
    parts = text.split()
    cmd = parts[0].lower().split("@", 1)[0]
    args = parts[1:]
    try:
        if cmd == "/start":
            _bot_send_message(chat_id, 
                f"🤖 <b>Veil Panel Bot</b>\nВаш Chat ID: <code>{chat_id}</code>\n\nВыберите действие:",
                "HTML", _main_menu_keyboard())
        elif cmd == "/clients":
            st = _load(STATE, {}) or {}
            lines = ["👥 <b>Клиенты:</b>"]
            for proto, inb in (st.get("inbounds") or {}).items():
                for c in inb.get("clients", []):
                    online = "🟢" if c.get("online") else "⚪"
                    limit = f" ({c.get('limit_gb', 0)} ГБ)" if c.get("limit_gb", 0) > 0 else ""
                    lines.append(f"{online} {_html.escape(str(c.get('name', '?')))} — {_html.escape(str(PROTO_LABELS.get(proto, proto)))}{limit}")
            _bot_send_message(chat_id, "\n".join(lines) if len(lines) > 1 else "Клиентов нет", "HTML", _main_menu_keyboard())
        elif cmd == "/restart":
            _restart_xray()
            _bot_send_message(chat_id, "🔄 Xray перезапущен", reply_markup=_main_menu_keyboard())
        elif cmd == "/addsub":
            BOT_NEW_SUB[chat_id] = {"step": "name", "name": ""}
            _bot_send_message(chat_id,
                "➕ <b>Новая подписка</b>\nШаг 1 из 3. Отправь <b>имя</b> клиента (например: <b>Мама</b>).\nОтмена: /cancel",
                "HTML")
        elif cmd == "/cancel":
            BOT_NEW_SUB.pop(chat_id, None)
            _bot_send_message(chat_id, "Отменено.", reply_markup=_main_menu_keyboard())
        elif cmd == "/help":
            _bot_send_message(chat_id, "<b>Команды:</b>\n/start — меню\n/status — статус и статистика\n/clients — список клиентов\n/restart — перезагрузить Xray\n/addsub — создать новую подписку (имя → лимит → срок)\n/2fa — настройка 2FA", "HTML", _main_menu_keyboard())
        elif cmd in ("/status", "/stats"):
            st = _load(STATE, {}) or {}
            running = subprocess.run(["systemctl", "is-active", "--quiet", "xray"]).returncode == 0
            clients = _client_count(st)
            uptime = _service_active_since("xray")
            gp = _gp_last_history()
            if gp:
                ok, total, pct, ts = gp
                gp_txt = f"🇷🇺 Доступность из РФ: {'🟢' if pct > 50 else '🔴'} {ok}/{total} ({pct:.0f}%) · {ts} UTC"
            else:
                gp_txt = "🇷🇺 Доступность из РФ: — (проверок ещё не было, открой панель)"
            cpu = mem = None
            try:
                m = get_system_metrics()
                cpu = m.get("cpu_usage"); mem = m.get("mem_usage")
            except Exception:
                pass
            disk = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=3).stdout
            _bot_send_message(chat_id,
                f"📊 <b>Статус и статистика</b>\nXray: {'🟢 работает' if running else '🔴 остановлен'}\n"
                f"Аптайм: {uptime or '—'}\nКлиентов: {clients}\nНод: {len(_load_nodes())}\n"
                f"{gp_txt}\n"
                f"CPU: {cpu if cpu is not None else '—'} · RAM: {mem if mem is not None else '—'}\n"
                f"Диск: {disk.splitlines()[1] if len(disk.splitlines())>1 else '—'}",
                "HTML", _main_menu_keyboard())
        elif cmd == "/2fa":
            _bot_send_message(chat_id, 
                "🔐 <b>2FA настройка</b>\nНастройте 2FA в панели: вкладка <b>Безопасность</b> → <b>Двухфакторная аутентификация</b>",
                "HTML", _main_menu_keyboard())
        else:
            _bot_send_message(chat_id, "Неизвестная команда. /help", reply_markup=_main_menu_keyboard())
    except Exception as e:
        import traceback
        print("[bot] ошибка обработки " + str(text) + ": " + str(e), flush=True)
        traceback.print_exc()
        try:
            _bot_send_message(chat_id, "⚠️ Ошибка: " + str(e))
        except Exception:
            pass

def _load_nodes():
    try:
        st = _load(STATE, {}) or {}
        return [n for n in (st.get("nodes") or {})]
    except Exception:
        return []

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


# ---------- node federation: входящий API (/api/ext/*) ----------

_EXT_SCOPES = ("read", "write")
_EXT_HITS = {}
_EXT_LOCK = threading.Lock()

def _node_tokens():
    toks = CFG_CACHE.get("node_tokens")
    return toks if isinstance(toks, list) else []

def _save_node_tokens(toks):
    CFG_CACHE["node_tokens"] = toks
    _save(CFG, CFG_CACHE)

def _ext_rate_ok(ip):
    now = time.time()
    with _EXT_LOCK:
        q = [t for t in (_EXT_HITS.get(ip) or []) if now - t < 10]
        if len(q) >= 30:
            _EXT_HITS[ip] = q
            return False
        q.append(now)
        _EXT_HITS[ip] = q
        if len(_EXT_HITS) > 512:
            for k in [k for k, v in _EXT_HITS.items() if not v or now - max(v) > 60]:
                _EXT_HITS.pop(k, None)
    return True

def _ext_auth(self, need_write=False):
    """Auth /api/ext/* по Bearer/X-Node-Token. Возвращает dict токена или None (ответ отправлен)."""
    ip = self.client_address[0] if getattr(self, "client_address", None) else "?"
    if not _ext_rate_ok(ip):
        _audit("ext_rate_limit", ip=ip)
        self._send(429, {"error": "слишком много запросов"})
        return None
    auth = self.headers.get("Authorization", "") or ""
    tok = auth[7:].strip() if auth.startswith("Bearer ") else (self.headers.get("X-Node-Token") or "").strip()
    if not tok or len(tok) > 128:
        self._send(401, {"error": "unauthorized"})
        return None
    given = hashlib.sha256(tok.encode()).hexdigest()
    match = None
    for t in _node_tokens():
        h = t.get("hash") or ""
        if isinstance(h, str) and h and secrets.compare_digest(given, h):
            match = t
            break
    if not match:
        _audit("ext_denied", ip=ip, token_hint=(given[:12] or None))
        self._send(401, {"error": "unauthorized"})
        return None
    if need_write and "write" not in (match.get("scopes") or []):
        self._send(403, {"error": "токен только для чтения"})
        return None
    now = int(time.time())
    if now - int(match.get("last_used") or 0) > 300:
        match["last_used"] = now
        _save_node_tokens(_node_tokens())
    return match

def _ext_owned_group(st, tid, u):
    return [c for proto, inb in (st.get("inbounds") or {}).items()
            for c in inb.get("clients", []) if c.get("uuid") == u and c.get("ext_owner") == tid]

# ---------- node federation: исходящий вызов мастер→нода ----------

def _node_call(node, path, body=None, timeout=8, need_token=True):
    """HTTPS-запрос к Node API ноды. (data, err, fp): fp — sha256 дерта сертификата.
    Pin-нинг: если у ноды задан pin, чужой сертификат отсекается до отправки токена."""
    import http.client
    host = (node.get("host") or "").strip()
    port = int(node.get("port") or 8443)
    if not host:
        return None, "нода без адреса", ""
    token = (node.get("token") or "").strip()
    if need_token and not token:
        return None, "у ноды не задан токен", ""
    ctx = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    try:
        conn.connect()
        der = conn.sock.getpeercert(True)
        fp = hashlib.sha256(der).hexdigest() if der else ""
        pin = (node.get("pin") or "").strip().lower()
        if pin and fp and pin != fp:
            return None, "сертификат ноды не совпадает с закреплённым отпечатком (возможен MITM)", fp
        hdrs = {"Authorization": f"Bearer {token}", "User-Agent": f"VeilPanel/{VERSION}"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        conn.request("POST" if body is not None else "GET", path, body=data, headers=hdrs)
        r = conn.getresponse()
        raw = r.read()
        if r.status >= 400:
            try:
                msg = json.loads(raw or b"{}").get("error")
            except Exception:
                msg = None
            return None, (msg or f"HTTP {r.status}"), fp
        return (json.loads(raw or b"{}"), None, fp)
    except Exception as e:
        return None, str(e)[:200], ""
    finally:
        try:
            conn.close()
        except Exception:
            pass

def _veil_plain_http_hint(node):
    """Диагностика «нода офлайн» для veil-нод: если HTTPS-рукопожатие упало, проверим,
    не отвечает ли этот порт обычным HTTP. Это типично для свежей панели без сертификата —
    Node API намеренно требует HTTPS, токен не поедет в открытом виде. Возвращаем
    подсказку или None. Сам транспорт это не ослабляет: связь с нодой по-прежнему только HTTPS."""
    import http.client
    host = (node.get("host") or "").strip()
    port = int(node.get("port") or 8443)
    if not host:
        return None
    try:
        c = http.client.HTTPConnection(host, port, timeout=6)
        c.request("GET", "/api/version", headers={"User-Agent": f"VeilPanel/{VERSION}"})
        r = c.getresponse(); raw = r.read(); c.close()
    except Exception:
        return None
    try:
        j = json.loads(raw or b"null")
    except Exception:
        j = None
    if isinstance(j, dict):
        return ("нода отвечает по HTTP, а Node API требует HTTPS (шифрование токена). "
                "Выпустите сертификат на панели-ноде: вкладка «Сайт» → Let's Encrypt, "
                "затем переподключите ноду.")
    return None

def _veil_nodes(nodes=None):
    nodes = nodes if nodes is not None else get_nodes()
    return [n for n in (nodes or []) if (n.get("type") or "agent") == "veil"]

def _agent_nodes(nodes=None):
    nodes = nodes if nodes is not None else get_nodes()
    return [n for n in (nodes or []) if (n.get("type") or "agent") == "agent"]

def _nodes_public():
    return [{k: v for k, v in n.items() if k != "token"} for n in get_nodes()]

def _node_poll_one(n):
    """Один опрос ноды (veil или agent): online/pin/кэш статуса. Меняет n на месте."""
    if (n.get("type") or "agent") == "veil":
        data, err, fp = _node_call(n, "/api/ext/status")
        if data is not None:
            n["online"] = True
            n["err"] = None
            n["remote_version"] = data.get("version")
            n["node_clients"] = data.get("clients")
            n["node_online"] = data.get("online")
            n["node_xray"] = data.get("xray")
            n["status_cache"] = {"inbounds": data.get("inbounds") or [],
                                 "at": int(time.time())}
        else:
            n["online"] = False
            e = (err or "")
            if ("SSL" in e or "record layer" in e.lower() or "handshake" in e.lower()
                    or "wrong version" in e.lower() or "decrypt" in e.lower()
                    or "tlsv" in e.lower() or "eof occurred" in e.lower()):
                n["err"] = _veil_plain_http_hint(n) or err
            else:
                n["err"] = err
    else:
        data, err, fp = _node_call(n, "/agent/status")
        if data is None:
            n["online"] = False
            n["err"] = err
            n["last_check"] = int(time.time())
            if fp and not (n.get("pin") or "").strip():
                n["pin"] = fp
            return
        n["online"] = True
        n["err"] = None
        n["remote_version"] = data.get("version")
        n["node_clients"] = data.get("clients")
        n["node_xray"] = data.get("xray")
        hd, herr, hfp = _node_call(n, "/agent/hello", need_token=False)
        if hd and hd.get("public_key"):
            hd["at"] = int(time.time())
            n["agent_params"] = hd
        elif not (n.get("agent_params") or {}):
            n["err"] = herr or "нода не вернула параметры"
    if not (n.get("pin") or "").strip() and fp:
        n["pin"] = fp  # TOFU: фиксируем при первом успешном контакте
    n["last_check"] = int(time.time())

def _nodes_poll_loop():
    import traceback
    while True:
        try:
            nodes = get_nodes()
            if nodes:
                for n in nodes:
                    _node_poll_one(n)
                save_nodes(nodes)
        except Exception:
            try:
                with open(f"{BASE}/logs/panel.err", "a") as f:
                    f.write("nodes_poll: " + traceback.format_exc() + "\n")
            except Exception:
                pass
        time.sleep(45)

# ========== АВТОПОДКЛЮЧЕНИЕ НОДЫ ПО SSH (бустрап) ==========
# Пароль SSH используется однократно (через SSH_ASKPASS, только в env процесса),
# нигде не сохраняется и не пишется в логи; дальше — ed25519-ключ панели.

NODE_KEYS_DIR = f"{BASE}/node_keys"
BOOT_JOBS = {}
BOOT_LOCK = threading.Lock()

def _boot_host_key(host):
    os.makedirs(NODE_KEYS_DIR, 0o700, exist_ok=True)
    slug = hashlib.sha1(host.encode()).hexdigest()[:16]
    base = f"{NODE_KEYS_DIR}/{slug}"
    if not os.path.exists(base):
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "",
                        "-C", f"veil-panel@{socket.gethostname()}", "-f", base, "-q"],
                       capture_output=True, timeout=30)
    try:
        os.chmod(base, 0o600)
    except Exception:
        pass
    return base, base + ".pub"

def _ssh_opts(keyfile):
    return ["-o", f"UserKnownHostsFile={NODE_KEYS_DIR}/known_hosts",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"IdentityFile={keyfile}", "-o", "IdentitiesOnly=yes",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15"]

def _boot_askpass_run(password, argv, timeout=60):
    """Запуск ssh/ssh-copy-id с вводом пароля через SSH_ASKPASS (пароль — только в env)."""
    fd, script = tempfile.mkstemp(prefix=".vpw")
    try:
        os.write(fd, b"#!/bin/sh\nprintf '%s\\n' \"$VP_SSH_PASS\"\n")
    finally:
        os.close(fd)
    os.chmod(script, 0o700)
    env = dict(os.environ)
    env.update(VP_SSH_PASS=password, SSH_ASKPASS=script, SSH_ASKPASS_REQUIRE="force",
               TMPDIR=os.path.dirname(script))
    env.pop("SSH_ASKPASS_DELAY", None)
    try:
        return subprocess.run(argv, capture_output=True, timeout=timeout, env=env,
                              stdin=subprocess.DEVNULL)
    finally:
        try:
            os.unlink(script)
        except Exception:
            pass

def _boot_new_job(params):
    jid = uuidlib.uuid4().hex[:12]
    steps = ["Подключение по SSH", "Права root", "Xray", "Файлы агента",
             "Конфиг и порты", "Служба veil-agent", "Файрвол",
             "Токен ноды", "Регистрация"]
    job = {"id": jid,
           "steps": [{"name": s, "state": "pending", "detail": ""} for s in steps],
           "done": False, "ok": False, "error": None,
           "created": int(time.time()), "params": params}
    with BOOT_LOCK:
        BOOT_JOBS[jid] = job
        if len(BOOT_JOBS) > 50:
            old = sorted(BOOT_JOBS, key=lambda k: BOOT_JOBS[k]["created"])[:-40]
            for k in [x for x in old if BOOT_JOBS[x]["done"]]:
                BOOT_JOBS.pop(k, None)
    return jid

def _boot_step(jid, idx, state, detail=""):
    with BOOT_LOCK:
        job = BOOT_JOBS.get(jid)
        if job:
            job["steps"][idx]["state"] = state
            if detail:
                job["steps"][idx]["detail"] = str(detail)[:300]

def _node_bootstrap_worker(jid):
    import traceback, shlex
    with BOOT_LOCK:
        job = BOOT_JOBS.get(jid) or {}
        prm = dict(job.get("params") or {})
    host = prm.get("host")
    sport = int(prm.get("ssh_port") or 22)
    user = prm.get("user") or "root"
    password = prm.get("password") or ""
    name = prm.get("name") or "Veil node"
    sni = prm.get("sni") or "www.samsung.com"

    def st(i, s, d=""):
        _boot_step(jid, i, s, d)

    def finish(ok, err=None):
        with BOOT_LOCK:
            job["done"] = True
            job["ok"] = ok
            job["error"] = err
            jp = job.get("params") or {}
            jp["password"] = ""

    def fail(i, msg):
        st(i, "failed", msg)
        finish(False, msg)
        try:
            _audit("node_bootstrap_fail", host=host, step=i, error=str(msg)[:200])
        except Exception:
            pass

    try:
        # --- 0. SSH-доступ: своим ключом, при отказе — пароль однократно + ssh-copy-id
        st(0, "running")
        keyfile, pubkey = _boot_host_key(host)
        base = ["/usr/bin/ssh", "-p", str(sport)] + _ssh_opts(keyfile)
        target = f"{user}@{host}"

        def key_run(cmd, timeout=60, input=None, text=True):
            return subprocess.run(base + [target, cmd], capture_output=True, text=text,
                                  timeout=timeout, input=input,
                                  stdin=subprocess.DEVNULL if input is None else None)

        try:
            r = key_run("true", timeout=20)
            ok_key = r.returncode == 0
        except Exception:
            ok_key = False
        if not ok_key:
            if not password:
                return fail(0, "нет доступа по ключу панели, а пароль не задан")
            r = _boot_askpass_run(password, base + [target, "echo VPOK"], timeout=45)
            if r.returncode != 0 or b"VPOK" not in (r.stdout or b""):
                etxt = (r.stderr or b"").decode("utf-8", "ignore")
                if "denied" in etxt.lower() or "permission" in etxt.lower():
                    etxt = "SSH отклонил логин/пароль"
                return fail(0, etxt[:200])
            # ssh-copy-id в OpenSSH 10.2 сломан (литерал ~ в mktemp) — ставим ключ напрямую
            try:
                pubtxt = open(pubkey).read().strip()
            except Exception:
                pubtxt = ""
            pubtxt = pubtxt.replace("'", "'\\''")
            if not pubtxt:
                return fail(0, "не читается публичный ключ панели")
            r = _boot_askpass_run(password, base + [target,
                                  "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; "
                                  "grep -qxF '%s' ~/.ssh/authorized_keys || printf '%%s\\n' '%s' "
                                  ">> ~/.ssh/authorized_keys" % (pubtxt, pubtxt)],
                                  timeout=45)
            if r.returncode != 0:
                return fail(0, "установка ключа: " + (r.stderr or b"").decode("utf-8", "ignore")[:200])
            try:
                ok_key = key_run("true", timeout=20).returncode == 0
            except Exception:
                ok_key = False
            if not ok_key:
                return fail(0, "ключ панели не принимается после установки")
        st(0, "done", "вход по ключу панели")

        # --- 1. root/sudo
        st(1, "running")
        r = key_run('u=$(id -u); p=$(command -v sudo || true); py=$(command -v python3 || true); '
                    'if [ "$u" = 0 ]; then m=root; elif [ -n "$p" ] && sudo -n true 2>/dev/null; '
                    'then m=sudo_n; elif [ -n "$p" ]; then m=s_s; else m=none; fi; '
                    'echo "$m $(uname -m) ${py:-nopy}"', timeout=30)
        if r.returncode != 0:
            return fail(1, "SSH-команда не прошла: " + (r.stderr or r.stdout or "")[:150])
        parts = (r.stdout or "").split()
        mode = parts[0] if parts else "none"
        arch = parts[1] if len(parts) > 1 else "?"
        haspy = len(parts) > 2 and parts[2] != "nopy"
        if mode == "s_s":
            try:
                if key_run("sudo -S -p '' true", timeout=30,
                           input=password.rstrip("\n") + "\n").returncode == 0:
                    mode = "sudo_s"
            except Exception:
                pass
        if mode not in ("root", "sudo_n", "sudo_s"):
            return fail(1, "нужны root или sudo (парольный или без пароля)")
        if not haspy:
            return fail(1, "на ноде нет python3 — агент не запустится")
        st(1, "done", {"root": "root", "sudo_n": "sudo без пароля",
                       "sudo_s": "sudo с паролем"}[mode])

        def rscript(script, args=(), timeout=180):
            shell = "bash -euo pipefail -s --"
            if mode == "sudo_n":
                shell = "sudo -n bash -euo pipefail -s --"
            elif mode == "sudo_s":
                script = password.rstrip("\n") + "\n" + script
                shell = "sudo -S -p '' bash -euo pipefail -s --"
            return subprocess.run(base + [target, shell] + [shlex.quote(str(a)) for a in args],
                                  capture_output=True, text=True, timeout=timeout, input=script)

        def rput(local_path, remote_tmp, timeout=600):
            with open(local_path, "rb") as f:
                return subprocess.run(base + [target, f"cat > {shlex.quote(remote_tmp)}"],
                                      stdin=f, capture_output=True, timeout=timeout)

        # --- 2. xray
        st(2, "running")
        r = rscript('command -v xray >/dev/null 2>&1 || [ -x /usr/local/bin/xray ] '
                    '&& echo have || echo need')
        if r.returncode != 0:
            return fail(2, (r.stderr or "")[:200])
        if "have" in (r.stdout or ""):
            st(2, "done", "xray уже есть")
        else:
            local_xray = shutil.which("xray") or (XRAY_BIN if os.path.exists(XRAY_BIN) else None)
            try:
                larch = socket.uname().machine
            except Exception:
                larch = ""
            if arch == "x86_64" and larch == "x86_64" and local_xray:
                if rput(local_xray, f"/tmp/.veil_xray_{jid}").returncode != 0:
                    return fail(2, "не удалось передать бинарник xray")
                r = rscript(f'install -m 0755 /tmp/.veil_xray_{jid} /usr/local/bin/xray '
                            f'&& rm -f /tmp/.veil_xray_{jid} && /usr/local/bin/xray version | head -1')
                if r.returncode != 0:
                    return fail(2, "установка локального xray: " + (r.stderr or "")[:150])
                st(2, "done", "скопирован xray с панели")
            else:
                r = rscript('curl -fsSL https://github.com/XTLS/Xray-install/raw/main/scripts/install-release.sh '
                            '-o /tmp/.veil_xi.sh || wget -qO /tmp/.veil_xi.sh '
                            'https://github.com/XTLS/Xray-install/raw/main/scripts/install-release.sh; '
                            'bash /tmp/.veil_xi.sh install >/dev/null 2>&1; rm -f /tmp/.veil_xi.sh; '
                            'xray version | head -1', timeout=300)
                if r.returncode != 0 or "Xray" not in (r.stdout or ""):
                    return fail(2, "не удалось установить xray (на ноде нужен интернет и curl/wget)")
                st(2, "done", "установлен xray из официального репозитория")

        # --- 3. файлы агента
        st(3, "running")
        agent_src = f"{BASE}/agent.py"
        if not os.path.exists(agent_src):
            return fail(3, "в каталоге панели нет agent.py")
        if rput(agent_src, f"/tmp/.veil_agent_{jid}", timeout=120).returncode != 0:
            return fail(3, "передача agent.py не удалась")
        r = rscript(f'mkdir -p /opt/veil-agent && install -m 0644 /tmp/.veil_agent_{jid} '
                    f'/opt/veil-agent/agent.py && rm -f /tmp/.veil_agent_{jid}')
        if r.returncode != 0:
            return fail(3, (r.stderr or "")[:200])
        st(3, "done", "/opt/veil-agent/agent.py")

        # --- 4. конфиг: свободные порты, имена
        st(4, "running")
        r = rscript('''set -e
freep() { for p in "$@"; do ss -H -ltnu 2>/dev/null | awk '{print $5}' | sed 's/.*://' | grep -qx "$p" || { echo "$p"; return 0; }; done; return 1; }
API=$(freep 9444 9445 19444 29444) || exit 21
XP=$(freep 8444 8445 14444 24444) || exit 22
SP=$(freep 10090 10091 10099 10199) || exit 23
XB=$(command -v xray || echo /usr/local/bin/xray)
python3 -c 'import json,sys; json.dump({"api_port": int(sys.argv[1]), "xport": int(sys.argv[2]), "stats_port": int(sys.argv[3]), "xray_bin": sys.argv[4], "name": sys.argv[5], "sni": sys.argv[6]}, open("/opt/veil-agent/agent.conf.json", "w"), ensure_ascii=False, indent=2)' "$API" "$XP" "$SP" "$XB" "$1" "$2"
echo "$API $XP $SP"
''', args=(name, sni), timeout=60)
        if r.returncode != 0:
            return fail(4, "конфиг не записан" +
                        (" (все кандидаты портов заняты)" if r.returncode in (21, 22, 23) else
                         ": " + (r.stderr or "")[:150]))
        try:
            api_port, x_port, sp_port = (r.stdout or "").split()[:3]
            api_port, x_port, sp_port = int(api_port), int(x_port), int(sp_port)
        except Exception:
            return fail(4, "не разобраны порты из конфига: " + (r.stdout or "")[:80])
        st(4, "done", f"API {api_port}, вход {x_port}")

        # --- 5. systemd-юнит
        st(5, "running")
        r = rscript('''set -e
cat > /etc/systemd/system/veil-agent.service <<'EOS'
[Unit]
Description=Veil node agent
After=network-online.target

[Service]
WorkingDirectory=/opt/veil-agent
ExecStart=/usr/bin/env python3 /opt/veil-agent/agent.py
Restart=always
RestartSec=5
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
EOS
systemctl daemon-reload
systemctl enable veil-agent >/dev/null 2>&1 || true
systemctl restart veil-agent
sleep 2
systemctl is-active veil-agent
''', timeout=90)
        if r.returncode != 0 or "active" not in (r.stdout or ""):
            return fail(5, "служба не запустилась: " + ((r.stderr or "") + (r.stdout or ""))[:200])
        st(5, "done", "veil-agent: active")

        # --- 6. файрвол (best-effort)
        st(6, "running")
        r = rscript(f'''ok=""
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow {x_port}/tcp >/dev/null 2>&1 && ok=ufw
  ufw allow {api_port}/tcp >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port={x_port}/tcp >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port={api_port}/tcp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 && ok="firewalld $ok"
fi
echo "${{ok:-не активно}}"
''', timeout=60)
        st(6, "done", ("открыты порты: " + (r.stdout or "").strip()) if r.returncode == 0
           else "файрвол не трогали (best-effort)")

        # --- 7. токен агента
        st(7, "running")
        r = rscript("cd /opt/veil-agent && python3 agent.py --token", timeout=60)
        token = ((r.stdout or "").strip().splitlines() or [""])[-1].strip()
        if r.returncode != 0 or not (30 <= len(token) <= 80) or not re.fullmatch(r"[A-Za-z0-9_\-]+", token):
            return fail(7, "не удалось прочитать токен агента: " + (r.stderr or "")[:150])
        st(7, "done", "получен")

        # --- 8. регистрация ноды + TOFU
        st(8, "running")
        nodes = get_nodes()
        entry = next((n for n in nodes
                      if (n.get("host") or "").strip().lower() == host.lower()), None)
        if entry is None:
            entry = {"added": int(time.time())}
            nodes.append(entry)
        entry.update({"name": name, "host": host, "port": api_port, "type": "agent",
                      "token": token, "online": False,
                      "ssh_user": user, "ssh_port": sport, "ssh_key": keyfile,
                      "ssh_sudo": mode})
        save_nodes(nodes)
        deadline = time.time() + 25
        while time.time() < deadline:
            _node_poll_one(entry)
            if entry.get("online"):
                break
            time.sleep(2)
        save_nodes(nodes)
        if entry.get("online"):
            st(8, "done", f"нода онлайн, отпечаток {str(entry.get('pin') or '')[:12]}… закреплён")
        else:
            st(8, "done", "нода добавлена, API ещё не отвечает — слежение включено")
        finish(True)
        _audit("node_bootstrap", host=host, name=name, api_port=api_port, x_port=x_port)
    except subprocess.TimeoutExpired:
        with BOOT_LOCK:
            cur = next((s["name"] for s in job["steps"] if s["state"] == "running"), "?")
        finish(False, f"таймаут на шаге «{cur}»")
    except Exception:
        try:
            with open(f"{BASE}/logs/panel.err", "a") as f:
                f.write("node_bootstrap: " + traceback.format_exc() + "\n")
        except Exception:
            pass
        with BOOT_LOCK:
            cur = next((s["name"] for s in job["steps"] if s["state"] == "running"), "?")
        finish(False, f"сбой на шаге «{cur}» (см. logs/panel.err)")

def _node_expiry_days(c):
    ex = int(c.get("expiry") or 0)
    if ex <= 0:
        return 0
    return max(0, -(-(ex - int(time.time())) // 86400))

def _client_node_entries(st, u):
    ents = {}
    for proto, inb in (st.get("inbounds") or {}).items():
        for c in inb.get("clients", []):
            if c.get("uuid") == u:
                for h, e in (c.get("nodes") or {}).items():
                    ents[h] = e
    return ents

def _agent_link(n, ap, u, c0):
    """vless+reality ссылка на агента-ноду из параметров /agent/hello."""
    host = (n.get("host") or "").strip()
    qparts = {"type": "tcp", "security": "reality",
              "pbk": ap.get("public_key") or "",
              "fp": ap.get("fp") or "firefox",
              "sni": ap.get("sni") or "", "sid": ap.get("sid") or "",
              "spx": "/", "flow": "xtls-rprx-vision"}
    q = urllib.parse.urlencode(qparts)
    name = f"{c0.get('name') or 'Veil'} · {n.get('name') or host}"
    return f"vless://{u}@{host}:{int(ap.get('port') or 443)}?{q}#{urllib.parse.quote(name)}"

# Порядок предпочтения протокола при размещении клиента на ноде:
# берём первый протокол клиента, который нода реально поддерживает.
_NODE_PROTO_PRIORITY = ("reality", "vless-xhttp-reality", "hysteria2",
                        "vless-xhttp-tls", "vless-ws-tls", "vless-tcp-tls", "vless-grpc-tls", "vless-ws",
                        "trojan-tcp-tls", "trojan-ws-tls", "trojan-grpc-tls",
                        "vmess-ws-tls", "vmess-tcp-tls", "vmess-grpc-tls", "vmess-ws",
                        "shadowsocks", "wireguard", "amneziawg")

def _deploy_client_to_nodes(st, u):
    """Разместить клиента u на всех онлайн-нодах (Veil API и агент). (deployed, skipped)."""
    deployed, skipped = [], []
    recs = [(proto, inb, c) for proto, inb in (st.get("inbounds") or {}).items()
            for c in inb.get("clients", []) if c.get("uuid") == u]
    if not recs:
        return deployed, [{"host": "-", "reason": "клиент не найден"}]
    by_proto = {proto: (proto, inb, c) for proto, inb, c in recs}
    nodes = get_nodes()
    for n in nodes:
        host = (n.get("host") or "").strip()
        is_agent = (n.get("type") or "agent") == "agent"
        if not n.get("online"):
            skipped.append({"host": host, "reason": "офлайн"})
            continue
        if any((c.get("nodes") or {}).get(host) for _, _, c in recs):
            skipped.append({"host": host, "reason": "уже размещён"})
            continue
        if is_agent:
            # агент поднимает только VLESS+Reality — ищем именно его среди протоколов клиента
            rec = by_proto.get("reality")
            if not rec:
                skipped.append({"host": host,
                                "reason": "у клиента нет VLESS+Reality — агент поддерживает только его"})
                continue
            dep, sk = _deploy_client_to_agent(n, host, recs, rec, u)
        else:
            dep, sk = _deploy_client_to_veil(n, host, recs, by_proto, u)
        deployed.extend(dep)
        skipped.extend(sk)
    if deployed:
        _save(STATE, st)
        save_nodes(nodes)
    return deployed, skipped

def _deploy_client_to_veil(n, host, recs, by_proto, u):
    deployed, skipped = [], []
    sc = n.get("status_cache") or {}
    inbs = sc.get("inbounds") or []
    if time.time() - int(sc.get("at") or 0) > 120:
        data, err, _ = _node_call(n, "/api/ext/inbounds")
        if data is None:
            return deployed, [{"host": host, "reason": err or "нет ответа"}]
        inbs = data.get("inbounds") or []
        n["status_cache"] = {"inbounds": inbs, "at": int(time.time())}
    node_protos = {i.get("proto") for i in inbs}
    proto_local = next((p for p in _NODE_PROTO_PRIORITY
                        if p in by_proto and p in node_protos), None)
    if proto_local is None:
        common = [p for p in by_proto if p in node_protos]
        proto_local = common[0] if common else None
    if proto_local is None:
        return deployed, [{"host": host, "reason": "нет общего поддерживаемого протокола с нодой"}]
    c0 = by_proto[proto_local][2]
    body = {"name": c0.get("name") or "Клиент", "proto": proto_local,
            "limit_gb": float(c0.get("limit_gb") or 0)}
    ed = _node_expiry_days(c0)
    if ed:
        body["expiry_days"] = ed
    if c0.get("reset_cycle"):
        body["reset_cycle"] = c0["reset_cycle"]
    if int(c0.get("max_devices") or 0) > 0:
        body["max_devices"] = int(c0["max_devices"])
    data, err, _ = _node_call(n, "/api/ext/clients", body)
    nc = (data or {}).get("client") or {}
    if data is None or not nc.get("uuid"):
        return deployed, [{"host": host, "reason": err or "ошибка ноды"}]
    for _, _, c in recs:
        c.setdefault("nodes", {})[host] = {
            "uuid": nc["uuid"], "proto": nc.get("proto") or proto_local,
            "link": nc.get("link") or "", "sub_url": nc.get("sub_url") or "",
            "at": int(time.time())}
    return [{"host": host, "name": n.get("name") or host}], []

def _deploy_client_to_agent(n, host, recs, rec, u):
    deployed, skipped = [], []
    c0 = rec[2]
    ap = n.get("agent_params") or {}
    if not ap.get("public_key") or time.time() - int(ap.get("at") or 0) > 900:
        hd, herr, _ = _node_call(n, "/agent/hello", need_token=False)
        if hd and hd.get("public_key"):
            hd["at"] = int(time.time())
            n["agent_params"] = ap = hd
        elif not ap.get("public_key"):
            return deployed, [{"host": host, "reason": herr or "нода не вернула параметры"}]
    body = {"action": "add", "uuid": u, "name": c0.get("name") or "Клиент",
            "limit_gb": float(c0.get("limit_gb") or 0)}
    ed = _node_expiry_days(c0)
    if ed:
        body["expiry_days"] = ed
    if c0.get("reset_cycle"):
        body["reset_cycle"] = c0["reset_cycle"]
    data, err, _ = _node_call(n, "/agent/apply", body)
    if data is None and "уже есть" not in (err or ""):
        return deployed, [{"host": host, "reason": err or "ошибка ноды"}]
    link = _agent_link(n, n.get("agent_params") or ap, u, c0)
    for _, _, c in recs:
        c.setdefault("nodes", {})[host] = {
            "uuid": u, "proto": "reality", "link": link, "sub_url": "",
            "at": int(time.time())}
    return [{"host": host, "name": n.get("name") or host}], []

def _nodes_by_host():
    out = {}
    for n in get_nodes():
        h = (n.get("host") or "").strip().lower()
        if h:
            out[h] = n
    return out

def _node_agent_purge(node):
    """Снять veil-agent с хоста agent-ноды (best-effort по ключу панели).
    veil-ноду (чужую полноценную панель) НЕ трогаем — вернёт (None, пояснение)."""
    if (node.get("type") or "agent") != "agent":
        return (None, "не агент-нода: чужая панель не демонтируется")
    host = (node.get("host") or "").strip()
    user = (node.get("ssh_user") or "root").strip() or "root"
    key = (node.get("ssh_key") or "").strip()
    try:
        sport = int(node.get("ssh_port") or 22)
    except Exception:
        sport = 22
    if not host or not key or not os.path.exists(key):
        return (False, "нет SSH-ключа панели — агент не снят автоматически")
    cmd = ("systemctl disable --now veil-agent >/dev/null 2>&1; "
           "pkill -9 -f '[x]ray-agent.json' >/dev/null 2>&1; "
           "pkill -9 -f '[v]eil-agent/agent.py' >/dev/null 2>&1; "
           "rm -rf /opt/veil-agent /etc/systemd/system/veil-agent.service; "
           "systemctl daemon-reload >/dev/null 2>&1; echo VPURGED")
    full = ["/usr/bin/ssh", "-p", str(sport)] + _ssh_opts(key) + [f"{user}@{host}", cmd]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=25,
                           stdin=subprocess.DEVNULL)
        if r.returncode == 0 and "VPURGED" in (r.stdout or ""):
            return (True, "агент снят с сервера")
        return (False, ((r.stderr or "") + (r.stdout or "")).strip()[:160] or "сбой SSH")
    except subprocess.TimeoutExpired:
        return (False, "таймаут SSH — агент остался на сервере")
    except Exception as e:
        return (False, str(e)[:160])

def _node_apply_remove(n, uuid):
    if (n.get("type") or "agent") == "agent":
        _node_call(n, "/agent/apply", {"action": "remove", "uuid": uuid}, timeout=6)
    else:
        _node_call(n, "/api/ext/clients/delete", {"uuid": uuid}, timeout=6)

def _undeploy_client_from_nodes(st, u):
    ents = _client_node_entries(st, u)
    nodes = _nodes_by_host()
    for host, e in ents.items():
        n = nodes.get(host.strip().lower())
        if n and e.get("uuid"):
            _node_apply_remove(n, e["uuid"])

def _repropagate_client_to_nodes(st, u):
    """Синхронизировать лимит/срок клиента на нодах, где он размещён."""
    ents = _client_node_entries(st, u)
    if not ents:
        return
    recs = [c for proto, inb in (st.get("inbounds") or {}).items()
            for c in inb.get("clients", []) if c.get("uuid") == u]
    if not recs:
        return
    c0 = recs[0]
    nodes = _nodes_by_host()
    for host, e in ents.items():
        n = nodes.get(host.strip().lower())
        if not n or not e.get("uuid"):
            continue
        if (n.get("type") or "agent") == "agent":
            _node_call(n, "/agent/apply", {
                "action": "set_limits", "uuid": e["uuid"],
                "limit_gb": float(c0.get("limit_gb") or 0),
                "expiry_days": _node_expiry_days(c0),
                "reset_cycle": c0.get("reset_cycle") or ""}, timeout=6)
        else:
            _node_call(n, "/api/ext/clients/update", {
                "uuid": e["uuid"], "limit_gb": float(c0.get("limit_gb") or 0),
                "expiry_days": _node_expiry_days(c0)}, timeout=6)


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
        users.append({
            "username": u.get("username", ""),
            "enabled": bool(u.get("enabled")),
            "link": _tg_pick_tls_link((u.get("links") or {}).get("tls")),
            "web_link": web_links.get(u.get("username", ""), ""),
            "ad_tag": u.get("user_ad_tag") or "",
            "connections": u.get("active_unique_ips", 1 if u.get("current_connections", 0) else 0),
            "total_octets": u.get("total_octets", 0),
        })
    for u in users:
        u["link"] = _tg_host_ok(u.get("link") or "")
    res = {"installed": True, "users": users, "sni": _tg_sni()}
    if web:
        res["web"] = web
    return res


def _tg_host_ok(link):
    host = (CFG_CACHE.get("panel_domain") or "").strip()
    if not host or not link:
        return link
    return re.sub(r"(?i)(server=)[^&:]+", lambda m: m.group(1)+host, link)

def _tg_ensure_secret_in_toml(username, secret):
    """Добавить секрет пользователя в [access.users] telemt.toml (если его там нет)."""
    if not (username and secret):
        return
    try:
        with open(TELEMT_CONF, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception:
        return
    if re.search(r"(?m)^\"?%s\"?\s*=" % re.escape(username), text):
        return
    if "[access.users]" in text:
        text = text.replace("[access.users]", '[access.users]\n%s = "%s"%s' % (username, secret, "\n" if text.split("[access.users]", 1)[1].strip() else ""), 1)
    else:
        text = text.rstrip("\n") + '\n[access.users]\n%s = "%s"\n' % (username, secret)
    with open(TELEMT_CONF, "w", encoding="utf-8") as f:
        f.write(text)

def _tg_pick_tls_link(tls):
    """Первая ссылка обычно IPv4 — предпочтём её."""
    for l in tls or []:
        if "server=" in l and ":" not in l.split("server=")[1].split("&")[0]:
            return l
    return (tls or [""])[0]

def _tg_web_enable_user(name):
    """Добавить пользователя в веб-профили vhosts (нужен включённый web в telemt)."""
    w = _tg_web_get()
    if not (w and w.get("enabled") and w.get("host")):
        return ""
    users = list(w["profiles"])
    if name not in users:
        users.append(name)
        try:
            _tg_web_set_profiles(users)
            w = _tg_web_get()
        except Exception:
            w = None
    if not w or name not in w["profiles"]:
        return ""
    return _tg_web_link(name)

def _tg_add(username, mode="both"):
    """Создать пользователя telemt. mode: mtproto | web | both."""
    name = (username or "").strip().replace(" ", "_")
    if not name:
        raise RuntimeError("имя пустое")
    if not re.match(r"^[a-zA-Z0-9_.-]{1,32}$", name):
        raise RuntimeError("только латиница, цифры, _ . - (до 32 символов)")
    mode = mode if mode in ("mtproto", "web", "both") else "both"
    if mode == "web":
        w0 = _tg_web_get()
        if not (w0 and w0.get("enabled") and w0.get("host")):
            raise RuntimeError("веб-прокси в telemt выключен — сначала установи Web Proxy (nginx)")
    d = _tg_api("POST", "/v1/users", {"username": name})
    secret = d.get("secret", "")
    _tg_ensure_secret_in_toml(name, secret)
    links = ((d.get("data") or {}).get("user") or {}).get("links", {})
    link = _tg_pick_tls_link(links.get("tls"))
    web_link = _tg_web_enable_user(name) if mode in ("web", "both") else ""
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

_TG_HEX32 = re.compile(r"^[0-9a-f]{32}$")

def _tg_user_row(username):
    return (_tg_api("GET", "/v1/users/" + urllib.parse.quote(username)).get("data") or {})

def _tg_set_adtag(username, tag):
    """Спонсорский канал @MTProxybot: телеметрик-тег пользователя (32 hex) либо null (снять).

    Ссылка клиента при этом НЕ меняется — телеграм подставляет канал по тегу на стороне прокси,
    для чего нужен general.use_middle_proxy = true (у telemt по умолчанию включён).
    """
    name = (username or "").strip()
    if not name:
        raise RuntimeError("имя пустое")
    tag = (tag or "").strip().lower()
    if tag and not _TG_HEX32.match(tag):
        raise RuntimeError("ad_tag — ровно 32 hex-символа из @MTProxybot (или пусто, чтобы снять)")
    _tg_api("PATCH", "/v1/users/" + urllib.parse.quote(name), {"user_ad_tag": tag or None})
    warn = ""
    if tag and not _tg_middle_proxy_on():
        warn = "нужен general.use_middle_proxy = true в telemt — включи и перезапусти telemt"
    return {"username": name, "ad_tag": tag or None, "warning": warn}

def _tg_middle_proxy_on():
    try:
        g = _tg_api("GET", "/v1/config").get("data", {}).get("general") or {}
    except Exception:
        return True
    return bool(g.get("use_middle_proxy", True))

def _tg_rotate_secret(username, secret=""):
    """Смена секрета пользователя: ссылка меняется, телеmt сам обновляет [access.users]."""
    name = (username or "").strip()
    if not name:
        raise RuntimeError("имя пустое")
    secret = (secret or "").strip().lower()
    if secret and not _TG_HEX32.match(secret):
        raise RuntimeError("секрет — 32 hex-символа или пусто (сгенерировать автоматически)")
    d = _tg_api("POST", "/v1/users/" + urllib.parse.quote(name) + "/rotate-secret",
                {"secret": secret} if secret else {}).get("data") or {}
    new_secret = d.get("secret") or ""
    if new_secret:
        _tg_ensure_secret_in_toml(name, new_secret)
    links = ((d.get("user") or {}).get("links") or {}).get("tls") or []
    return {"username": name, "secret": new_secret,
            "link": _tg_host_ok(_tg_pick_tls_link(links)),
            "web_link": _tg_web_link(name)}

def _tg_sni():
    """SNI (маскировка) прокси: censorship.tls_domain + список tls_domains."""
    try:
        c = _tg_api("GET", "/v1/config").get("data", {}).get("censorship") or {}
    except Exception:
        return {"tls_domain": "", "tls_domains": []}
    return {"tls_domain": c.get("tls_domain") or "", "tls_domains": c.get("tls_domains") or []}

def _tg_sni_set(tls_domain=None, tls_domains=None):
    dom = (tls_domain or "").strip().lower() if tls_domain is not None else None
    if dom is not None:
        if dom and not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,252}[a-z0-9])?", dom):
            raise RuntimeError("домен: только имя хоста без портов и путей")
    extra = None
    if tls_domains is not None:
        extra = []
        for d0 in tls_domains:
            d0 = (d0 or "").strip().lower()
            if not d0:
                continue
            if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,252}[a-z0-9])?", d0):
                raise RuntimeError("домен: только имя хоста без портов и путей")
            if d0 not in extra:
                extra.append(d0)
    body = {}
    if dom is not None:
        body["tls_domain"] = dom
    if extra is not None:
        body["tls_domains"] = extra
    if not body:
        raise RuntimeError("нечего менять")
    _tg_api("PATCH", "/v1/config", {"censorship": body})
    _audit("tg_sni", **({"domain": dom} if dom is not None else {}))
    return _tg_sni()

_TG_TRANS = {"а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "yo",
             "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
             "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
             "ф": "f", "х": "h", "ц": "c", "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "",
             "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya"}

def _tg_slug(name, fallback="client"):
    """Имя клиента в допустимое имя пользователя telemt (латиница, _ . -)."""
    s = "".join(_TG_TRANS.get(ch, ch) for ch in (name or "").lower())
    s = re.sub(r"[^a-z0-9_.-]", "_", s).strip("._-")[:24]
    return s or fallback

def _tg_ensure_user(username, web=True):
    """Вернуть {username, link, web_link} для пользователя telemt, создав его при отсутствии.

    None — если telemt/API недоступны (тогда подписка отдаётся без прокси-ссылок).
    """
    name = _tg_slug(username)
    try:
        users = [u.get("username") for u in (_tg_api("GET", "/v1/users").get("data") or [])]
    except Exception:
        return None
    if name not in users:
        try:
            _tg_add(name, "both" if web else "mtproto")
        except Exception:
            return None
    try:
        u = _tg_user_row(name)
    except Exception:
        return None
    return {"username": name,
            "link": _tg_host_ok(_tg_pick_tls_link((u.get("links") or {}).get("tls"))),
            "web_link": _tg_web_link(name) if web else ""}

def _tg_sub_links(client=None):
    """Ссылки Telegram-прокси, добавляемые в подписку клиента (обычные и персональные)."""
    mode = ((client or {}).get("tg_proxy") or CFG_CACHE.get("sub_tg_mode") or "").strip().lower()
    if mode in ("", "off", "none", "0"):
        return []
    if mode == "personal":
        name = (client or {}).get("tg_user") or ""
        if not name:
            name = _tg_slug((client or {}).get("name"), "client") + "-" + \
                   ((client or {}).get("sub_token") or "x")[:6]
    else:
        name = CFG_CACHE.get("tg_shared_user") or "common"
    u = _tg_ensure_user(name, web=True)
    if not u:
        return []
    return [l for l in (u.get("link"), u.get("web_link")) if l]

def _sub_settings():
    try:
        h = max(1, min(168, int(CFG_CACHE.get("sub_update_hours") or 24)))
    except Exception:
        h = 24
    mode = (CFG_CACHE.get("sub_tg_mode") or "off").strip().lower()
    if mode not in ("off", "shared", "personal"):
        mode = "off"
    return {"update_hours": h, "tg_mode": mode,
            "tg_shared_user": CFG_CACHE.get("tg_shared_user") or "common"}

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

def _tg_dcs():
    """Покрытие дата-центров Telegram движком telemt (ME-writers): таблица по DC,
    итоги и порог fresh-покрытия. Источник — /v1/stats/dcs + /v1/config."""
    d = _tg_api("GET", "/v1/stats/dcs").get("data") or {}
    rows = []
    for x in (d.get("dcs") or []):
        req = int(x.get("required_writers") or 0)
        alive = int(x.get("alive_writers") or 0)
        rows.append({
            "dc": x.get("dc"),
            "rtt": round(float(x.get("rtt_ms") or 0), 1),
            "alive": alive, "required": req,
            "coverage": round(float(x.get("coverage_pct") or 0), 1),
            "fresh": round(float(x.get("fresh_coverage_pct") or 0), 1),
            "endpoints": int(x.get("available_endpoints") or 0),
            "endpoints_pct": round(float(x.get("available_pct") or 0), 1)})
    req = sum(r["required"] for r in rows)
    counted = sum(min(r["alive"], r["required"]) for r in rows)
    alive = sum(r["alive"] for r in rows)
    thr = None
    try:
        g = (_tg_api("GET", "/v1/config").get("data") or {}).get("general") or {}
        thr = round(float(g.get("me_pool_min_fresh_ratio") or 0.9) * 100)
    except Exception:
        pass
    return {"dcs": rows, "generated": int(d.get("generated_at_epoch_secs") or 0),
            "totals": {"required": req, "counted": counted, "alive": alive,
                       "coverage": round(counted / req * 100, 1) if req else 0.0},
            "threshold": thr}

def _tg_set_fresh_ratio(pct):
    pct = float(pct)
    if not (10 <= pct <= 100):
        raise RuntimeError("порог должен быть 10–100 %")
    _tg_api("PATCH", "/v1/config", {"general": {"me_pool_min_fresh_ratio": pct / 100.0}})
    _audit("tg_fresh_ratio", pct=pct)
    return {"ok": True, "pct": pct}

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

def _strip_web_section(text):
    out, in_web = [], False
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            in_web = s.startswith("[web")
            if in_web:
                continue
        if not in_web:
            out.append(ln)
    return "\n".join(out).rstrip("\n") + "\n"

def _tg_web_ensure():
    """Включить telemt WEB (слушатель 127.0.0.1:18080 + vhost домена) и перезапустить telemt.

    После этого в панели появляются ссылки tg://webproxy?server=ДОМЕН&secret=dd...
    Заглушка (NES-эмулятор из /opt/vpnpanel/decoy) раздаётся telemt для обычных запросов.
    """
    for p in ("/etc/telemt", "/etc/telemt/telemt.toml"):
        if os.path.exists(p):
            subprocess.run(["chown", "telemt:telemt", p], capture_output=True)
    domain = (CFG_CACHE.get("panel_domain") or "").strip()
    if not domain or ":" in domain or "//" in domain or "/" in domain:
        raise RuntimeError("нет домена — внеси его во вкладке Сайт (раздел DDNS)")
    if not _tg_available():
        raise RuntimeError("telemt не доступен (API 127.0.0.1:9091)")
    ip4 = _pub_ip4() or "127.0.0.1"
    with open(TELEMT_CONF, "r", encoding="utf-8") as f:
        text = f.read()
    backup = text

    try:
        users = [u.get("username", "") for u in (_tg_api("GET", "/v1/users").get("data") or []) if u.get("username")]
    except Exception:
        users = []
    m = re.search(r"(?ms)^\s*\[access\.users\]\s*$(.+?)(?=^\s*\[|\Z)", backup)
    if m:
        for line in m.group(1).splitlines():
            mm = re.match(r'^"?([^"=\s]+)"?\s*=\s*"([0-9a-fA-F]+)"', line.strip())
            if mm and mm.group(1) not in users:
                users.append(mm.group(1))
    users = [u for u in dict.fromkeys(users) if u]
    if not users:
        raise RuntimeError("нет пользователей telemt — создайте хотя бы одного")

    changed = False
    if 'transport = "web"' not in text:
        text += ("\n[[server.listeners]]\n"
                 'ip = "127.0.0.1"\n'
                 "port = 18080\n"
                 'transport = "web"\n'
                 "proxy_protocol = false\n"
                 "reuse_allow = false\n"
                 'web_client_ip_source = "x_forwarded_for"\n'
                 'web_trusted_proxy_cidrs = ["127.0.0.1/32"]\n')
        changed = True

    web_block = ('[web]\n'
                 "enabled = true\n"
                 'carrier = "https"\n'
                 "\n[[web.vhosts]]\n"
                 'host = "%s"\n'
                 'public_addr = "%s:443"\n'
                 "\n[web.vhosts.decoy]\n"
                 'mode = "static_directory"\n'
                 'directory = "/opt/vpnpanel/decoy"\n'
                 'index = "index.html"\n' % (domain, ip4))
    for u in users:
        web_block += ('\n[[web.vhosts.profiles]]\n'
                      'user = "%s"\n'
                      'secret_mode = "dd"\n'
                      "max_sessions = 8\n"
                      "max_streams = 512\n"
                      "max_streams_per_session = 64\n" % u)

    if not re.search(r"(?m)^\[web\]\s*$", text):
        text = _strip_web_section(text) + web_block + "\n"
        changed = True
    elif "\n[[web.vhosts]]" not in text.replace("\r", ""):
        text = text.rstrip("\n") + "\n" + web_block + "\n"
        changed = True

    if not changed:
        return _tg_web_get()

    with open(TELEMT_CONF, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        r = subprocess.run(["systemctl", "restart", "telemt"], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise RuntimeError("systemctl restart telemt: " + (r.stderr or r.stdout)[-300:])
    except Exception:
        with open(TELEMT_CONF, "w", encoding="utf-8") as f:
            f.write(backup)
        subprocess.run(["systemctl", "restart", "telemt"], capture_output=True, timeout=120)
        raise RuntimeError("telemt не принял WEB-конфиг — изменение откачено")
    return _tg_web_get()

_NG_WEBPROXY_TEMPLATE = """map $http_upgrade $telemt_connection_upgrade {
    default upgrade;
    ''      '';
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

    location / {
        proxy_pass http://telemt_web;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $telemt_connection_upgrade;

        proxy_hide_header Cache-Control;
        add_header Cache-Control "no-store, no-cache" always;

        # telemt жёстко отдаёт CSP без 'wasm-unsafe-eval' — под ней WASM-эмулятор
        # заглушки не запускается. Переопределяем своей политикой (всё с этого хоста).
        proxy_hide_header Content-Security-Policy;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" always;

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
    
    cp = _cert_pathes()
    has_cert = bool((cp["cert"] and os.path.exists(cp["cert"])) or (CFG_CACHE.get("cert") and os.path.exists(CFG_CACHE.get("cert"))))
    
    busy = []
    if not free80: busy.append(80)
    if not free443: busy.append(443)
    return {"installed": installed, "nginx": bool(nginx_bin), "config": ng_conf,
            "active": ng_active, "port80": free80, "port443": free443,
            "busy": busy, "domain": domain, "domain_set": domain_set,
            "cert_ready": has_cert,
            "can_install": (not installed) and (not busy) and domain_set and has_cert}

def _webproxy_apply(domain):
    _tg_web_ensure()
    subprocess.run(["rm", "-f", "/etc/nginx/sites-enabled/default"], capture_output=True)
    cert, key = _ng_certs(domain)
    conf = _NG_WEBPROXY_TEMPLATE.replace("{domain}", domain).replace("{cert}", cert).replace("{key}", key)
    os.makedirs(os.path.dirname(_NG_CONF), exist_ok=True)
    with open(_NG_CONF, "w") as f:
        f.write(conf)
    t = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=20)
    if t.returncode != 0:
        raise RuntimeError("nginx -t: " + (t.stderr or t.stdout)[-400:])
    subprocess.run(["systemctl", "enable", "nginx"], capture_output=True)
    subprocess.run(["systemctl", "restart", "nginx"], check=True, capture_output=True, timeout=60)

def _webproxy_install():
    st = _webproxy_status()
    if st["installed"]:
        _webproxy_apply(st["domain"])
        return {"ok": True, "status": _webproxy_status(),
                "message": "Web Proxy переустановлен — конфигурация обновлена и nginx перезапущен"}
    if st["busy"]:
        raise RuntimeError("порт %s занят — освободи его, после этого кнопка установки появится" %
                           "/".join(map(str, st["busy"])))
    if not st["domain_set"]:
        raise RuntimeError("нет домена или DDNS — внеси его во вкладке Сайт (раздел DDNS)")
    if not st["cert_ready"]:
        raise RuntimeError("нет SSL-сертификата — сначала выпустите сертификат (Let's Encrypt) во вкладке Сайт")
    domain = st["domain"]
    if not st["nginx"]:
        r = subprocess.run(["apt-get", "install", "-y", "-qq", "nginx"],
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            raise RuntimeError("apt nginx: " + (r.stderr or r.stdout)[-300:])
    _webproxy_apply(domain)
    return {"ok": True, "status": _webproxy_status()}

def _sock_occupant(port):
    """Кто держит TCP-листнер на :port. Вернуть {free, proc, pids}.
    Панель работает под root, поэтому ss показывает имена чужих процессов."""
    res = {"free": True, "proc": "", "pids": []}
    if not (isinstance(port, int) and 0 < port < 65536):
        return res
    try:
        out = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=8).stdout
    except Exception:
        return res
    names, pids = [], []
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 4:
            continue
        local = cols[3]
        if not local.endswith(":" + str(port)):
            continue
        for nm, pid in re.findall(r'\("([^"]+)",pid=(\d+)', line):
            names.append(nm)
            pids.append(int(pid))
    if names:
        res["free"] = False
        res["proc"] = ",".join(sorted(set(names)))
        res["pids"] = sorted(set(pids))
    elif not _port_free(port):
        res["free"] = False   # занято, но процесс не виден (не root / чужое ns)
        res["proc"] = "?"
    return res

def _nginx_stream_info():
    info = {"installed": False, "active": False, "stream": False, "stream_dynamic": False,
            "ssl_preread": False, "version": ""}
    binp = shutil.which("nginx")
    if not binp:
        return info
    info["installed"] = True
    try:
        info["active"] = subprocess.run(["systemctl", "is-active", "--quiet", "nginx"]).returncode == 0
    except Exception:
        pass
    try:
        r = subprocess.run([binp, "-V"], capture_output=True, text=True, timeout=10)
        v = (r.stderr or "") + (r.stdout or "")
    except Exception:
        v = ""
    info["stream"] = "--with-stream" in v
    info["stream_dynamic"] = "--with-stream=dynamic" in v
    info["ssl_preread"] = "--with-stream_ssl_preread_module" in v
    m = re.search(r"nginx/([0-9][0-9.]*)", v)
    info["version"] = m.group(1) if m else ""
    return info

def _mux_status():
    """ТОЛЬКО диагностика (без изменений): кто занял :443/:80, готов ли nginx к SNI-mux,
    что произойдёт при включении мюкса и какие красные предупреждения."""
    o443 = _sock_occupant(443)
    o80 = _sock_occupant(80)
    ng = _nginx_stream_info()
    cp = _cert_pathes()
    domain = (CFG_CACHE.get("panel_domain") or "").strip()
    has_cert = bool(cp["cert"] and os.path.exists(cp["cert"]))
    cert_dns = _cert_renewal_is_dns(cp["domain"] or domain)
    st = _load(STATE, {}) or {}
    reality_port = None
    tls_ports = []
    for proto, inb in (st.get("inbounds") or {}).items():
        p = inb.get("port")
        if not p:
            continue
        meta = _proto_meta(proto) or {}
        if meta.get("group") == "reality":
            reality_port = p
        if meta.get("tls"):
            tls_ports.append(p)
    xray_holds_443 = ("xray" in (o443.get("proc") or "")) or (reality_port == 443)
    can_mux = bool(ng["installed"] and ng["stream"] and ng["ssl_preread"])
    our_nginx_443 = (not o443["free"] and "nginx" in (o443.get("proc") or "")
                     and ng["active"] and os.path.exists(_NG_CONF))
    applied = bool(ng["active"] and os.path.exists(_NG_CONF))
    plan = []
    if not o443["free"]:
        if our_nginx_443:
            plan.append("перенастроить НАШ веб-прокси nginx на :443 в stream/ssl_preread-мюкс (это тот же nginx, ничего чужого не трогаем)")
        else:
            plan.append("остановить текущий сервис на :443 (%s) — он будет отключён" % (o443["proc"] or "?"))
    plan.append("поднять наш stream/ssl_preread nginx на :443 (SNI-развилка по сертификату домена)")
    plan.append("cert-TLS inbound'ы (%s) завести на общий :443 через SNI" % (",".join(map(str, tls_ports)) or "—"))
    if reality_port:
        plan.append("Reality (: %s) через ssl_preread НЕ mux-ится (общий SNI с реальным сайтом) — оставить на отдельном порту" % reality_port)
    warnings = []
    if not o443["free"] and not our_nginx_443:
        warnings.append("На :443 сейчас чужой сервис (%s). При включении мюкса панель ОСТАНОВИТ его и не несёт ответственности за его работу после." % (o443["proc"] or "?"))
    if not o80["free"] and not has_cert and not cert_dns:
        warnings.append("Порт :80 занят (%s) и сертификата нет — HTTP-01 недоступен; выпустите сертификат через DNS-01 (Cloudflare)." % (o80["proc"] or "?"))
    if not ng["stream"] or not ng["ssl_preread"]:
        warnings.append("nginx не собран со stream_ssl_preread_module — SNI-mux через этот nginx невозможен.")
    elif ng["stream_dynamic"]:
        warnings.append("stream-модуль динамический (--with-stream=dynamic) — потребуется load_module в nginx.conf (это будет сделано во 2-м срезе).")
    return {"free443": o443["free"], "occupant443": o443, "free80": o80["free"], "occupant80": o80,
            "nginx": ng, "can_mux": can_mux, "xray_holds_443": xray_holds_443, "our_nginx_443": our_nginx_443,
            "reality_port": reality_port, "tls_ports": tls_ports, "domain": domain,
            "has_cert": has_cert, "cert_dns": cert_dns, "applied": applied,
            "plan": plan, "warnings": warnings}

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


def _all_iface_ips():
    """Все адреса всех интерфейсов VPS (lo и внешние), IPv4 и IPv6."""
    out = []
    try:
        r = subprocess.run(["ip", "-o", "addr", "show"],
                           capture_output=True, text=True, timeout=5).stdout
        iface_map = {}
        for line in r.splitlines():
            toks = line.split()
            if len(toks) < 4:
                continue
            ifname = toks[1]
            fam = toks[2]
            if fam not in ("inet", "inet6"):
                continue
            addr = toks[3].split("/")[0]
            iface_map.setdefault(ifname, {"ipv4": [], "ipv6": []})
            if fam == "inet":
                iface_map[ifname]["ipv4"].append(addr)
            else:
                iface_map[ifname]["ipv6"].append(addr)
        for ifname, ips in iface_map.items():
            out.append({"iface": ifname, "ipv4": ips["ipv4"], "ipv6": ips["ipv6"]})
    except Exception:
        pass
    if not out:
        out = [{"iface": "?", "ipv4": [_my_ip() or ""], "ipv6": [_my_ipv6() or ""]}]
    return out


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
    try:
        _f2b_maybe_ban(client_ip)
    except Exception as e:
        print("[f2b] " + str(e), flush=True)

def _login_ok(client_ip):
    _LOGIN_FAILS.pop(client_ip, None)

# ---------- fail2ban-lite: баны по IP в nftables (без fail2ban демона) ----------
# Таблица inet veil_bans: множества b4/b6 с timeout — IP отваливается сам.
# protected: IP с активной сессией панели НЕ банится (защита от самоблокировки),
# приватные/loopback адреса не банятся вообще. bans.json — персист ре-аппрая после рестарта.

BANS_FILE = f"{BASE}/bans.json"
BANS = {}

def _bans_load():
    global BANS
    try:
        d = json.load(open(BANS_FILE)) or {}
        if isinstance(d, dict):
            now = time.time()
            BANS = {ip: v for ip, v in d.items()
                    if isinstance(v, dict) and int(v.get("until") or 0) > now}
    except Exception:
        BANS = {}

def _bans_save():
    try:
        _save(BANS_FILE, BANS)
    except Exception as e:
        print("[f2b] bans save: " + str(e), flush=True)

def _bans_cleanup():
    """Убирает просроченные записи из BANS. True = были удаления."""
    now = time.time()
    gone = [ip for ip, v in BANS.items() if int(v.get("until") or 0) <= now]
    for ip in gone:
        BANS.pop(ip, None)
    if gone:
        _bans_save()
    return bool(gone)

def _f2b_cfg():
    if not CFG_CACHE.get("f2b_enabled", True):
        return None
    try:
        thr = max(1, int(CFG_CACHE.get("f2b_threshold") or 5))
        win = max(1, int(CFG_CACHE.get("f2b_window_min") or 10)) * 60
        ban = max(1, int(CFG_CACHE.get("f2b_ban_hours") or 24)) * 3600
    except Exception:
        return None
    return thr, win, ban

def _f2b_public(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except Exception:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or
                a.is_multicast or a.is_unspecified)

def _f2b_has_session(ip):
    now = time.time()
    for tok, meta in SESSIONS_META.items():
        if isinstance(meta, dict) and meta.get("ip") == ip and \
           float(SESSIONS.get(tok) or 0) > now:
            return True
    return False

def _f2b_nft(*args):
    try:
        subprocess.run(("nft",) + tuple(args), capture_output=True, text=True, timeout=10)
    except Exception as e:
        print("[f2b] nft " + " ".join(args[:3]) + ": " + str(e), flush=True)

def _f2b_bootstrap():
    """Пересоздаёт таблицу (идемпотентно при рестартах панели) и возвращает живые баны."""
    _f2b_nft("delete", "table", "inet", "veil_bans")
    _f2b_nft("add", "table", "inet", "veil_bans")
    _f2b_nft("add", "chain", "inet", "veil_bans", "input",
             "{ type filter hook input priority -100; policy accept; }")
    _f2b_nft("add", "set", "inet", "veil_bans", "b4", "{ type ipv4_addr; flags timeout; }")
    _f2b_nft("add", "set", "inet", "veil_bans", "b6", "{ type ipv6_addr; flags timeout; }")
    _f2b_nft("add", "rule", "inet", "veil_bans", "input",
             'iifname != "lo" ip saddr @b4 drop')
    _f2b_nft("add", "rule", "inet", "veil_bans", "input",
             'iifname != "lo" meta nfproto ipv6 ip6 saddr @b6 drop')
    now = time.time()
    for ip, v in list(BANS.items()):
        left = int(v.get("until") or 0) - now
        if left <= 0:
            BANS.pop(ip, None)
            continue
        fam = "b6" if ":" in ip else "b4"
        _f2b_nft("add", "element", "inet", "veil_bans", fam,
                 "{ " + ip + " timeout " + str(int(left)) + "s }")
    _bans_save()

def _ban_ip(ip, secs, reason):
    """Общий бан IP через inet/veil_bans + bans.json. False = уже забанен."""
    if ip in BANS:
        return False
    BANS[ip] = {"until": int(time.time()) + secs, "reason": reason, "fails": 0}
    _bans_save()
    fam = "b6" if ":" in ip else "b4"
    _f2b_nft("add", "element", "inet", "veil_bans", fam,
             "{ " + ip + " timeout " + str(secs) + "s }")
    return True

def _f2b_maybe_ban(ip):
    cfgf = _f2b_cfg()
    if not cfgf or ip in BANS:
        return
    thr, win, ban_sec = cfgf
    now = time.time()
    fails = [x for x in _LOGIN_FAILS.get(ip, []) if x > now - win]
    if len(fails) < thr:
        return
    if not _f2b_public(ip) or _f2b_has_session(ip):
        return
    if not _ban_ip(ip, ban_sec, "login fails"):
        return
    BANS[ip]["fails"] = len(fails)
    _bans_save()
    _audit("f2b_ban", ip=ip, fails=len(fails), hours=ban_sec // 3600)
    print("[f2b] бан " + ip + " на " + str(ban_sec // 3600) + "ч", flush=True)
    try:
        ids = CFG_CACHE.get("bot_chat_ids") or []
        if ids:
            _bot_send_message(ids[0],
                f"🔒 <b>fail2ban-lite:</b> {ip} забанен на {ban_sec // 3600}ч "
                f"({len(fails)} неудачных входов за {win // 60} мин)", "HTML")
    except Exception:
        pass

def _f2b_unban(ip):
    if ip not in BANS:
        return False
    BANS.pop(ip, None)
    _bans_save()
    fam = "b6" if ":" in ip else "b4"
    _f2b_nft("delete", "element", "inet", "veil_bans", fam, "{ " + ip + " }")
    _audit("f2b_unban", ip=ip)
    return True

# ---------- лимит устройств на клиента (P3) ----------
# Источник — access-лог Xray (в нём email == uuid клиента). Окно активности 15 мин;
# при превышении max_devices самый «свежий» публичный IP банируется на 2ч через
# veil_bans. WireGuard/amneziawg идут мимо Xray — для них лимит не применяется.

_XRAY_ACCESS = f"{BASE}/logs/xray-access.log"
_DEV_WIN_SEC = 900
_DEV_BAN_SEC = 2 * 3600
_DEVTRACK = {}          # uuid -> {ip: last_seen_ts}
_DEV_POS = [0, 0]       # [offset чтения, последний размер файла]

# Пример строки: `2026-09-22 12:56:32.927 from 1.2.3.4:5678 accepted vless:... [in] [uuid]`
_ACC_RE = re.compile(r"^\S+\s+\S+\s+(?:from\s+)?(\S+)\s+accepted\b")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

def _acc_email(line):
    for b in re.findall(r"\[([^\]]*)\]", line):
        if _UUID_RE.match(b.strip()):
            return b.strip()
    return ""

def _access_log_lines():
    try:
        sz = os.path.getsize(_XRAY_ACCESS)
    except OSError:
        return []
    if sz < _DEV_POS[1]:
        _DEV_POS[0] = 0              # copytruncate-ротация — читаем заново с нуля
    if sz == _DEV_POS[1] and _DEV_POS[0] == sz:
        return []
    try:
        with open(_XRAY_ACCESS, "r", errors="replace") as f:
            f.seek(_DEV_POS[0])
            data = f.read()
            _DEV_POS[0] = f.tell()
        _DEV_POS[1] = sz
    except OSError:
        return []
    return data.splitlines()

def _strip_port(addr):
    if addr.startswith("["):
        j = addr.find("]")
        return addr[1:j] if j > 0 else addr
    return addr.rsplit(":", 1)[0] if addr.count(":") == 1 else addr

def _device_tick(st):
    limits = {}
    names = {}
    for proto, inb in (st.get("inbounds") or {}).items():
        for c in inb.get("clients", []):
            names[c["uuid"]] = c.get("name") or str(c["uuid"])[:8]
            if proto in ("wireguard", "amneziawg"):
                continue
            md = int(c.get("max_devices") or 0)
            if md > 0:
                limits[c["uuid"]] = max(limits.get(c["uuid"], 0), md)
    now = time.time()
    for line in _access_log_lines():
        m = _ACC_RE.match(line)
        if not m:
            continue
        email = _acc_email(line)
        if not email or email not in limits:
            continue
        ip = _strip_port(m.group(1))
        if _f2b_public(ip):
            _DEVTRACK.setdefault(email, {})[ip] = now
    if not limits:
        _DEVTRACK.clear()
        return
    for email, md in limits.items():
        d = _DEVTRACK.get(email)
        if not d:
            continue
        for ip, ts in list(d.items()):
            if now - ts > _DEV_WIN_SEC:
                d.pop(ip, None)
        while len(d) > md:
            newest = max(d, key=lambda ip: d[ip])
            d.pop(newest, None)
            if _f2b_has_session(newest):
                continue
            if not _ban_ip(newest, _DEV_BAN_SEC, "devices:" + str(email)[:8]):
                break
            _audit("device_ban", ip=newest, uuid=email, name=names.get(email, ""),
                   max_devices=md)
            print("[devices] бан " + newest + " (клиент " + names.get(email, "") + ")",
                  flush=True)
            try:
                ids = CFG_CACHE.get("bot_chat_ids") or []
                if ids:
                    _bot_send_message(ids[0],
                        f"📱 <b>Лимит устройств</b>\nКлиент: {names.get(email, '?')}\n"
                        f"Разрешено: {md}, новый IP {newest} забанен на 2ч", "HTML")
            except Exception:
                pass

def _ensure_logrotate():
    """ротация access-лога Xray (50M, 2 копии) — панель ведёт лог постоянно."""
    try:
        os.makedirs(BASE + "/logs", exist_ok=True)
        with open("/etc/logrotate.d/veil-xray", "w") as f:
            f.write('"' + _XRAY_ACCESS + '" {\n    size 50M\n    rotate 2\n'
                    '    copytruncate\n    missingok\n    notifempty\n}\n')
    except Exception as e:
        print("logrotate: " + str(e), flush=True)

# ---------- P6: зеркалирование rule-set'ов RU/IR + полный sing-box конфиг ----------
# Панель скачивает свежие rule-set'ы из upstream-релизов и раздаёт их с себя
# (/rulesets/<файл>): клиенту не нужен доступ к GitHub из-под VPN.

RULESET_DIR = f"{BASE}/rulesets"
_RULESET_FILES = {"geoip-ru.srs", "geosite-ru.srs", "geoip-ir.db", "geosite-ir.db"}
_RULESET_STATE = {"updated": 0, "error": "", "tag_ru": "", "tag_ir": ""}

def _gh_release_latest(repo):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers=_gh_headers())
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)

def _rulesets_update():
    os.makedirs(RULESET_DIR, exist_ok=True)
    errs = []
    with tempfile.TemporaryDirectory(prefix="rs-") as tmp:
        try:
            rel = _gh_release_latest("runetfreedom/russia-v2ray-rules-dat")
            assets = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
            if "sing-box.zip" not in assets:
                raise RuntimeError("в релизе нет sing-box.zip")
            zp = os.path.join(tmp, "sb.zip")
            _dl(assets["sing-box.zip"], zp)
            with zipfile.ZipFile(zp) as z:
                # локальное имя <- участник архива: RU-напрямую = категории RU-сайтов
                want = {"geoip-ru.srs": "geoip-ru.srs",
                        "geosite-ru.srs": "geosite-category-ru.srs"}
                for local, member in want.items():
                    mem = [m for m in z.namelist() if m.endswith("/" + member)]
                    if not mem:
                        raise RuntimeError("в архиве нет " + member)
                    with z.open(mem[0]) as src, \
                         open(os.path.join(RULESET_DIR, local), "wb") as dst:
                        shutil.copyfileobj(src, dst)
            _RULESET_STATE["tag_ru"] = str(rel.get("tag_name", ""))
        except Exception as e:
            errs.append("ru: " + str(e))
        try:
            rel = _gh_release_latest("chocolate4u/Iran-sing-box-rules")
            assets = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
            for src_name, dst_name in (("geoip.db", "geoip-ir.db"),
                                       ("geosite.db", "geosite-ir.db")):
                if src_name not in assets:
                    raise RuntimeError("в релизе нет " + src_name)
                p = os.path.join(tmp, src_name)
                _dl(assets[src_name], p)
                shf = os.path.join(tmp, src_name + ".sha")
                _dl(assets[src_name + ".sha256sum"], shf)
                with open(shf) as f:
                    expected = f.read().strip().split()[0]
                if _sha256_file(p).lower() != expected.lower():
                    raise RuntimeError("sha256 не совпал: " + src_name)
                shutil.copy2(p, os.path.join(RULESET_DIR, dst_name))
            _RULESET_STATE["tag_ir"] = str(rel.get("tag_name", ""))
        except Exception as e:
            errs.append("ir: " + str(e))
    _RULESET_STATE["error"] = "; ".join(errs)
    if not errs:
        _RULESET_STATE["updated"] = int(time.time())
    print(("[rulesets] обновлены ru=" + _RULESET_STATE["tag_ru"] +
           " ir=" + _RULESET_STATE["tag_ir"]) if not errs
          else "[rulesets] " + _RULESET_STATE["error"], flush=True)
    return not errs

def _rulesets_loop():
    time.sleep(20)  # не тормозим старт панели
    while True:
        try:
            _rulesets_update()
        except Exception as e:
            _RULESET_STATE["error"] = str(e)
            print("[rulesets] " + str(e), flush=True)
        time.sleep(86400)

def _sb_config(st, sub_path, host, panel_port):
    """Полный standalone-конфиг sing-box для подписчика: tun + all outbounds
    + split-tunnel RU/IR через rule-sets, раздаваемые панелью. None = нет клиента."""
    outs = []
    tags = []
    split = (CFG_CACHE.get("split_tunnel") or "off").strip().lower()
    for proto, inb in (st.get("inbounds") or {}).items():
        if proto == "amneziawg":
            continue  # magic-амнезия в sing-box wireguard не импортируется
        for c in inb.get("clients", []):
            if c.get("sub_token") != sub_path and c.get("uuid") != sub_path:
                continue
            try:
                ob = _singbox_outbound(proto, inb, c, host)
            except Exception:
                continue
            if ob["tag"] in tags:
                continue
            # приоритет WG-туннелю: он стабильнее TCP-протоколов на мобильных
            if proto == "wireguard":
                outs.insert(0, ob)
                tags.insert(0, ob["tag"])
            else:
                outs.append(ob)
                tags.append(ob["tag"])
    if not outs:
        return None
    first = outs[0]["tag"]
    # ru: российские домены/сети — напрямую, остальное через VPN (аналог ru_bypass);
    # ir: перечисленные сервисы — через VPN, остальное напрямую (bypass-профиль).
    want = []
    proxy_matched = False
    if split == "ru":
        want = [("geoip-ru.srs", "geoip-ru"), ("geosite-ru.srs", "geosite-ru")]
    elif split == "ir":
        want = [("geoip-ir.db", "geoip-ir"), ("geosite-ir.db", "geosite-ir")]
        proxy_matched = True
    rule_sets = []
    for fname, tag in want:
        if not os.path.exists(os.path.join(RULESET_DIR, fname)):
            continue
        rule_sets.append({"tag": tag, "type": "remote", "format": "binary",
                          "url": f"{_pb(host, panel_port)}/rulesets/{fname}",
                          "download_detour": "direct"})
    rules = [{"protocol": ["dns"], "outbound": "dns-out"}]
    final = first
    if rule_sets:
        rules.append({"rule_set": [x["tag"] for x in rule_sets],
                      "outbound": first if proxy_matched else "direct"})
        if proxy_matched:
            final = "direct"
    dns = {"servers": [
               {"tag": "local-dns", "address": "https://dns.yandex.com/dns-query",
                "detour": "direct"},
               {"tag": "remote-dns", "address": "https://dns.google/dns-query",
                "detour": first}],
           "final": "remote-dns"}
    dns_rules = []
    if split == "ru" and any(x["tag"] == "geosite-ru" for x in rule_sets):
        dns_rules.append({"rule_set": ["geosite-ru"], "server": "local-dns"})
    if dns_rules:
        dns["rules"] = dns_rules
    return {
        "log": {"level": "warning"},
        "dns": dns,
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "interface_name": "veiltun",
             "address": ["172.19.0.1/30"], "auto_route": True,
             "strict_route": False, "stack": "mixed", "sniff": True},
            {"type": "mixed", "tag": "http-in", "listen": "127.0.0.1",
             "listen_port": 2080}],
        "outbounds": outs + [{"type": "direct", "tag": "direct"},
                             {"type": "dns", "tag": "dns-out"}],
        "route": {"rules": rules, "rule_set": rule_sets, "final": final}}

# ---------- P5: Prometheus-экспорт ----------

def _ms_label(s):
    return re.sub(r'[^A-Za-z0-9_.-]', '_', str(s or ""))[:64]

def _metrics_text():
    st = _load(STATE) or {}
    L = []
    def m(name, value, labels="", help_text=""):
        if help_text:
            L.append(f"# HELP {name} {help_text}")
            L.append(f"# TYPE {name} gauge")
        lab = ("{" + labels + "}") if labels else ""
        L.append(f"{name}{lab} {value}")
    m("veil_panel_up", 1, help_text="Veil panel process alive")
    m("veil_version_info", 1, f'version="{_ms_label(VERSION)}"', "Panel version")
    try:
        r = subprocess.run(["systemctl", "is-active", "xray"],
                           capture_output=True, text=True, timeout=5)
        m("veil_xray_active", 1 if r.stdout.strip() == "active" else 0,
          help_text="systemd xray unit active")
    except Exception:
        pass
    users = {}
    for proto, inb in (st.get("inbounds") or {}).items():
        for c in inb.get("clients", []):
            u = users.setdefault(c["uuid"], c)
    m("veil_clients_total", len(users), help_text="Unique subscription users")
    for uid, c in list(users.items())[:500]:
        lab = (f'email="{_ms_label(c.get("name") or str(uid)[:8])}",'
               f'uuid="{_ms_label(str(uid)[:8])}"')
        m("veil_client_used_bytes", _user_traffic(c), lab, "Traffic in current cycle")
        lim = float(c.get("limit_gb") or 0)
        m("veil_client_limit_bytes", int(lim * _GB), lab, "Traffic limit (0=unlimited)")
        m("veil_client_expiry_timestamp", int(c.get("expiry") or 0), lab, "Expiry unix ts")
        m("veil_client_blocked", 1 if c.get("blocked") else 0, lab, "Blocked by limits")
        m("veil_client_devices", len(_DEVTRACK.get(uid) or {}), lab, "Active devices (15m)")
    m("veil_login_fail_ips", sum(1 for v in _LOGIN_FAILS.values() if v),
      help_text="IPs with recent failed login attempts")
    m("veil_bans_active", len(BANS), help_text="Active nft bans (veil_bans)")
    try:
        du = shutil.disk_usage("/")
        m("veil_disk_total_bytes", du.total)
        m("veil_disk_free_bytes", du.free)
    except Exception:
        pass
    try:
        mi = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                mi[k.strip()] = int(v.split()[0]) * 1024
        m("veil_mem_total_bytes", mi.get("MemTotal", 0))
        m("veil_mem_available_bytes", mi.get("MemAvailable", 0))
    except Exception:
        pass
    try:
        if not _CERT_STATE.get("expire"):
            try: _cert_status()
            except Exception: pass
        exp = _CERT_STATE.get("expire") or 0
        if exp:
            m("veil_cert_expire_timestamp", int(exp), help_text="TLS cert expiry")
            m("veil_cert_days_left", int((exp - time.time()) / 86400))
    except Exception:
        pass
    m("veil_rulesets_updated_timestamp", _RULESET_STATE.get("updated") or 0,
      help_text="Last successful RU/IR ruleset mirror")
    m("veil_inbounds_total", len(st.get("inbounds") or {}))
    return "\n".join(L) + "\n"

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
        if "=" in out:
            val = out.split("=", 1)[1].strip()
            if not val or val == "n/a":
                return "не запущен"
            parts = val.split(" ", 1)
            if len(parts) == 2:
                dt_str = parts[1].replace(" UTC", "").strip()
                dt = datetime.datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                diff = int(time.time() - dt.replace(tzinfo=datetime.timezone.utc).timestamp())
                if diff < 0:
                    diff = 0
                if diff < 60:
                    return f"{diff} сек."
                elif diff < 3600:
                    return f"{diff // 60} мин."
                elif diff < 86400:
                    return f"{diff // 3600} ч. {(diff % 3600) // 60} мин."
                else:
                    return f"{diff // 86400} д. {(diff % 86400) // 3600} ч."
            return val
    except Exception:
        pass
    return "не запущен"

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
    """Создание или подключение зоны dynv6."""
    name = (name or "").strip().lower()
    account_token = (account_token or "").strip()
    if not name or not account_token:
        raise RuntimeError("нужны имя зоны и токен dynv6")
    if "." not in name:
        name = name + ".dynv6.net"
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", name):
        raise RuntimeError("имя зоны: латиница/цифры/./- (2–32 символа)")

    # Сохраняем зону и токен в конфиг сразу, чтобы пользователь не ждал таймаутов
    CFG_CACHE["dynv6_host"] = name
    CFG_CACHE["dynv6_token"] = account_token
    _save(CFG, CFG_CACHE)
    if not (CFG_CACHE.get("panel_domain") or "").strip():
        CFG_CACHE["panel_domain"] = name
        CFG_CACHE["dynv6_host"] = name
        _save(CFG, CFG_CACHE)

    # Быстрая попытка создания через API v2 с коротким таймаутом
    try:
        body = json.dumps({"name": name}).encode()
        req = urllib.request.Request("https://dynv6.com/api/v2/zones", data=body,
                                     method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Accept": "application/json",
                                              "Authorization": "Bearer " + account_token})
        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception:
        pass

    up = None
    try:
        up = _dynv6_update()
    except Exception as e:
        up = {"ok": False, "error": str(e)}
    return {"ok": True, "host": name, "token": account_token, "zone_created": True, "update": up}

def _dynv6_update(force4=None):
    conf = _dynv6_conf()
    host, token = conf["host"], conf["token"]
    if not host or not token:
        raise RuntimeError("dynv6 не настроен (нужны host и token)")
    if not re.fullmatch(r"(?i)[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", host):
        raise RuntimeError("некорректный dynv6-host")
    ip4, ip6 = _pub_ip4(), _pub_ip6()
    if force4:
        ip4 = str(force4)
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


# ---------- АВТОЗАМЕНА IP ПРИ ПАДЕНИИ ДОСТУПНОСТИ ИЗ РФ ----------

_ROT = {"ts": 0.0, "ok": 0, "total": 0, "pct": None, "state": "idle",
        "suspect_since": 0.0, "last_swap": 0.0, "ip": "", "error": "",
        "events": [], "busy": False}
_ROT_LOCK = threading.Lock()


def _is_ip4(s):
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", s or "")) and all(
        int(x) < 256 for x in (s or "0").split("."))


def _is_pub_ip4(s):
    """Публичный IPv4 (не loopback/private/CGNAT/link-local/multicast/reserved)."""
    if not _is_ip4(s):
        return False
    try:
        import ipaddress
        return ipaddress.ip_address(s).is_global
    except Exception:
        return False


def _rot_conf():
    def _num(key, dflt, lo, hi):
        try:
            v = float(CFG_CACHE.get(key) if CFG_CACHE.get(key) is not None else dflt)
        except Exception:
            v = float(dflt)
        return max(lo, min(hi, v))
    prov = (CFG_CACHE.get("rot_provider") or "dynv6").strip().lower()
    if prov not in ("off", "dynv6", "cloudflare", "both"):
        prov = "dynv6"
    pool = [x.strip() for x in (CFG_CACHE.get("rot_pool") or []) if _is_ip4(x.strip())]
    dom = (CFG_CACHE.get("panel_domain") or "").strip()
    return {
        "enabled": bool(CFG_CACHE.get("rot_enabled")),
        "threshold": _num("rot_threshold", 50, 1, 100),
        "window_min": int(_num("rot_window_min", 5, 0, 180)),
        "check_min": int(_num("rot_check_min", 15, 5, 240)),
        "cooldown_min": int(_num("rot_cooldown_min", 30, 1, 1440)),
        "provider": prov,
        "pool": pool,
        "use_iface": bool(CFG_CACHE.get("rot_use_iface", True)),
        "target": (CFG_CACHE.get("rot_target") or dom or _pub_ip4() or "").strip(),
        "port": int(_num("rot_port", 443, 1, 65535)),
        "path": (CFG_CACHE.get("rot_path") or "/").strip() or "/",
        "cf_zone": (CFG_CACHE.get("cf_zone") or "").strip(),
        "cf_records": list(CFG_CACHE.get("cf_records") or []),
        "cf_has_token": bool(CFG_CACHE.get("cf_token")),
    }


def _rot_event(text, kind="info"):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%d.%m %H:%M")
    with _ROT_LOCK:
        _ROT["events"] = (_ROT["events"] + [{"ts": ts, "text": text, "kind": kind}])[-40:]


def _rot_notify(text):
    ids = CFG_CACHE.get("bot_chat_ids") or []
    if not ids:
        return
    try:
        _bot_send_message(ids[0], text, "HTML")
    except Exception:
        pass


def _rot_candidates():
    """Кандидаты на замену: явно заданный пул + адреса интерфейсов (если разрешено)."""
    cfg = _rot_conf()
    out = []
    for ip in cfg["pool"]:
        if ip not in out:
            out.append(ip)
    if cfg["use_iface"]:
        try:
            for a in _all_iface_ips():
                for ip in a.get("ipv4") or []:
                    if _is_pub_ip4(ip) and ip not in out:
                        out.append(ip)
        except Exception:
            pass
    return out


def _rot_pick_ip(cur):
    """Следующий свободный IP после текущего (round-robin по списку)."""
    cand = [ip for ip in _rot_candidates() if ip != cur]
    if not cand:
        return ""
    last = (CFG_CACHE.get("rot_last_ip") or "").strip()
    if last in cand:
        try:
            i = (cand.index(last) + 1) % len(cand)
            return cand[i]
        except Exception:
            pass
    return cand[0]


def _gp_probe(target, port=443, path="/", proto=None, limit=20, wait_s=200):
    """Серверная проверка доступности через Globalping (зонды из РФ). -> (ok, total)"""
    if not target:
        raise RuntimeError("не задан адрес для проверки")
    proto = proto or ("HTTPS" if port in (443, 8443, 2053, 2083, 2087, 2096) else "HTTP")
    body = {"type": "http", "target": target,
            "locations": [{"country": "RU", "limit": limit}],
            "measurementOptions": {"protocol": proto, "port": port,
                                   "request": {"method": "GET", "path": path}}}
    def _req(url, data=None):
        req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                     headers={"Content-Type": "application/json",
                                              "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=25) as r:
            return json.loads(r.read().decode("utf-8", "replace") or "{}")
    d = _req("https://api.globalping.io/v1/measurements", json.dumps(body).encode())
    mid = (d.get("id") or "").strip()
    if not mid:
        raise RuntimeError("Globalping не вернул id измерения")
    deadline = time.time() + wait_s
    results = None
    while time.time() < deadline:
        time.sleep(6)
        try:
            dd = _req("https://api.globalping.io/v1/measurements/" + mid)
        except Exception:
            continue
        if dd.get("status") == "finished":
            results = dd.get("results") or []
            break
        if dd.get("status") == "failed":
            raise RuntimeError("Globalping: измерение не удалось")
    if results is None:
        raise RuntimeError("таймаут ожидания результатов Globalping")
    ok = 0
    for r in results:
        st = (r.get("result") or {})
        if st.get("statusCode") and 200 <= int(st["statusCode"]) < 400:
            ok += 1
    return ok, len(results)


def _cf_api(method, path, body=None):
    tok = (CFG_CACHE.get("cf_token") or "").strip()
    if not tok:
        raise RuntimeError("не задан API-токен Cloudflare (Zone → DNS:Edit)")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request("https://api.cloudflare.com/client/v4" + path, data=data,
                                 method=method,
                                 headers={"Authorization": "Bearer " + tok,
                                          "Content-Type": "application/json",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            d = json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        try:
            txt = e.read().decode("utf-8", "replace")[:200]
        except Exception:
            txt = ""
        raise RuntimeError("cloudflare HTTP %d %s" % (e.code, txt))
    if not d.get("success"):
        errs = d.get("errors") or []
        msg = errs[0].get("message") if errs and isinstance(errs[0], dict) else str(errs)
        raise RuntimeError("cloudflare: " + str(msg)[:200])
    return d.get("result")


def _cf_zone():
    z = (CFG_CACHE.get("cf_zone") or "").strip().lower()
    if not z:
        dom = (CFG_CACHE.get("panel_domain") or "").strip().lower()
        if dom:
            z = ".".join(dom.rsplit(".", 2)[-2:])
    if not z:
        raise RuntimeError("не задана зона Cloudflare")
    cached = CFG_CACHE.get("cf_zone_id")
    if cached:
        return cached, z
    res = _cf_api("GET", "/zones?" + urllib.parse.urlencode({"name": z})) or []
    if not res:
        raise RuntimeError("зона %s не найдена в Cloudflare" % z)
    zid = res[0].get("id") or ""
    if zid:
        CFG_CACHE["cf_zone_id"] = zid
        _save(CFG, CFG_CACHE)
    return zid, z


def _cf_record_names():
    raw = CFG_CACHE.get("cf_records") or []
    if isinstance(raw, str):
        raw = re.split(r"[,\s]+", raw)
    _, zone = _cf_zone()
    out = []
    for n in raw:
        n = (n or "").strip().strip(".").lower()
        if not n or n in ("@", "apex"):
            n = zone
        elif not n.endswith("." + zone) and n != zone and "." not in n:
            n = n + "." + zone
        if n not in out:
            out.append(n)
    if not out:
        dom = (CFG_CACHE.get("panel_domain") or "").strip().lower()
        out = [dom or zone]
    return out


def _cf_current_ip():
    """IP, на который сейчас смотрит первая A-запись (или '' если не определён)."""
    try:
        zid, _ = _cf_zone()
        names = _cf_record_names()
        res = _cf_api("GET", "/zones/%s/dns_records?type=A&name=%s&per_page=5" %
                      (urllib.parse.quote(zid), urllib.parse.quote(names[0]))) or []
        return (res[0].get("content") if res else "") or ""
    except Exception:
        return ""


def _cf_set_ip(ip):
    """Заменить content у всех настроенных A-записей. Вернуть список изменений."""
    zid, zone = _cf_zone()
    changed = []
    for name in _cf_record_names():
        res = _cf_api("GET", "/zones/%s/dns_records?type=A&name=%s&per_page=5" %
                      (urllib.parse.quote(zid), urllib.parse.quote(name))) or []
        if not res:
            raise RuntimeError("A-запись %s не найдена в зоне %s" % (name, zone))
        for rec in res:
            if (rec.get("content") or "") == ip:
                continue
            body = {"type": "A", "name": name, "content": ip,
                    "ttl": int(rec.get("ttl") or 60), "proxied": bool(rec.get("proxied"))}
            _cf_api("PUT", "/zones/%s/dns_records/%s" % (urllib.parse.quote(zid),
                                                         urllib.parse.quote(rec.get("id") or "")),
                    body)
            changed.append({"name": name, "from": rec.get("content"), "to": ip,
                            "proxied": body["proxied"]})
    return changed


def _rot_apply(ip):
    """Применить новый IP к выбранным провайдерам DNS. Вернуть отчёт."""
    cfg = _rot_conf()
    rep = []
    prov = cfg["provider"]
    if prov in ("dynv6", "both"):
        try:
            r = _dynv6_update(force4=ip)
            rep.append("dynv6: %s → %s" % (r.get("host"), ip))
        except Exception as e:
            rep.append("dynv6: ошибка %s" % str(e)[:120])
    if prov in ("cloudflare", "both"):
        try:
            ch = _cf_set_ip(ip)
            rep.append("cloudflare: " + (", ".join("%s %s→%s%s" %
                       (c["name"], c["from"], c["to"], " (оранжевое облако)" if c["proxied"] else "")
                       for c in ch) if ch else "записи уже актуальны"))
        except Exception as e:
            rep.append("cloudflare: ошибка %s" % str(e)[:160])
    if prov == "off":
        rep.append("провайдер смены выключен")
    return rep


def _rotate_ip(reason=""):
    """Одна замена IP. Возвращает (ok, сообщение)."""
    cfg = _rot_conf()
    if cfg["provider"] == "off":
        return False, "провайдер смены не выбран"
    if time.time() - _ROT["last_swap"] < cfg["cooldown_min"] * 60:
        return False, "кулдаун %d мин после прошлой замены" % cfg["cooldown_min"]
    cur = _cf_current_ip() if cfg["provider"] in ("cloudflare", "both") else (_pub_ip4() or "")
    if not cur:
        cur = _pub_ip4() or ""
    new = _rot_pick_ip(cur)
    if not new:
        return False, "нет свободных IP в пуле (текущий %s)" % (cur or "?")
    rep = _rot_apply(new)
    CFG_CACHE["rot_last_ip"] = new
    _save(CFG, CFG_CACHE)
    with _ROT_LOCK:
        _ROT["last_swap"] = time.time()
        _ROT["ip"] = new
        _ROT["state"] = "idle"
        _ROT["suspect_since"] = 0.0
    _rot_event("замена IP %s → %s%s: %s" % (cur or "?", new, (" (" + reason + ")") if reason else "",
                                            "; ".join(rep)), "swap")
    _audit("ip_rotate", frm=cur, to=new, provider=cfg["provider"], reason=reason)
    _rot_notify("🔁 <b>Сменён IP: %s → %s</b>\n%s\nПричина: %s" %
                (cur or "?", new, "\n".join(rep), reason or "доступность из РФ"))
    return True, "; ".join(rep)


def _rot_tick():
    """Один шаг монитора: замер, при низком результате — окно перепроверки и замена."""
    cfg = _rot_conf()
    if not cfg["enabled"] or cfg["provider"] == "off" or not cfg["target"]:
        return
    with _ROT_LOCK:
        if _ROT["busy"]:
            return
        _ROT["busy"] = True
    try:
        ok, total = _gp_probe(cfg["target"], cfg["port"], cfg["path"])
    except Exception as e:
        with _ROT_LOCK:
            _ROT["error"] = str(e)[:200]
            _ROT["busy"] = False
        _rot_event("проверка доступности не удалась: " + str(e)[:160], "err")
        return
    if total <= 0:
        with _ROT_LOCK:
            _ROT["error"] = "нет ответов от зондов"
            _ROT["busy"] = False
        return
    pct = ok * 100.0 / total
    now = time.time()
    with _ROT_LOCK:
        _ROT.update(ts=now, ok=ok, total=total, pct=pct, error="")
        state = _ROT["state"]
        suspect = _ROT["suspect_since"]
    _gp_record_history(ok, total, cfg)
    if pct > cfg["threshold"]:
        if state != "idle":
            _rot_event("доступность восстановилась: %d/%d (%.0f%%)" % (ok, total, pct), "ok")
        with _ROT_LOCK:
            _ROT["state"] = "idle"
            _ROT["suspect_since"] = 0.0
        return
    if state != "suspect":
        _rot_event("доступность %.0f%% ≤ порога %.0f%% (%d/%d)" % (pct, cfg["threshold"], ok, total),
                   "warn")
        with _ROT_LOCK:
            _ROT["state"] = "suspect"
            _ROT["suspect_since"] = now
        if cfg["window_min"] <= 0:
            _rotate_ip("сразу: %.0f%%" % pct)
        return
    if now - suspect < cfg["window_min"] * 60:
        return
    _rotate_ip("повторно %.0f%% через %d мин" % (pct, cfg["window_min"]))


def _gp_record_history(ok, total, cfg):
    """Записать серверный замер в ту же историю, что и браузерные проверки."""
    entry = {"created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
             "success": ok == total, "success_count": ok, "total_count": total,
             "source": "panel", "target": "%s:%d%s" % (cfg["target"], cfg["port"], cfg["path"]),
             "details": []}
    try:
        p = f"{BASE}/globalping_history.json"
        h = _load(p, []) or []
        if not isinstance(h, list):
            h = []
        h = (h + [entry])[-50:]
        _save(p, h)
        _gp_maybe_alert(entry)
    except Exception:
        pass


def _rotate_loop():
    time.sleep(45)
    while True:
        try:
            cfg = _rot_conf()
            iv = max(300, cfg["check_min"] * 60)
            t0 = time.time()
            if cfg["enabled"]:
                _rot_tick()
            with _ROT_LOCK:
                busy = _ROT["busy"]
            if not busy:
                time.sleep(max(30, min(120, iv - (time.time() - t0))))
        except Exception as e:
            try:
                _ROT["error"] = str(e)[:200]
            except Exception:
                pass
            time.sleep(120)


def _rot_status():
    cfg = _rot_conf()
    with _ROT_LOCK:
        st = dict(_ROT)
        st["events"] = list(_ROT["events"])[-12:]
    st["conf"] = cfg
    st["pool"] = _rot_candidates()
    st["now_ip4"] = _pub_ip4() or ""
    st["iface_ips"] = [a.get("ipv4") or [] for a in _all_iface_ips()]
    st["iface"] = [{"iface": a.get("iface"), "ipv4": a.get("ipv4") or []} for a in _all_iface_ips()]
    if cfg["provider"] in ("cloudflare", "both"):
        st["cf_ip"] = _cf_current_ip()
        st["cf_records"] = _cf_record_names() if CFG_CACHE.get("cf_token") else []
    return st


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


def _pb(host, panel_port):
    """Базовый URL панели; схема следует реальному режиму: https только когда серт подключён."""
    return ("https" if _WEB_CTX is not None else "http") + f"://{host}:{panel_port}"


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

def _cf_txt_upsert(name, content, ttl=120):
    """Создать/обновить TXT-запись в зоне Cloudflare (для DNS-01)."""
    zid, _ = _cf_zone()
    base = "/zones/%s/dns_records" % urllib.parse.quote(zid)
    q = urllib.parse.urlencode({"type": "TXT", "name": name})
    found = _cf_api("GET", base + "?" + q) or []
    body = {"type": "TXT", "name": name, "content": content, "ttl": int(ttl)}
    if found:
        return _cf_api("PUT", base + "/" + urllib.parse.quote(found[0].get("id") or ""), body)
    return _cf_api("POST", base, body)


def _cf_txt_delete(name):
    """Удалить все TXT-записи с таким именем в зоне Cloudflare."""
    zid, _ = _cf_zone()
    base = "/zones/%s/dns_records" % urllib.parse.quote(zid)
    q = urllib.parse.urlencode({"type": "TXT", "name": name})
    for rec in (_cf_api("GET", base + "?" + q) or []):
        rid = rec.get("id")
        if rid:
            _cf_api("DELETE", base + "/" + urllib.parse.quote(rid))


def _dns01_provider():
    """Провайдер DNS-01 по настройкам: cloudflare | '' (dynv6 DNS-01 не поддерживает)."""
    c = CFG_CACHE or {}
    if (c.get("cf_token") or "").strip():
        return "cloudflare"
    return ""


def _dns01_hook_main(argv=None):
    """Режим хука certbot DNS-01: `python3 panel.py --dns01-hook auth|cleanup`.
    Читает CERTBOT_DOMAIN / CERTBOT_VALIDATION из окружения и обновляет TXT
    _acme-challenge.<domain> через API DNS-провайдера. Запускается certbot отдельным
    процессом, поэтому перечитывает config.json при импорте."""
    import sys
    argv = argv if argv is not None else sys.argv
    action = (argv[2] if len(argv) > 2 else "").strip().lower()
    domain = (os.environ.get("CERTBOT_DOMAIN") or "").strip().rstrip(".").lower()
    value = (os.environ.get("CERTBOT_VALIDATION") or "").strip()
    if not domain:
        raise RuntimeError("CERTBOT_DOMAIN не задан")
    name = "_acme-challenge." + domain
    prov = _dns01_provider()
    if prov != "cloudflare":
        raise RuntimeError("DNS-01 доступен только при настроенном Cloudflare (токен Zone→DNS:Edit + зона)")
    if action == "auth":
        _cf_txt_upsert(name, value)
        time.sleep(8)   # даём записи распространиться, прежде чем ACME проверит
    elif action == "cleanup":
        _cf_txt_delete(name)
    else:
        raise RuntimeError("неизвестное действие хука DNS-01: " + (action or "?"))


def _cert_issue(email=None, mode="auto"):
    if _CERT_STATE.get("busy"):
        raise RuntimeError("выпуск сертификата уже идёт")
    domain = (CFG_CACHE.get("panel_domain") or "").strip()
    if not domain or re.fullmatch(r"[0-9.]+", domain) or ":" in domain or "//" in domain:
        raise RuntimeError("сначала задай домен (не IP) — в поле ниже или через DDNS")
    mode = (mode or "auto").strip().lower()
    if mode not in ("auto", "http01", "dns01"):
        mode = "auto"
    free80 = _port_free(80)
    if mode == "auto":
        mode = "http01" if free80 else "dns01"
    if mode == "http01":
        if not free80:
            raise RuntimeError("порт 80 занят — HTTP-01 невозможен; используйте DNS-01 (нужен Cloudflare)")
    else:  # dns01
        if _dns01_provider() != "cloudflare":
            raise RuntimeError("DNS-01 требует Cloudflare (токен Zone→DNS:Edit + зона). "
                               "dynv6 не умеет выпускать TXT для ACME своим update-токеном. "
                               + ("Порт :80 занят — освободите его для HTTP-01. " if not free80 else "")
                               + "Настройте Cloudflare во вкладке Сайт.")
    cur = _pub_ip4()
    if cur and mode == "http01":
        point = _domain_points(domain, {cur})
        if not point:
            raise RuntimeError("домен " + domain + " сейчас не указывает на этот сервер (" +
                               cur + ") — сначала DDNS / A-запись")
    os.makedirs(CERT_DIR, exist_ok=True)
    live = f"{CERT_DIR}/live/veil-{domain}"
    certp = f"{live}/fullchain.pem"; keyp = f"{live}/privkey.pem"
    _CERT_STATE["busy"] = True
    try:
        email = (email or CFG_CACHE.get("cert_email") or "").strip()
        if mode == "http01":
            args = ["certbot", "certonly", "--standalone", "--preferred-challenges", "http",
                    "-d", domain, "--non-interactive", "--agree-tos"]
        else:
            import sys
            me = os.path.abspath(__file__)
            py = sys.executable or "python3"
            args = ["certbot", "certonly", "--manual", "--preferred-challenges", "dns",
                    "--manual-auth-hook", "%s %s --dns01-hook auth" % (py, me),
                    "--manual-cleanup-hook", "%s %s --dns01-hook cleanup" % (py, me),
                    "-d", domain, "--non-interactive", "--agree-tos"]
        if email:
            args += ["--email", email]
        else:
            args += ["--register-unsafely-without-email"]
        args += ["--config-dir", CERT_DIR, "--work-dir", CERT_DIR + "/work",
                 "--logs-dir", CERT_DIR + "/logs", "--cert-name", "veil-" + domain]
        r = subprocess.run(args, capture_output=True, text=True, timeout=320)
        if r.returncode != 0:
            raise RuntimeError("certbot: " + (r.stderr or r.stdout)[-400:])
        subprocess.run(["chmod", "-R", "o+rX", CERT_DIR], capture_output=True)
        if not (os.path.exists(certp) and os.path.exists(keyp)):
            raise RuntimeError("certbot завершился, но no fullchain/privkey")
        if email:
            CFG_CACHE["cert_email"] = email
        CFG_CACHE["cert"] = certp; CFG_CACHE["cert_key"] = keyp
        CFG_CACHE["cert_domain"] = domain
        CFG_CACHE["panel_cert_path"] = certp
        CFG_CACHE["panel_key_path"] = keyp
        CFG_CACHE["panel_domain"] = domain
        _save(CFG, CFG_CACHE)
        _CERT_STATE.update(domain=domain, cert=certp, key=keyp,
                           issued=os.path.getmtime(certp), expire=_cert_expire(certp), error="")
        _attach_cert_to_tls()
        try:
            _reload_cert_runtime()
        except Exception:
            pass
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

def _cert_renewal_is_dns(domain):
    """True, если сертификат создан через DNS-01 (manual-auth-hook) — тогда продление
    не требует свободного :80 и certbot renew сам перезапустит хуки."""
    if not domain:
        return False
    try:
        with open(f"{CERT_DIR}/renewal/veil-{domain}.conf") as f:
            t = f.read()
    except Exception:
        return False
    return "manual-auth-hook" in t or "dns-cloudflare" in t

def _cert_maybe_renew():
    if not CFG_CACHE.get("cert_auto", True):
        return
    cp = _cert_pathes()
    if not (cp["cert"] and os.path.exists(cp["cert"])):
        return
    exp = _cert_expire(cp["cert"])
    if exp and exp > time.time() + 30 * 86400:
        return
    if not _port_free(80) and not _cert_renewal_is_dns(cp["domain"]):
        _CERT_STATE["error"] = "порт 80 занят — автопродление (HTTP-01) сейчас невозможно"
        return
    r = subprocess.run(["certbot", "renew", "--config-dir", CERT_DIR,
                        "--work-dir", CERT_DIR + "/work", "--logs-dir", CERT_DIR + "/logs",
                        "--non-interactive"], capture_output=True, text=True, timeout=320)
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
    if not _port_free(80) and not _cert_renewal_is_dns(cp["domain"]):
        raise RuntimeError("порт 80 занят — продление (HTTP-01) невозможно; перевыпустите сертификат через DNS-01 (Cloudflare)")
    _CERT_STATE["busy"] = True
    try:
        r = subprocess.run(["certbot", "renew", "--force-renewal",
                            "--config-dir", CERT_DIR,
                            "--work-dir", CERT_DIR + "/work", "--logs-dir", CERT_DIR + "/logs",
                            "--non-interactive"], capture_output=True, text=True, timeout=320)
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
                try:
                    if _traffic_tick(st):
                        _save(STATE, st)
                except Exception as e:
                    print("[traffic] " + str(e), flush=True)
                try:
                    if _maybe_traffic_alerts(st):
                        _save(STATE, st)
                except Exception as e:
                    print("[alert] " + str(e), flush=True)
                try:
                    _bans_cleanup()
                except Exception as e:
                    print("[f2b] " + str(e), flush=True)
                try:
                    _device_tick(st)
                except Exception as e:
                    print("[devices] " + str(e), flush=True)
                bl = _autoblock_limits(st)
                if bl:
                    _save(STATE, st)
                    try:
                        _awg_sync(st)
                        _wg_sync(st)
                        _write_xray(st); _restart_xray()
                    except Exception as e:
                        print("[limits] " + str(e), flush=True)
                    print("[limits] автоблок: " +
                          ", ".join(f"{b['name']}({b['reason']})" for b in bl), flush=True)
                    _notify_blocked(bl)
        except Exception as e:
            print("[limits] " + str(e), flush=True)
        time.sleep(60)

def _bot_poll_loop():
    time.sleep(10)
    last_update_id = 0
    while True:
        try:
            token = CFG_CACHE.get("bot_token", "")
            if token:
                url = f"https://api.telegram.org/bot{token}/getUpdates?offset={last_update_id + 1}&timeout=25"
                with urllib.request.urlopen(url, timeout=40) as resp:
                    data = json.load(resp)
                if data.get("ok"):
                    for update in data.get("result", []):
                        last_update_id = max(last_update_id, update["update_id"])
                        try:
                            _process_bot_update(update)
                        except Exception as e:
                            print("[bot] poll update error: " + str(e), flush=True)
                elif data.get("description"):
                    print("[bot] getUpdates: " + str(data.get("description")), flush=True)
        except (socket.timeout, TimeoutError):
            pass
        except urllib.error.URLError as e:
            if not isinstance(getattr(e, "reason", None), (socket.timeout, TimeoutError)):
                print("[bot] poll loop error: " + str(e), flush=True)
        except Exception as e:
            print("[bot] poll loop error: " + str(e), flush=True)
        time.sleep(2)

threading.Thread(target=_ddns_loop, daemon=True).start()
threading.Thread(target=_rotate_loop, daemon=True).start()
threading.Thread(target=_limits_loop, daemon=True).start()
threading.Thread(target=_bot_poll_loop, daemon=True).start()
threading.Thread(target=_rulesets_loop, daemon=True).start()

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

    def handle_error(self, request, client_address):
        import sys as _sys
        et = _sys.exc_info()[0]
        if et and issubclass(et, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                                  socket.timeout, TimeoutError)):
            return
        super().handle_error(request, client_address)

    def _send(self, code, obj, ctype="application/json"):
        if code == 200 and isinstance(obj, dict) and "ok" not in obj:
            obj = dict(obj)
            obj["ok"] = True
        b = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).replace(r'\/', '/').encode()
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

    # ----.ext: входящий API для внешних панелей/узлов----
    def _ext_get(self, p):
        t = _ext_auth(self)
        if t is None:
            return
        st = _load(STATE) or {}
        inbs = st.get("inbounds") or {}
        if p == "/api/ext/status":
            try:
                with open("/proc/uptime") as f:
                    uptime = int(float(f.read().split()[0]))
            except Exception:
                uptime = 0
            today_k = time.strftime("%Y-%m-%d")
            uuids = {c.get("uuid") for inb in inbs.values() for c in inb.get("clients", [])}
            online = 0
            for u in uuids:
                try: online += _online_count(u)
                except Exception: pass
            inb_list = [{"proto": proto, "port": inb.get("port"),
                         "clients": len(inb.get("clients") or [])}
                        for proto, inb in inbs.items()]
            return self._send(200, {
                "version": VERSION, "uptime": uptime,
                "xray": subprocess.run(["systemctl", "is-active", "--quiet", "xray"]).returncode == 0,
                "clients": len(uuids), "online": online,
                "traffic_today": int(_TRAFFIC_DAYS.get(today_k) or 0),
                "inbounds": inb_list})
        if p == "/api/ext/inbounds":
            return self._send(200, {"inbounds": [
                {"proto": proto, "port": inb.get("port"),
                 "clients": len(inb.get("clients") or [])}
                for proto, inb in inbs.items()]})
        if p == "/api/ext/traffic":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            u = (qs.get("uuid") or [""])[0].strip()
            out = []
            for proto, inb in inbs.items():
                for c in inb.get("clients") or []:
                    if c.get("ext_owner") != t.get("id"):
                        continue
                    if u and c.get("uuid") != u:
                        continue
                    try: on = _online_count(c.get("uuid"))
                    except Exception: on = 0
                    out.append({"uuid": c.get("uuid"), "name": c.get("name"),
                                "proto": proto, "up": int(c.get("up") or 0),
                                "down": int(c.get("down") or 0),
                                "limit_gb": float(c.get("limit_gb") or 0),
                                "expiry": int(c.get("expiry") or 0),
                                "blocked": bool(c.get("blocked")), "online": on})
            if u and not out:
                return self._send(404, {"error": "клиент не найден или не принадлежит токену"})
            return self._send(200, {"clients": out})
        return self._send(404, {"error": "not found"})

    def _ext_post(self, p):
        t = _ext_auth(self, need_write=True)
        if t is None:
            return
        try:
            b = self._body()
        except Exception:
            return self._send(400, {"error": "bad json"})
        tid = t.get("id")
        if p == "/api/ext/clients":
            name = (b.get("name") or "").strip() or "Клиент"
            proto = (b.get("proto") or "").strip()
            st = _load(STATE) or {}
            inb = (st.get("inbounds") or {}).get(proto)
            if not inb:
                return self._send(400, {"error": "inbound не найден; допустимы только существующие"})
            limit_gb = float(b.get("limit_gb") or 0) or None
            try:
                _edays = int(b.get("expiry_days") or 0)
            except Exception:
                return self._send(400, {"error": "expiry_days не число"})
            expiry = (int(time.time()) + _edays * 86400) if _edays > 0 else 0
            reset_cycle = (b.get("reset_cycle") or "").strip().lower()
            try:
                max_devices = max(0, int(b.get("max_devices") or 0))
            except Exception:
                max_devices = 0
            c = _new_client(name, proto, inb, limit_gb=limit_gb, expiry=expiry,
                            reset_cycle=reset_cycle, max_devices=max_devices)
            c["ext_owner"] = tid
            inb.setdefault("clients", []).append(c)
            host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
            host = host if "://" not in host else urllib.parse.urlparse(host).netloc
            panel_port = CFG_CACHE.get("panel_port", 8444)
            _awg_sync(st); _wg_sync(st)
            _write_xray(st); _save(STATE, st)
            _restart_xray()
            link = ""
            try:
                link = _link(inb, host, c, proto)
            except Exception:
                pass
            _audit("ext_client_add", uuid=c["uuid"], name=name, proto=proto, token=t.get("label"))
            return self._send(200, {"client": {
                "uuid": c["uuid"], "name": name, "proto": proto,
                "sub_token": c.get("sub_token"),
                "sub_url": f"{_pb(host, panel_port)}/sub/{c.get('sub_token')}",
                "link": link}})
        if p == "/api/ext/clients/update":
            u = (b.get("uuid") or "").strip()
            st = _load(STATE) or {}
            group = _ext_owned_group(st, tid, u)
            if not group:
                return self._send(404, {"error": "клиент не найден или не принадлежит токену"})
            if "limit_gb" in b:
                try: lg = max(0.0, float(b.get("limit_gb") or 0))
                except Exception: return self._send(400, {"error": "limit_gb не число"})
                for c in group:
                    c["limit_gb"] = lg
                    if lg > 0: c["warned_80"] = False
            if "expiry_days" in b:
                try: d = max(0, int(b.get("expiry_days") or 0))
                except Exception: return self._send(400, {"error": "expiry_days не число"})
                exp = (int(time.time()) + d * 86400) if d > 0 else 0
                for c in group:
                    c["expiry"] = exp; c["warned_days"] = []
            if "reset_cycle" in b:
                rc = (b.get("reset_cycle") or "").strip().lower()
                if rc not in ("", "day", "week", "month"):
                    return self._send(400, {"error": "reset_cycle: day|week|month или ''"})
                for c in group: c["reset_cycle"] = rc
            if "max_devices" in b:
                try: md = max(0, int(b.get("max_devices") or 0))
                except Exception: return self._send(400, {"error": "max_devices не число"})
                for c in group: c["max_devices"] = md
            _awg_sync(st); _wg_sync(st)
            _write_xray(st); _save(STATE, st)
            _restart_xray()
            _audit("ext_client_update", uuid=u, token=t.get("label"))
            return self._send(200, {"ok": True})
        if p == "/api/ext/clients/delete":
            u = (b.get("uuid") or "").strip()
            st = _load(STATE) or {}
            group = _ext_owned_group(st, tid, u)
            if not group:
                return self._send(404, {"error": "клиент не найден или не принадлежит токену"})
            for proto, inb in list((st.get("inbounds") or {}).items()):
                inb["clients"] = [c for c in inb.get("clients") or []
                                  if not (c.get("uuid") == u and c.get("ext_owner") == tid)]
            if st.get("active") not in st.get("inbounds", {}):
                st["active"] = _proto_of(st)
            _awg_sync(st); _wg_sync(st)
            _write_xray(st); _save(STATE, st)
            _restart_xray()
            _audit("ext_client_delete", uuid=u, token=t.get("label"))
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})

    # ---- GET ----
    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        
        if p.startswith("/sub/") or p in ("/sub", "/sub/"):
            # Универсальная подписка (/sub) или личная подписка клиента (/sub/<subId>).
            # Как в 3x-ui: возвращается base64-список ссылок на ВСЕ протоколы, где есть клиент,
            # плюс заголовок subscription-userinfo (upload/download/total/expire) для v2rayNG и др.
            try:
                import base64
                sub_path = p[5:].strip("/") if p.startswith("/sub/") else ""
                st = _load(STATE) or {}
                host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
                host = host if "://" not in host else urllib.parse.urlparse(host).netloc
                panel_port = CFG_CACHE.get("panel_port", 8444)

                links = []
                seen_uuids = set()
                tg_links = []
                found_client = False
                state_changed = False
                up = down = total = 0
                expiry = 0
                sub_name = ""

                # Все вхождения клиента по ключу могут быть в нескольких инбаундах —
                # соберём их в один список ссылок (по одному на протокол).
                inb_links = {}
                inc_links = {}
                sb_objs = {}
                node_links = {}
                for proto, inb in (st.get("inbounds") or {}).items():
                    for c in inb.get("clients", []):
                        if not c.get("sub_token"):
                            c["sub_token"] = secrets.token_urlsafe(16)
                            state_changed = True
                        match = (not sub_path) or (c.get("sub_token") == sub_path) or (c["uuid"] == sub_path)
                        if not match:
                            continue
                        found_client = True
                        sub_name = c.get("name") or sub_name
                        key = c["uuid"]
                        if key not in seen_uuids:
                            seen_uuids.add(key)
                            up += int(c.get("up") or 0)
                            down += int(c.get("down") or 0)
                            lim = float(c.get("limit_gb") or 0)
                            if lim > 0:
                                total = max(total, int(lim * 1024 ** 3))
                            ex = int(c.get("expiry") or 0)
                            if ex:
                                expiry = max(expiry, ex)
                            try:
                                for l in _tg_sub_links(c):
                                    if l not in tg_links:
                                        tg_links.append(l)
                            except Exception:
                                pass
                        try:
                            if proto not in inb_links:
                                inb_links[proto] = _link(inb, host, c, proto)
                            if proto not in inc_links:
                                inc_links[proto] = _incy_link(proto, inb, c, host)
                            if proto not in sb_objs:
                                sb_objs[proto] = _singbox_outbound(proto, inb, c, host)
                        except Exception:
                            continue
                        for h, e in (c.get("nodes") or {}).items():
                            lk = (e or {}).get("link")
                            if lk:
                                node_links[h] = lk

                if state_changed:
                    _save(STATE, st)

                if sub_path and not found_client:
                    return self._send(404, {"error": "клиент не найден"})
                if not inb_links:
                    return self._send(404, {"error": "нет клиентов"})

                links = list(inb_links.values())
                # Формат ответа:
                #  * INCY — открытые ссылки по одной в строке (в т.ч. wireguard:// и
                #    amneziawg://); базовый тип для Xray-клиентов с их же документации.
                #  * sing-box JSON (массив outbound'ов) — только по явному ?format=sing-box.
                #  * по умолчанию — классический base64 v2ray-список (v2rayNG, NekoBox и др.).
                q = urllib.parse.urlparse(self.path).query
                ua = self.headers.get("User-Agent", "") or ""
                xc = self.headers.get("x-client") or ""
                fmt = (urllib.parse.parse_qs(q).get("format") or [""])[0].lower()
                use_sb = fmt in ("sing-box", "singbox", "sbox", "json")
                force_v2 = fmt in ("v2ray", "base64", "text")
                is_incy = (not use_sb and not force_v2 and sub_path
                           and _is_incy_client(ua, xc))
                if sub_path:
                    _xff = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
                    _dip = _xff or (self.client_address[0] if getattr(self, "client_address", None) else "?")
                    try:
                        _subdev_note(sub_path, _dip, ua, xc)
                    except Exception:
                        pass
                    _pin = _subdev_pref(sub_path)
                    if _pin == "base64":
                        use_sb = False; is_incy = False
                    elif _pin == "singbox":
                        use_sb = True; is_incy = False
                if use_sb:
                    payload = json.dumps(list(sb_objs.values()), ensure_ascii=False).replace(r'\/', '/')
                    b = payload.encode("utf-8")
                    ctype = "application/json; charset=utf-8"
                elif is_incy:
                    payload = "\n".join(inc_links.values())
                    b = payload.encode("utf-8")
                    ctype = "text/plain; charset=utf-8"
                else:
                    # ссылки нод, куда клиент размещён мастером — в общий base64-список
                    links = links + list(node_links.values()) + tg_links
                    # Однострочные ссылки сначала, многострочные WG/AmneziaWG-блоки в конец:
                    # парсеры, спотыкающиеся о [Interface], всё равно импортируют остальное.
                    one = [l for l in links if l.startswith(("vless://", "vmess://", "trojan://", "ss://", "hy2://", "tg://"))]
                    if len(one) < len(links):
                        links = one + [l for l in links if l not in one]
                    payload = base64.b64encode("\n".join(links).encode()).decode()
                    b = payload.encode()
                    ctype = "text/plain; charset=utf-8"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(b)))
                self.send_header("Cache-Control", "no-store")
                # subscription-userinfo — клиенты (v2rayNG, Hiddify, NekoBox) показывают трафик и срок
                exp_val = int(expiry)
                if not _expire_seconds_client(ua, xc):
                    exp_val *= 1000  # миллисекунды
                ui = f"upload={up}; download={down}; total={total}; expire={exp_val}"
                self.send_header("subscription-userinfo", ui)
                if sub_name:
                    pt = "base64:" + base64.b64encode(sub_name.encode("utf-8")).decode()
                    self.send_header("profile-title", pt)
                try:
                    pui = str(max(1, min(168, int(CFG_CACHE.get("sub_update_hours") or 24))))
                except Exception:
                    pui = "24"
                self.send_header("profile-update-interval", pui)
                self.send_header("profile-web-page-url",
                                 f"{_pb(host, panel_port)}/p/{sub_path}" if sub_path
                                 else f"{_pb(host, panel_port)}/")
                self.end_headers(); self.wfile.write(b)
                return None
            except Exception as e:
                return self._send(500, {"error": str(e)})


        if p == "/metrics":
            # Prometheus-экспорт. Отключён, если токен не задан (503).
            tok = (CFG_CACHE.get("metrics_token") or "").strip()
            if not tok:
                return self._send(503, {"error": "metrics отключены: задайте токен в настройках"})
            auth = self.headers.get("Authorization", "") or ""
            qt = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            given = auth[7:].strip() if auth.lower().startswith("bearer ") else \
                    (qt.get("token") or [""])[0]
            if not secrets.compare_digest(given or "\x00", tok):
                return self._send(401, {"error": "unauthorized"})
            try:
                body = _metrics_text().encode("utf-8")
            except Exception as e:
                return self._send(500, {"error": str(e)})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers(); self.wfile.write(body)
            return None

        if p.startswith("/rulesets/"):
            name = os.path.basename(p[len("/rulesets/"):])
            if name not in _RULESET_FILES:
                return self._send(404, {"error": "not found"})
            fp = os.path.join(RULESET_DIR, name)
            try:
                with open(fp, "rb") as f:
                    data = f.read()
            except OSError:
                return self._send(404, {"error": "файлы ещё не загружены"})
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers(); self.wfile.write(data)
            return None

        if p.startswith("/sb/"):
            # Полный standalone-конфиг sing-box (tun + split-tunnel) для подписчика.
            tok = p[4:].strip("/")
            if not tok:
                return self._send(400, {"error": "нужен токен подписки"})
            st = _load(STATE) or {}
            host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
            host = host if "://" not in host else urllib.parse.urlparse(host).netloc
            panel_port = CFG_CACHE.get("panel_port", 8444)
            cfgj = _sb_config(st, tok, host, panel_port)
            if cfgj is None:
                return self._send(404, {"error": "клиент не найден"})
            return self._send(200, cfgj)

        if p.startswith("/p/"):
            # Публичная страница подписки: сюда ведёт profile-web-page-url (кнопка «i»
            # в клиентах). Показывает имя, статус, срок, трафик и способы подключения.
            tok = p[3:].strip("/")
            st = _load(STATE) or {}
            if _migrate_state(st):
                _save(STATE, st)
            u = next((x for x in _subs_summary(st)
                      if x["sub_token"] == tok or x["uuid"] == tok), None)
            if not u:
                return self._send(404, {"error": "подписка не найдена"})
            host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
            host = host if "://" not in host else urllib.parse.urlparse(host).netloc
            panel_port = CFG_CACHE.get("panel_port", 8444)
            sub_url = f"{_pb(host, panel_port)}/sub/{u['sub_token']}"
            html = _sub_page_html(u, sub_url, host, panel_port,
                                  self.headers.get("User-Agent", "") or "",
                                  devs=_subdev_list(tok))
            b = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b)
            return None


        if p.startswith("/api/wgconf/") or p.startswith("/api/awgconf/"):
            only_proto = "wireguard" if p.startswith("/api/wgconf/") else "amneziawg"
            tok = p[len("/api/wgconf/"):].strip("/") or p[len("/api/awgconf/"):].strip("/")
            st = _load(STATE, {}) or {}
            host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
            host = host if "://" not in host else urllib.parse.urlparse(host).netloc
            conf = ""
            name = "client"
            for proto, inb in (st.get("inbounds") or {}).items():
                if proto != only_proto:
                    continue
                for c in inb.get("clients", []):
                    if c.get("sub_token") == tok or c["uuid"] == tok:
                        conf = _link(inb, host, c, proto)
                        name = c.get("name") or "client"
                        break
                if conf:
                    break
            if not conf:
                return self._send(404, {"error": "конфиг не найден"})
            src_name = (re.sub(r"[^\wа-яёА-ЯЁ -]+", "", name).strip().replace(" ", "_") or "client")
            ascii_name = re.sub(r"[^\x00-\x7f]+", "", src_name) or "client"
            b = conf.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition",
                             'attachment; filename="' + ascii_name + '.conf"; filename*=UTF-8\'\'' + urllib.parse.quote(src_name + ".conf"))
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b)
            return None

        if p == "/logo.png":
            if not _LOGO_PNG:
                return self._send(404, {"error": "logo not found"})
            try:
                with open(_LOGO_PNG, "rb") as f:
                    data = f.read()
            except Exception:
                return self._send(404, {"error": "logo not found"})
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(data)
            return None

        if p.startswith("/api/ext/"):
            return self._ext_get(p)
        if p == "/api/metrics":
            return self._send(200, get_system_metrics())
        if p == "/api/selftest":
            return self._send(200, run_protocol_self_test())
        if p == "/api/nodes":
            if not _authed(self):
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, _nodes_public())
        if p == "/api/nodes/bootstrap/status":
            if not _authed(self):
                return self._send(401, {"error": "unauthorized"})
            jid = (urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                   .get("id") or [""])[0].strip()[:12]
            with BOOT_LOCK:
                job = BOOT_JOBS.get(jid)
                out = None if not job else {
                    "id": jid, "done": job["done"], "ok": job["ok"], "error": job["error"],
                    "steps": [dict(s) for s in job["steps"]]}
            if out is None:
                return self._send(404, {"error": "задача не найдена (перезапуск панели?)"})
            return self._send(200, out)
        if p == "/api/nodes/tokens":
            if not _authed(self):
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, {"tokens": [
                {"id": t.get("id"), "label": t.get("label"), "scopes": t.get("scopes") or [],
                 "created": t.get("created"), "last_used": t.get("last_used")}
                for t in _node_tokens()]})

        if p == "/test_links.txt":
            try:
                with open(f"{BASE}/test_links.txt", "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except Exception:
                self.send_error(404)
            return None

        if p in ("/", "/index.html"):
            with open(HTML, "rb") as f:
                content = f.read()
            style = (CFG_CACHE.get("ui_style") or "new").strip().lower()
            content = content.replace(b"__UI_STYLE__", b"classic" if style == "classic" else b"new")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(content)
            return None
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
        if p == "/api/inbound/get":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            proto = (urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                     .get("proto") or [""])[0].strip()
            inb = (_load(STATE) or {}).get("inbounds", {}).get(proto)
            if not inb: return self._send(404, {"error": "inbound не найден"})
            return self._send(200, _inbound_public(proto, inb))
        if p == "/api/clients":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            st = _load(STATE)
            if not st: return self._send(200, {"clients": [], "configured": False})
            if _migrate_state(st): _save(STATE, st)
            host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
            host = host if "://" not in host else urllib.parse.urlparse(host).netloc
            panel_port = CFG_CACHE.get("panel_port", 8444)
            ipv6 = _my_ipv6()
            out = []
            state_changed = False
            for proto, inb in (st.get("inbounds") or {}).items():
                for c in inb.get("clients", []):
                    if not c.get("sub_token"):
                        c["sub_token"] = secrets.token_urlsafe(16)
                        state_changed = True
                    sub_token = c["sub_token"]
                    sub_url = f"{_pb(host, panel_port)}/sub/{sub_token}"
                    cu = int(c.get("up") or 0); cdn = int(c.get("down") or 0)
                    item = {"uuid": c["uuid"], "name": c["name"],
                            "link": _link(inb, host, c, proto),
                            "sub_token": sub_token,
                            "sub_url": sub_url,
                            "sb_url": f"{_pb(host, panel_port)}/sb/{sub_token}",
                            "up": cu, "down": cdn,
                            "limit_gb": float(c.get("limit_gb") or 0),
                            "expiry": int(c.get("expiry") or 0),
                            "reset_cycle": c.get("reset_cycle") or "",
                            "tg_proxy": c.get("tg_proxy") or "",
                            "tg_user": c.get("tg_user") or "",
                            "cycle": c.get("cycle") or "lifetime",
                            "max_devices": int(c.get("max_devices") or 0),
                            "used_gb": round((cu + cdn) / (1024**3), 3),
                            "ipv6": ipv6,
                            "proto": proto, "port": inb["port"],
                            "proto_label": _proto_meta(proto)["label"],
                            "created": c.get("created", 0)}
                    if c.get("nodes"):
                        item["nodes"] = c["nodes"]
                    if c.get("ext_owner"):
                        item["ext_by"] = next(
                            (t.get("label") for t in _node_tokens() if t.get("id") == c["ext_owner"]),
                            "внешняя панель")
                    if ipv6:
                        item["link6"] = _link(inb, f"[{ipv6}]", c, proto)
                    if proto == "wireguard" and c.get("address"):
                        item["address"] = c["address"]
                        item["link6"] = ""
                        item["conf_url"] = f"{_pb(host, panel_port)}/api/wgconf/{sub_token}"
                    if proto == "amneziawg" and c.get("address"):
                        item["address"] = c["address"]
                        item["link6"] = ""
                        item["conf_url"] = f"{_pb(host, panel_port)}/api/awgconf/{sub_token}"
                    if len(out) < 16:
                        item["online"] = _online_count(c["uuid"])
                    out.append(item)
            if state_changed:
                _save(STATE, st)
            return self._send(200, {"clients": out,
                                    "configured": bool(out),
                                    "active": _proto_of(st),
                                    "ipv6": ipv6})
        if p == "/api/subs":
            # Агрегированный список подписчиков для вкладки «Подписка» (как в 3x-ui).
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            st = _load(STATE)
            if not st: return self._send(200, {"subs": [], "configured": False})
            if _migrate_state(st): _save(STATE, st)
            subs = _subs_summary(st)
            try:
                _subdev_prune({(u.get("sub_token") or "") for u in subs})
            except Exception:
                pass
            for u in subs:
                tok = u.get("sub_token") or ""
                devs = _subdev_list(tok)
                u["devices"] = devs
                u["fmt"] = _subdev_pref(tok)
                top = devs[0] if devs else {}
                u["client"] = top.get("client", "")
                u["client_version"] = top.get("version", "")
                u["client_os"] = top.get("os", "")
                u["client_device"] = top.get("type", "")
                u["client_old"] = bool(top.get("old"))
                u["last_seen"] = top.get("last_ts", "")
            return self._send(200, {"subs": subs, "configured": bool(subs),
                                    "active": _proto_of(st)})
        if p == "/api/subs/export":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            fmt = ((qs.get("format") or ["json"])[0]).strip().lower()
            st = _load(STATE) or {}
            if _migrate_state(st): _save(STATE, st)
            stamp = time.strftime("%Y%m%d-%H%M")
            if fmt == "links":
                b = _subs_export_links(st).encode("utf-8")
                ctype, fname = "text/plain; charset=utf-8", "veil-subs-" + stamp + ".txt"
            else:
                b = json.dumps(_subs_export_json(st), ensure_ascii=False, indent=2).encode("utf-8")
                ctype, fname = "application/json; charset=utf-8", "veil-subs-" + stamp + ".json"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", 'attachment; filename="' + fname + '"')
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b)
            return None
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
        if p == "/api/rotate/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            try:
                return self._send(200, _rot_status())
            except Exception as e:
                return self._send(200, {"error": str(e)[:200]})
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
        if p == "/api/globalping/history":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            history_file=f"{BASE}/globalping_history.json"
            try:
                with open(history_file,'r') as f:
                    history=json.load(f)
            except Exception:
                history=[]
            return self._send(200, {"history": history[-20:]})
        if p == "/api/audit":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            ev = (qs.get("ev") or [""])[0].strip(); q = (qs.get("q") or [""])[0].strip().lower()
            limit = 200
            try: limit = max(1, min(500, int((qs.get("limit") or [""])[0] or 200)))
            except Exception: pass
            try:
                with open(AUDIT_FILE, encoding="utf-8") as _f: _d = json.load(_f)
                items = _d if isinstance(_d, list) else (_d.get("items") or [])
            except Exception:
                items = []
            if ev:
                items = [x for x in items if x.get("ev") == ev]
            if q:
                items = [x for x in items if q in json.dumps(x, ensure_ascii=False).lower()]
            return self._send(200, {"items": items[-limit:][::-1], "total": len(items),
                                    "events": sorted({x.get("ev") for x in AUDIT})})
        if p == "/api/login/history":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try: limit = max(1, min(500, int((qs.get("limit") or [""])[0] or 100)))
            except Exception: limit = 100
            try:
                with open(LOGIN_HIST_FILE, encoding="utf-8") as _f: _d = json.load(_f)
                hist = _d if isinstance(_d, list) else (_d.get("items") or [])
            except Exception:
                hist = list(_LOGIN_HIST)
            return self._send(200, {"items": hist[-limit:][::-1]})
        if p == "/api/sessions":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            cur = None
            for k in SESSIONS:
                if _cookie(self) == k:
                    cur = k; break
            items = []
            now = time.time()
            for t, exp in SESSIONS.items():
                m = SESSIONS_META.get(t) or {}
                items.append({"sid": t[:12], "expires": exp,
                               "current": (t == cur),
                               "ip": m.get("ip"), "ua": (m.get("ua") or "")[:120],
                               "created": m.get("created"), "last_seen": m.get("last_seen"),
                               "remember": bool(m.get("remember"))})
            items.sort(key=lambda x: x["current"] is False)
            return self._send(200, {"items": items, "count": len(SESSIONS)})
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
                   "ipv4": _my_ip(), "ipv6": _my_ipv6(), "addrs": _all_iface_ips(),
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
                "f2b_enabled": bool(CFG_CACHE.get("f2b_enabled", True)),
                "f2b_threshold": int(CFG_CACHE.get("f2b_threshold") or 5),
                "f2b_window_min": int(CFG_CACHE.get("f2b_window_min") or 10),
                "f2b_ban_hours": int(CFG_CACHE.get("f2b_ban_hours") or 24),
                "metrics_token": CFG_CACHE.get("metrics_token", ""),
                "split_tunnel": CFG_CACHE.get("split_tunnel", "off"),
                "ui_style": (CFG_CACHE.get("ui_style") or "new").strip().lower(),
                "rulesets": dict(_RULESET_STATE),
            })
        if p == "/api/dashboard":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            st = _load(STATE) or {}
            uuids = set()
            for proto, inb in (st.get("inbounds") or {}).items():
                for c in inb.get("clients", []):
                    uuids.add(c.get("uuid"))
            now = time.gmtime()
            days = []
            for i in range(29, -1, -1):
                k = time.strftime("%Y-%m-%d", time.gmtime(time.time() - i * 86400))
                days.append([k, int(_TRAFFIC_DAYS.get(k) or 0)])
            today_k = time.strftime("%Y-%m-%d", now)
            mo_k = time.strftime("%Y-%m", now)
            week = sum(int(_TRAFFIC_DAYS.get(
                time.strftime("%Y-%m-%d", time.gmtime(time.time() - i * 86400))
            ) or 0) for i in range(7))
            month = sum(v for k, v in _TRAFFIC_DAYS.items() if k.startswith(mo_k))
            yest_k = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))
            yesterday = int(_TRAFFIC_DAYS.get(yest_k) or 0)
            try:
                with open("/proc/uptime") as f:
                    uptime = int(float(f.read().split()[0]))
            except Exception:
                uptime = 0
            online = 0
            for u in uuids:
                try:
                    if u and _online_count(u):
                        online += 1
                except Exception:
                    pass
            running = subprocess.run(["systemctl", "is-active", "--quiet", "xray"]).returncode == 0
            tg_running = subprocess.run(["systemctl", "is-active", "--quiet", "telemt"]).returncode == 0
            protos = []
            _grp_lbl = {"reality": "VLESS + Reality", "vless": "VLESS", "vmess": "VMess",
                        "trojan": "Trojan", "ss": "Shadowsocks", "hy2": "Hysteria2",
                        "wg": "WireGuard", "awg": "AmneziaWG", "amneziawg": "AmneziaWG", "mtproto": "MTProto"}
            agg = {}
            for proto, inb in (st.get("inbounds") or {}).items():
                n = len(inb.get("clients", []))
                if not n:
                    continue
                try:
                    grp = _proto_meta(proto).get("group") or proto
                except Exception:
                    grp = proto
                a = agg.setdefault(grp, {"clients": 0, "port": inb.get("port")})
                a["clients"] += n
            for grp, a in agg.items():
                protos.append({"proto": grp, "label": _grp_lbl.get(grp, grp),
                               "clients": a["clients"], "port": a["port"], "running": running})
            if tg_running:
                protos.append({"proto": "mtproto", "label": "MTProto Proxy",
                               "clients": 0, "port": None, "running": True})
            return self._send(200, {
                "days": days,
                "today": int(_TRAFFIC_DAYS.get(today_k) or 0),
                "yesterday": yesterday,
                "week": week, "month": month,
                "clients": len(uuids),
                "online": online,
                "protos": protos,
                "active": _proto_of(st),
                "inbounds": len(st.get("inbounds") or {}),
                "bans": len([1 for ip, v in BANS.items()
                             if int(v.get("until") or 0) > time.time()]),
                "xray": bool(running),
                "version": VERSION,
                "uptime": uptime,
            })
        if p == "/api/bans":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            now = time.time()
            out = []
            for ip, v in sorted(BANS.items(), key=lambda x: -int(x[1].get("until") or 0)):
                out.append({"ip": ip, "until": int(v.get("until") or 0),
                            "reason": v.get("reason", ""), "fails": int(v.get("fails") or 0),
                            "left_min": max(0, int((int(v.get("until") or 0) - now) / 60))})
            return self._send(200, {"bans": out, "enabled": bool(CFG_CACHE.get("f2b_enabled", True))})
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
        if p == "/api/subscription/settings":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            out = _sub_settings()
            out["users"] = [u["username"] for u in (_tg_status().get("users") or [])]
            return self._send(200, out)
        if p == "/api/tg/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _tg_status())
        if p == "/api/tg/dcs":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            try:
                return self._send(200, _tg_dcs())
            except Exception as e:
                return self._send(200, {"error": str(e)[:200], "dcs": []})
        if p == "/api/webproxy/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _webproxy_status())
        if p == "/api/webmux":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _mux_status())
        if p == "/api/stats":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _stats())
        if p == "/api/backup":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _backup())
        if p == "/api/2fa/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            enabled = bool(CFG_CACHE.get("totp_enabled"))
            secret = CFG_CACHE.get("totp_secret", "")
            if not secret:
                secret = _totp_generate_secret()
                CFG_CACHE["totp_pending_secret"] = secret
                _save(CFG, CFG_CACHE)
            elif not enabled:
                secret = CFG_CACHE.get("totp_pending_secret") or secret
            return self._send(200, {"enabled": enabled, "secret": secret, "uri": f"otpauth://totp/VeilPanel:{CFG_CACHE.get('login', 'admin')}?secret={secret}&issuer=VeilPanel"})
        if p == "/api/bot/config":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, {
                "token": CFG_CACHE.get("bot_token", ""),
                "chat_ids": CFG_CACHE.get("bot_chat_ids", [])
            })
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
        if p == "/api/2fa/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            enabled = bool(CFG_CACHE.get("totp_enabled"))
            secret = CFG_CACHE.get("totp_secret", "")
            if not secret:
                secret = _totp_generate_secret()
                CFG_CACHE["totp_pending_secret"] = secret
                _save(CFG, CFG_CACHE)
            elif not enabled:
                secret = CFG_CACHE.get("totp_pending_secret") or secret
            return self._send(200, {"enabled": enabled, "secret": secret, "uri": f"otpauth://totp/VeilPanel:{CFG_CACHE.get('login', 'admin')}?secret={secret}&issuer=VeilPanel"})
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
                ua_h = (self.headers.get("User-Agent") or "")[:256]
                if not (b.get("login") == CFG_CACHE.get("login") and
                        self._is_cur_pw(b.get("password", ""))):
                    _login_fail(cip)
                    _login_history("fail", ip=cip, ua=ua_h, user=b.get("login"))
                    return self._send(401, {"error": "неверный логин или пароль"})
                if CFG_CACHE.get("totp_enabled"):
                    totp_code = (b.get("totp_code") or "").strip()
                    if not totp_code or not _totp_verify(CFG_CACHE.get("totp_secret", ""), totp_code):
                        _login_fail(cip)
                        _login_history("fail", ip=cip, ua=ua_h, user=b.get("login"), err="totp")
                        return self._send(401, {"error": "требуется код Google/Yandex Authenticator", "totp_required": True})
                _login_ok(cip)
                t = secrets.token_hex(32)
                rem = bool(b.get("remember"))
                SESSIONS[t] = time.time() + (30 * 86400 if rem else 72 * 3600)
                SESSIONS_META[t] = {"ip": cip, "ua": ua_h, "created": _now_iso(),
                                    "last_seen": _now_iso(), "remember": bool(rem)}
                _login_history("ok", ip=cip, ua=ua_h, user=b.get("login"))
                _audit("login", ip=cip, ua=ua_h, user=b.get("login"), ok=True)
                _save_sessions()
                ma = 2592000 if rem else 259200
                self._cookies = ["sid=" + t + "; Path=/; HttpOnly; Max-Age=" + str(ma) + "; SameSite=Lax"]
                return self._send(200, {"ok": True, "sid": t, "remember": rem})
            if (not _authed(self) and p != "/api/bot/webhook"
                    and not p.startswith("/api/ext/")
                    and not (p.startswith("/p/") and p.endswith("/forget"))):
                return self._send(401, {"error": "unauthorized"})
            if p.startswith("/p/") and p.endswith("/forget"):
                # Публичное «забыть устройство» со страницы подписки /p/<tok>.
                # Токен сам является правом доступа: кто знает токен — видит и подписку.
                tok = p[3:-len("/forget")].strip("/")
                st = _load(STATE) or {}
                if _migrate_state(st): _save(STATE, st)
                ok_sub = any(x["sub_token"] == tok or x["uuid"] == tok
                             for x in _subs_summary(st))
                if not ok_sub:
                    return self._send(404, {"error": "подписка не найдена"})
                ip = (self._body().get("ip") or "")[:64]
                if not ip:
                    return self._send(400, {"error": "нужен ip"})
                _subdev_remove(tok, ip)
                return self._send(200, {"ok": True, "devices": _subdev_list(tok)})
            if p == "/api/inbound/settings":
                b = self._body()
                proto = (b.get("proto") or "").strip()
                if proto in ("wireguard", "amneziawg"):
                    return self._send(400, {"error": "для WireGuard/AmneziaWG точечные настройки пока недоступны"})
                st = _load(STATE) or {}
                inb = (st.get("inbounds") or {}).get(proto)
                if not inb:
                    return self._send(404, {"error": "inbound не найден: " + proto})
                def _put(key, val):
                    if val in (None, "", [], {}):
                        inb.pop(key, None)
                    else:
                        inb[key] = val
                if "snis" in b: _put("snis", _as_list(b.get("snis")))
                if "sids" in b: _put("sids", _as_list(b.get("sids")))
                if "alpn" in b: _put("alpn", _as_list(b.get("alpn")))
                for key in ("sni", "dest", "path", "host", "service", "mode", "flow"):
                    if key in b: _put(key, (str(b.get(key) or "")).strip()[:200])
                if "sniff" in b:
                    sv = b.get("sniff")
                    if isinstance(sv, dict): _put("sniff", sv)
                    elif sv in (False, "false", 0, "0"): _put("sniff", False)
                    elif sv in (True, "true", 1, "1"): _put("sniff", True)
                    else: _put("sniff", None)
                for key in ("_adv", "_adv_ib"):
                    if key in b:
                        ov = b.get(key)
                        if ov in (None, "", {}, "null"):
                            inb.pop(key, None); continue
                        if not isinstance(ov, dict):
                            return self._send(400, {"error": key + " должен быть JSON-объектом"})
                        if len(json.dumps(ov)) > 8000:
                            return self._send(400, {"error": key + ": слишком большой overriding"})
                        if key == "_adv_ib":
                            ov = {k: v for k, v in ov.items()
                                  if k not in ("protocol", "settings", "port", "tag", "clients")}
                        inb[key] = ov
                ok, err = _validate_and_apply(st, force_proto=proto)
                if not ok:
                    return self._send(400, {"error": err or "конфиг не прошёл проверку"})
                return self._send(200, {"ok": True, "inbound": _inbound_public(proto, inb)})
            if p == "/api/bot/webhook":
                # Telegram webhook endpoint (no auth needed - called by Telegram)
                if self.command != "POST":
                    return self._send(405, {"error": "Method not allowed"})
                try:
                    b = self._body()
                    if not b:
                        return self._send(400, {"error": "empty body"})
                    _process_bot_update(b)
                    return self._send(200, {"ok": True})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/logout":
                t = _cookie(self)
                if t is None:
                    t = (self.headers.get("X-Sid") or "").strip() or None
                if t:
                    SESSIONS.pop(t, None); _save_sessions()
                self._cookies = ["sid=; Path=/; Max-Age=0"]
                return self._send(200, {"ok": True})

            if p == "/api/sessions/revoke":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                b = self._body() or {}
                sid = (b.get("sid") or "").strip()
                cip = self.client_address[0]
                ua_h = (self.headers.get("User-Agent") or "")[:256]
                if sid in SESSIONS:
                    m = SESSIONS_META.pop(sid, None)
                    SESSIONS.pop(sid, None); _save_sessions()
                    _audit("session_revoke", sid=(sid or "")[:12],
                           ip=cip, ua=ua_h, remote=sid[:12] != (b.get("sid") or ""),
                           detail="сессия отозвана", **({"who": CFG_CACHE.get("login")} if False else {}))
                    _save_sessions()
                    return self._send(200, {"ok": True, "revoked": sid[:12]})
                return self._send(404, {"error": "сессия не найдена"})
            if p == "/api/sessions/revoke_others":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                cur = _cookie(self)
                if cur is None:
                    cur = (self.headers.get("X-Sid") or "").strip() or None
                n = 0
                cip = self.client_address[0]
                ua_h = (self.headers.get("User-Agent") or "")[:256]
                for t in list(SESSIONS):
                    if t != cur:
                        SESSIONS_META.pop(t, None)
                        SESSIONS.pop(t, None); n += 1
                _save_sessions()
                _audit("sessions_revoke_others", count=n, ip=cip, ua=ua_h)
                return self._send(200, {"ok": True, "revoked": n})

            if p == "/api/restart":
                subprocess.Popen(["bash", "-c", "sleep 1 && systemctl restart vpnpanel"])
                return self._send(200, {"ok": True, "restarting": True})

            if p == "/api/globalping/history":
                b = self._body() or {}
                history_file = f"{BASE}/globalping_history.json"
                try:
                    with open(history_file, "r") as f:
                        history = json.load(f)
                    if not isinstance(history, list):
                        history = []
                except Exception:
                    history = []
                entry = {
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "success": bool(b.get("success")),
                    "success_count": int(b.get("success_count") or 0),
                    "total_count": int(b.get("total_count") or 0),
                    "details": b.get("details") or [],
                }
                history.append(entry)
                history = history[-50:]
                try:
                    tmp = history_file + ".tmp"
                    with open(tmp, "w") as f:
                        json.dump(history, f, ensure_ascii=False)
                    os.replace(tmp, history_file)
                except Exception as e:
                    return self._send(500, {"error": str(e)})
                _gp_maybe_alert(entry)
                return self._send(200, {"ok": True, "count": len(history)})

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
                sub_token = secrets.token_urlsafe(16)
                client_uuid = str(uuidlib.uuid4())
                
                host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
                host = host if "://" not in host else urllib.parse.urlparse(host).netloc
                panel_port = CFG_CACHE.get("panel_port", 8444)
                
                added_links = []
                c = _new_client(name, proto, inb)
                c["uuid"] = client_uuid
                c["sub_token"] = sub_token
                inb.setdefault("clients", []).append(c)
                added_links.append(_link(inb, host, c, proto))
                    
                st["active"] = proto
                _write_xray(st); _save(STATE, st)
                _restart_xray()
                
                sub_url = f"{_pb(host, panel_port)}/sub/{sub_token}"
                first_link = added_links[0] if added_links else ""
                return self._send(200, {"ok": True, "link": first_link,
                                        "port": inb["port"], "proto": proto,
                                        "name": name, "uuid": client_uuid,
                                        "sub_token": sub_token, "sub_url": sub_url})

            # ---- clients ----
            if p.startswith("/api/ext/"):
                return self._ext_post(p)
            if p == "/api/nodes/tokens/add":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                b = self._body()
                label = (b.get("label") or "").strip() or "Токен"
                scopes = [s for s in (b.get("scopes") or []) if s in _EXT_SCOPES]
                if not scopes:
                    return self._send(400, {"error": "выбери хотя бы один scope"})
                toks = _node_tokens()
                if len(toks) >= 20:
                    return self._send(400, {"error": "не более 20 токенов"})
                token = secrets.token_urlsafe(24)
                tid = uuidlib.uuid4().hex[:12]
                toks.append({"id": tid, "hash": hashlib.sha256(token.encode()).hexdigest(),
                             "label": label[:40], "scopes": scopes,
                             "created": int(time.time()), "last_used": 0})
                _save_node_tokens(toks)
                _audit("node_token_add", label=label[:40], scopes=",".join(scopes))
                return self._send(200, {"id": tid, "token": token, "label": label[:40], "scopes": scopes})
            if p == "/api/nodes/tokens/revoke":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                b = self._body()
                tid = (b.get("id") or "").strip()
                toks = _node_tokens()
                label = next((t.get("label") for t in toks if t.get("id") == tid), None)
                out = [t for t in toks if t.get("id") != tid]
                if len(out) == len(toks):
                    return self._send(404, {"error": "токен не найден"})
                _save_node_tokens(out)
                _audit("node_token_revoke", token_id=tid, label=label)
                return self._send(200, {"ok": True})
            if p == "/api/nodes/check":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                b = self._body()
                host = (b.get("host") or "").strip()
                nodes = get_nodes()
                node = next((n for n in nodes
                             if (n.get("host") or "").strip().lower() == host.lower()), None)
                if not node:
                    return self._send(404, {"error": "нода не найдена"})
                is_agent = (node.get("type") or "agent") == "agent"
                pinned = bool((node.get("pin") or "").strip())
                _node_poll_one(node)
                save_nodes(nodes)
                if not node.get("online"):
                    return self._send(200, {"online": False, "error": node.get("err")})
                status = {"version": node.get("remote_version"),
                          "clients": node.get("node_clients"),
                          "xray": node.get("node_xray")}
                if is_agent:
                    status["params"] = node.get("agent_params")
                else:
                    status["online"] = node.get("node_online")
                    status["inbounds"] = (node.get("status_cache") or {}).get("inbounds")
                return self._send(200, {"online": True, "status": status,
                                        "pin": node.get("pin"),
                                        "new_pin": (not pinned) and bool(node.get("pin"))})
            if p == "/api/nodes/add":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                b = self._body()
                name = (b.get("name") or "").strip() or "Нода"
                host = (b.get("host") or "").strip()
                port = int((b.get("port") or 0) or 0)
                token = (b.get("token") or "").strip()
                ntype = (b.get("type") or "agent").strip().lower()
                if ntype not in ("agent", "veil"):
                    return self._send(400, {"error": "type: agent|veil"})
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
                nodes.append({"name": name, "host": host, "port": port, "type": ntype,
                              "token": token, "online": False, "added": int(time.time())})
                save_nodes(nodes)
                return self._send(200, {"ok": True, "nodes": _nodes_public()})
            if p == "/api/nodes/delete":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                b = self._body()
                host = (b.get("host") or "").strip()
                nodes = get_nodes()
                node = next((n for n in nodes
                             if (n.get("host") or "").strip().lower() == host.lower()), None)
                out = [n for n in nodes
                       if (n.get("host") or "").strip().lower() != host.lower()]
                if len(out) == len(nodes):
                    return self._send(404, {"error": "нода не найдена"})
                purge_note = None
                if node and b.get("purge", True):
                    pok, pmsg = _node_agent_purge(node)
                    purge_note = pmsg if pok is not None else None
                save_nodes(out)
                return self._send(200, {"ok": True, "nodes": _nodes_public(),
                                        "purge": purge_note})
            if p == "/api/nodes/bootstrap":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                b = self._body()
                host = (b.get("host") or "").strip()
                user = (b.get("user") or "").strip()
                password = str(b.get("password") or "")
                name = ((b.get("name") or "").strip() or "Veil node")[:40]
                sni = (b.get("sni") or "").strip()[:80]
                try:
                    sport = int(b.get("ssh_port") or 22)
                except Exception:
                    return self._send(400, {"error": "неверный SSH-порт"})
                if not host or not user:
                    return self._send(400, {"error": "укажи адрес ноды и SSH-логин"})
                if host in ("0.0.0.0", "::", "localhost"):
                    return self._send(400, {"error": "этот адрес — не внешняя нода"})
                if not (1 <= sport <= 65535):
                    return self._send(400, {"error": "SSH-порт должен быть от 1 до 65535"})
                with BOOT_LOCK:
                    busy = any((not j["done"]) and (j.get("params") or {}).get("host") == host
                               for j in BOOT_JOBS.values())
                if busy:
                    return self._send(400, {"error": "для этого адреса подключение уже идёт"})
                jid = _boot_new_job({"host": host, "ssh_port": sport, "user": user,
                                     "password": password, "name": name, "sni": sni})
                threading.Thread(target=_node_bootstrap_worker, args=(jid,), daemon=True).start()
                _audit("node_bootstrap_start", host=host, user=user)
                return self._send(200, {"id": jid})
            if p == "/api/subs/import":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                b = self._body()
                fmt = (b.get("format") or "json").strip().lower()
                st = _load(STATE)
                if st is None:
                    st = _new_state()
                _migrate_state(st)
                try:
                    if fmt == "json":
                        data = b.get("data")
                        if isinstance(data, str):
                            data = json.loads(data)
                        if not isinstance(data, dict):
                            return self._send(400, {"error": "ожидаю объект JSON"})
                        imported, warnings = _import_from_json(st, data)
                    else:
                        text = b.get("text") or ""
                        if not text.strip():
                            return self._send(400, {"error": "пустой текст ссылок"})
                        imported, warnings = _import_from_links(st, text)
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
                except Exception as e:
                    return self._send(400, {"error": "разбор не удался: " + str(e)[:160]})
                if not imported:
                    return self._send(400, {"error": "ничего не найдено для импорта",
                                            "warnings": warnings})
                _awg_sync(st); _wg_sync(st)
                ok, err = _validate_and_apply(st)
                if not ok:
                    return self._send(400, {"error": "конфиг не принят: " + str(err)[:200],
                                            "warnings": warnings})
                _audit("subs_import", format=fmt, subs=imported)
                return self._send(200, {"ok": True, "imported": imported,
                                        "warnings": warnings,
                                        "subs": _subs_summary(st)})
            if p == "/api/clients/add":
                b = self._body()
                name = (b.get("name") or "").strip() or "Клиент"
                want_proto = (b.get("proto") or "").strip()
                st = _load(STATE)
                if st is None:
                    st = _new_state(want_proto or "reality")
                _migrate_state(st)

                sub_token = secrets.token_urlsafe(16)
                client_uuid = str(uuidlib.uuid4())
                limit_gb = float(b.get("limit_gb") or 0) or None
                _edays = int(b.get("expiry_days") or 0) or 0
                expiry = (int(time.time()) + _edays * 86400) if _edays > 0 else 0
                reset_cycle = (b.get("reset_cycle") or "").strip().lower()
                try: max_devices = max(0, int(b.get("max_devices") or 0))
                except Exception: max_devices = 0
                # Telegram-прокси в подписке: отдельная (персональная) ссылка, общая или не надо
                tg_mode = (b.get("tg_proxy") or "").strip().lower()
                if tg_mode not in ("off", "shared", "personal"):
                    tg_mode = ""
                tg_user = (_tg_slug(name, "client") + "-" + sub_token[:6]) if tg_mode == "personal" else ""

                host = (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")
                host = host if "://" not in host else urllib.parse.urlparse(host).netloc
                panel_port = CFG_CACHE.get("panel_port", 8444)

                added_links = []
                first_link = ""
                if want_proto:
                    target_proto = want_proto if (want_proto in (st.get("inbounds") or {})) else (_proto_of(st) or "reality")
                    inb = (st.get("inbounds") or {}).get(target_proto)
                    if not inb:
                        inb = _alloc_inbound(st, target_proto)
                        st.setdefault("inbounds", {})[target_proto] = inb
                    c = _new_client(name, target_proto, inb, limit_gb=limit_gb, expiry=expiry,
                                    reset_cycle=reset_cycle, max_devices=max_devices)
                    c["uuid"] = client_uuid
                    c["sub_token"] = sub_token
                    if tg_mode:
                        c["tg_proxy"] = tg_mode
                        if tg_user:
                            c["tg_user"] = tg_user
                    inb.setdefault("clients", []).append(c)
                    lnk = _link(inb, host, c, target_proto)
                    added_links.append({"proto": target_proto, "link": lnk})
                    first_link = lnk
                else:
                    inbounds = st.setdefault("inbounds", {})
                    for proto in _VALID_PROTOCOLS:
                        if proto not in inbounds:
                            try:
                                inbounds[proto] = _alloc_inbound(st, proto)
                            except Exception as e:
                                print(f"clients/add alloc {proto} -> {e}", flush=True)
                    if not inbounds:
                        inbounds["reality"] = _alloc_inbound(st, "reality")
                    for proto, inb in inbounds.items():
                        c = _new_client(name, proto, inb, limit_gb=limit_gb, expiry=expiry,
                                        reset_cycle=reset_cycle, max_devices=max_devices)
                        c["uuid"] = client_uuid
                        c["sub_token"] = sub_token
                        if tg_mode:
                            c["tg_proxy"] = tg_mode
                            if tg_user:
                                c["tg_user"] = tg_user
                        inb.setdefault("clients", []).append(c)
                        lnk = _link(inb, host, c, proto)
                        added_links.append({"proto": proto, "link": lnk})
                        if not first_link:
                            first_link = lnk

                _awg_sync(st)
                _wg_sync(st)
                _write_xray(st); _save(STATE, st)
                _restart_xray()

                nodes_res = None
                if b.get("to_nodes"):
                    try:
                        dep, skip = _deploy_client_to_nodes(st, client_uuid)
                        nodes_res = {"deployed": dep, "skipped": skip}
                    except Exception as e:
                        nodes_res = {"error": str(e)[:120]}
                sub_url = f"{_pb(host, panel_port)}/sub/{sub_token}"
                tg_preview = []
                try:
                    tg_preview = _tg_sub_links({"tg_proxy": tg_mode, "tg_user": tg_user,
                                                "name": name, "sub_token": sub_token})
                except Exception:
                    pass
                return self._send(200, {"ok": True, "client": {
                    "uuid": client_uuid, "name": name,
                    "sub_token": sub_token, "sub_url": sub_url,
                    "link": first_link, "links": added_links,
                    "tg_user": tg_user, "tg_links": tg_preview},
                    "nodes": nodes_res})

            if p == "/api/clients/deploy":
                b = self._body()
                u = (b.get("uuid") or "").strip()
                st = _load(STATE)
                if not st: return self._send(404, {"error": "нет состояния"})
                try:
                    dep, skip = _deploy_client_to_nodes(st, u)
                except Exception as e:
                    return self._send(500, {"error": str(e)[:200]})
                if dep:
                    _audit("client_deploy", uuid=u, nodes=",".join(d["host"] for d in dep))
                return self._send(200, {"deployed": dep, "skipped": skip})

            if p == "/api/clients/undeploy":
                b = self._body()
                u = (b.get("uuid") or "").strip()
                host = (b.get("host") or "").strip().lower()
                st = _load(STATE)
                if not st: return self._send(404, {"error": "нет состояния"})
                recs = [c for proto, inb in (st.get("inbounds") or {}).items()
                        for c in inb.get("clients", []) if c.get("uuid") == u]
                if not recs: return self._send(404, {"error": "клиент не найден"})
                ents = _client_node_entries(st, u)
                e = next((v for k, v in ents.items() if k.strip().lower() == host), None)
                node = next((n for n in get_nodes()
                             if (n.get("host") or "").strip().lower() == host), None)
                if e and e.get("uuid") and node:
                    if (node.get("type") or "agent") == "agent":
                        _, err, _ = _node_call(node, "/agent/apply",
                                               {"action": "remove", "uuid": e["uuid"]})
                    else:
                        _, err, _ = _node_call(node, "/api/ext/clients/delete",
                                               {"uuid": e["uuid"]})
                    if err and "не найден" not in str(err):
                        return self._send(502, {"error": "нода не приняла удаление: " + str(err)[:120]})
                removed = False
                for c in recs:
                    for k in [k for k in (c.get("nodes") or {}) if k.strip().lower() == host]:
                        del c["nodes"][k]; removed = True
                if removed:
                    _save(STATE, st)
                    _audit("client_undeploy", uuid=u, node=host)
                return self._send(200, {"ok": True})

            if p == "/api/clients/delete":
                b = self._body()
                u = b.get("uuid")
                st = _load(STATE)
                if not st or _client_count(st) == 0:
                    return self._send(400, {"error": "нет клиентов"})
                if _client_count(st) <= 1:
                    return self._send(400, {"error": "нельзя удалить последнего клиента"})

                try:
                    _undeploy_client_from_nodes(st, u)
                except Exception:
                    pass

                target_sub_token = None
                for proto, inb in (st.get("inbounds") or {}).items():
                    for c in inb.get("clients", []):
                        if c["uuid"] == u or c.get("sub_token") == u:
                            target_sub_token = c.get("sub_token")
                            break
                    if target_sub_token: break
                    
                removed = False
                for proto, inb in list((st.get("inbounds") or {}).items()):
                    orig_len = len(inb.get("clients", []))
                    inb["clients"] = [c for c in inb["clients"] if c["uuid"] != u and c.get("sub_token") != (target_sub_token or u)]
                    if len(inb["clients"]) < orig_len:
                        removed = True
                    if not inb["clients"] and proto != "amneziawg":
                        del st["inbounds"][proto]
                        
                if not removed:
                    return self._send(404, {"error": "клиент не найден"})
                    
                if st.get("active") not in st.get("inbounds", {}):
                    st["active"] = _proto_of(st)
                    
                _awg_sync(st)
                _wg_sync(st)
                _write_xray(st); _save(STATE, st)
                _restart_xray()
                return self._send(200, {"ok": True})

            if p == "/api/clients/unblock":
                b = self._body()
                u = b.get("uuid")
                st = _load(STATE)
                if not st: return self._send(404, {"error": "нет состояния"})
                group = [c for proto, inb in (st.get("inbounds") or {}).items()
                         for c in inb.get("clients", []) if c["uuid"] == u]
                if not group: return self._send(404, {"error": "клиент не найден"})
                was = any(c.get("blocked") for c in group)
                by_limit = any(c.get("blocked") and c.get("blocked_reason") == "limit" for c in group)
                for c in group:
                    c.pop("blocked", None); c.pop("blocked_reason", None)
                    if by_limit:
                        # без обнуления счётчика автоблок вернулся бы через минуту
                        c["up"] = 0; c["down"] = 0
                        c["warned_80"] = False
                if was:
                    _save(STATE, st)
                    try:
                        _awg_sync(st); _wg_sync(st)
                        _write_xray(st); _restart_xray()
                    except Exception as e:
                        return self._send(500, {"error": str(e)})
                _audit("client_unblock", uuid=u, name=group[0].get("name"))
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

            if p == "/api/clients/update":
                # Правка лимитов существующего клиента: ГБ, срок (в днях от сейчас),
                # цикл сброса трафика и лимит устройств. Применяется ко всем записям uuid.
                b = self._body()
                u = b.get("uuid")
                st = _load(STATE)
                if not st: return self._send(404, {"error": "нет состояния"})
                group = [c for proto, inb in (st.get("inbounds") or {}).items()
                         for c in inb.get("clients", []) if c["uuid"] == u]
                if not group: return self._send(404, {"error": "клиент не найден"})
                if "limit_gb" in b:
                    try: group[0]["limit_gb"] = max(0.0, float(b.get("limit_gb") or 0))
                    except Exception: return self._send(400, {"error": "limit_gb не число"})
                    for c in group: c["limit_gb"] = group[0]["limit_gb"]
                    if float(group[0]["limit_gb"]) > 0:
                        for c in group: c["warned_80"] = False
                if "expiry_days" in b:
                    try: d = max(0, int(b.get("expiry_days") or 0))
                    except Exception: return self._send(400, {"error": "expiry_days не число"})
                    group[0]["expiry"] = (int(time.time()) + d * 86400) if d > 0 else 0
                    for c in group:
                        c["expiry"] = group[0]["expiry"]; c["warned_days"] = []
                if "reset_cycle" in b:
                    rc = (b.get("reset_cycle") or "").strip().lower()
                    if rc not in ("", "day", "week", "month"):
                        return self._send(400, {"error": "reset_cycle: day|week|month или ''"})
                    for c in group: c["reset_cycle"] = rc
                    # смена цикла обнулит накопанный трафик на следующем тике
                if "max_devices" in b:
                    try: md = max(0, int(b.get("max_devices") or 0))
                    except Exception: return self._send(400, {"error": "max_devices не число"})
                    for c in group: c["max_devices"] = md
                if "tg_proxy" in b:
                    tm = (b.get("tg_proxy") or "").strip().lower()
                    if tm not in ("off", "shared", "personal"):
                        return self._send(400, {"error": "tg_proxy: off|shared|personal"})
                    for c in group:
                        c["tg_proxy"] = tm
                        if tm == "personal" and not c.get("tg_user"):
                            c["tg_user"] = _tg_slug(c.get("name"), "client") + "-" + (c.get("sub_token") or "x")[:6]
                if b.get("unblock"):
                    for c in group:
                        c.pop("blocked", None); c.pop("blocked_reason", None)
                _save(STATE, st)
                try:
                    _repropagate_client_to_nodes(st, u)
                except Exception:
                    pass
                if b.get("unblock"):
                    try:
                        _awg_sync(st); _wg_sync(st)
                        _write_xray(st); _restart_xray()
                    except Exception as e:
                        return self._send(500, {"error": str(e)})
                return self._send(200, {"ok": True})

            if p == "/api/bans/unban":
                b = self._body()
                ip = (b.get("ip") or "").strip()
                if not ip: return self._send(400, {"error": "ip не указан"})
                if not _f2b_unban(ip): return self._send(404, {"error": "такого бана нет"})
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
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
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
            if p == "/api/rotate/settings":
                b = self._body()
                if "enabled" in b:
                    CFG_CACHE["rot_enabled"] = bool(b.get("enabled"))
                for key, lo, hi in (("rot_threshold", 1, 100), ("rot_window_min", 0, 180),
                                    ("rot_check_min", 5, 240), ("rot_cooldown_min", 1, 1440),
                                    ("rot_port", 1, 65535)):
                    if key not in b:
                        continue
                    try:
                        v = int(float(b.get(key)))
                    except Exception:
                        return self._send(400, {"error": "%s: не число" % key})
                    if not lo <= v <= hi:
                        return self._send(400, {"error": "%s: %s…%s" % (key, lo, hi)})
                    CFG_CACHE[key] = v
                if "provider" in b:
                    pv = (b.get("provider") or "").strip().lower()
                    if pv not in ("off", "dynv6", "cloudflare", "both"):
                        return self._send(400, {"error": "provider: off|dynv6|cloudflare|both"})
                    CFG_CACHE["rot_provider"] = pv
                if "use_iface" in b:
                    CFG_CACHE["rot_use_iface"] = bool(b.get("use_iface"))
                if "pool" in b:
                    raw = b.get("pool")
                    if isinstance(raw, str):
                        raw = re.split(r"[,\s]+", raw)
                    ips = []
                    for x in raw or []:
                        x = (x or "").strip()
                        if not x:
                            continue
                        if not _is_ip4(x):
                            return self._send(400, {"error": "не верный IPv4 в пуле: %s" % x[:40]})
                        if x not in ips:
                            ips.append(x)
                    CFG_CACHE["rot_pool"] = ips
                if "target" in b:
                    t0 = (b.get("target") or "").strip()
                    if t0 and (t0.startswith("http") or "/" in t0 or " " in t0 or ":" in t0):
                        return self._send(400, {"error": "адрес проверки: только имя хоста или IPv4"})
                    CFG_CACHE["rot_target"] = t0
                if "path" in b:
                    pth = (b.get("path") or "/").strip()
                    if not pth.startswith("/"):
                        pth = "/" + pth
                    CFG_CACHE["rot_path"] = pth[:200]
                if "cf_token" in b:
                    tk = (b.get("cf_token") or "").strip()
                    if tk:
                        CFG_CACHE["cf_token"] = tk
                        CFG_CACHE.pop("cf_zone_id", None)
                    else:
                        CFG_CACHE.pop("cf_token", None)
                        CFG_CACHE.pop("cf_zone_id", None)
                if "cf_zone" in b:
                    z = (b.get("cf_zone") or "").strip().lower()
                    if z and not re.fullmatch(r"(?i)[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", z):
                        return self._send(400, {"error": "зона: имя домена"})
                    CFG_CACHE["cf_zone"] = z
                    CFG_CACHE.pop("cf_zone_id", None)
                if "cf_records" in b:
                    raw = b.get("cf_records")
                    if isinstance(raw, str):
                        raw = re.split(r"[,\s]+", raw)
                    rec = []
                    for x in raw or []:
                        x = (x or "").strip().strip(".").lower()
                        if not x:
                            continue
                        if not re.fullmatch(r"(?i)@?[a-z0-9][a-z0-9.-]*|@|apex", x):
                            return self._send(400, {"error": "имя записи: некорректное %s" % x[:40]})
                        if x not in rec:
                            rec.append(x)
                    CFG_CACHE["cf_records"] = rec
                _save(CFG, CFG_CACHE)
                _audit("rotate_settings", enabled=bool(CFG_CACHE.get("rot_enabled")),
                       provider=CFG_CACHE.get("rot_provider"),
                       threshold=CFG_CACHE.get("rot_threshold"),
                       window=CFG_CACHE.get("rot_window_min"))
                return self._send(200, {"ok": True, **_rot_status()})
            if p == "/api/rotate/check":
                th = threading.Thread(target=_rot_tick, daemon=True)
                th.start()
                _audit("rotate_check")
                return self._send(200, {"ok": True, "message": "проверка запущена (до 3–4 минут)"})
            if p == "/api/rotate/swap":
                b = self._body()
                ip = (b.get("ip") or "").strip()
                if ip and not _is_ip4(ip):
                    return self._send(400, {"error": "не верный IPv4"})
                if ip:
                    cfg = _rot_conf()
                    if cfg["provider"] == "off":
                        return self._send(400, {"error": "провайдер смены не выбран"})
                    rep = _rot_apply(ip)
                    CFG_CACHE["rot_last_ip"] = ip
                    _save(CFG, CFG_CACHE)
                    with _ROT_LOCK:
                        _ROT["last_swap"] = time.time()
                        _ROT["ip"] = ip
                    _rot_event("ручная замена → %s: %s" % (ip, "; ".join(rep)), "swap")
                    _audit("ip_rotate_manual", to=ip, provider=cfg["provider"])
                    return self._send(200, {"ok": True, "applied": rep, "ip": ip})
                ok, msg = _rotate_ip("вручную из панели")
                return self._send(200 if ok else 400, {"ok": ok, "message": msg[:400]})
            if p == "/api/rotate/cloudflare/test":
                try:
                    zid, zone = _cf_zone()
                    recs = []
                    res = _cf_api("GET", "/zones/%s/dns_records?type=A&per_page=50" % urllib.parse.quote(zid)) or []
                    names = _cf_record_names()
                    for r0 in res:
                        if r0.get("name") in names or not names:
                            recs.append({"name": r0.get("name"), "content": r0.get("content"),
                                         "ttl": r0.get("ttl"), "proxied": bool(r0.get("proxied"))})
                    return self._send(200, {"ok": True, "zone": zone, "zone_id": zid,
                                            "records": recs, "wanted": names})
                except Exception as e:
                    return self._send(400, {"error": str(e)[:250]})
            if p == "/api/dynv6/create-zone":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
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
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                try:
                    return self._send(200, _dynv6_update())
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/cert/issue":
                try:
                    b = self._body()
                    return self._send(200, _cert_issue((b or {}).get("email") or CFG_CACHE.get("cert_email"),
                                                       (b or {}).get("mode") or "auto"))
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

            # ---- 2fa ----
            if p == "/api/2fa/status":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                enabled = bool(CFG_CACHE.get("totp_enabled"))
                secret = CFG_CACHE.get("totp_secret", "")
                if not secret:
                    secret = _totp_generate_secret()
                    CFG_CACHE["totp_pending_secret"] = secret
                    _save(CFG, CFG_CACHE)
                elif not enabled:
                    secret = CFG_CACHE.get("totp_pending_secret") or secret
                return self._send(200, {"enabled": enabled, "secret": secret, "uri": f"otpauth://totp/VeilPanel:{CFG_CACHE.get('login', 'admin')}?secret={secret}&issuer=VeilPanel"})

            if p == "/api/2fa/setup":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                b = self._body() or {}
                code = (b.get("code") or "").strip()
                secret = (b.get("secret") or CFG_CACHE.get("totp_pending_secret") or "").strip()
                if not secret or not code:
                    return self._send(400, {"error": "укажи секрет и код подтверждения"})
                if not _totp_verify(secret, code):
                    return self._send(400, {"error": "неверный код подтверждения"})
                CFG_CACHE["totp_secret"] = secret
                CFG_CACHE["totp_enabled"] = True
                CFG_CACHE.pop("totp_pending_secret", None)
                _save(CFG, CFG_CACHE)
                return self._send(200, {"ok": True})

            if p == "/api/2fa/disable":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                b = self._body() or {}
                code = (b.get("code") or "").strip()
                secret = CFG_CACHE.get("totp_secret", "")
                if secret and code and not _totp_verify(secret, code):
                    return self._send(400, {"error": "неверный код 2FA"})
                CFG_CACHE["totp_enabled"] = False
                CFG_CACHE.pop("totp_secret", None)
                _save(CFG, CFG_CACHE)
                return self._send(200, {"ok": True})

            # ---- telegram bot ----
            if p == "/api/bot/config":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                if self.command == "GET":
                    return self._send(200, {
                        "token": CFG_CACHE.get("bot_token", ""),
                        "chat_ids": CFG_CACHE.get("bot_chat_ids", [])
                    })
                if self.command == "POST":
                    b = self._body() or {}
                    token = (b.get("token") or "").strip()
                    chat_ids_raw = b.get("chat_ids")
                    if isinstance(chat_ids_raw, str):
                        chat_ids = [x.strip() for x in chat_ids_raw.split(",") if x.strip()]
                    elif isinstance(chat_ids_raw, list):
                        chat_ids = [str(x).strip() for x in chat_ids_raw if str(x).strip()]
                    else:
                        chat_ids = []
                    if token:
                        CFG_CACHE["bot_token"] = token
                    CFG_CACHE["bot_chat_ids"] = chat_ids
                    _save(CFG, CFG_CACHE)
                    return self._send(200, {"ok": True})

            if p == "/api/bot/test":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                token = CFG_CACHE.get("bot_token", "")
                if not token:
                    return self._send(400, {"error": "бот не настроен"})
                try:
                    url = f"https://api.telegram.org/bot{token}/getMe"
                    with urllib.request.urlopen(url, timeout=10) as resp:
                        data = json.load(resp)
                    if data.get("ok"):
                        return self._send(200, {"info": data["result"]})
                    return self._send(400, {"error": "бот не ответил"})
                except Exception as e:
                    return self._send(400, {"error": str(e)})

            if p == "/api/bot/set_webhook":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                b = self._body() or {}
                token = CFG_CACHE.get("bot_token", "")
                if not token:
                    return self._send(400, {"error": "бот не настроен"})
                url = b.get("url") or (f"https://{CFG_CACHE.get('panel_domain', '').strip()}:{CFG_CACHE.get('panel_port', 8444)}/api/bot/webhook")
                try:
                    url = f"https://api.telegram.org/bot{token}/setWebhook?url={urllib.parse.quote(url)}"
                    with urllib.request.urlopen(url, timeout=10) as resp:
                        data = json.load(resp)
                    if data.get("ok"):
                        CFG_CACHE["bot_webhook_url"] = url
                        _save(CFG, CFG_CACHE)
                        return self._send(200, {"ok": True, "url": url})
                    return self._send(400, {"error": data.get("description", "failed")})
                except Exception as e:
                    return self._send(400, {"error": str(e)})

            if p == "/api/bot/delete_webhook":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                token = CFG_CACHE.get("bot_token", "")
                if not token:
                    return self._send(400, {"error": "бот не настроен"})
                try:
                    url = f"https://api.telegram.org/bot{token}/deleteWebhook"
                    with urllib.request.urlopen(url, timeout=10) as resp:
                        data = json.load(resp)
                    if data.get("ok"):
                        CFG_CACHE.pop("bot_webhook_url", None)
                        _save(CFG, CFG_CACHE)
                        return self._send(200, {"ok": True})
                    return self._send(400, {"error": data.get("description", "failed")})
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
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                n = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(n) if n else b""
                try: body = json.loads(raw.decode() or "{}")
                except Exception: body = {}
                t = _load(THEME, {}) or {}
                for k in ("bg","bg2","card","card2","fg","mut","br","acc","acc2","font","layout","swipe"):
                    if k in body: t[k] = body[k]
                _save(THEME, t)
                self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers()
                self.wfile.write(b'{"ok":true}'); return
            if p == "/api/wallpaper":
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
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
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
                f2b_changed = False
                if "f2b_enabled" in body:
                    CFG_CACHE["f2b_enabled"] = bool(body["f2b_enabled"])
                    f2b_changed = True
                for fk, fmin, fmax in (("f2b_threshold", 1, 1000),
                                       ("f2b_window_min", 1, 1440),
                                       ("f2b_ban_hours", 1, 720)):
                    if fk in body:
                        try: fv = int(body[fk])
                        except Exception:
                            return self._send(400, {"error": fk + ": не число"})
                        if not (fmin <= fv <= fmax):
                            return self._send(400, {"error": f"{fk}: диапазон {fmin}..{fmax}"})
                        CFG_CACHE[fk] = fv
                        f2b_changed = True
                if "metrics_token" in body:
                    mt = (body["metrics_token"] or "").strip()
                    if mt and not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", mt):
                        return self._send(400, {"error": "metrics_token: 8-64 символа [A-Za-z0-9_-]"})
                    if mt:
                        CFG_CACHE["metrics_token"] = mt
                    else:
                        CFG_CACHE.pop("metrics_token", None)
                    f2b_changed = True
                if "split_tunnel" in body:
                    stv = (body["split_tunnel"] or "off").strip().lower()
                    if stv not in ("off", "ru", "ir"):
                        return self._send(400, {"error": "split_tunnel: off|ru|ir"})
                    CFG_CACHE["split_tunnel"] = stv
                    f2b_changed = True
                if "ui_style" in body:
                    uv = (body["ui_style"] or "new").strip().lower()
                    if uv not in ("new", "classic"):
                        return self._send(400, {"error": "ui_style: new|classic"})
                    CFG_CACHE["ui_style"] = uv
                    f2b_changed = True
                if xray_changed or panel_changed or f2b_changed:
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
                    res = _tg_add(b.get("name", ""), (b.get("mode") or "both"))
                    return self._send(200, {"ok": True, "user": res})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/tg/user/adtag":
                b = self._body()
                try:
                    res = _tg_set_adtag(b.get("username", ""), b.get("ad_tag", ""))
                    _audit("tg_adtag", username=res["username"], set=bool(res["ad_tag"]))
                    return self._send(200, {"ok": True, **res})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/tg/user/rotate":
                b = self._body()
                try:
                    res = _tg_rotate_secret(b.get("username", ""), b.get("secret", ""))
                    _audit("tg_rotate", username=res["username"])
                    return self._send(200, {"ok": True, "user": res})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/subscription/settings":
                b = self._body()
                if "update_hours" in b:
                    try:
                        h = int(b.get("update_hours"))
                    except Exception:
                        return self._send(400, {"error": "update_hours не число"})
                    if not 1 <= h <= 168:
                        return self._send(400, {"error": "update_hours: 1..168"})
                    CFG_CACHE["sub_update_hours"] = h
                if "tg_mode" in b:
                    m = (b.get("tg_mode") or "").strip().lower()
                    if m not in ("off", "shared", "personal"):
                        return self._send(400, {"error": "tg_mode: off|shared|personal"})
                    CFG_CACHE["sub_tg_mode"] = m
                if "tg_shared_user" in b:
                    su = _tg_slug(b.get("tg_shared_user"), "")
                    if not su:
                        return self._send(400, {"error": "имя общего прокси пустое"})
                    CFG_CACHE["tg_shared_user"] = su
                _save(CFG, CFG_CACHE)
                _audit("sub_settings", **_sub_settings())
                return self._send(200, {"ok": True, **_sub_settings()})
            if p == "/api/sub/format":
                b = self._body()
                tok = (b.get("sub_token") or "").strip()
                fmt = (b.get("fmt") or "auto").strip().lower()
                if not tok:
                    return self._send(400, {"error": "нужен sub_token"})
                if not _subdev_set_pref(tok, fmt):
                    return self._send(400, {"error": "fmt: auto|base64|singbox"})
                _audit("sub_format", sub=tok, fmt=fmt)
                return self._send(200, {"ok": True, "fmt": fmt})
            if p == "/api/sub/devices/del":
                b = self._body()
                tok = (b.get("sub_token") or "").strip()
                ip = (b.get("ip") or "").strip()
                if not (tok and ip):
                    return self._send(400, {"error": "нужны sub_token и ip"})
                _subdev_remove(tok, ip)
                _audit("sub_device_del", sub=tok, ip=ip)
                return self._send(200, {"ok": True, "devices": _subdev_list(tok)})
            if p == "/api/tg/sni":
                b = self._body()
                try:
                    res = _tg_sni_set(b.get("tls_domain"), b.get("tls_domains"))
                    return self._send(200, {"ok": True, "sni": res})
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
            if p == "/api/tg/threshold":
                b = self._body()
                try:
                    return self._send(200, _tg_set_fresh_ratio(b.get("pct")))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/port80/free":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                try:
                    for srv in ("nginx", "apache2", "apache", "httpd"):
                        subprocess.run(["systemctl", "stop", srv], capture_output=True)
                        subprocess.run(["systemctl", "disable", srv], capture_output=True)
                    subprocess.run(["fuser", "-k", "80/tcp"], capture_output=True)
                    return self._send(200, {"ok": True, "message": "Порт 80 освобожден"})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/port443/free":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                try:
                    for srv in ("apache2", "apache", "httpd"):
                        subprocess.run(["systemctl", "stop", srv], capture_output=True)
                        subprocess.run(["systemctl", "disable", srv], capture_output=True)
                    subprocess.run(["fuser", "-k", "443/tcp"], capture_output=True)
                    return self._send(200, {"ok": True, "message": "Порт 443 освобожден"})
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
                                   "Content-Length: 0\r\n"
                                   "Connection: close\r\n\r\n" % (host, int(port))).encode())
                except Exception: pass
                try: sock.close()
                except Exception: pass
                raise ConnectionRefusedError("plain http -> https")
        return sock, addr

if __name__ == "__main__":
    import sys
    if "--dns01-hook" in sys.argv:
        try:
            _dns01_hook_main()
            sys.exit(0)
        except Exception as e:
            print("dns01-hook: " + str(e), file=sys.stderr)
            sys.exit(1)
    port = CFG_CACHE.get("panel_port", 8443)
    bind = (CFG_CACHE.get("panel_bind") or "0.0.0.0").strip()
    print("Veil " + VERSION + " слушает " + bind + ":" + str(port), flush=True)
    _load_sessions()
    try:
        _bans_load()
        _f2b_bootstrap()
        _ensure_logrotate()
    except Exception as e:
        print("f2b init: " + str(e), flush=True)
    try:
        st = _load(STATE)
        xc = _load(XRAY)
        chg = _ensure_wg_std(st)
        chg = _ensure_xray_keys_urlsafe(st) or chg
        # chg = _ensure_all_protos(st) or chg
        # WireGuard: kernel-интерфейс veilwg и AmneziaWG: системный awg0 —
        # импорт/синхронизация после возможного рестарта ОС.
        _ensure_wg_net()
        try:
            _awg_sync(st)
        except Exception as e:
            print("awg sync init: " + str(e), flush=True)
        try:
            _wg_sync(st)
        except Exception as e:
            print("wg sync init: " + str(e), flush=True)
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
    threading.Thread(target=_nodes_poll_loop, daemon=True).start()
    with S((bind, port), H) as srv:
        srv.serve_forever()

