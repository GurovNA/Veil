#!/usr/bin/env python3
import base64, json, os, subprocess, secrets, hashlib, uuid as uuidlib, re, ssl, time, threading, socket, hmac, struct
import ssl, socketserver, http.server
import urllib.parse, urllib.request, urllib.error
import shutil, tarfile, tempfile, datetime, gzip
import html as _html
import zipfile

BASE = "/opt/vpnpanel"
CFG = f"{BASE}/config.json"
STATE = f"{BASE}/state.json"
THEME = f"{BASE}/theme.json"
WALL = f"{BASE}/wallpaper.bin"
HTML = f"{BASE}/index.html"
_HTML_GZ = None
XRAY = "/usr/local/etc/xray/config.json"
XRAY_BIN = "/usr/local/bin/xray"
TOKEN_FILE = f"{BASE}/github.token"
TELEMT_API = "http://127.0.0.1:9091"
TELEMT_CONF = "/etc/telemt/telemt.toml"
REPO = "GurovNA/Veil"
VERSION = "2.13.0"
# 2.13.0: «Переезд» — автоматическая миграция на новый VPS (порт-в-порт, ссылки не меняются,
#        захват портов по подтверждению, DNS по часам, журнал шагов — продолжение с места остановки);
#        сайт-маска TLS-F (свой фронт) + «Главная ссылка Telegram»; устройства — по токену
#        установки, а не IP; passkey-вход по умолчанию; лимит устройств TG-прокси; C8 «чем
#        пользуетесь»; B5 самопривязка смены адреса; кнопки бота «➕ Прокси / 💳 Продлить»;
#        A2 самопроверка MTProto под VPN; A3 IPv6-зеркало SYN-лимита.
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
          "trojan-tcp-tls": 18443, "vless-grpc-tls": 19443,
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

def _audit_redact(v):
    if isinstance(v, str) and ("tok=" in v or "token=" in v):
        v = re.sub(r"(tok|token)=[A-Za-z0-9_.\-]{8,}", r"\1=***", v)
    return v

def _audit(ev, **kw):
    """Запись в аудит-журнал. ev — событие, kw — детали (имя клиента, uuid, ip и т.п.)."""
    entry = {"ts": _now_iso(), "ev": ev}
    entry.update({k: _audit_redact(v) for k, v in kw.items() if v is not None})
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
# Персистентный «токен установки» в User-Agent: у Happ и клиентов той же схемы
# длинное число после ОС живёт всю жизнь конкретной установки приложения.
# Это честный идентификатор устройства: MAC по интернету не виден, а UA-токен — да.
_DEV_FP_RE = re.compile(r"/(?:android|ios|pc|x|win|mac|linux)/(\d{12,})(?:[/?\s]|$)", re.I)

def _dev_fp(ua):
    m = _DEV_FP_RE.search(ua or "")
    return "i:" + m.group(1) if m else ""
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
        _subdev_fixup()
    if _SUBPREF is None:
        try:
            d = json.load(open(_SUBPREF_FILE))
            _SUBPREF = d if isinstance(d, dict) else {}
        except Exception:
            _SUBPREF = {}

def _subdev_fixup():
    """Однократно при загрузке: проставить отпечатки старым записям и склеить
    одну установку приложения, записанную раньше как несколько IP-строк."""
    changed = False
    for token, lst in list((_SUBDEV or {}).items()):
        if not isinstance(lst, list):
            continue
        merged, seen = [], {}
        for d in lst:
            if not isinstance(d, dict):
                continue
            fp = d.get("fp") or _dev_fp(d.get("ua") or "")
            if fp and not d.get("fp"):
                d["fp"] = fp
                changed = True
            if not fp:
                merged.append(d)
                continue
            prev = seen.get(fp)
            if prev is None:
                seen[fp] = d
                merged.append(d)
                continue
            ip = prev.get("ip") or ""
            extra = [ip] + (prev.get("ips") or []) + [d.get("ip") or ""] + (d.get("ips") or [])
            prev["ips"] = list(dict.fromkeys(x for x in extra if x))[:8]
            prev["n"] = int(prev.get("n") or 0) + int(d.get("n") or 0)
            if (d.get("last_ts") or "") > (prev.get("last_ts") or ""):
                prev["last_ts"] = d["last_ts"]
                for k in ("ua", "client", "version", "os", "type", "old"):
                    if d.get(k) not in (None, "", False):
                        prev[k] = d[k]
            if (d.get("first_ts") or "9") < (prev.get("first_ts") or "9"):
                prev["first_ts"] = d["first_ts"]
            prev["ip"] = prev.get("ip") or (prev["ips"][0] if prev["ips"] else "")
            changed = True
        merged.sort(key=lambda d: d.get("last_ts", ""), reverse=True)
        _SUBDEV[token] = merged[:_SUBDEV_MAX_IPS]
    if changed:
        try:
            _save(_SUBDEV_FILE, _SUBDEV)
        except Exception:
            pass

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
    fp = _dev_fp(ua)
    ts = _now_iso()
    with _SUBDEV_LOCK:
        _subdev_load()
        lst = _SUBDEV.get(token) or []
        # устройство = отпечаток установки, а не IP: ушёл человек с Wi-Fi на 4G —
        # это тот же клиент, а не «второе устройство»
        dev = next((d for d in lst if fp and d.get("fp") == fp), None)
        if dev is None:
            dev = next((d for d in lst if d.get("ip") == ip), None)
        if dev:
            if dev.get("ip") != ip:
                old_ip = dev.get("ip") or ""
                dev["ip"] = ip
                dev["ips"] = ([old_ip] + [x for x in (dev.get("ips") or [])
                                          if x and x != ip and x != old_ip])[:8]
            dev["last_ts"] = ts
            dev["n"] = int(dev.get("n", 0)) + 1
            if fp:
                dev["fp"] = fp
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
            lst.append({"ip": ip, "ips": [], "fp": fp, "ua": (ua or "")[:200], "client": name,
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
        _SUBDEV[token] = [d for d in (_SUBDEV.get(token) or [])
                          if not (d.get("ip") == ip or ip in (d.get("ips") or []))]
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
        try:  # журнал «чем пользуется» чистим вместе с удалёнными подписками
            with _PROTOACT_LOCK:
                pa = _protoact_load()
                stale = [k for k in pa if k not in valid_tokens]
                for k in stale:
                    pa.pop(k, None)
                if stale:
                    _save(_PROTOACT_FILE, pa)
        except Exception:
            pass

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
    # старый формат (sha256 за проход) — нужен только для проверки унаследованных hash'ей
    return hashlib.sha256((salt + pw).encode()).hexdigest()

def _hash2(salt, pw, iters=300000):
    dk = hashlib.pbkdf2_hmac("sha256", str(pw).encode(), str(salt).encode(), iters)
    return "pbkdf2_sha256$%d$%s" % (iters, dk.hex())

def _pw_match(salt, pw, stored):
    stored = str(stored or "")
    if stored.startswith("pbkdf2_sha256$"):
        parts = stored.split("$", 2)
        try:
            cand = _hash2(salt, pw, int(parts[1]))
        except Exception:
            return False
        return secrets.compare_digest(cand, stored)
    ok = secrets.compare_digest(_hash(salt, pw), stored)
    if ok:  # прозрачная миграция старого формата — установку не ломаем, пароль не теряем
        try:
            CFG_CACHE["pass_hash"] = _hash2(salt, pw)
            _save(CFG, CFG_CACHE)
        except Exception:
            pass
    return ok

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

_SNI_PQ_CACHE = {}

def _sni_mlkem_ok(host, ttl=600):
    """Отвечает ли домен по TLS1.3 постквантовой группой X25519MLKEM768 (кодопойнт
    0x11ec). Наблюдение MEKO: свежий Telegram iOS капризничает на MTProto/webproxy,
    если SNI-фронт не поддерживает PQ — андроид всё терпит. True/False, None = не
    проверить (нет openssl/домена). Кэш 10 минут: дёргаем из каждой выдачи /api/tg."""
    host = (host or "").strip().lower()
    if not host or not re.fullmatch(r"[a-z0-9.-]+", host):
        return None
    now = time.time()
    c = _SNI_PQ_CACHE.get(host)
    if c and now - c[1] < ttl:
        return c[0]
    res = None
    try:
        r = subprocess.run(["openssl", "s_client", "-connect", host + ":443",
                            "-servername", host, "-tls1_3",
                            "-groups", "X25519MLKEM768:X25519", "-tlsextdebug"],
                           input=b"", capture_output=True, timeout=10)
        out = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace")
        m = re.search(r'server extension "key share"[^\n]*\n\s*0+ - ([0-9a-f]{2}) ([0-9a-f]{2})',
                      out, re.IGNORECASE)
        if m:
            res = (m.group(1) == "11" and m.group(2) == "ec")
        elif r.returncode != 0:
            res = False
    except Exception:
        res = None
    _SNI_PQ_CACHE[host] = (res, now)
    return res

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
# ULA-адреса ВНУТРИ туннелей. Клиенты (INCY/нативный WG) вешают в туннель
# AllowedIPs ::/0; без собственного v6-адреса в туннеле все IPv6-запросы
# приложения чёрнеют (на мобильном LTE v6 — норма). Выдаём каждому клиенту
# v6, выведенный из v4-октета, и делаем masquerade наружу.
WG_ADDR6 = "fd10:10::1/64"
AWG_ADDR6 = "fd20:10::1/64"
AWG_POOL = "10.20.0."
# MTU туннеля. 1420 — дефолт wg под IPv4-транспорт (путь 1500). Но телефон
# часто приходит по IPv6-транспорту мобильной сети, где путь < 1500, а IPv6 не
# фрагментируется на маршрутизаторах: крупные пакеты (ответы сервера) молча
# чёрнеют — handshake и DNS (мелкие) проходят, а первое же крупное TCP/TLS
# соединение виснет («VPN загорелся, но интернет падает»). 1280 — гарантированный
# минимум IPv6, влезает в любой мобильный путь (outer = 1280 + 80 = 1360).
WG_MTU = 1280

def _tun6(c, prefix="fd10:10::"):
    """IPv6 внутри туннеля из последнего октета v4-адреса клиента.
    Никакой миграции state.json: адреса детерминированы."""
    host = str(c.get("address") or "").split("/")[0].rsplit(".", 1)[-1]
    try:
        return prefix + str(int(host)) if host.isdigit() and 0 < int(host) < 256 else ""
    except Exception:
        return ""

_WG4 = {}
def _wg_ep(host):
    """Транспорт WireGuard/AmneziaWG — только IPv4. WG не требует hostname/SNI
    (шифрование привязано к ключам), а мобильный IPv6-транспорт рвётся: префикс
    переназначается, NAT-состояния живут недолго, handshake перестаёт
    обновляться — «VPN загорается и падает». Поэтому вместо домена основного
    хоста (у него есть AAAA → телефон уйдёт в v6) подставляем A-only домен
    wg.<...> — панель заводит его сама. Hop-узлы не подменяем: нашего IP у них
    нет, для них резолвим домен в IPv4-литерал. Fallback: IPv4-литерал."""
    h = str(host or "").strip().strip("[]")
    if not h:
        return h
    try:
        socket.inet_pton(socket.AF_INET, h)
        return h
    except Exception:
        pass
    pd = str(CFG_CACHE.get("panel_domain") or "").strip().lower()
    if h.lower() == pd:
        wd = (CFG_CACHE.get("wg_domain") or "").strip() or _wg_auto_domain()
        if wd:
            return wd
    try:
        now = time.time()
        c = _WG4.get(h)
        if c and now - c[1] < 600:
            return c[0]
        v4 = socket.gethostbyname(h)
        _WG4[h] = (v4, now)
        return v4
    except Exception:
        return h
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
            "mtu": int(mt.group(1)) if mt else WG_MTU}

def _awg_write_conf(inb):
    os.makedirs(os.path.dirname(AWG_CONF), exist_ok=True)
    jk = AWG_JUNK
    with open(AWG_CONF, "w") as f:
        f.write("[Interface]\n"
                f"Address = {(inb.get('address') or AWG_ADDR)}, {AWG_ADDR6}\n"
                f"ListenPort = {inb['port']}\n"
                f"PrivateKey = {inb['private_key']}\n"
                f"MTU = {inb.get('mtu', WG_MTU)}\n"
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
            a6 = _tun6(c, "fd20:10::")
            f.write("\n[Peer]\n"
                    f"PublicKey = {c['client_public_key']}\n"
                    f"AllowedIPs = {c['address']}" + ((", " + a6 + "/128") if a6 else "") + "\n"
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
        # MTU на диске должен совпадать с желаемым, иначе перезапускаем (иначе
        # интерфейс останется на старом 1420 и крупные пакеты чёрнеют на v6-пути)
        if int(cur.get("mtu") or 0) != int(inb.get("mtu") or WG_MTU):
            return False
        # v6-адрес внутри туннеля должен уже быть в конфиге, иначе перезапускаем
        try:
            with open(AWG_CONF) as f:
                if AWG_ADDR6 not in f.read():
                    return False
        except Exception:
            return False
        r = subprocess.run(["ip", "link", "show", AWG_IFACE], capture_output=True, text=True)
        if r.returncode != 0:
            return False
        return True
    except Exception:
        return False

def _awg_restart_iface(st):
    try:
        inb = st["inbounds"]["amneziawg"]
        try:
            with open(AWG_CONF) as f:
                old = f.read()
        except OSError:
            old = ""
        _awg_write_conf(inb)
        with open(AWG_CONF) as f:
            new = f.read()
        # мягкий путь, как у veilwg: peers без разрыва активных сессий
        exists = subprocess.run(["ip", "link", "show", AWG_IFACE],
                                capture_output=True).returncode == 0
        if old and exists and old.partition("[Peer]")[0] == new.partition("[Peer]")[0]:
            if _soft_sync(AWG_IFACE, new):
                return True
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
            inb.setdefault("mtu", int(conf.get("mtu") or WG_MTU))
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
            a6 = _tun6(c, "fd20:10::")
            want[c["client_public_key"]] = c["address"] + ((", " + a6) if a6 else "")
    for pub in cur:
        if pub not in want:
            try:
                subprocess.run(["/usr/bin/awg", "set", AWG_IFACE, "peer", pub, "remove"],
                               capture_output=True, text=True, timeout=10)
            except Exception:
                pass
    for pub, addr in want.items():
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
             f"Address = {inb.get('address') or WG_ADDR}, {WG_ADDR6}\n",
             f"ListenPort = {inb['port']}\n",
             f"PrivateKey = {inb['private_key']}\n",
             f"MTU = {inb.get('mtu', WG_MTU)}\n"]
    for c in inb.get("clients", []):
        if c.get("blocked"):
            continue
        if not (c.get("client_public_key") and c.get("address")):
            continue
        a6 = _tun6(c)
        parts += ["\n[Peer]\n",
                  f"PublicKey = {c['client_public_key']}\n",
                  f"AllowedIPs = {c['address']}" + ((", " + a6 + "/128") if a6 else "") + "\n",
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

def _wg_iface_section(text):
    return text.partition("[Peer]")[0]

def _soft_sync(iface, conf_text):
    """Применяет конфиг без пересоздания интерфейса. wg/awg syncconf не понимают
    директивы wg-quick (Address/MTU) — подаём копию без них. Бинарник wg ограничен
    AppArmor и читает только из /etc/wireguard — временный файл кладём туда же.
    Ошибка -> False, вызывающий пойдёт жёстким путём."""
    path = "/etc/wireguard/.veil-soft-%d.conf" % os.getpid()
    try:
        lines = [l for l in conf_text.splitlines()
                 if l.split("=", 1)[0].strip() not in ("Address", "MTU")]
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        tool = "awg" if iface == AWG_IFACE else "wg"
        r = subprocess.run([tool, "syncconf", iface, path],
                           capture_output=True, text=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

def _wg_restart_iface(st):
    try:
        inb = st["inbounds"]["wireguard"]
        new = _wg_conf_text(inb)
        try:
            with open(WG_CONF) as f:
                old = f.read()
        except OSError:
            old = ""
        _wg_write_conf(inb)
        # Мягкий путь: если параметры самого интерфейса не менялись, syncconf
        # обновляет только peers — активные туннели (и роумящие клиенты) не
        # рвутся. Полный down/up только при смене порта/ключа/MTU/адреса.
        exists = subprocess.run(["ip", "link", "show", WG_IFACE],
                                capture_output=True).returncode == 0
        if old and exists and _wg_iface_section(old) == _wg_iface_section(new):
            if _soft_sync(WG_IFACE, new):
                return True
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
    """IPv4/IPv6-forwarding + NAT masquerade для туннельных подсетей
    (wireguard 10.10.0.0/24 + fd10:10::/64 и amneziawg 10.20.0.0/24 + fd20:10::/64).
    Идемпотентно; повторно применяется при каждом старте панели."""
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                       capture_output=True, text=True, timeout=10)
        subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
                       capture_output=True, text=True, timeout=10)
        # ULA внутри туннеля: ответный трафик уходит в тот же интерфейс, но RPF
        # на net0 может его гасить — ослабляем reverse-path для туннельных ifaces.
        subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"],
                       capture_output=True, text=True, timeout=10)
        with open("/etc/sysctl.d/99-veil-wg.conf", "w") as f:
            f.write("net.ipv4.ip_forward = 1\n"
                    "net.ipv6.conf.all.forwarding = 1\n"
                    "net.ipv4.conf.all.rp_filter = 0\n")
    except Exception:
        pass
    try:
        subprocess.run(["nft", "create", "table", "ip", "veil_wg"],
                       capture_output=True, text=True, timeout=10)
        subprocess.run(["nft", "create", "chain", "ip", "veil_wg", "post",
                        "{ type nat hook postrouting priority srcnat; policy accept; }"],
                       capture_output=True, text=True, timeout=10)
        subprocess.run(["nft", "create", "table", "ip6", "veil_wg"],
                       capture_output=True, text=True, timeout=10)
        subprocess.run(["nft", "create", "chain", "ip6", "veil_wg", "post",
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
        subprocess.run(["nft", "flush", "table", "ip6", "veil_wg"],
                       capture_output=True, text=True, timeout=10)
        subprocess.run(["nft", "add", "rule", "ip6", "veil_wg", "post",
                        "ip6", "saddr", "fd10:10::/64", "masquerade"],
                       capture_output=True, text=True, timeout=10)
        subprocess.run(["nft", "add", "rule", "ip6", "veil_wg", "post",
                        "ip6", "saddr", "fd20:10::/64", "masquerade"],
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
    os.chmod(key, 0o600)   # xray и панель работают от root — приватный ключ не должен читаться всеми
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
                    "address": "10.10.0.1/24", "mtu": WG_MTU, "next_address": 2})
    if proto == "amneziawg":
        priv, pub = _gen_keys()
        inb.update({"private_key": _wg_key_std(priv), "public_key": _wg_key_std(pub),
                    "address": AWG_ADDR, "mtu": WG_MTU, "next_address": 2})
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
    ib = {"listen": inb.get("listen") or "0.0.0.0", "port": inb["port"], "tag": proto}
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
            "mtu": inb.get("mtu", WG_MTU),
            "peers": [{"publicKey": c["client_public_key"],
                       "preSharedKey": inb.get("psk", ""),
                       "allowedIPs": ["0.0.0.0/0", "::/0"],
                       "email": c["uuid"]}
                      for c in inb["clients"]]}
        ib["sniffing"] = {"enabled": False}
        return ib
    # facade-фронт не должен становиться destination'ом при sniffing (см. _veil_front_domains)
    ib["sniffing"] = {"enabled": True, "destOverride": ["http", "tls", "quic"],
                      "domainsExcluded": _veil_front_domains()}
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
        if inb.get("disabled"):
            continue
        if inb.get("clients") or inb.get("_mux_enabled") or proto == force_proto:
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
            tgc = str(c.get("tg_chat") or "")
            sub_msgs = []
            lim = float(c.get("limit_gb") or 0)
            if lim > 0 and not c.get("warned_80"):
                if _user_traffic(c) >= lim * _GB * 0.8:
                    msgs.append(
                        f"⚠️ <b>80% лимита</b>\nКлиент: {c.get('name')}\n"
                        f"Использовано: {_user_traffic(c) / _GB:.2f} из {lim:g} ГБ")
                    if tgc:
                        sub_msgs.append(("a80", c.get("name") or "",
                                         f"{_user_traffic(c) / _GB:.2f}", f"{lim:g}"))
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
                        if tgc:
                            sub_msgs.append(("aexp", c.get("name") or "", days_left))
                        warned.append(d)
                        for g in group: g["warned_days"] = warned
                        changed = True
                        break
            if msgs:
                try:
                    _bot_send_message(ids[0], "\n".join(msgs), "HTML")
                except Exception as e:
                    print("[alert] " + str(e), flush=True)
            if tgc and sub_msgs:
                try:
                    Bs = _bot_B(tgc)
                    lines = []
                    for sm in sub_msgs:
                        nm = _html.escape(sm[1])
                        if sm[0] == "a80":
                            lines.append(Bs["sub_a80"] % (nm, sm[2], sm[3]))
                        else:
                            lines.append(Bs["sub_aexp"] % (nm, sm[2]))
                    kb = None
                    if c.get("sub_token"):
                        try:
                            kb = {"inline_keyboard": [[
                                {"text": Bs["m_sub_page"],
                                 "url": _bot_sub_urls(c)[1]}]]}
                        except Exception:
                            kb = None
                    _bot_send_message(tgc, "\n".join(lines), "HTML", kb)
                except Exception as e:
                    print("[alert-sub] " + str(e), flush=True)
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
    host = _hop_pub_host()
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
                     "tg_chat": str(c.get("tg_chat") or ""),
                     "links": {}, "protos": [], "up": 0, "down": 0}
                users[key] = u
            elif not u.get("tg_chat") and c.get("tg_chat"):
                u["tg_chat"] = str(c["tg_chat"])
            if not inb.get("disabled"):
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

def _link(inb, host, client, proto, std=False):
    """Ссылка подключения. std=True — канонический Xray-формат (строгий парсер
    INCY): encryption=none, без allowInsecure (удалён из свежих ядер), обычный
    base64 в vmess, реальные path/service из inbound. По умолчанию std=False —
    исторический формат, который понимают Happ/Shadowrocket/v2rayNG."""
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
        a6 = _tun6(client, "fd20:10::")
        return ("[Interface]\n"
                f"PrivateKey = {client['client_private_key']}\n"
                f"Address = {client['address']}" + ((", " + a6 + "/128") if a6 else "") + "\n"
                f"DNS = 1.1.1.1, 8.8.8.8\n"
                f"MTU = {inb.get('mtu', WG_MTU)}\n"
                + cli_junk
                + "[Peer]\n"
                f"PublicKey = {inb['public_key']}\n"
                f"Endpoint = {_wg_ep(host)}:{inb['port']}\n"
                f"AllowedIPs = {_wg_full_tunnel_allowed_ips()}\n"
                "PersistentKeepalive = 25\n"
                "")
    if proto == "wireguard":
        a6 = _tun6(client)
        return ("[Interface]\n"
                f"PrivateKey = {client['client_private_key']}\n"
                f"Address = {client['address']}" + ((", " + a6 + "/128") if a6 else "") + "\n"
                f"DNS = 1.1.1.1, 8.8.8.8\n"
                f"MTU = {inb.get('mtu', WG_MTU)}\n\n"
                "[Peer]\n"
                f"PublicKey = {inb['public_key']}\n"
                f"Endpoint = {_wg_ep(host)}:{inb['port']}\n"
                f"AllowedIPs = {_wg_full_tunnel_allowed_ips()}\n"
                "PersistentKeepalive = 25\n"
                "")
    if proto.startswith("shadowsocks"):
        cred = (inb.get("method") or "aes-256-gcm") + ":" + (inb.get("password") or "")
        raw = base64.urlsafe_b64encode(cred.encode()).decode().rstrip("=")
        return f"ss://{raw}@{host}:{inb['port']}#{urllib.parse.quote(name)}"
    if proto.startswith("vmess"):
        add = host.strip("[]")
        if std:
            p = {"v": "2", "ps": name, "add": add, "port": inb["port"],
                 "id": client["uuid"], "aid": "0", "scy": "auto",
                 "net": meta["net"], "type": "none", "host": inb.get("host") or "",
                 "path": (inb.get("path") or "/veil") if meta["net"] == "ws"
                         else ((inb.get("service") or "veil") if meta["net"] == "grpc" else ""),
                 "tls": "tls" if meta["tls"] else ""}
            if meta["tls"]:
                p["sni"] = host; p["fp"] = fp
            if meta["net"] == "grpc":
                # gRPC говорит по HTTP/2; без явного alpn=h2 свежие ядра приложений
                # могут согласовать http/1.1 и молча не открыть соединение.
                p["alpn"] = "h2"
            return "vmess://" + base64.b64encode(json.dumps(p, separators=(",", ":")).encode()).decode()
        p = {"v": "2", "ps": name, "add": add, "port": int(inb["port"]), "id": client["uuid"],
             "aid": "0", "scy": "auto", "net": meta["net"], "type": "none", "host": "",
             "path": "/veil" if meta["net"] == "ws" else ("veil" if meta["net"] == "grpc" else ""),
             "tls": "tls" if meta["tls"] else ""}
        # allowInsecure НЕ добавляем: сертификат валидный LE, а свежие ядра
        # (Happ 5.9+, INCY) удалили флаг и роняют весь vmess-JSON при его виде.
        if meta["tls"]:
            p["sni"] = host; p["fp"] = fp
        if meta["net"] == "grpc":
            p["alpn"] = "h2"
        return "vmess://" + base64.urlsafe_b64encode(json.dumps(p).encode()).decode()
    if proto.startswith("trojan"):
        scheme = "trojan://" + urllib.parse.quote(client.get("password") or inb.get("password") or "") + "@"
    else:
        scheme = f"vless://{client['uuid']}@"
    qparts = {"type": meta["net"]}
    if std and not proto.startswith("trojan"):
        qparts["encryption"] = "none"
    if meta["net"] == "ws":
        qparts["path"] = (inb.get("path") or "/veil") if std else "/veil"
        if std and inb.get("host"):
            qparts["host"] = inb["host"]
    elif meta["net"] == "grpc":
        qparts["serviceName"] = (inb.get("service") or "veil") if std else "veil"
        qparts["alpn"] = "h2"
        if std:
            md = inb.get("mode")
            if md and md != "gun":
                qparts["mode"] = md
            if inb.get("host"):
                qparts["authority"] = inb["host"]
        else:
            qparts["mode"] = "gun"
    elif meta["net"] in ("xhttp", "splithttp"):
        qparts["path"] = (inb.get("path") or "/veil") if std else "/veil"
    if proto in ("reality", "vless-xhttp-reality"):
        qparts.update({"security": "reality", "pbk": inb["public_key"],
                       "fp": fp, "sni": inb["sni"], "sid": inb["sid"],
                       "spx": "/"})
        if proto == "reality":
            qparts["flow"] = "xtls-rprx-vision"
        else:
            qparts["host"] = inb["sni"]
    elif meta["tls"]:
        # allowInsecure нигде не ставим: сертификат валидный LE, а свежие ядра
        # Xray (Happ 5.9+ и INCY) удалили флаг и отвергают ссылку целиком.
        qparts.update({"security": "tls", "sni": host, "fp": fp})
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
    host = _hop_pub_host()
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
    if net == "grpc": return "vmess-ws-tls" if tls else "vmess-ws"  # VMess+gRPC убран (ядра Happ/INCY не возят) — импорт переезжает на WebSocket
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

def _url_host_is_public(url):
    """SSRF-guard: http(s) на публичный хост; запрещаем loopback/RFC1918/link-local/CGNAT/metadata
    и прямые IP-обходы. Хост резолвится; если резолв не нужен (уже IP) — проверяется напрямую."""
    import ipaddress
    try:
        u = urllib.parse.urlparse(url)
    except Exception:
        return False
    if u.scheme not in ("http", "https"):
        return False
    host = (u.hostname or "").strip()
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    addrs = {i[4][0] for i in infos}
    if not addrs:
        return False
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except Exception:
            return False
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast \
                or ip.is_reserved or ip.is_unspecified:
            return False
    return True

def _fetch_subscription(url):
    """Бounded server-side GET подписки по URL администратора (для импорта ссылок)."""
    if not _url_host_is_public(url):
        raise ValueError("разрешены только внешние http/https адреса")
    req = urllib.request.Request(url, headers={"User-Agent": "veil-panel-import"})
    ctx = ssl.create_default_context()
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

# ---------- импорт баз 3x-ui / x-ui / Marzban (sqlite, только чтение) ----------
# Файл базы присылает браузер (b64) или читается путь на этом сервере; разбор — в
# staging-память (30 мин), применится отдельной кнопкой, чтобы человек видел список
# до записи. Исходные uuid/пароли сохраняем — подписчики уцелеют при переносе.

EXTIMPORT = {}
EXTIMPORT_LOCK = threading.Lock()
_EXTIMP_MAX_DB = 16 * 1024 * 1024

_EXTIMP_PROTO_MAP = {
    "vless": {
        "reality|tcp": "reality", "reality|xhttp": "vless-xhttp-reality",
        "reality|ws": "reality", "reality|grpc": "reality", "reality|*": "reality",
        "tls|ws": "vless-ws-tls", "tls|tcp": "vless-tcp-tls", "tls|grpc": "vless-grpc-tls",
        "tls|xhttp": "vless-xhttp-tls", "tls|*": "vless-ws-tls",
        "none|ws": "vless-ws",
    },
    "vmess": {"tls|ws": "vmess-ws-tls", "tls|tcp": "vmess-tcp-tls", "tls|grpc": "vmess-ws-tls",
              "tls|xhttp": "vmess-ws-tls", "none|ws": "vmess-ws", "none|*": "vmess-ws"},
    "trojan": {"tls|ws": "trojan-ws-tls", "tls|tcp": "trojan-tcp-tls", "tls|grpc": "trojan-grpc-tls",
               "tls|xhttp": "trojan-ws-tls", "reality|tcp": "trojan-tcp-tls", "reality|*": "trojan-tcp-tls",
               "tls|*": "trojan-tcp-tls"},
    "shadowsocks": {"*|*": "shadowsocks"},
    "hysteria2": {"*|*": "hysteria2"},
}

def _xui_proto_key(protocol, stream):
    """(protocol, streamSettings) → veil inbound id или None (не маппится)."""
    p = str(protocol or "").lower()
    table = _EXTIMP_PROTO_MAP.get(p)
    if not table:
        return None
    net = str((stream or {}).get("network") or "tcp").lower()
    if net in ("http", "xhttp"): net = "xhttp"
    if net in ("raw", "mrpb"): net = "tcp"
    sec = str((stream or {}).get("security") or "none").lower() or "none"
    return table.get(sec + "|" + net) or table.get(sec + "|*") or table.get("*|*")

def _xui_expiry(v):
    """x-ui хранит срок в миллисекундах (0/-1 = без ограничения); marzban — в секундах."""
    try: v = int(v or 0)
    except Exception: return 0
    if v <= 0: return 0
    if v >= 10**11: return v // 1000
    if v >= 10**8: return v
    return 0

def _bytes_to_gb(v):
    try: v = float(v or 0)
    except Exception: return 0.0
    if v <= 0: return 0.0
    if v > 1024 ** 2:  # явно байты (в x-ui поле totalGB хранит байты)
        return round(v / (1024 ** 3), 2)
    return round(v, 2)

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

def _jload(v):
    if isinstance(v, dict): return v
    if isinstance(v, (bytes, bytearray)): v = v.decode("utf-8", "replace")
    try: return json.loads(v or "{}")
    except Exception: return {}

def _xui_parse_items(con, warnings):
    cols = {r[1] for r in con.execute("PRAGMA table_info(inbounds)")}
    if "protocol" not in cols:
        raise RuntimeError("в таблице inbounds нет колонки protocol")
    scol = "settings" if "settings" in cols else ("protocol_settings" if "protocol_settings" in cols else None)
    tcol = "streamSettings" if "streamSettings" in cols else ("stream_settings" if "stream_settings" in cols else None)
    if not scol:
        raise RuntimeError("не вижу колонок настроек inbound")
    ecol = ", enable" if "enable" in cols else ""
    ncol = ", name" if "name" in cols else ""
    cur = con.execute("SELECT id, protocol, port, %s%s%s%s FROM inbounds" % (
        scol, (", " + tcol) if tcol else "", ecol, ncol))
    names = [d[0] for d in cur.description]
    items = []
    for r in cur.fetchall():
        row = dict(zip(names, r))
        protocol, port = row.get("protocol"), row.get("port")
        stream = _jload(row.get(tcol) if tcol else "{}")
        enable = bool(row.get("enable")) if "enable" in row else True
        inb_name = str(row.get("name") or "") or (str(protocol) + ":" + str(port))
        s = _jload(row.get(scol))
        veil_proto = _xui_proto_key(protocol, stream)
        if str(protocol).lower() == "shadowsocks":
            warnings.append("пропуск «%s»: в Veil Shadowsocks — один общий пароль на порт, перенеси вручную" % inb_name)
            continue
        if not veil_proto:
            warnings.append("пропуск «%s»: %s+%s+%s Veil не поддерживается (можно перенести ссылками)" %
                            (inb_name, protocol, stream.get("network"), stream.get("security")))
            continue
        if str(protocol).lower() in ("vless", "trojan") and str(stream.get("security") or "") == "reality":
            warnings.append("«%s»: Reality-ключей перенос нет — %s импортируется со своими ключами (ссылки подписчикам обновятся)" %
                            (inb_name, "reality-группа" if protocol == "vless" else "trojan-tcp-tls"))
        for c in (s.get("clients") or []):
            if not isinstance(c, dict): continue
            name = (str(c.get("email") or c.get("remark") or "").strip() or inb_name or "Кент")[:40]
            it = {"name": name, "veil_proto": veil_proto, "uuid": None, "password": None,
                  "limit_gb": _bytes_to_gb(c.get("totalGB")), "expiry": _xui_expiry(c.get("expiryTime")),
                  "blocked": not (enable and c.get("enable", True)), "flow": str(c.get("flow") or "")}
            if str(protocol).lower() in ("vless", "vmess"):
                u = str(c.get("id") or "")
                if _UUID_RE.fullmatch(u): it["uuid"] = u
                else: continue
            elif str(protocol).lower() == "trojan":
                pw = str(c.get("password") or "").strip()
                if 4 <= len(pw) <= 128: it["password"] = pw
                else: continue
            else:
                continue
            if it["blocked"]: it["blocked_reason"] = "неактивен в источнике"
            items.append(it)
    return items

def _marzban_parse_items(con, warnings):
    cols = {r[1] for r in con.execute("PRAGMA table_info(users)")}
    if "proxy_protocol" not in cols:
        raise RuntimeError("это не база Marzban (у users нет proxy_protocol)")
    sel = "SELECT username, status, data_limit, expire, proxy_protocol, proxy_settings" + \
          (", key" if "key" in cols else "") + " FROM users"
    items = []
    for row in con.execute(sel):
        username, status, data_limit, expire = row[0], row[1], row[2], row[3]
        proxy_protocol, proxy_settings = str(row[4] or "").lower(), _jload(row[5])
        key = str(row[6]) if len(row) > 6 and row[6] else ""
        proto_map = {"vless": "reality", "trojan": "trojan-tcp-tls", "shadowsocks": "shadowsocks",
                     "hysteria2": "hysteria2"}
        veil_proto = proto_map.get(proxy_protocol)
        if not veil_proto:
            warnings.append("пропуск пользователя %s: протокол %s не маппится" % (username, proxy_protocol))
            continue
        it = {"name": (str(username or "Кент").strip() or "Кент")[:40], "veil_proto": veil_proto,
              "uuid": None, "password": None, "limit_gb": _bytes_to_gb(data_limit),
              "expiry": _xui_expiry(expire), "blocked": str(status or "active") != "active",
              "flow": str(proxy_settings.get("flow") or "")}
        if it["blocked"]: it["blocked_reason"] = "статус в источнике: " + str(status)
        u = str(proxy_settings.get("id") or "")
        pw = str(proxy_settings.get("password") or key or "").strip()
        if _UUID_RE.fullmatch(u): it["uuid"] = u
        elif key and _UUID_RE.fullmatch(key): it["uuid"] = key
        elif proxy_protocol == "vless": continue
        if not it["uuid"] and 4 <= len(pw) <= 128:
            it["password"] = pw
        if not it["uuid"] and not it["password"]: continue
        items.append(it)
    return items

def _extimport_parse(raw):
    """bytes sqlite-файла → (source, items, warnings). Файл открывается строго read-only."""
    import sqlite3
    fd, tmp = tempfile.mkstemp(prefix=".veilimport", suffix=".db")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        con = sqlite3.connect("file:%s?mode=ro&immutable=1" % tmp, uri=True, timeout=5)
        try:
            tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "users" in tables:
                cols = {r[1] for r in con.execute("PRAGMA table_info(users)")}
                if "proxy_protocol" in cols:
                    source, items = "Marzban", _marzban_parse_items(con, warnings := [])
                else:
                    source, items = "x-ui/3x-ui", _xui_parse_items(con, warnings := [])
            elif "inbounds" in tables:
                source, items = "x-ui/3x-ui", _xui_parse_items(con, warnings := [])
            else:
                raise RuntimeError("не узнаю базу: нет таблиц inbounds/users")
            return source, items, warnings
        finally:
            try: con.close()
            except Exception: pass
    finally:
        try: os.unlink(tmp)
        except Exception: pass

def _extimport_apply(st, items):
    """Пишем нормализованные items в state.inbounds (inbound создаём при необходимости)."""
    warnings, imported = [], 0
    per = {}
    by_uuid = {c.get("uuid") for inb in (st.get("inbounds") or {}).values()
               for c in inb.get("clients", []) if c.get("uuid")}
    for it in items:
        proto = it.get("veil_proto")
        if proto not in _VALID_PROTOCOLS:
            warnings.append(it.get("name", "?") + ": неизвестный протокол " + str(proto))
            continue
        inb = (st.get("inbounds") or {}).get(proto)
        if inb is None:
            try:
                inb = _alloc_inbound(st, proto)
                st.setdefault("inbounds", {})[proto] = inb
                warnings.append("создан новый inbound %s (порт %s) — проверь его точечные настройки" % (proto, inb.get("port")))
            except Exception as e:
                warnings.append(it.get("name", "?") + ": inbound " + proto + ": " + str(e)[:70])
                continue
        u = it.get("uuid")
        if u and u in by_uuid:
            c = _new_client(it.get("name") or "Кент", proto, inb)
            warnings.append("дубликат uuid у «%s» — выдан новый (ссылка изменится)" % (it.get("name") or "?"))
        else:
            c = _new_client(it.get("name") or "Кент", proto, inb)
            if u: c["uuid"] = u
        if proto.startswith("trojan") and it.get("password"):
            c["password"] = it["password"]
        if proto == "hysteria2" and it.get("password"):
            c["auth"] = it["password"]
        if it.get("limit_gb"): c["limit_gb"] = it["limit_gb"]
        if it.get("expiry"): c["expiry"] = int(it["expiry"])
        if it.get("blocked"):
            c["blocked"] = True
            c["blocked_reason"] = it.get("blocked_reason") or "импорт: неактивен в источнике"
        if proto in ("reality", "vless-xhttp-reality") and it.get("flow"):
            inb["flow"] = it["flow"]
        inb.setdefault("clients", []).append(c)
        if u: by_uuid.add(u)
        imported += 1
        per[proto] = per.get(proto, 0) + 1
    return imported, warnings, per

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

def _routing_profile_b64(base=""):
    """Профиль маршрутизации (split-tunnel) для Xray-клиентов INCY и Happ —
    у них одинаковая схема JSON-профиля. Возвращает base64(JSON) или None.
    В подписку строка подставляется с префиксом:
      * INCY  →  incy://routing/onadd/{b64} (+ старая безымянная строка ://… )
      * Happ  →  happ://routing/onadd/{b64}
    Формат — по докам (routing.md): base64(JSON), обновляется по совпадению Name.
    Гео-базы раздаёт сама панель (/rulesets/*.dat, зеркало runetfreedom):
    телефон без VPN до GitHub не достанет, а кода geosite:ru в базах нет —
    он называется category-ru (проверено xray -test)."""
    split = (CFG_CACHE.get("split_tunnel") or "off").strip().lower()
    gh = "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/"
    def _u(dst, gname):
        if base and os.path.exists(os.path.join(RULESET_DIR, dst)):
            return base + "/rulesets/" + dst
        return gh + gname
    private = ["geoip:private",
               "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12",
               "192.168.0.0/16", "224.0.0.0/4",
               "::1/128", "fc00::/7", "fe80::/10"]
    # Адреса самой панели всегда напрямую: под VPN клиент иначе уходит туннелем
    # на тот же VPS (петля) и MTProto/webproxy-ссылка не подключается —
    # то самое «вписать IP в исключительные маршруты», только из коробки.
    own = _own_direct_ips()
    dom = (CFG_CACHE.get("panel_domain") or "").strip()
    own_sites = [dom] if dom and ":" not in dom and not re.fullmatch(r"[0-9.]+", dom) else []
    if split == "ru":
        # РФ напрямую, остальное через туннель
        fields = {"GlobalProxy": "true",
                  "DirectSites": ["geosite:category-ru"] + own_sites,
                  "DirectIp": ["geoip:ru"] + private + own}
    elif split == "ir":
        # только иранские сервисы через туннель, остальное напрямую
        # (geosite:ir в зеркале отсутствует — опираемся на geoip:ir)
        fields = {"GlobalProxy": "false",
                  "ProxyIp": ["geoip:ir"]}
    else:
        if not own:
            return None
        fields = {"GlobalProxy": "true", "DirectIp": private + own}
    prof = {"Name": "Veil", "LastUpdated": int(time.time()),
            "DomainStrategy": "IPIfNonMatch",
            "Geoipurl": _u("geoip-ru.dat", "geoip.dat"),
            "Geositeurl": _u("geosite-ru.dat", "geosite.dat")}
    prof.update(fields)
    return base64.b64encode(json.dumps(prof, ensure_ascii=False).encode("utf-8")).decode()

def _expire_seconds_client(ua="", xclient=""):
    # subscription-userinfo.expire: по умолчанию миллисекунды (v2rayNG, NekoBox,
    # Hiddify, Clash-клиенты), но INCY (по докам — Unix-секунды), Happ Plus и
    # Shadowrocket (иначе дата искажается) ждут секунды.
    u = (ua or "").lower()
    return ("shadowrocket" in u or "incy" in u or "happ" in u
            or (xclient or "").lower() == "incy")

def _incy_wg_ep(host):
    """WG-endpoint специально для Incy: только IPv4-литерал. Пинг-проверка Incy
    не резолвит хостнеймы (показывает «na», даже когда туннель живой), а WG-
    транспорту hostname не нужен — шифрование привязано к ключам. Подписка
    обновляется чаще, чем меняется IP, так что литерал не устаревает."""
    ep = str(_wg_ep(host) or "")
    if re.fullmatch(r"[0-9.]+", ep):
        return ep
    try:
        now = time.time()
        c = _WG4.get(ep)
        if c and now - c[1] < 600:
            return c[0]
        v4 = socket.gethostbyname(ep)
        _WG4[ep] = (v4, now)
        return v4
    except Exception:
        return ep

def _incy_link(proto, inb, c, host):
    """Ссылка в формате INCY: по одной в строке, WG/AmneziaWG — однострочными схемами."""
    meta = _proto_meta(proto)
    base = c.get("name") or "Veil"
    name = f"{base} · {meta['label']}"
    if proto == "amneziawg":
        conf = _link(inb, _incy_wg_ep(host), c, proto)
        b64 = base64.urlsafe_b64encode(conf.encode("utf-8")).decode().rstrip("=")
        return f"amneziawg://{b64}#{urllib.parse.quote(name)}"
    if proto == "wireguard":
        # INCY: userinfo (secretKey) он percent-декодирует, а query-параметры — НЕТ
        # (в его конфиг уезжали "N%2FrePA...%3D" и "10.10.0.2%2F32/32").
        # Поэтому: ключ в userinfo кодируем, publickey/address — плейнтекстом,
        # address без префикса /32. Формат: wireguard://secretKey@host:port?publickey=K&address=IP#name
        # mtu обязателен: по умолчанию приложения берут 1500, а туннельный
        # интерфейс — WG_MTU (1280); на мобильном IPv6-пути крупные пакеты не
        # фрагментируются и молча чёрнеют (handshake есть, трафика нет).
        addr = (c.get("address") or "10.10.0.2/32").split("/")[0]
        a6 = _tun6(c)
        if a6:
            addr = addr + "," + a6
        key = urllib.parse.quote(c.get("client_private_key") or "", safe="")
        q = ("publickey=" + (inb.get("public_key") or "") + "&address=" + addr
             + "&mtu=" + str(int(inb.get("mtu") or WG_MTU)))
        return (f"wireguard://{key}@{_incy_wg_ep(host)}:{inb['port']}?{q}#{urllib.parse.quote(name)}")
    return _link(inb, host, c, proto, std=True)

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
            t = {"type": "ws", "path": inb.get("path") or "/veil"}
            if inb.get("host"):
                t["headers"] = {"Host": inb["host"]}
            return t
        if meta["net"] == "grpc":
            t = {"type": "grpc", "service_name": inb.get("service") or "veil"}
            if inb.get("host"):
                t["authority"] = inb["host"]
            return t
        if meta["net"] in ("xhttp", "splithttp"):
            return {"type": "xhttp", "path": inb.get("path") or "/veil"}
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
        a6 = _tun6(c, "fd20:10::" if proto == "amneziawg" else "fd10:10::")
        addrs = [addr] + ([a6 + "/128"] if a6 else [])
        ob = {"type": "wireguard", "tag": tag,
              "secretKey": priv,
              "address": addrs,
              "peers": [{
                  "publicKey": pub,
                  "endpoint": f"{_wg_ep(host)}:{port}",
                  "preSharedKey": inb.get("psk", "")
              }],
              "mtu": int(inb.get("mtu", WG_MTU))}
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
            if inb.get("disabled"):
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
        {"name": "Happ", "ic": "H", "col": "#059669", "col2": "#84cc16", "store": "https://apps.apple.com/app/happ-proxy-utility/id6504287215", "link": "happ://", "precopy": 1},
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
        {"name": "Happ", "ic": "H", "col": "#059669", "col2": "#84cc16", "store": "https://play.google.com/store/apps/details?id=com.happproxy", "link": "happ://", "precopy": 1},
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
_SUB_APP_ICONS = {
    "INCY": "incy.jpg", "Happ": "happ.jpg", "sing-box": "singbox.jpg",
    "Streisand": "streisand.jpg", "Foxray": "foxray.jpg", "WireGuard": "wireguard.jpg",
    "AmneziaWG": "amneziawg.jpg", "Shadowrocket": "shadowrocket.jpg",
    "Stash": "stash.jpg", "Loon": "loon.jpg", "v2rayNG": "v2rayng.png",
    "Hiddify": "hiddify.webp", "Karing": "karing.jpg", "NekoBox": "nekobox.png",
    "FlClash": "flclash.png", "Hysteria2": "hy2.svg", "Amnezia VPN": "amneziavpn.webp",
    "v2rayN": "v2rayn.ico", "Clash Verge Rev": "clashverge.png",
    "sing-box (GUI)": "guisingbox.png",
}

def _sub_app_icon(name):
    n = str(name or "")
    f = _SUB_APP_ICONS.get(n) or _SUB_APP_ICONS.get(n.split(" (")[0])
    return "/appicons/" + f if f else ""

_SUB_PLATFORM_LABELS = {
    "ios": "iOS", "android": "Android", "windows": "Windows", "macos": "macOS",
    "apple_tv": "Apple TV", "android_tv": "Android TV", "linux": "Linux",
}

def _sub_status(u, now=None):
    now = now or time.time()
    if u.get("blocked"):
        reason = u.get("blocked_reason") or ""
        key = {"limit": "st_block_limit", "expired": "st_block_expired"}.get(reason, "st_block")
        return "disabled", key
    ex = int(u.get("expiry") or 0)
    if ex and now > ex:
        return "disabled", "st_expired"
    lim = float(u.get("limit_gb") or 0)
    used = float(u.get("used_gb") or 0)
    if lim > 0 and used >= lim * 0.95:
        return "disabled", "st_limit"
    return "active", "st_active"

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

_SUB_LANGS = ("ru", "en", "fa", "zh")
_SUB_LANG_NAV = (("ru", "RU"), ("en", "EN"), ("fa", "فارسی"), ("zh", "中文"))
# RU — значения по умолчанию; остальные языки перекрывают их частично.
_SUB_TXT_RU = {
    "ttl": "подписка",
    "tagline": "личный кабинет подписки",
    "st_active": "Активна",
    "st_expired": "Отключена — срок действия истёк",
    "st_limit": "Отключена — исчерпан лимит трафика",
    "st_block_limit": "Отключена — исчерпан лимит трафика",
    "st_block_expired": "Отключена — подписка истекла",
    "st_block": "Отключена — заблокирован",
    "lb_exp": "Окончание", "lb_trf": "Трафик", "lb_onl": "Онлайн",
    "lb_conns": "Протоколов", "lb_used": "использовано трафика", "lb_rt": "Маршрутизация",
    "noexp": "Без ограничения", "exp_over": "срок истёк",
    "exp_lt1d": "осталось меньше суток", "exp_unset": "срок не задан",
    "datefmt": "%d.%m.%Y",
    "lim_over": "лимит исчерпан", "unlim": "безлимит",
    "reset_day": "сброс ежедневно", "reset_week": "сброс еженедельно",
    "reset_month": "сброс ежемесячно", "maxdev": "до %d устр.",
    "head_valid": "Подписка <b>до %s</b>", "head_never": "Подписка <b>бессрочная</b>",
    "sec_dev": "Устройство", "sec_mydev": "Мои устройства",
    "forget": "Забыть", "client_default": "Клиент",
    "devnote": "Устройства, которые запрашивали вашу подписку. Приложение узнаётся по себе — смена сети (Wi-Fi → мобильный интернет) не добавляет новое устройство. «Забыть» уберёт запись, пока клиент снова не обновит подписку.",
    "sec_usage": "Чем вы пользуетесь", "us_line": "%s заходов за 7 дней · последний: %s",
    "us_note": "По журналу подключений сервера: какими протоколами и как часто вы пользовались за последние 7 дней. WireGuard и Telegram-прокси подключений в этом журнале не отмечают — их здесь нет.",
    "ago_now": "только что", "ago_min": "%d мин назад", "ago_hr": "%d ч назад",
    "ago_day": "%d дн назад",
    "conf_sb": "sing-box · полный конфиг",
    "tg_mp": "MTProto · Telegram",
    "tg_web": "Web-прокси · Telegram",
    "btn_add": "Добавить / Импортировать", "btn_install": "Установить конфиг",
    "btn_how": "Как подключиться", "btn_copy": "Скопировать подписку",
    "btn_share": "Поделиться",
    "hint_pick": "Выберите приложение и нажмите «Добавить / Импортировать».",
    "ft_sub": "Подписка:", "ft_page": "Ваша страница:",
    "tag_paid": "платно", "store_dl": "Скачать ↗",
    "js_first": "Сначала выберите приложение из списка.",
    "js_wg_open": "%s: откроется импорт или скачается .conf.",
    "js_wg_dl": "%s: конфиг будет скачан как .conf.",
    "js_opening": "Открываем «%s…». Если не открылось — скопируйте подписку кнопкой ниже.",
    "js_ext": "«%s» — внешний клиент: установите из магазина (ссылка «Скачать») и импортируйте подписку через «Скопировать подписку».",
    "js_happ": "Скопируем подписку и откроем Happ — он сам предложит добавить её из буфера. Обход РФ включится автоматически: ничего искать и вставлять вручную не нужно.",
    "js_copied": "Ссылка подписки скопирована.",
    "js_copied_open": "Ссылка подписки скопирована. Откройте «%s» и импортируйте её.",
    "js_nocopy": "Не удалось скопировать автоматически.",
    "js_manual": "Копируйте ссылку вручную кнопкой выше.",
    "js_forget_q": "Забыть это устройство?",
    "js_forgot": "Устройство забыто.",
    "js_forget_err": "Не удалось забыть устройство: %s",
    "ava_tip": "Сменить фото профиля", "ava_rm_tip": "Убрать фото",
    "ava_saved": "Фото обновлено", "ava_removed": "Фото убрано",
    "ava_big": "Картинка слишком большая (максимум 5 МБ)",
    "ava_bad": "Не получилось прочитать эту картинку",
    "ava_err": "Не удалось сохранить фото",
    "js_err": "ошибка", "js_net": "Сеть недоступна.",
    "rt_ru": "<b>Российские сайты и приложения идут напрямую</b>, остальное — через туннель.<br>"
             "В <b>Happ</b> и <b>INCY</b> ничего настраивать не нужно: профиль обхода «Veil» приходит прямо в подписке и включается сам при её добавлении или обновлении. "
             "Остальным приложениям готовый набор правил даёт кнопка «sing-box · полный конфиг» — <b>SFI/SFA, Streisand, NekoBox и Hiddify добавляйте именно ей</b>. "
             "Клиентам, которые импортируют только ссылки, правило включается в самом приложении:"
             "<ul>"
             "<li><b>Happ</b>: нажмите «Добавить / Импортировать» (или «Скопировать подписку» и вставьте в Happ) — обычная ссылка-подписка, обход включится автоматически. "
             "Файл <code>veil.json</code> Happ не подходит: у него ядро Xray, а не sing-box.</li>"
             "<li><b>Shadowrocket</b>: Настройки → Маршрутизация → добавить правила <code>GEOSITE,category-ru,DIRECT</code> и <code>GEOIP,ru,DIRECT</code>.</li>"
             "<li><b>v2rayNG</b>: Настройки маршрутизации → «Пользовательские» → правило <code>geosite:category-ru</code> → Direct.</li>"
             "<li><b>INCY</b>: ничего настраивать не нужно — профиль обхода подставляется прямо в подписку и включается сам при её добавлении/обновлении. "
             "Ноду «VLESS + WebSocket» без TLS новые ядра блокируют — используйте ноду «VLESS + WebSocket + TLS» или Reality.</li>"
             "</ul>",
    "addr_nt": ("🔄 <b>Адрес сервера изменён %s.</b> Если прокси перестал подключаться: обнови подписку "
                "в приложении (обычно это кнопка «обновить» у профиля) или добавь ссылку заново — все ссылки на этой странице и в боте уже с новым адресом."),
    "rt_ir": "<b>Через туннель идут только иранские сервисы</b>, остальной трафик — напрямую.<br>"
             "В <b>Happ</b> и <b>INCY</b> настраивать не нужно: профиль туннеля приходит прямо в подписке и включается сам. "
             "Готовые правила для других приложений — в кнопке «sing-box · полный конфиг». В ссылочных клиентах правило настраивается в самом приложении:"
             "<ul>"
             "<li><b>Happ</b>: добавьте обычную ссылку-подписку — профиль туннеля активируется автоматически.</li>"
             "<li><b>Shadowrocket</b>: Настройки → Маршрутизация → <code>GEOIP,ir,PROXY</code> и <code>GEOSITE,ir,PROXY</code>, финальное правило — DIRECT.</li>"
             "<li><b>v2rayNG</b>: «Пользовательские» → <code>geoip:ir</code> / <code>geosite:ir</code> → Proxy, остальные правила → Direct.</li>"
             "<li><b>INCY</b>: настраивать не нужно — профиль туннеля добавляется прямо в подписку автоматически.</li>"
             "</ul>",
}
_SUB_TXT = {
"en": {
    "ttl": "subscription", "tagline": "your subscription dashboard",
    "st_active": "Active", "st_expired": "Disabled — subscription expired",
    "st_limit": "Disabled — traffic limit reached",
    "st_block_limit": "Disabled — traffic limit reached",
    "st_block_expired": "Disabled — subscription expired", "st_block": "Disabled — blocked",
    "lb_exp": "Expiry", "lb_trf": "Traffic", "lb_onl": "Online",
    "lb_conns": "Protocols", "lb_used": "traffic used", "lb_rt": "Routing",
    "noexp": "No limit", "exp_over": "expired",
    "exp_lt1d": "less than a day left", "exp_unset": "no date set",
    "datefmt": "%d %b %Y",
    "lim_over": "limit reached", "unlim": "unlimited",
    "reset_day": "resets daily", "reset_week": "resets weekly",
    "reset_month": "resets monthly", "maxdev": "up to %d devices",
    "head_valid": "Valid <b>until %s</b>", "head_never": "Subscription <b>never expires</b>",
    "sec_dev": "Device", "sec_mydev": "My devices",
    "forget": "Forget", "client_default": "Client",
    "devnote": "Devices that requested your subscription. Each app is recognized by itself — switching networks (Wi-Fi → mobile) does not add a new device. “Forget” removes the entry until the client refreshes the subscription again.",
    "sec_usage": "What you use", "us_line": "%s connections in 7 days · last: %s",
    "us_note": "From the server connection log: which protocols you used and how often over the last 7 days. WireGuard and the Telegram proxy don’t appear in this log.",
    "ago_now": "just now", "ago_min": "%d min ago", "ago_hr": "%d h ago",
    "ago_day": "%d d ago",
    "conf_sb": "sing-box · full config",
    "tg_mp": "MTProto · Telegram",
    "tg_web": "Web proxy · Telegram",
    "btn_add": "Add / Import", "btn_install": "Install config",
    "btn_how": "How to connect", "btn_copy": "Copy subscription",
    "btn_share": "Share",
    "hint_pick": "Choose an app and tap “Add / Import”.",
    "ft_sub": "Subscription:", "ft_page": "Your page:",
    "tag_paid": "paid", "store_dl": "Download ↗",
    "js_first": "Pick an app from the list first.",
    "js_wg_open": "%s: import will open or the .conf file will download.",
    "js_wg_dl": "%s: the config will download as a .conf file.",
    "js_opening": "Opening “%s…”. If nothing happened — copy the subscription with the button below.",
    "js_ext": "“%s” is a third-party client: install it from the store (the “Download” link) and import the subscription via “Copy subscription”.",
    "js_happ": "We’ll copy the subscription and open Happ — it will offer to add it from the clipboard. RU bypass turns on automatically: no manual searching or pasting needed.",
    "js_copied": "Subscription link copied.",
    "js_copied_open": "Subscription link copied. Open “%s” and import it.",
    "js_nocopy": "Automatic copy failed.",
    "js_manual": "Copy the link manually with the button above.",
    "js_forget_q": "Forget this device?",
    "js_forgot": "Device forgotten.",
    "js_forget_err": "Could not forget the device: %s",
    "ava_tip": "Change profile photo", "ava_rm_tip": "Remove photo",
    "ava_saved": "Photo updated", "ava_removed": "Photo removed",
    "ava_big": "Image is too large (max 5 MB)",
    "ava_bad": "Could not read this image",
    "ava_err": "Failed to save the photo",
    "js_err": "error", "js_net": "Network unavailable.",
    "exp_1": "%d day left", "exp_n": "%d days left",
    "rt_ru": "<b>Russian sites and apps go direct</b>, everything else through the tunnel.<br>"
             "In <b>Happ</b> and <b>INCY</b> nothing to configure: the “Veil” bypass profile ships inside the subscription and activates itself when you add or update it. "
             "For other apps the ready rule set is in the “sing-box · full config” button — <b>add SFI/SFA, Streisand, NekoBox and Hiddify with it</b>. "
             "Link-only clients must enable the rule inside the app:"
             "<ul>"
             "<li><b>Happ</b>: tap “Add / Import” (or “Copy subscription” and paste it in Happ) — a plain subscription link, bypass turns on automatically. "
             "The <code>veil.json</code> file does NOT work in Happ: its core is Xray, not sing-box.</li>"
             "<li><b>Shadowrocket</b>: Settings → Route → add <code>GEOSITE,category-ru,DIRECT</code> and <code>GEOIP,ru,DIRECT</code>.</li>"
             "<li><b>v2rayNG</b>: Routing settings → “Custom” → rule <code>geosite:category-ru</code> → Direct.</li>"
             "<li><b>INCY</b>: nothing to configure — the bypass profile is embedded in the subscription and applies itself. "
             "New cores block the plaintext “VLESS + WebSocket” node — use the “VLESS + WebSocket + TLS” or Reality node instead.</li>"
             "</ul>",
    "rt_ir": "<b>Only Iranian services go through the tunnel</b>, the rest is direct.<br>"
             "In <b>Happ</b> and <b>INCY</b> nothing to configure: the tunnel profile ships inside the subscription and activates itself. "
             "Ready rules for other apps are in the “sing-box · full config” button. In link-based clients the rule is set inside the app:"
             "<ul>"
             "<li><b>Happ</b>: just add the plain subscription link — the tunnel profile activates automatically.</li>"
             "<li><b>Shadowrocket</b>: Settings → Route → <code>GEOIP,ir,PROXY</code> and <code>GEOSITE,ir,PROXY</code>, final rule — DIRECT.</li>"
             "<li><b>v2rayNG</b>: “Custom” → <code>geoip:ir</code> / <code>geosite:ir</code> → Proxy, other rules → Direct.</li>"
             "<li><b>INCY</b>: nothing to configure — the tunnel profile is embedded in the subscription.</li>"
             "</ul>",
    "addr_nt": ("🔄 <b>The server address changed on %s.</b> If the proxy stopped connecting: refresh the subscription "
                "in your app (usually an “update” button on the profile) or add the link again — every link on this page and in the bot already uses the new address."),
},
"fa": {
    "ttl": "اشتراک", "tagline": "پنل شخصی اشتراک",
    "st_active": "فعال", "st_expired": "غیرفعال — اشتراک منقضی شده",
    "st_limit": "غیرفعال — ترافیک مصرف شده",
    "st_block_limit": "غیرفعال — ترافیک مصرف شده",
    "st_block_expired": "غیرفعال — اشتراک منقضی شده", "st_block": "غیرفعال — مسدود",
    "lb_exp": "انقضا", "lb_trf": "ترافیک", "lb_onl": "آنلاین",
    "lb_conns": "پروتکل‌ها", "lb_used": "ترافیک مصرف‌شده", "lb_rt": "مسیریابی",
    "noexp": "بدون محدودیت", "exp_over": "منقضی شده",
    "exp_lt1d": "کمتر از یک روز مانده", "exp_unset": "تاریخی ثبت نشده",
    "datefmt": "%Y/%m/%d",
    "lim_over": "ترافیک تمام شده", "unlim": "نامحدود",
    "reset_day": "ریست روزانه", "reset_week": "ریست هفتگی",
    "reset_month": "ریست ماهانه", "maxdev": "حداکثر %d دستگاه",
    "head_valid": "اعتبار اشتراک <b>تا %s</b>", "head_never": "اشتراک <b>بدون انقضا</b>",
    "sec_dev": "دستگاه", "sec_mydev": "دستگاه‌های من",
    "forget": "فراموشی", "client_default": "کلاینت",
    "devnote": "دستگاه‌هایی که اشتراک شما را درخواست کرده‌اند. هر اپلیکیشن خودش شناخته می‌شود — تغییر شبکه (Wi-Fi → اینترنت موبایل) دستگاه جدید اضافه نمی‌کند. «فراموشی» ورودی را پاک می‌کند تا وقتی کلاینت دوباره اشتراک را تازه‌سازی کند.",
    "sec_usage": "با چه چیزی استفاده می‌کنید", "us_line": "%s اتصال در 7 روز · آخرین: %s",
    "us_note": "از گزارش اتصال سرور: در 7 روز گذشته کدام پروتکل‌ها و چند بار استفاده شده‌اند. WireGuard و پروکسی تلگرام در این گزارش ثبت نمی‌شوند.",
    "ago_now": "همین الان", "ago_min": "%d دقیقه پیش", "ago_hr": "%d ساعت پیش",
    "ago_day": "%d روز پیش",
    "conf_sb": "sing-box · کانفیگ کامل",
    "tg_mp": "MTProto · تلگرام",
    "tg_web": "پروکسی وب · تلگرام",
    "btn_add": "افزودن / وارد کردن", "btn_install": "نصب کانفیگ",
    "btn_how": "چگونه وصل شویم", "btn_copy": "کپی اشتراک",
    "btn_share": "اشتراک‌گذاری",
    "hint_pick": "یک اپ انتخاب کنید و «افزودن / وارد کردن» را بزنید.",
    "ft_sub": "اشتراک:", "ft_page": "صفحه شما:",
    "tag_paid": "پولی", "store_dl": "دانلود ↗",
    "js_first": "اول یک اپ از لیست انتخاب کنید.",
    "js_wg_open": "%s: یا وارد می‌شود یا فایل .conf دانلود می‌شود.",
    "js_wg_dl": "%s: کانفیگ به‌صورت فایل .conf دانلود می‌شود.",
    "js_opening": "در حال باز کردن «%s…». باز نشد، اشتراک را با دکمه پایین کپی کنید.",
    "js_ext": "«%s» یک کلاینت خارجی است: از فروشگاه (لینک «دانلود») نصب کنید و اشتراک را با «کپی اشتراک» وارد کنید.",
    "js_happ": "اشتراک کپی می‌شود و Happ باز می‌شود — خودش پیشنهاد می‌کند از حافظه وارد کنید. عبور روسی خودکار فعال می‌شود: نیازی به جست‌وجو یا جای‌گذاری دستی نیست.",
    "js_copied": "لینک اشتراک کپی شد.",
    "js_copied_open": "لینک اشتراک کپی شد. «%s» را باز کنید و وارد کنید.",
    "js_nocopy": "کپی خودکار نشد.",
    "js_manual": "لینک را دستی با دکمه بالا کپی کنید.",
    "js_forget_q": "این دستگاه فراموش شود؟",
    "js_forgot": "دستگاه فراموش شد.",
    "js_forget_err": "فراموشی ممکن نشد: %s",
    "ava_tip": "تغییر عکس پروفایل", "ava_rm_tip": "حذف عکس",
    "ava_saved": "عکس به‌روزرسانی شد", "ava_removed": "عکس حذف شد",
    "ava_big": "تصویر خیلی بزرگ است (حداکثر ۵ مگابایت)",
    "ava_bad": "این تصویر خوانده نشد",
    "ava_err": "ذخیره عکس ناموفق بود",
    "js_err": "خطا", "js_net": "شبکه در دسترس نیست.",
    "exp_n": "%d روز مانده",
    "rt_ru": "<b>سایت‌ها و اپ‌های روسی مستقیم می‌روند</b> و بقیه از تونل.<br>"
             "در <b>Happ</b> و <b>INCY</b> نیازی به تنظیم نیست: پروفایل عبور «Veil» داخل خود اشتراک می‌آید و هنگام افزودن یا به‌روزرسانی به‌طور خودکار فعال می‌شود. "
             "برای بقیه اپ‌ها قوانین آماده در دکمه «sing-box · کانفیگ کامل» است — <b>SFI/SFA، Streisand، NekoBox و Hiddify را با همان کانفیگ کامل اضافه کنید</b>. "
             "در کلاینت‌های لینکی باید قانون را در خود اپ فعال کنید:"
             "<ul>"
             "<li><b>Happ</b>: روی «افزودن / وارد کردن» بزنید (یا «کپی اشتراک» و در Happ جای‌گذاری کنید) — همان لینک اشتراک معمولی، عبور خودکار فعال می‌شود. فایل <code>veil.json</code> در Happ کار نمی‌کند: هسته‌اش Xray است نه sing-box.</li>"
             "<li><b>Shadowrocket</b>: تنظیمات → Route → افزودن <code>GEOSITE,category-ru,DIRECT</code> و <code>GEOIP,ru,DIRECT</code>.</li>"
             "<li><b>v2rayNG</b>: تنظیمات مسیریابی → «Custom» → قانون <code>geosite:category-ru</code> → Direct.</li>"
             "<li><b>INCY</b>: نیازی به تنظیم ندارد — پروفایل تونل به‌صورت خودکار در اشتراک قرار می‌گیرد. "
             "هسته‌های جدید گره «VLESS + WebSocket» بدون TLS را مسدود می‌کنند — از گره «VLESS + WebSocket + TLS» یا Reality استفاده کنید.</li>"
             "</ul>",
    "rt_ir": "<b>فقط سرویس‌های ایران از تونل می‌روند</b> و بقیه مستقیم.<br>"
             "در <b>Happ</b> و <b>INCY</b> نیازی به تنظیم نیست: پروفایل تونل داخل خود اشتراک می‌آید و خودکار فعال می‌شود. "
             "قوانین آماده برای بقیه اپ‌ها در دکمه «sing-box · کانفیگ کامل». در کلاینت‌های لینکی قانون داخل خود اپ تنظیم می‌شود:"
             "<ul>"
             "<li><b>Happ</b>: همان لینک اشتراک معمولی را اضافه کنید — پروفایل تونل خودکار فعال می‌شود.</li>"
             "<li><b>Shadowrocket</b>: تنظیمات → Route → <code>GEOIP,ir,PROXY</code> و <code>GEOSITE,ir,PROXY</code>؛ قانون آخر — DIRECT.</li>"
             "<li><b>v2rayNG</b>: «Custom» → <code>geoip:ir</code> / <code>geosite:ir</code> → Proxy و بقیه → Direct.</li>"
             "<li><b>INCY</b>: نیازی به تنظیم ندارد — پروفایل تونل خودکار داخل اشتراک است.</li>"
             "</ul>",
    "addr_nt": ("🔄 <b>نشانی سرور در %s تغییر کرد.</b> اگر پروکسی دیگر وصل نمی‌شود: اشتراک را در برنامه "
                "به‌روزرسانی کنید (معمولاً دکمهٔ «به‌روزرسانی» روی پروفایل) یا لینک را دوباره اضافه کنید — همهٔ لینک‌های این صفحه و ربات نشانی جدید دارند."),
},
"zh": {
    "ttl": "订阅", "tagline": "我的订阅中心",
    "st_active": "生效中", "st_expired": "已停用 — 订阅到期",
    "st_limit": "已停用 — 流量用尽",
    "st_block_limit": "已停用 — 流量用尽",
    "st_block_expired": "已停用 — 订阅到期", "st_block": "已停用 — 已封禁",
    "lb_exp": "到期", "lb_trf": "流量", "lb_onl": "在线",
    "lb_conns": "协议数", "lb_used": "已用流量", "lb_rt": "分流路由",
    "noexp": "无限制", "exp_over": "已过期",
    "exp_lt1d": "不足一天", "exp_unset": "未设到期",
    "datefmt": "%Y-%m-%d",
    "lim_over": "流量用尽", "unlim": "无限制",
    "reset_day": "每日重置", "reset_week": "每周重置",
    "reset_month": "每月重置", "maxdev": "最多 %d 台设备",
    "head_valid": "订阅<b>有效期至 %s</b>", "head_never": "订阅<b>永久有效</b>",
    "sec_dev": "设备", "sec_mydev": "我的设备",
    "forget": "忘记", "client_default": "客户端",
    "devnote": "请求过您订阅的设备。应用可被识别——切换网络（Wi-Fi → 移动网络）不会增加新设备。「忘记」会删除记录，直到该客户端再次刷新订阅。",
    "sec_usage": "您在用什么", "us_line": "7 天内连接 %s 次 · 最近：%s",
    "us_note": "来自服务器连接日志：最近 7 天您用过哪些协议、用了多少次。WireGuard 和 Telegram 代理不在此日志中。",
    "ago_now": "刚刚", "ago_min": "%d 分钟前", "ago_hr": "%d 小时前",
    "ago_day": "%d 天前",
    "conf_sb": "sing-box · 完整配置",
    "tg_mp": "MTProto · Telegram",
    "tg_web": "网页代理 · Telegram",
    "btn_add": "添加 / 导入", "btn_install": "安装配置",
    "btn_how": "如何连接", "btn_copy": "复制订阅",
    "btn_share": "分享",
    "hint_pick": "选择应用，然后点「添加 / 导入」。",
    "ft_sub": "订阅：", "ft_page": "您的页面：",
    "tag_paid": "付费", "store_dl": "下载 ↗",
    "js_first": "请先从列表选择应用。",
    "js_wg_open": "%s：将打开导入或下载 .conf 文件。",
    "js_wg_dl": "%s：配置将作为 .conf 文件下载。",
    "js_opening": "正在打开「%s…」。没反应请用下方按钮复制订阅。",
    "js_ext": "「%s」是第三方客户端：请从商店（“下载”链接）安装，再用「复制订阅」导入。",
    "js_happ": "我们会复制订阅并打开 Happ — 它会自动提示从剪贴板添加。俄区绕行会自动生效：无需手动查找或粘贴。",
    "js_copied": "订阅链接已复制。",
    "js_copied_open": "订阅链接已复制。打开「%s」并导入。",
    "js_nocopy": "自动复制失败。",
    "js_manual": "请用上方按钮手动复制链接。",
    "js_forget_q": "忘记此设备？",
    "js_forgot": "已忘记该设备。",
    "js_forget_err": "无法忘记设备：%s",
    "ava_tip": "更换头像", "ava_rm_tip": "移除头像",
    "ava_saved": "头像已更新", "ava_removed": "头像已移除",
    "ava_big": "图片太大（最大 5 MB）",
    "ava_bad": "无法读取该图片",
    "ava_err": "保存头像失败",
    "js_err": "错误", "js_net": "网络不可用。",
    "exp_n": "还剩 %d 天",
    "rt_ru": "<b>俄罗斯网站和应用直连</b>，其余走代理。<br>"
             "在 <b>Happ</b> 和 <b>INCY</b> 无需设置：绕行配置「Veil」直接随订阅下发，添加或更新订阅时会自动启用。"
             "其他应用可用上方「sing-box · 完整配置」按钮 — <b>SFI/SFA、Streisand、NekoBox、Hiddify 请用该完整配置添加</b>。仅导入链接的客户端需在应用内开启规则："
             "<ul>"
             "<li><b>Happ</b>：点「添加 / 导入」（或「复制订阅」后在 Happ 粘贴）— 用普通订阅链接即可，绕行自动生效。<code>veil.json</code> 文件在 Happ 无效：它的内核是 Xray，不是 sing-box。</li>"
             "<li><b>Shadowrocket</b>：设置 → 路由 → 添加 <code>GEOSITE,category-ru,DIRECT</code> 和 <code>GEOIP,ru,DIRECT</code>。</li>"
             "<li><b>v2rayNG</b>：路由设置 → 自定义 → 规则 <code>geosite:category-ru</code> → Direct。</li>"
             "<li><b>INCY</b>：无需设置 — 分流配置自动嵌入订阅。新版内核会拦截无 TLS 的「VLESS + WebSocket」节点 — 请改用「VLESS + WebSocket + TLS」或 Reality 节点。</li>"
             "</ul>",
    "rt_ir": "<b>只有伊朗服务走代理</b>，其余直连。<br>"
             "在 <b>Happ</b> 和 <b>INCY</b> 无需设置：分流配置直接随订阅下发并自动启用。"
             "其他应用的现成规则见上方「sing-box · 完整配置」按钮。链接类客户端需在应用内设置规则："
             "<ul>"
             "<li><b>Happ</b>：添加普通订阅链接即可 — 分流配置自动启用。</li>"
             "<li><b>Shadowrocket</b>：设置 → 路由 → <code>GEOIP,ir,PROXY</code> 和 <code>GEOSITE,ir,PROXY</code>，最后一条 — DIRECT。</li>"
             "<li><b>v2rayNG</b>：自定义 → <code>geoip:ir</code> / <code>geosite:ir</code> → Proxy，其余 → Direct。</li>"
             "<li><b>INCY</b>：无需设置 — 分流配置自动嵌入订阅。</li>"
             "</ul>",
    "addr_nt": ("🔄 <b>服务器地址已于 %s 变更。</b>如果代理无法连接：请在应用中刷新订阅"
                "（通常是配置文件上的「更新」按钮），或重新添加链接 — 本页和机器人中的所有链接已是新地址。"),
},
}

def _sub_L(lang):
    d = dict(_SUB_TXT_RU)
    d.update(_SUB_TXT.get(lang) or {})
    return d

def _sub_lang_pick(qs="", cookie="", accept=""):
    for cand in (qs, cookie):
        c = str(cand or "").strip().lower()
        for l in _SUB_LANGS:
            if c == l:
                return l
    for pr in str(accept or "").split(","):
        pr = pr.strip().split(";")[0].lower()
        for l in _SUB_LANGS:
            if pr == l or pr.startswith(l + "-"):
                return l
    return "ru"

def _sub_days_left(L, lang, n):
    if lang == "ru":
        m10, m100 = n % 10, n % 100
        if m10 == 1 and m100 != 11:
            return "остался %d день" % n
        if 2 <= m10 <= 4 and not 12 <= m100 <= 14:
            return "осталось %d дня" % n
        return "осталось %d дней" % n
    if lang == "en":
        return L.get("exp_1", "%d day left") % n if n == 1 else L["exp_n"] % n
    return L["exp_n"] % n

_AVATAR_DIR = os.path.join(BASE, "avatars")

def _avatar_path(tok):
    """Путь к файлу аватара подписчика (токен — право доступа; на диске, не в state.json)."""
    t = re.sub(r"[^A-Za-z0-9_-]", "", str(tok or ""))[:64]
    if not t:
        return ""
    return os.path.join(_AVATAR_DIR, t + ".img")

def _avatar_save(tok, data):
    """Проверяет, что bytes — PNG/JPEG/GIF/WebP ≤ 160 КБ, и пишет в файл. Возвращает mime или None."""
    if not data or len(data) > 160 * 1024:
        return None
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        mime = "image/png"
    elif data[:3] == b"\xff\xd8\xff":
        mime = "image/jpeg"
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        mime = "image/gif"
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        mime = "image/webp"
    else:
        return None
    path = _avatar_path(tok)
    if not path:
        return None
    try:
        os.makedirs(_AVATAR_DIR, exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        return mime
    except Exception:
        return None

def _avatar_remove(tok):
    try:
        os.remove(_avatar_path(tok))
    except OSError:
        pass

def _avatar_data_url(tok):
    """data: URL для встраивания в <img>, или '' если аватара нет."""
    path = _avatar_path(tok)
    if not path:
        return ""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return ""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        mime = "image/png"
    elif data[:3] == b"\xff\xd8\xff":
        mime = "image/jpeg"
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        mime = "image/gif"
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        mime = "image/webp"
    else:
        return ""
    return "data:" + mime + ";base64," + base64.b64encode(data).decode()

def _avatar_version(tok):
    """Метка времени файла аватара для cache-busting URL (?v=...), или 0 если файла нет."""
    path = _avatar_path(tok)
    if not path:
        return 0
    try:
        return int(os.path.getmtime(path))
    except OSError:
        return 0

def _avatar_mime(raw):
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if raw[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if raw[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    return "application/octet-stream"

def _avatar_serve(tok):
    """(mime, bytes) аватара для отдачи по GET, или (None, None) если файла нет."""
    path = _avatar_path(tok)
    if not path:
        return None, None
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return None, None
    mime = _avatar_mime(raw)
    if mime == "application/octet-stream":
        return None, None
    return mime, raw

def _sub_page_html(u, sub_url, host, panel_port, ua="", devs=None, lang="ru", pact=None):
    if lang not in _SUB_LANGS:
        lang = "ru"
    L = _sub_L(lang)
    status, st_key = _sub_status(u)
    status_txt = L[st_key]
    now = time.time()
    ex = int(u.get("expiry") or 0)
    if ex:
        exp_txt = time.strftime(L["datefmt"], time.localtime(ex))
        dl = int(ex - now)
        if dl < 0:
            exp_sub = L["exp_over"]
        elif dl < 86400:
            exp_sub = L["exp_lt1d"]
        else:
            exp_sub = _sub_days_left(L, lang, int(dl // 86400))
    else:
        exp_txt = L["noexp"]
        exp_sub = L["exp_unset"]
    lim = float(u.get("limit_gb") or 0)
    used = float(u.get("used_gb") or 0)
    if lim > 0:
        pct = min(100.0, used / lim * 100)
        trf_txt = f"{used:.2f} / {lim:.1f} GB"
        pct_txt = L["lim_over"] if pct >= 100 else f"{pct:.1f}%"
    else:
        pct = 0.0
        trf_txt = f"{used:.2f} GB · " + L["unlim"]
        pct_txt = L["unlim"]
    name_plain = str(u.get("name") or L["ttl"])
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
                           + L["conf_sb"] + '</a>')
    try:
        _tgl = _tg_sub_links(u) or []
    except Exception:
        _tgl = []
    _mp = next((l for l in _tgl if l.startswith("tg://proxy")), "")
    _wb = next((l for l in _tgl if l.startswith("tg://webproxy")), "")
    _tgsvg = ('<svg viewBox="0 0 24 24"><path d="M21 4L3 11l5 2 2 6 3-4 5 4 3-15z"/></svg>')
    for _link, _lab in ((_mp, L["tg_mp"]), (_wb, L["tg_web"])):
        if not _link:
            continue
        h = (_link.replace("&", "&amp;").replace('"', "&quot;")
                  .replace("<", "&lt;").replace(">", "&gt;"))
        conf_blocks.append('<a class="btn-conf" href="' + h + '">' + _tgsvg + _lab + '</a>')
    confs_html = "<div class='confs'>" + "".join(conf_blocks) + "</div>" if conf_blocks else ""
    # Строка под именем: лимиты вместо дубля окончания срока (он есть в карточках).
    cyc_label = {"day": L["reset_day"], "week": L["reset_week"],
                 "month": L["reset_month"]}.get(u.get("reset_cycle") or "", "")
    try: mdev = int(u.get("max_devices") or 0)
    except Exception: mdev = 0
    segs = []
    if cyc_label:
        segs.append(cyc_label)
    if mdev:
        segs.append(L["maxdev"] % mdev)
    if segs:
        head_line = "<b>" + " · ".join(segs) + "</b> · " + exp_sub
    else:
        head_line = ((L["head_valid"] % exp_txt if ex else L["head_never"]) + " · " + exp_sub)
    split = (CFG_CACHE.get("split_tunnel") or "off").strip().lower()
    rt_html = ""
    if split == "ru":
        rt_html = ("<div class='sec'><h2>" + L["lb_rt"] + "</h2><div class='rt'>"
                   + L["rt_ru"] + "</div></div>")
    elif split == "ir":
        rt_html = ("<div class='sec'><h2>" + L["lb_rt"] + "</h2><div class='rt'>"
                   + L["rt_ir"] + "</div></div>")
    addr_html = ""
    try:
        _ach = int(CFG_CACHE.get("addr_changed") or 0)
        if _ach and now - _ach < 7 * 86400:
            addr_html = ("<div class='sec'><div class='rt' style='border-left:3px solid var(--warn,#f59e0b)'>"
                         + (L["addr_nt"] % time.strftime(L["datefmt"], time.localtime(_ach)))
                         + "</div></div>")
    except Exception:
        addr_html = ""
    hy2_conf = links.get("hysteria2") or ""
    cat = {k: [dict(a) for a in v
               if not (a.get("wg") and not wg_conf)
               and not (a.get("awg") and not awg_conf)
               and not (a.get("hy2") and not hy2_conf)]
           for k, v in _SUB_APP_CATALOG.items()}
    for _apps in cat.values():
        for _a in _apps:
            _a["img"] = _sub_app_icon(_a.get("name"))
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
        if s < 120: return L["ago_now"]
        if s < 3600: return L["ago_min"] % (s // 60)
        if s < 86400: return L["ago_hr"] % (s // 3600)
        return L["ago_day"] % (s // 86400)
    drows = []
    for d in (devs or [])[:10]:
        cli = _esc(d.get("client") or L["client_default"])
        ver = _esc(d.get("version") or "")
        typ = _esc(d.get("type") or "")
        osl = _esc(d.get("os") or "")
        ip = _esc(d.get("ip") or "")
        ago = _esc(_ago_txt(d.get("last_ts") or ""))
        try: n = int(d.get("n") or 1)
        except Exception: n = 1
        nets = len({x for x in ([d.get("ip")] + list(d.get("ips") or [])) if x})
        if nets > 1:
            ip += " ·IP×%d" % nets
        who = cli + ((" " + ver) if ver else "")
        sub = " · ".join(x for x in (typ or osl, ip,
                     (ago + ((" ×%d" % n) if n > 1 else "")) if ago else "") if x)
        drows.append('<div class="devr"><div class="devi"><b>' + who +
                     '</b><span>' + sub + '</span></div>'
                     '<button class="devx" data-ip="' + ip + '">' + L["forget"] + '</button></div>')
    if drows:
        devs_html = ('<div class="sec"><h2>' + L["sec_mydev"] + '</h2><div class="devlist">'
                     + "".join(drows) + '</div><div class="devnote">' + L["devnote"] + '</div></div>')
    else:
        devs_html = ''
    urows = []
    try:
        for a in (pact or [])[:8]:
            n = int(a.get("n") or 0)
            if n <= 0:
                continue
            tag = str(a.get("tag") or "")
            try:
                lab = _proto_meta(tag)["label"]
            except Exception:
                lab = tag
            lt = int(a.get("last") or 0)
            ago = _ago_txt(datetime.datetime.fromtimestamp(
                lt, datetime.timezone.utc).isoformat()) if lt > 0 else ""
            if lt and now - lt > (_PA_KEEP + 1) * 86400:
                ago = ""
            nstr = f"{n:,}".replace(",", "\u202f")
            urows.append('<div class="devr"><div class="devi"><b>' + _esc(lab) +
                         '</b><span>' + _esc(L["us_line"] % (nstr, ago or L["ago_now"])) +
                         '</span></div></div>')
    except Exception:
        urows = []
    if urows:
        usage_html = ('<div class="sec"><h2>' + L["sec_usage"] + '</h2><div class="devlist">'
                      + "".join(urows) + '</div><div class="devnote">' + L["us_note"] +
                      '</div></div>')
    else:
        usage_html = ''
    plats_json = json.dumps([[k, _SUB_PLATFORM_LABELS.get(k, k)] for k in cat], ensure_ascii=False)
    langnav = "".join('<a href="?lang=' + lk + '"' + (' class="sel"' if lk == lang else "") +
                      '>' + _esc(ln) + '</a>' for lk, ln in _SUB_LANG_NAV)
    js_keys = ("js_first js_wg_open js_wg_dl js_opening js_ext js_happ js_copied js_copied_open "
               "js_nocopy js_manual js_forget_q js_forgot js_forget_err js_err js_net "
               "btn_add btn_install btn_how tag_paid store_dl").split()
    ljs_json = json.dumps({k: L[k] for k in js_keys}, ensure_ascii=False)
    tpl = """<!DOCTYPE html><html lang="__LANG__" dir="__DIR__"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/png" href="/logo.png">
<meta name="theme-color" content="#0a122a">
<title>__NAMEHT__ · __TTL__</title><style>
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
.hbar{display:grid;grid-template-columns:auto minmax(0,1fr) auto;
  grid-template-areas:"logo br pill" "logo br langs";
  column-gap:11px;row-gap:6px;align-items:center;margin-bottom:18px;padding:0 2px}
.hbar .lg{grid-area:logo;align-self:center;width:40px;height:40px;border-radius:12px;object-fit:cover;box-shadow:0 8px 20px -6px rgba(34,211,238,.5)}
.hbar .br{grid-area:br;align-self:center;min-width:0;display:flex;flex-direction:column;justify-content:center}
.hbar .br b{font-size:15px;font-weight:800;letter-spacing:3px;line-height:1}
.hbar .br span{font-size:10.5px;color:#8b94b5;letter-spacing:.3px;margin-top:3px;overflow-wrap:anywhere}
.langs{grid-area:langs;justify-self:end;display:grid;grid-template-columns:repeat(2,min-content);gap:4px}
[dir=rtl] .langs{justify-self:start}
.langs a{font-size:10.5px;font-weight:700;letter-spacing:.4px;color:#8b94b5;text-decoration:none;
  padding:6px 8px;border-radius:999px;border:1px solid rgba(66,84,130,.45);background:rgba(22,29,52,.6);text-align:center}
.langs a.sel{color:#04101f;background:linear-gradient(90deg,#3b82f6,#22d3ee);border-color:transparent}
.hbar .pill{grid-area:pill;justify-self:end;display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:999px;
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
.ava img{width:100%;height:100%;object-fit:cover;display:block;position:relative;border-radius:20px}
.avawrap{display:flex;flex-direction:column;align-items:center;gap:6px;flex:0 0 auto}
.avactl{display:flex;gap:6px}
.avabtn{width:26px;height:26px;border-radius:9px;border:1px solid rgba(255,255,255,.16);cursor:pointer;
  background:rgba(255,255,255,.07);color:#c6cee6;font-size:13px;line-height:1;display:flex;align-items:center;justify-content:center;padding:0}
.avabtn:hover{background:rgba(255,255,255,.14)}
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
.rt ul{margin:8px 0 0;padding-inline-start:18px}
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
h2::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,rgba(66,84,130,.5),transparent);margin-inline-start:12px}
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
.ic img{width:100%;height:100%;object-fit:cover;border-radius:11px;display:block}
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
  <div class="br"><b>VEIL</b><span>__TAG__</span></div>
  <span class="pill __CLS__"><i></i>__STATUS__</span>
  <nav class="langs">__LANGS__</nav>
 </header>
 <main class="card fade" style="animation-delay:.08s">
  <div class="head">
   <div class="avawrap">
    <div class="ava" id="avaEl"><span class="ring"></span>__AVA__</div>
    <div class="avactl">__AVABTN____AVARM__</div>
    <input type="file" id="avaFile" accept="image/*" hidden>
   </div>
   <div class="meta">
    <div class="name">__NAMEHT__</div>
    <div class="sub">__HEADLINE__</div>
   </div>
  </div>
  <div class="stats">
   <div class="stat"><svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg><div class="lb">__LBEXP__</div><b>__EXP__<span class="dim"> · __EXPSUB__</span></b></div>
   <div class="stat"><svg viewBox="0 0 24 24"><circle cx="12" cy="15" r="8"/><path d="M12 15l3.5-3.5M5 5l4 4"/></svg><div class="lb">__LBTRF__</div><b>__TRF__</b></div>
   <div class="stat"><svg viewBox="0 0 24 24"><path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z"/></svg><div class="lb">__LBONL__</div><b>__ONL__</b></div>
   <div class="stat"><svg viewBox="0 0 24 24"><path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/></svg><div class="lb">__LBCON__</div><b>__CONNS__</b></div>
  </div>
  <div class="barwrap">
   <div class="track"><i style="width:__PCT__%"></i></div>
   <div class="tl"><span>__LBUSED__</span><b>__PCTLBL__</b></div>
  </div>
  __ADDRNT__
  __CONFS__
  <div class="sec">
   <h2>__SECDEV__</h2>
   <div class="chips" id="chips"></div>
   <div id="apps" class="apps"></div>
  </div>
  __DEVS__
  __USAGE__
  __RT__
  __PAYBLOCK__
 </main>
 <div class="action">
  <button class="btn btn-add fade" style="animation-delay:.16s" id="addBtn"><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg><span id="addLbl">__BTNADD__</span></button>
  <div class="btn-row fade" style="animation-delay:.22s">
   <button class="btn btn-copy" id="copyBtn"><svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54 0l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54 0l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>__BTNCOPY__</button>
   <button class="btn btn-copy" id="shareBtn"><svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="M8.6 13.5l6.8 4M15.4 6.5l-6.8 4"/></svg>__BTNSHARE__</button>
  </div>
  <div class="hint" id="hint" style="animation:none">__HINTPICK__</div>
 </div>
 <div class="footer"><b>__SUBFT__</b> <code>__SUB__</code><br><b>__PAGEFT__</b> <code>__PAGE__</code></div>
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
const L=__LJS__;
function F(s){var a=[].slice.call(arguments,1);return String(s).replace(/%s/g,function(){return a.shift()});}
let cur=null;
let lastK=__PLATDEFAULT__;
const HP=document.getElementById.bind(document);
function hint(m,c){const h=HP('hint');h.textContent=m;h.style.color=c||'#8b94b5';}
function buildLink(a){return (a.link||'')
  .replace('{b64}',B64).replace('{rawsub}',SUB).replace('{sub}',encodeURIComponent(SUB))
  .replace('{name}',encodeURIComponent(NAME)).replace('{wgconf}',WGCONF).replace('{awgconf}',AWGCONF);}
function selHint(){
  if(!cur){hint(L.js_first,'#fbbf24');return false;}
  if(cur.wg||cur.awg){
    if(cur.link){hint(F(L.js_wg_open,cur.wg?'WireGuard':'AmneziaWG'),'#7dd3fc');}
    else{hint(F(L.js_wg_dl,cur.wg?'WireGuard':'AmneziaWG'),'#7dd3fc');}
  }else if(cur.precopy){
    hint(L.js_happ,'#7dd3fc');
  }else if(cur.link){
    hint(F(L.js_opening,cur.name));
  }else{
    hint(F(L.js_ext,cur.name),'#fbbf24');
  }
  return true;
}
function app(a){
  const d=document.createElement('div');d.className='app fade';
  d.style.animationDelay=Math.min((CATALOG[lastK]||[]).indexOf(a)*.03,.3)+'s';
  const ic=document.createElement('span');ic.className='ic';
  const _letter=String(a.ic||(a.name||'?')[0]).toUpperCase();
  ic.textContent=_letter;
  ic.style.background='linear-gradient(135deg,'+(a.col||'#3b82f6')+' 0%,'+(a.col2||'#22d3ee')+' 100%)';
  if(a.img){const im=document.createElement('img');im.src=a.img;im.alt='';im.onerror=function(){im.remove();ic.textContent=_letter;};ic.textContent='';ic.appendChild(im);}
  const inf=document.createElement('div');inf.className='inf';
  const b=document.createElement('b');b.textContent=a.name;
  const tg=document.createElement('div');tg.className='tags';
  if(a.pay){const p=document.createElement('span');p.className='tag pay';p.textContent=L.tag_paid;tg.appendChild(p);}
  else if(a.wg||a.awg){const p=document.createElement('span');p.className='tag cfg';p.textContent='.conf';tg.appendChild(p);}
  if(a.store){const x=document.createElement('a');x.href=a.store;x.target='_blank';x.rel='noopener';x.className='store';x.textContent=L.store_dl;
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
  if(cur&&cur.link)lbl.textContent=L.btn_add;
  else if(cur&&(cur.wg||cur.awg))lbl.textContent=L.btn_install;
  else if(cur)lbl.textContent=L.btn_how;
  else lbl.textContent=L.btn_add;
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
    if(cur.precopy){
      var _lk=buildLink(cur);
      if(navigator.clipboard){navigator.clipboard.writeText(SUB).then(function(){location.href=_lk;})
        .catch(function(){location.href=_lk;});}
      else{location.href=_lk;}
      return;
    }
    if(cur.link){location.href=buildLink(cur);return;}
    if(navigator.clipboard){
      navigator.clipboard.writeText(SUB).then(function(){
        hint(F(L.js_copied_open,cur.name),'#4ade80');
      }).catch(function(){hint(L.js_nocopy);});
    }else{hint(L.js_nocopy);}
  });
  HP('copyBtn').addEventListener('click',function(){
    if(navigator.clipboard){
      navigator.clipboard.writeText(SUB).then(function(){hint(L.js_copied,'#4ade80');})
        .catch(function(){hint(L.js_nocopy);});
    }else{hint(L.js_nocopy);}
  });
  HP('shareBtn').addEventListener('click',function(){
    if(navigator.share){
      navigator.share({title:NAME,text:NAME,url:SUB}).catch(function(){hint(L.js_manual);});
    }else if(navigator.clipboard){
      navigator.clipboard.writeText(SUB).then(function(){hint(L.js_copied,'#4ade80');})
        .catch(function(){hint(L.js_nocopy);});
    }else{hint(L.js_nocopy);}
  });
  Array.prototype.forEach.call(document.querySelectorAll('.devx'),function(btn){
    btn.addEventListener('click',function(){
      var ip=btn.getAttribute('data-ip');
      if(!confirm(L.js_forget_q))return;
      btn.disabled=true;
      fetch('/p/'+encodeURIComponent(TOK)+'/forget',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})})
        .then(function(r){return r.json();})
        .then(function(j){ if(j&&j.ok){var row=btn.closest('.devr'); if(row) row.remove(); hint(L.js_forgot,'#4ade80');} else {hint(F(L.js_forget_err,(j&&j.error)||L.js_err),'#fb7185'); btn.disabled=false;} })
        .catch(function(){hint(L.js_net,'#fb7185'); btn.disabled=false;});
    });
  });
  (function(){
    var f=document.getElementById('avaFile'),b=document.getElementById('avaBtn'),rb=document.getElementById('avaRm');
    if(!f||!b)return;
    function post(body,after){
      b.disabled=true; if(rb)rb.disabled=true;
      fetch('/p/'+encodeURIComponent(TOK)+'/avatar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
        .then(function(r){return r.json();})
        .then(function(j){ b.disabled=false; if(rb)rb.disabled=false;
          if(j&&j.ok){after&&after(j);}else{hint(j&&j.error||L.ava_err,'#fb7185');} })
        .catch(function(){ b.disabled=false; if(rb)rb.disabled=false; hint(L.js_net,'#fb7185'); });
    }
    b.addEventListener('click',function(){f.click();});
    f.addEventListener('change',function(){
      var file=f.files&&f.files[0]; f.value='';
      if(!file)return;
      if(file.size>5*1024*1024){hint(L.ava_big,'#fb7185');return;}
      var fr=new FileReader();
      fr.onload=function(){
        var im=new Image();
        im.onload=function(){
          try{
            var s=Math.min(im.width,im.height)||1,cv=document.createElement('canvas');
            cv.width=cv.height=192;
            var x=cv.getContext('2d');
            x.drawImage(im,(im.width-s)/2,(im.height-s)/2,s,s,0,0,192,192);
            post({img:cv.toDataURL('image/png')},function(){location.reload();});
          }catch(e){hint(L.ava_err,'#fb7185');}
        };
        im.onerror=function(){hint(L.ava_bad,'#fb7185');};
        im.src=fr.result;
      };
      fr.onerror=function(){hint(L.ava_bad,'#fb7185');};
      fr.readAsDataURL(file);
    });
    if(rb)rb.addEventListener('click',function(){ if(confirm(L.ava_rm_tip)) post({},function(){location.reload();}); });
  })();
});
</script></body></html>"""
    payblock = ""
    try:
        payblock = _pay_block_html(u.get("sub_token") or "", L)
    except Exception:
        pass
    # аватар — отдельным кэшируемым файлом: base64 внутри страницы добавлял ~95 КБ
    # к каждому показу /p, и страница с ним не кэшировалась вообще
    _av = _avatar_version(tok)
    ava_img = ("/p/" + tok + "/avatar?v=" + str(_av)) if _av else ""
    avatar_html = ('<img src="' + ava_img + '" alt>' if ava_img else avatar)
    _ava_cam = ('<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" '
                'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
                '<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/>'
                '<circle cx="12" cy="13" r="4"/></svg>')
    ava_btn = ('<button type="button" class="avabtn" id="avaBtn" title="' + _esc(L["ava_tip"])
               + '" aria-label="' + _esc(L["ava_tip"]) + '">' + _ava_cam + '</button>')
    ava_rm = ('<button type="button" class="avabtn" id="avaRm" title="' + _esc(L["ava_rm_tip"])
              + '" aria-label="' + _esc(L["ava_rm_tip"]) + '">&#10005;</button>') if ava_img else ''
    return (tpl.replace("__LANGS__", langnav)
                .replace("__LANG__", lang).replace("__DIR__", "rtl" if lang == "fa" else "ltr")
                .replace("__TTL__", L["ttl"]).replace("__TAG__", L["tagline"])
                .replace("__AVA__", avatar_html)
                .replace("__AVABTN__", ava_btn).replace("__AVARM__", ava_rm)
                .replace("__NAMEHT__", name_html)
                .replace("__CLS__", cls).replace("__STATUS__", status_txt)
                .replace("__EXP__", exp_txt).replace("__EXPSUB__", exp_sub)
                .replace("__TRF__", trf_txt).replace("__PCT__", f"{pct:.2f}")
                .replace("__PCTLBL__", pct_txt)
                .replace("__LBEXP__", L["lb_exp"]).replace("__LBTRF__", L["lb_trf"])
                .replace("__LBONL__", L["lb_onl"]).replace("__LBCON__", L["lb_conns"])
                .replace("__LBUSED__", L["lb_used"])
                .replace("__ONL__", str(onl)).replace("__CONNS__", str(conns))
                .replace("__SUB__", sub_url).replace("__PAGE__", page_url)
                .replace("__CONFS__", confs_html)
                .replace("__ADDRNT__", addr_html)
                .replace("__HEADLINE__", head_line)
                .replace("__SECDEV__", L["sec_dev"])
                .replace("__BTNADD__", L["btn_add"]).replace("__BTNCOPY__", L["btn_copy"])
                .replace("__BTNSHARE__", L["btn_share"]).replace("__HINTPICK__", L["hint_pick"])
                .replace("__SUBFT__", L["ft_sub"]).replace("__PAGEFT__", L["ft_page"])
                .replace("__DEVS__", devs_html)
                .replace("__USAGE__", usage_html)
                .replace("__RT__", rt_html)
                .replace("__PAYBLOCK__", payblock)
                .replace("__SUBJS__", json.dumps(sub_url))
                .replace("__B64JS__", json.dumps(sub64))
                .replace("__NAMEJS__", json.dumps(name_plain, ensure_ascii=False))
                .replace("__WGCONF__", json.dumps(wg_b64))
                .replace("__AWGCONF__", json.dumps(awg_b64))
                .replace("__WGDOWN__", json.dumps(wg_url))
                .replace("__AWGDOWN__", json.dumps(awg_url))
                .replace("__CAT__", catalog_json)
                .replace("__PLATS__", plats_json)
                .replace("__LJS__", ljs_json)
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

BOT_LANGS = f"{BASE}/bot_langs.json"
_BOT_RU = {
    "m_status": "📊 Статус", "m_clients": "👥 Клиенты",
    "m_addsub": "➕ Добавить подписку", "m_restart": "🔄 Перезапустить Xray",
    "m_2fa": "🔐 2FA", "m_help": "❓ Помощь", "m_lang": "🌐 Язык",
    "start": "🤖 <b>Veil Panel Bot</b>\nВаш Chat ID: <code>%s</code>\n\nВыберите действие:",
    "norights": "⛔ Нет прав доступа. Ваш ID: %s. Админ ID: %s",
    "norights_short": "⛔ Нет прав доступа",
    "nocallback": "Ошибка: нет сообщения",
    "add_step1": "➕ <b>Новая подписка</b>\nШаг 1 из 3. Отправь <b>имя</b> клиента (например: <b>Мама</b>).\nОтмена: /cancel",
    "add_nameempty": "Имя не может быть пустым. Напиши имя ещё раз или /cancel",
    "add_limitq": "👤 Имя: <b>%s</b>\nТеперь <b>лимит</b> трафика в ГБ (число, <code>0</code> = безлимит, можно дробное: 12.5):\nОтмена: /cancel",
    "add_num": "Нужно число. Повтори лимит (0 = безлимит) или /cancel",
    "add_daysq": "Лимит: <b>%s</b> ГБ\nТеперь <b>срок</b> в днях (число, <code>0</code> = бессрочно):\nОтмена: /cancel",
    "add_intnum": "Нужно целое число дней. Повтори (0 = бессрочно) или /cancel",
    "add_err": "❌ Ошибка создания: %s",
    "created": "✅ <b>Подписка создана</b>\nИмя: <code>%s</code>\nЛимит: %s · Срок: %s\nПодписка: <code>%s</code>\nСкопируй ссылку в приложение (v2rayNG / Hiddify / Streisand / NekoBox / Happ / Shadowrocket).",
    "unlim": "безлимит", "gb": "%s ГБ", "daysu": "%s дн.", "forever": "бессрочно",
    "clients_hdr": "👥 <b>Клиенты:</b>", "clients_empty": "Клиентов нет",
    "restarted": "🔄 Xray перезапущен", "cancelled": "Отменено.",
    "help": "<b>Команды:</b>\n/start — меню\n/status — статус и статистика\n/clients — список клиентов\n/restart — перезагрузить Xray\n/addsub — создать новую подписку (имя → лимит → срок)\n/2fa — настройка 2FA\n/pay — оплата: сводка и счета\n/paycheck — проверить статусы оплат\n/backup — автобэкапы: список и восстановление\n/lang — язык / language",
    "m_pay": "💳 Оплата",
    "pay_off": "💳 Приём оплаты <b>выключен</b>. Включается в панели: вкладка «💳 Оплата».",
    "pay_hdr": "💳 Приём оплаты: <b>включён</b>\nСпособ: %s\nТарифов: %d · неоплаченных счетов: %d · собрано: %s %s",
    "pay_none": "Счетов ещё не было.",
    "pay_recent": "<b>Последние счета:</b>",
    "pay_line": "%s — %s · %s %s · %s",
    "pay_wait": "⏳ ожидает",
    "pay_paidst": "✅ оплачен",
    "pay_none_open": "Неоплаченных счетов нет — проверять нечего.",
    "pay_checked": "Проверено счетов: %d · подтверждено оплат: %d",
    "m_backup": "🗄 Бэкап",
    "bk_hdr": "🗄 <b>Автобэкапы</b>: %d шт. (раньше сверху — новее)",
    "bk_none": "Автобэкапов ещё нет. Создай новый кнопкой или включи расписание в панели: «💾 Бэкапы».",
    "bk_new_btn": "🆕 Создать",
    "bk_send_btn": "📤 Прислать свежий",
    "bk_file_btn": "%s UTC · %d КБ",
    "bk_created": "✅ Бэкап создан: %s (%d КБ)",
    "bk_sent": "📤 Отправляю файл бэкапа...",
    "bk_noent": "Файл %s не найден.",
    "bk_ask": "⚠️ Восстановить панель из бэкапа <b>%s</b>?\nСоздан: %s UTC · клиентов в нём: %s\nТекущие данные будут перезаписаны (страховочная копия сервера делается автоматически).",
    "bk_yes": "✅ Да, восстановить",
    "bk_no": "❌ Отмена",
    "bk_done": "✅ Восстановлено из %s · клиентов: %s. Xray перезапущен.",
    "bk_cancel": "Отменено.",
    "bk_err": "⚠️ Ошибка бэкапа: %s",
    "status_hdr": "📊 <b>Статус и статистика</b>\nXray: %s\nАптайм: %s\nКлиентов: %s\nНод: %s\n%s\nCPU: %s · RAM: %s\nДиск: %s",
    "xray_on": "🟢 работает", "xray_off": "🔴 остановлен",
    "gp_ok": "🇷🇺 Доступность из РФ: %s %s/%s (%s%%) · %s UTC",
    "gp_none": "🇷🇺 Доступность из РФ: — (проверок ещё не было, открой панель)",
    "twofa": "🔐 <b>2FA настройка</b>\nНастройте 2FA в панели: вкладка <b>Безопасность</b> → <b>Двухфакторная аутентификация</b>",
    "unknown": "Неизвестная команда. /help",
    "err": "⚠️ Ошибка: %s",
    "lang_q": "🌐 Выберите язык / Choose language / زبان را انتخاب کنید / 请选择语言：",
    "lang_saved": "Готово: %s",
    "gp_low": "🚨 <b>Доступность из РФ упала ниже 50%%!</b>\nЗонды: %s/%s (%s%%)\nВремя: %s UTC\nПодробности проведи проверку в панели или нажми %s",
    "gp_recover": "✅ Доступность из РФ восстановилась: %s/%s (%s%%) · %s UTC",
    "sub_welcome": ("👋 <b>Привет! Я помощник подписчиков Veil.</b>\n\n"
                    "Отправь сюда <b>ссылку своей подписки</b> — она начинается на <code>https://…/sub/…</code> "
                    "(была в сообщении, где тебе выдали подписку). После привязки я:\n"
                    "• покажу статус, срок и трафик (кнопка «📊 Моя подписка»);\n"
                    "• пришлю ссылку и подсказку по приложениям;\n"
                    "• добавлю прокси в Telegram в один тап (кнопка «➕ Прокси в Telegram»);\n"
                    "• помогу продлить подписку (кнопка «💳 Продлить»);\n"
                    "• напомню, когда подписка будет заканчиваться.\n\n"
                    "Никакого публичного доступа: по ссылке я вижу только ТВОЮ подписку. "
                    "Отвязать Telegram можно кнопкой «🔗 Отвязать»."),
    "sub_bound": "✅ Готово! Telegram привязан к подписке «<b>%s</b>». Выбери действие:",
    "sub_badlink": ("🤔 Не нашёл в сообщении ссылку подписки.\n"
                    "Нужна ссылка вида <code>https://…/sub/…</code> — скопируй её целиком и отправь одним сообщением.\n\n"
                    "Команды: /start — помощь, /status — статус, /proxy — прокси в Telegram, "
                    "/renew — продлить, /link — ссылка, /apps — приложения."),
    "sub_none": "Подписка ещё не привязана. Как привязать — покажет /start.",
    "sub_unbound": "🔓 Telegram отвязан от подписки. Привязать заново — /start.",
    "sub_menu_q": "🤖 Меню подписчика:",
    "m_sub_status": "📊 Моя подписка", "m_sub_link": "🔑 Ссылка",
    "m_sub_apps": "📱 Приложения", "m_sub_unbind": "🔗 Отвязать",
    "m_sub_tg": "➕ Прокси в Telegram", "m_sub_renew": "💳 Продлить",
    "sub_tg_hdr": "➕ <b>%s</b> — одно нажатие, и Telegram сам добавит прокси:",
    "sub_tg_mp": "🔌 MTProto-прокси", "sub_tg_web": "🌐 Веб-прокси",
    "sub_tg_none": "Персональный Telegram-прокси для тебя пока не настроен — попроси администратора включить его в разделе «Telegram-прокси».",
    "sub_renew_hdr": "💳 <b>%s</b> · срок: %s — выбери тариф, откроется страница оплаты:",
    "sub_renew_sent": "✅ Запрос на продление отправлен администратору. Он продлит подписку и пришлёт сюда реквизиты, если нужна оплата.",
    "sub_renew_wait": "⏳ Запрос уже отправлен несколько минут назад — администратор уведомлён. Попробуй позже.",
    "sub_renew_none": "Сначала привяжи подписку (/start) — потом попрошу для неё продление.",
    "sub_renew_admin": ("🔔 <b>Подписчик просит продлить</b>\nКлиент: <b>%s</b>\nЕго Telegram chat id: <code>%s</code>\n%s\nОтветь ему в этом чате или продли срок во вкладке «Клиенты»."),
    "m_sub_page": "📱 Страница подписки", "noexp": "бессрочно",
    "addr_admin": ("🔔 <b>Адрес сервера в подписках изменён</b>: <code>%s</code> → <code>%s</code>\n"
                   "Подписчикам с Telegram отправлено уведомлений: %d. Ссылки /sub пересобираются сами."),
    "addr_moved": ("🔄 <b>Адрес сервера изменился</b> — теперь <code>%s</code>.\n"
                   "Если прокси перестал подключаться: нажми «🔑 Ссылка» и добавь ещё раз, "
                   "либо обнови подписку в приложении (если добавлял по ссылке — она обновляется сам)."),
    "sub_hdr": "📊 <b>Мои подписки:</b>",
    "sub_link_msg": ("🔑 Скопируй и вставь в приложение (Happ, v2rayNG, Streisand, NekoBox…) — "
                     "все серверы импортируются сразу:\n<code>%s</code>"),
    "sub_apps_msg": "📱 Твоя личная страница с приложениями и кнопками подключения:\n%s",
    "sub_a80": "⚠️ Подписка «%s»: использовано 80%% трафика (%s из %s ГБ).",
    "sub_aexp": "⏳ Подписка «%s» истекает через %d дн. Продлить можно на личной странице.",
    "onboard_msg": ("🎉 <b>Твой VPN готов — прямо из коробки!</b>\n\n"
                    "Я завёл тебе личную подписку «Я»: без лимита трафика и срока. "
                    "Она сама обновляется, если я добавлю новые протоколы или серверы.\n\n"
                    "🔑 Ссылка подписки — вставь её один раз в приложение "
                    "(Happ, Streisand, v2rayNG, NekoBox…):\n<code>%s</code>\n\n"
                    "📱 Личная страница с приложениями и кнопкой «Подключить»:\n%s\n\n"
                    "Кнопка «👥 Клиенты» покажет тебя в списке. Когда захочешь добавить близких — "
                    "жми «➕ Добавить подписку», а им напоминать ничего не надо: "
                    "дай им ссылку со страницы и всё."),
}
_BOT_TXT = {
"en": {
    "m_status": "📊 Status", "m_clients": "👥 Clients",
    "m_addsub": "➕ Add subscription", "m_restart": "🔄 Restart Xray",
    "m_2fa": "🔐 2FA", "m_help": "❓ Help", "m_lang": "🌐 Language",
    "start": "🤖 <b>Veil Panel Bot</b>\nYour Chat ID: <code>%s</code>\n\nChoose an action:",
    "norights": "⛔ Access denied. Your ID: %s. Admin IDs: %s",
    "norights_short": "⛔ Access denied",
    "nocallback": "Error: no message",
    "add_step1": "➕ <b>New subscription</b>\nStep 1 of 3. Send the client <b>name</b> (e.g. <b>Mom</b>).\nCancel: /cancel",
    "add_nameempty": "Name can't be empty. Send the name again or /cancel",
    "add_limitq": "👤 Name: <b>%s</b>\nNow the traffic <b>limit</b> in GB (number, <code>0</code> = unlimited, fractions OK: 12.5):\nCancel: /cancel",
    "add_num": "A number is required. Repeat the limit (0 = unlimited) or /cancel",
    "add_daysq": "Limit: <b>%s</b> GB\nNow the <b>validity</b> in days (number, <code>0</code> = forever):\nCancel: /cancel",
    "add_intnum": "A whole number of days is required. Repeat (0 = forever) or /cancel",
    "add_err": "❌ Creation failed: %s",
    "created": "✅ <b>Subscription created</b>\nName: <code>%s</code>\nLimit: %s · Valid: %s\nSubscription: <code>%s</code>\nCopy the link into your app (v2rayNG / Hiddify / Streisand / NekoBox / Happ / Shadowrocket).",
    "unlim": "unlimited", "gb": "%s GB", "daysu": "%s d", "forever": "forever",
    "clients_hdr": "👥 <b>Clients:</b>", "clients_empty": "No clients",
    "restarted": "🔄 Xray restarted", "cancelled": "Cancelled.",
    "help": "<b>Commands:</b>\n/start — menu\n/status — status and stats\n/clients — client list\n/restart — restart Xray\n/addsub — create a subscription (name → limit → days)\n/2fa — 2FA setup\n/pay — payments summary and invoices\n/paycheck — poll payment statuses\n/backup — auto-backups: list and restore\n/lang — язык / language",
    "m_pay": "💳 Payments",
    "pay_off": "💳 Payments are <b>off</b>. Turn them on in the panel: “💳 Payments” tab.",
    "pay_hdr": "💳 Payments: <b>on</b>\nProvider: %s\nPlans: %d · unpaid invoices: %d · collected: %s %s",
    "pay_none": "No invoices yet.",
    "pay_recent": "<b>Recent invoices:</b>",
    "pay_line": "%s — %s · %s %s · %s",
    "pay_wait": "⏳ pending",
    "pay_paidst": "✅ paid",
    "pay_none_open": "No unpaid invoices to check.",
    "pay_checked": "Invoices checked: %d · payments confirmed: %d",
    "m_backup": "🗄 Backup",
    "bk_hdr": "🗄 <b>Auto-backups</b>: %d (newest on top)",
    "bk_none": "No auto-backups yet. Create one with the button or enable the schedule in the panel: '💾 Backups'.",
    "bk_new_btn": "🆕 Create",
    "bk_send_btn": "📤 Send newest",
    "bk_file_btn": "%s UTC · %d KB",
    "bk_created": "✅ Backup created: %s (%d KB)",
    "bk_sent": "📤 Sending the backup file...",
    "bk_noent": "File %s not found.",
    "bk_ask": "⚠️ Restore the panel from backup <b>%s</b>?\nCreated: %s UTC · clients inside: %s\nCurrent data will be overwritten (a safety copy of the server is made automatically).",
    "bk_yes": "✅ Yes, restore",
    "bk_no": "❌ Cancel",
    "bk_done": "✅ Restored from %s · clients: %s. Xray restarted.",
    "bk_cancel": "Cancelled.",
    "bk_err": "⚠️ Backup error: %s",
    "status_hdr": "📊 <b>Status and stats</b>\nXray: %s\nUptime: %s\nClients: %s\nNodes: %s\n%s\nCPU: %s · RAM: %s\nDisk: %s",
    "xray_on": "🟢 running", "xray_off": "🔴 stopped",
    "gp_ok": "🇷🇺 Access from Russia: %s %s/%s (%s%%) · %s UTC",
    "gp_none": "🇷🇺 Access from Russia: — (no checks yet, open the panel)",
    "twofa": "🔐 <b>2FA setup</b>\nConfigure 2FA in the panel: tab <b>Security</b> → <b>Two-factor authentication</b>",
    "unknown": "Unknown command. /help",
    "err": "⚠️ Error: %s",
    "lang_q": "🌐 Выберите язык / Choose language / زبان را انتخاب کنید / 请选择语言：",
    "lang_saved": "Done: %s",
    "gp_low": "🚨 <b>Access from Russia dropped below 50%%!</b>\nProbes: %s/%s (%s%%)\nTime: %s UTC\nCheck the panel or press %s",
    "gp_recover": "✅ Access from Russia recovered: %s/%s (%s%%) · %s UTC",
    "sub_welcome": ("👋 <b>Hi! I am the Veil subscriber assistant.</b>\n\n"
                    "Send here your <b>subscription link</b> — it starts with <code>https://…/sub/…</code> "
                    "(it was in the message you received with the subscription). After binding I will:\n"
                    "• show status, expiry and traffic (button «📊 My subscription»);\n"
                    "• send your link and app hints;\n"
                    "• add the proxy to Telegram in one tap (button «➕ Proxy to Telegram»);\n"
                    "• help you renew the subscription (button «💳 Renew»);\n"
                    "• remind you when the subscription is about to expire.\n\n"
                    "No public access: a link shows me only YOUR subscription. "
                    "Unbind Telegram any time with «🔗 Unbind»."),
    "sub_bound": "✅ Done! Telegram is now bound to subscription «<b>%s</b>». Choose an action:",
    "sub_badlink": ("🤔 I didn't find a subscription link in your message.\n"
                    "I need a link like <code>https://…/sub/…</code> — copy it fully and send as one message.\n\n"
                    "Commands: /start — help, /status — status, /link — link, /apps — apps."),
    "sub_none": "Subscription is not bound yet. /start explains how.",
    "sub_unbound": "🔓 Telegram unbound from the subscription. To bind again — /start.",
    "sub_menu_q": "🤖 Subscriber menu:",
    "m_sub_status": "📊 My subscription", "m_sub_link": "🔑 Link",
    "m_sub_apps": "📱 Apps", "m_sub_unbind": "🔗 Unbind",
    "m_sub_tg": "➕ Proxy to Telegram", "m_sub_renew": "💳 Renew",
    "sub_tg_hdr": "➕ <b>%s</b> — one tap and Telegram adds the proxy itself:",
    "sub_tg_mp": "🔌 MTProto proxy", "sub_tg_web": "🌐 Web proxy",
    "sub_tg_none": "No personal Telegram proxy for you yet — ask the admin to enable it in the “Telegram proxy” section.",
    "sub_renew_hdr": "💳 <b>%s</b> · expires: %s — pick a plan, a payment page opens:",
    "sub_renew_sent": "✅ Renewal request sent to the admin. They will extend the subscription and reply with payment details if needed.",
    "sub_renew_wait": "⏳ Request already sent a few minutes ago — the admin is notified. Try later.",
    "sub_renew_none": "Bind your subscription first (/start) — then I can ask for a renewal.",
    "sub_renew_admin": ("🔔 <b>Subscriber asks for renewal</b>\nClient: <b>%s</b>\nTheir Telegram chat id: <code>%s</code>\n%s\nReply in this chat or extend the expiry in the “Clients” tab."),
    "m_sub_page": "📱 Subscription page", "noexp": "never",
    "addr_admin": ("🔔 <b>Server address in subscriptions changed</b>: <code>%s</code> → <code>%s</code>\n"
                   "Subscribers with Telegram notified: %d. /sub links rebuild themselves."),
    "addr_moved": ("🔄 <b>The server address has changed</b> — now <code>%s</code>.\n"
                   "If the proxy stopped connecting: press «🔑 Link» and add it again, "
                   "or refresh the subscription in your app (if it was added by link, it updates itself)."),
    "sub_hdr": "📊 <b>My subscriptions:</b>",
    "sub_link_msg": ("🔑 Copy and paste into your app (Happ, v2rayNG, Streisand, NekoBox…) — "
                     "all servers are imported at once:\n<code>%s</code>"),
    "sub_apps_msg": "📱 Your personal page with apps and connection buttons:\n%s",
    "sub_a80": "⚠️ Subscription «%s»: 80%% of traffic used (%s of %s GB).",
    "sub_aexp": "⏳ Subscription «%s» expires in %d day(s). Renew on your personal page.",
    "onboard_msg": ("🎉 <b>Your VPN is ready — right out of the box!</b>\n\n"
                    "I created a personal subscription «Я» for you: no traffic or time limits. "
                    "It updates itself when new protocols or servers are added.\n\n"
                    "🔑 Subscription link — paste it once into your app "
                    "(Happ, Streisand, v2rayNG, NekoBox…):\n<code>%s</code>\n\n"
                    "📱 Personal page with apps and a «Connect» button:\n%s\n\n"
                    "The «👥 Clients» button shows you in the list. To add family later press "
                    "«➕ Add subscription» — just hand them the link from the page."),
},
"fa": {
    "m_status": "📊 وضعیت", "m_clients": "👥 کاربران",
    "m_addsub": "➕ افزودن اشتراک", "m_restart": "🔄 ریستارت Xray",
    "m_2fa": "🔐 2FA", "m_help": "❓ راهنما", "m_lang": "🌐 زبان",
    "start": "🤖 <b>ربات Veil Panel</b>\nشناسه گفتگوی شما: <code>%s</code>\n\nیک عملیات انتخاب کنید:",
    "norights": "⛔ دسترسی ندارید. شناسه شما: %s. شناسه مدیر: %s",
    "norights_short": "⛔ دسترسی ندارید",
    "nocallback": "خطا: پیامی وجود ندارد",
    "add_step1": "➕ <b>اشتراک جدید</b>\nمرحله ۱ از ۳. <b>نام</b> کاربر را بفرستید (مثلاً <b>مامان</b>).\nلغو: /cancel",
    "add_nameempty": "نام نمی‌تواند خالی باشد. دوباره نام بفرستید یا /cancel",
    "add_limitq": "👤 نام: <b>%s</b>\nحالا <b>محدوده</b> ترافیک به گیگ (عدد، <code>0</code> = نامحدود، اعشاری هم می‌شود: 12.5):\nلغو: /cancel",
    "add_num": "عدد لازم است. محدوده را دوباره بفرستید (0 = نامحدود) یا /cancel",
    "add_daysq": "محدوده: <b>%s</b> گیگ\nحالا <b>مدت اعتبار</b> به روز (عدد، <code>0</code> = بدون انقضا):\nلغو: /cancel",
    "add_intnum": "عدد کامل روز لازم است. دوباره بفرستید (0 = بدون انقضا) یا /cancel",
    "add_err": "❌ ساخت اشتراک ناموفق: %s",
    "created": "✅ <b>اشتراک ساخته شد</b>\nنام: <code>%s</code>\nمحدوده: %s · اعتبار: %s\nلینک اشتراک: <code>%s</code>\nلینک را در اپ کپی کنید (v2rayNG / Hiddify / Streisand / NekoBox / Happ / Shadowrocket).",
    "unlim": "نامحدود", "gb": "%s گیگ", "daysu": "%s روز", "forever": "بدون انقضا",
    "clients_hdr": "👥 <b>کاربران:</b>", "clients_empty": "کاربری نیست",
    "restarted": "🔄 Xray ریستارت شد", "cancelled": "لغو شد.",
    "help": "<b>دستورات:</b>\n/start — منو\n/status — وضعیت\n/clients — کاربران\n/restart — ریستارت Xray\n/addsub — اشتراک جدید (نام → محدودیت → مدت)\n/2fa — تنظیم 2FA\n/pay — خلاصه پرداخت‌ها و فاکتورها\n/paycheck — بررسی وضعیت پرداخت‌ها\n/backup — پشتیبان‌های خودکار: فهرست و بازگردانی\n/lang — язык / language",
    "m_pay": "💳 پرداخت",
    "pay_off": "💳 دریافت پرداخت <b>خاموش</b> است. از تب «💳 پرداخت» در پنل روشن کنید.",
    "pay_hdr": "💳 دریافت پرداخت: <b>روشن</b>\nروش: %s\nپلن‌ها: %d · فاکتور پرداخت‌نشده: %d · جمع‌شده: %s %s",
    "pay_none": "هنوز فاکتوری ثبت نشده.",
    "pay_recent": "<b>آخرین فاکتورها:</b>",
    "pay_line": "%s — %s · %s %s · %s",
    "pay_wait": "⏳ در انتظار",
    "pay_paidst": "✅ پرداخت شد",
    "pay_none_open": "فاکتور پرداخت‌نشده‌ای برای بررسی وجود ندارد.",
    "pay_checked": "بررسی شد: %d · پرداخت تأییدشده: %d",
    "m_backup": "🗄 پشتیبان",
    "bk_hdr": "🗄 <b>پشتیبان‌های خودکار</b>: %d (جدیدترین در بالا)",
    "bk_none": "هنوز پشتیبان خودکاری نیست. با دکمه بسازید یا زمان‌بندی را در پنل فعال کنید: «💾 پشتیبان‌ها».",
    "bk_new_btn": "🆕 ساخت",
    "bk_send_btn": "📤 ارسال جدیدترین",
    "bk_file_btn": "%s UTC · %d کیلوبایت",
    "bk_created": "✅ پشتیبان ساخته شد: %s (%d کیلوبایت)",
    "bk_sent": "📤 در حال ارسال فایل پشتیبان...",
    "bk_noent": "فایل %s پیدا نشد.",
    "bk_ask": "⚠️ پنل از پشتیبان <b>%s</b> بازگردانی شود؟\nساخته: %s UTC · مشتری‌های داخل آن: %s\nداده‌های فعلی بازنویسی می‌شوند (نسخه امن خودکار ساخته می‌شود).",
    "bk_yes": "✅ بله، بازگردانی",
    "bk_no": "❌ انصراف",
    "bk_done": "✅ از %s بازگردانی شد · مشتری‌ها: %s. Xray ریستارت شد.",
    "bk_cancel": "لغو شد.",
    "bk_err": "⚠️ خطای پشتیبان: %s",
    "status_hdr": "📊 <b>وضعیت و آمار</b>\nXray: %s\nآپتایم: %s\nکاربران: %s\nنودها: %s\n%s\nCPU: %s · RAM: %s\nدیسک: %s",
    "xray_on": "🟢 فعال", "xray_off": "🔴 متوقف",
    "gp_ok": "🇷🇺 دسترس‌پذیری از روسیه: %s %s/%s (%s%%) · %s UTC",
    "gp_none": "🇷🇺 دسترس‌پذیری از روسیه: — (بررسی انجام نشده، پنل را باز کنید)",
    "twofa": "🔐 <b>تنظیم 2FA</b>\nدر پنل تنظیم کنید: تب <b>امنیت</b> → <b>احراز دو مرحله‌ای</b>",
    "unknown": "دستور نامعلوم. /help",
    "err": "⚠️ خطا: %s",
    "lang_q": "🌐 Выберите язык / Choose language / زبان را انتخاب کنید / 请选择语言：",
    "lang_saved": "انجام شد: %s",
    "gp_low": "🚨 <b>دسترس‌پذیری از روسیه زیر ۵۰٪ افتاد!</b>\nکاوش‌ها: %s/%s (%s%%)\nزمان: %s UTC\nدر پنل بررسی کنید یا %s را بزنید",
    "gp_recover": "✅ دسترس‌پذیری از روسیه برگشت: %s/%s (%s%%) · %s UTC",
    "sub_welcome": ("👋 <b>سلام! من دستیار مشترکان Veil هستم.</b>\n\n"
                    "<b>لینک اشتراک</b> خود را اینجا بفرستید — با <code>https://…/sub/…</code> شروع می‌شود "
                    "(در پیامی که اشتراک را تحویل گرفتید بود). پس از پیوند من:\n"
                    "• وضعیت، مهلت و ترافیک را نشان می‌دهم (دکمه «📊 اشتراک من»);\n"
                    "• لینک و راهنمای برنامه‌ها را می‌فرستم;\n"
                    "• وقتی اشتراک نزدیک انقضا باشد یادآوری می‌کنم.\n\n"
                    "دسترسی عمومی وجود ندارد: با لینک فقط اشتراک <b>شما</b> را می‌بینم. "
                    "با دکمه «🔗 قطع پیوند» می‌توانید جدا کنید."),
    "sub_bound": "✅ انجام شد! Telegram به اشتراک «<b>%s</b>» متصل شد. یک عملیات انتخاب کنید:",
    "sub_badlink": ("🤔 در پیام شما لینک اشتراک پیدا نشد.\n"
                    "لینکی به شکل <code>https://…/sub/…</code> لازم است — کامل کپی کنید و در یک پیام بفرستید.\n\n"
                    "دستورات: /start — راهنما، /status — وضعیت، /link — لینک، /apps — برنامه‌ها."),
    "sub_none": "اشتراک هنوز متصل نشده. نحوه اتصال را /start نشان می‌دهد.",
    "sub_unbound": "🔓 Telegram از اشتراک جدا شد. برای اتصال مجدد — /start.",
    "sub_menu_q": "🤖 منوی مشترک:",
    "m_sub_status": "📊 اشتراک من", "m_sub_link": "🔑 لینک",
    "m_sub_apps": "📱 برنامه‌ها", "m_sub_unbind": "🔗 جدا کردن",
    "m_sub_tg": "➕ پروکسی در تلگرام", "m_sub_renew": "💳 تمدید",
    "sub_tg_hdr": "➕ <b>%s</b> — با یک لمس، تلگرام خودش پروکسی را اضافه می‌کند:",
    "sub_tg_mp": "🔌 پروکسی MTProto", "sub_tg_web": "🌐 پروکسی وب",
    "sub_tg_none": "هنوز پروکسی شخصی تلگرام برای شما تنظیم نشده — از مدیر بخواهید آن را در بخش «پروکسی تلگرام» فعال کند.",
    "sub_renew_hdr": "💳 <b>%s</b> · انقضا: %s — یک پلن انتخاب کنید، صفحه پرداخت باز می‌شود:",
    "sub_renew_sent": "✅ درخواست تمدید برای مدیر ارسال شد. او اشتراک را تمدید می‌کند و در صورت نیاز جزئیات پرداخت را می‌فرستد.",
    "sub_renew_wait": "⏳ درخواست چند دقیقه پیش ارسال شده — مدیر مطلع است. بعداً تلاش کنید.",
    "sub_renew_none": "اول اشتراک خود را متصل کنید (/start) — سپس درخواست تمدید ممکن است.",
    "sub_renew_admin": ("🔔 <b>درخواست تمدید مشترک</b>\nمشترک: <b>%s</b>\nشناسه چت تلگرام او: <code>%s</code>\n%s\nدر همین چت پاسخ دهید یا تاریخ انقضا را از تب «مشترکان» تمدید کنید."),
    "m_sub_page": "📱 صفحه اشتراک", "noexp": "بدون پایان",
    "addr_admin": ("🔔 <b>نشانی سرور در اشتراک‌ها تغییر کرد</b>: <code>%s</code> → <code>%s</code>\n"
                   "به %d مشترک تلگرام‌دار اطلاع داده شد. لینک‌های /sub خودکار بازسازی می‌شوند."),
    "addr_moved": ("🔄 <b>نشانی سرور تغییر کرد</b> — اکنون <code>%s</code>.\n"
                   "اگر پروکسی دیگر وصل نمی‌شود: «🔑 لینک» را بزنید و دوباره اضافه کنید، "
                   "یا اشتراک را در برنامه به‌روزرسانی کنید (اگر با لینک اضافه شده، خودکار نو می‌شود)."),
    "sub_hdr": "📊 <b>اشتراک‌های من:</b>",
    "sub_link_msg": ("🔑 کپی کنید و در برنامه (Happ, v2rayNG, Streisand, NekoBox…) بچسبانید — "
                     "همه سرورها یکجا وارد می‌شوند:\n<code>%s</code>"),
    "sub_apps_msg": "📱 صفحه شخصی شما با برنامه‌ها و دکمه‌های اتصال:\n%s",
    "sub_a80": "⚠️ اشتراک «%s»: ۸۰٪ ترافیک مصرف شد (%s از %s گیگابایت).",
    "sub_aexp": "⏳ اشتراک «%s» تا %d روز دیگر منقضی می‌شود. تمدید در صفحه شخصی.",
    "onboard_msg": ("🎉 <b>VPN شما آماده — بدون تنظیمات!</b>\n\n"
                    "اشتراک شخصی «Я» برایتان ساخته شد: بدون محدودیت ترافیک و زمان. "
                    "با افزودن پروتکل‌ها یا سرورهای تازه خودش به‌روز می‌شود.\n\n"
                    "🔑 لینک اشتراک — یک‌بار در برنامه (Happ, Streisand, v2rayNG, NekoBox…) بچسبانید:\n<code>%s</code>\n\n"
                    "📱 صفحه شخصی با برنامه‌ها و دکمه «اتصال»:\n%s\n\n"
                    "دکمه «👥 کاربران» شما را در فهرست نشان می‌دهد. برای افزودن نزدیکان «➕ افزودن اشتراک» را بزنید — "
                    "کافی است لینک صفحه را به آن‌ها بدهید."),
},
"zh": {
    "m_status": "📊 状态", "m_clients": "👥 客户",
    "m_addsub": "➕ 添加订阅", "m_restart": "🔄 重启 Xray",
    "m_2fa": "🔐 两步验证", "m_help": "❓ 帮助", "m_lang": "🌐 语言",
    "start": "🤖 <b>Veil 面板机器人</b>\n您的 Chat ID：<code>%s</code>\n\n请选择操作：",
    "norights": "⛔ 无权限。您的 ID：%s。管理员 ID：%s",
    "norights_short": "⛔ 无权限",
    "nocallback": "错误：没有消息",
    "add_step1": "➕ <b>新建订阅</b>\n第 1/3 步：发送客户<b>名字</b>（例如<b>妈妈</b>）。\n取消：/cancel",
    "add_nameempty": "名字不能为空。请重发或 /cancel",
    "add_limitq": "👤 名字：<b>%s</b>\n现在输入流量<b>限额</b>（GB，数字，<code>0</code> = 无限制，可小数 12.5）：\n取消：/cancel",
    "add_num": "需要数字。请重发限额（0 = 无限制）或 /cancel",
    "add_daysq": "限额：<b>%s</b> GB\n现在输入<b>有效期</b>（天数，<code>0</code> = 永久）：\n取消：/cancel",
    "add_intnum": "需要整数天数。请重发（0 = 永久）或 /cancel",
    "add_err": "❌ 创建失败：%s",
    "created": "✅ <b>订阅已创建</b>\n名字：<code>%s</code>\n限额：%s · 有效期：%s\n订阅链接：<code>%s</code>\n把链接复制到应用（v2rayNG / Hiddify / Streisand / NekoBox / Happ / Shadowrocket）。",
    "unlim": "无限制", "gb": "%s GB", "daysu": "%s 天", "forever": "永久",
    "clients_hdr": "👥 <b>客户：</b>", "clients_empty": "暂无客户",
    "restarted": "🔄 Xray 已重启", "cancelled": "已取消。",
    "help": "<b>命令：</b>\n/start — 菜单\n/status — 状态统计\n/clients — 客户列表\n/restart — 重启 Xray\n/addsub — 新建订阅（名字 → 限额 → 天数）\n/2fa — 两步验证\n/pay — 收款概览与账单\n/paycheck — 查询支付状态\n/backup — 自动备份：列表与恢复\n/lang — язык / language",
    "m_pay": "💳 支付",
    "pay_off": "💳 收款功能<b>未开启</b>。请在面板「💳 支付」标签页中开启。",
    "pay_hdr": "💳 收款：<b>已开启</b>\n方式：%s\n套餐：%d · 待支付账单：%d · 已收款：%s %s",
    "pay_none": "还没有账单。",
    "pay_recent": "<b>最近账单：</b>",
    "pay_line": "%s — %s · %s %s · %s",
    "pay_wait": "⏳ 等待中",
    "pay_paidst": "✅ 已支付",
    "pay_none_open": "没有待支付账单可查询。",
    "pay_checked": "已检查账单：%d · 新确认支付：%d",
    "m_backup": "🗄 备份",
    "bk_hdr": "🗄 <b>自动备份</b>：%d 个（最新在上）",
    "bk_none": "还没有自动备份。点按钮新建一个，或在面板「💾 备份」里开启计划。",
    "bk_new_btn": "🆕 新建",
    "bk_send_btn": "📤 发送最新的",
    "bk_file_btn": "%s UTC · %d KB",
    "bk_created": "✅ 备份已创建：%s（%d KB）",
    "bk_sent": "📤 正在发送备份文件……",
    "bk_noent": "找不到文件 %s。",
    "bk_ask": "⚠️ 从备份 <b>%s</b> 恢复面板？\n创建时间：%s UTC · 内含客户：%s\n当前数据将被覆盖（服务器会自动先做一份保险副本）。",
    "bk_yes": "✅ 确认恢复",
    "bk_no": "❌ 取消",
    "bk_done": "✅ 已从 %s 恢复 · 客户数：%s。Xray 已重启。",
    "bk_cancel": "已取消。",
    "bk_err": "⚠️ 备份出错：%s",
    "status_hdr": "📊 <b>状态与统计</b>\nXray：%s\n运行时长：%s\n客户数：%s\n节点数：%s\n%s\nCPU：%s · 内存：%s\n磁盘：%s",
    "xray_on": "🟢 运行中", "xray_off": "🔴 已停止",
    "gp_ok": "🇷🇺 俄罗斯可达性：%s %s/%s (%s%%) · %s UTC",
    "gp_none": "🇷🇺 俄罗斯可达性：—（尚未检测，请打开面板）",
    "twofa": "🔐 <b>两步验证</b>\n请在面板设置：「安全」→「两步验证」",
    "unknown": "未知命令。/help",
    "err": "⚠️ 错误：%s",
    "lang_q": "🌐 Выберите язык / Choose language / زبان را انتخاب کنید / 请选择语言：",
    "lang_saved": "完成：%s",
    "gp_low": "🚨 <b>俄罗斯可达性低于 50%%！</b>\n探测：%s/%s (%s%%)\n时间：%s UTC\n请在面板检查或按 %s",
    "gp_recover": "✅ 俄罗斯可达性已恢复：%s/%s (%s%%) · %s UTC",
    "sub_welcome": ("👋 <b>你好！我是 Veil 订阅用户助手。</b>\n\n"
                    "请把<b>订阅链接</b>发到这里 — 它以 <code>https://…/sub/…</code> 开头"
                    "（在发放订阅的消息里）。绑定后我会：\n"
                    "• 显示状态、期限和流量（按钮「📊 我的订阅」）；\n"
                    "• 发送链接和应用推荐；\n"
                    "• 在订阅即将到期时提醒你。\n\n"
                    "没有公开访问：通过链接我只能看到<b>你的</b>订阅。"
                    "随时可用按钮「🔗 解绑」解除绑定。"),
    "sub_bound": "✅ 完成！Telegram 已绑定订阅「<b>%s</b>」。请选择操作：",
    "sub_badlink": ("🤔 没有在消息中找到订阅链接。\n"
                    "需要 <code>https://…/sub/…</code> 形式的链接 — 请完整复制并单独发送。\n\n"
                    "命令：/start — 帮助，/status — 状态，/link — 链接，/apps — 应用。"),
    "sub_none": "尚未绑定订阅。绑定方法见 /start。",
    "sub_unbound": "🔓 已解除 Telegram 绑定。重新绑定请发 /start。",
    "sub_menu_q": "🤖 订阅用户菜单：",
    "m_sub_status": "📊 我的订阅", "m_sub_link": "🔑 链接",
    "m_sub_apps": "📱 应用", "m_sub_unbind": "🔗 解绑",
    "m_sub_tg": "➕ 添加代理到 Telegram", "m_sub_renew": "💳 续费",
    "sub_tg_hdr": "➕ <b>%s</b> — 一键点按，Telegram 会自动添加代理：",
    "sub_tg_mp": "🔌 MTProto 代理", "sub_tg_web": "🌐 Web 代理",
    "sub_tg_none": "尚未为你配置个人 Telegram 代理——请管理员在「Telegram 代理」中启用。",
    "sub_renew_hdr": "💳 <b>%s</b> · 到期：%s — 选择套餐，将打开付款页面：",
    "sub_renew_sent": "✅ 续费请求已发送给管理员。管理员会延长订阅，如需付款会把详情发到这里。",
    "sub_renew_wait": "⏳ 请求几分钟前已发送——管理员已收到。请稍后再试。",
    "sub_renew_none": "请先绑定订阅（/start）——然后才能请求续费。",
    "sub_renew_admin": ("🔔 <b>订阅者请求续费</b>\n客户：<b>%s</b>\n其 Telegram chat id：<code>%s</code>\n%s\n请在此聊天回复，或在「客户」标签页延长有效期。"),
    "m_sub_page": "📱 订阅页面", "noexp": "无限期",
    "addr_admin": ("🔔 <b>订阅中的服务器地址已变更</b>：<code>%s</code> → <code>%s</code>\n"
                   "已通知 %d 位绑定 Telegram 的订阅者。/sub 链接会自动重建。"),
    "addr_moved": ("🔄 <b>服务器地址已变更</b> — 现为 <code>%s</code>。\n"
                   "如果代理无法连接：点击「🔑 链接」重新添加，"
                   "或在应用中刷新订阅（若是通过链接添加的，会自动更新）。"),
    "sub_hdr": "📊 <b>我的订阅：</b>",
    "sub_link_msg": ("🔑 复制并粘贴到应用（Happ、v2rayNG、Streisand、NekoBox…）——"
                     "所有服务器将一次性导入：\n<code>%s</code>"),
    "sub_apps_msg": "📱 你的个人页面（应用和连接按钮）：\n%s",
    "sub_a80": "⚠️ 订阅「%s」：已使用 80%% 流量（%s / %s GB）。",
    "sub_aexp": "⏳ 订阅「%s」将在 %d 天后到期。可在个人页面续费。",
    "onboard_msg": ("🎉 <b>你的 VPN 已就绪——开箱即用！</b>\n\n"
                    "已为你创建个人订阅「Я」：不限流量、不限时长。新增协议或服务器时它会自动更新。\n\n"
                    "🔑 订阅链接——在应用（Happ、Streisand、v2rayNG、NekoBox…）里粘贴一次即可：\n<code>%s</code>\n\n"
                    "📱 含应用和「连接」按钮的个人页面：\n%s\n\n"
                    "按钮「👥 用户」可在列表中看到你。想为家人添加时按「➕ 添加订阅」——把页面链接发给他们即可。"),
},
}

def _bot_B(chat_id, tg_code=None):
    lang = ""
    try:
        lang = str((_load(BOT_LANGS) or {}).get(str(chat_id)) or "")
    except Exception:
        pass
    if lang not in _SUB_LANGS:
        c = (tg_code or "").lower()
        lang = next((l for l in ("en", "fa", "zh", "ru") if c.startswith(l)), "ru")
    d = dict(_BOT_RU)
    d.update(_BOT_TXT.get(lang) or {})
    d["__lang"] = lang
    return d

def _bot_lang_set(chat_id, lang):
    if lang not in _SUB_LANGS:
        return
    try:
        d = _load(BOT_LANGS) or {}
        d[str(chat_id)] = lang
        _save(BOT_LANGS, d)
    except Exception:
        pass

def _main_menu_keyboard(B=None):
    B = B or _BOT_RU
    return {"inline_keyboard": [
        [{"text": B["m_status"], "callback_data": "cmd_status"},
         {"text": B["m_clients"], "callback_data": "cmd_clients"}],
        [{"text": B["m_addsub"], "callback_data": "cmd_addsub"},
         {"text": B["m_restart"], "callback_data": "cmd_restart"}],
        [{"text": B["m_2fa"], "callback_data": "cmd_2fa"},
         {"text": B["m_help"], "callback_data": "cmd_help"}],
        [{"text": B["m_pay"], "callback_data": "cmd_pay"},
         {"text": B["m_backup"], "callback_data": "cmd_backup"}],
        [{"text": B["m_lang"], "callback_data": "cmd_lang"}],
    ]}

def _bot_sub_keyboard(B):
    return {"inline_keyboard": [
        [{"text": B["m_sub_status"], "callback_data": "sub_status"},
         {"text": B["m_sub_tg"], "callback_data": "sub_tg"}],
        [{"text": B["m_sub_renew"], "callback_data": "sub_renew"},
         {"text": B["m_sub_apps"], "callback_data": "sub_apps"}],
        [{"text": B["m_sub_link"], "callback_data": "sub_link"}],
        [{"text": B["m_sub_unbind"], "callback_data": "sub_unbind"},
         {"text": B["m_lang"], "callback_data": "sub_lang"}],
    ]}

def _bot_sub_link_tok(text):
    """Достаёт токен подписки из ссылки вида https://…/sub/<tok> (или /p/<tok>)."""
    m = re.search(r"(?:/sub/|/p/)([A-Za-z0-9_-]{8,64})", text or "")
    return m.group(1) if m else ""

def _bot_bind(chat_id, tok):
    """Привязывает Telegram-чат к подписке по sub_token или uuid. Возвращает имя клиента или ''."""
    t = re.sub(r"[^A-Za-z0-9_-]", "", str(tok or ""))[:64]
    if not t:
        return ""
    st = _load(STATE) or {}
    name = ""
    changed = False
    for inb in (st.get("inbounds") or {}).values():
        for c in inb.get("clients", []):
            if c.get("sub_token") == t or c.get("uuid") == t:
                if str(c.get("tg_chat") or "") != str(chat_id):
                    c["tg_chat"] = str(chat_id)
                    changed = True
                name = c.get("name") or name
    if name and changed:
        _save(STATE, st)
        try:
            _audit("bot_bind", chat=str(chat_id), client=name)
        except Exception:
            pass
    return name

def _bot_unbind(chat_id):
    st = _load(STATE) or {}
    changed = n = 0
    for inb in (st.get("inbounds") or {}).values():
        for c in inb.get("clients", []):
            if str(c.get("tg_chat") or "") == str(chat_id):
                c.pop("tg_chat", None)
                changed = 1
                n += 1
    if changed:
        _save(STATE, st)
    return bool(changed)

def _bot_subs_of(chat_id):
    return [x for x in _subs_summary(_load(STATE) or {})
            if str(x.get("tg_chat") or "") == str(chat_id)]

def _bot_sub_urls(u):
    host = _hop_pub_host()
    host = host if "://" not in host else urllib.parse.urlparse(host).netloc
    base = _pb(host, CFG_CACHE.get("panel_port", 8444))
    return base + "/sub/" + u["sub_token"], base + "/p/" + u["sub_token"]

def _bot_sub_status_msg(u, B):
    lang = B.get("__lang", "ru")
    try:
        L = dict(_SUB_TXT_RU); L.update((_SUB_TXT or {}).get(lang) or {})
    except Exception:
        L = _SUB_TXT_RU
    status, key = _sub_status(u)
    name = _html.escape(str(u.get("name") or L["ttl"]))
    now = time.time()
    ex = int(u.get("expiry") or 0)
    if ex:
        exp_txt = time.strftime(L["datefmt"], time.localtime(ex))
        dl = int(ex - now)
        if dl < 0:
            exp_txt += " · " + L["exp_over"]
        elif dl < 86400:
            exp_txt += " · " + L["exp_lt1d"]
        else:
            exp_txt += " · " + _sub_days_left(L, lang, int(dl // 86400))
    else:
        exp_txt = L["noexp"]
    lim = float(u.get("limit_gb") or 0)
    used = float(u.get("used_gb") or 0)
    if lim > 0:
        trf_txt = f"{used:.2f} / {lim:.1f} GB"
    else:
        trf_txt = f"{used:.2f} GB · " + L["unlim"]
    return ("• <b>" + name + "</b> — " + L[key] + "\n"
            + "  ⏳ " + L["lb_exp"] + ": " + exp_txt + "\n"
            + "  📈 " + L["lb_trf"] + ": " + trf_txt)

_BOT_RENEW_TS = {}   # chat_id -> ts запроса продления при выключенных платежах

def _bot_sub_cb(chat_id, data, B):
    """Кнопки меню подписчика (callback_data с префиксом sub_)."""
    if data == "sub_lang":
        return _bot_send_message(chat_id, B["lang_q"], "HTML", _lang_keyboard())
    subs = _bot_subs_of(chat_id)
    if not subs:
        return _bot_send_message(chat_id, B["sub_none"], "HTML", _bot_sub_keyboard(B))
    if data == "sub_status":
        return _bot_send_message(chat_id, B["sub_hdr"] + "\n\n" +
                                 "\n\n".join(_bot_sub_status_msg(u, B) for u in subs),
                                 "HTML", _bot_sub_keyboard(B))
    if data == "sub_link":
        for u in subs[:5]:
            sub_url, _page = _bot_sub_urls(u)
            _bot_send_message(chat_id, B["sub_link_msg"] % sub_url, "HTML")
        return
    if data == "sub_apps":
        for u in subs[:5]:
            _bot_send_message(chat_id, B["sub_apps_msg"] % _bot_sub_urls(u)[1], "HTML")
        return
    if data == "sub_tg":
        sent = 0
        for u in subs[:5]:
            try:
                tgls = _tg_sub_links(u) or []
            except Exception:
                tgls = []
            mp = next((l for l in tgls if l.startswith("tg://proxy")), "")
            wb = next((l for l in tgls if l.startswith("tg://webproxy")), "")
            if not (mp or wb):
                continue
            rows = []
            if mp:
                rows.append([{"text": B["sub_tg_mp"], "url": mp}])
            if wb:
                rows.append([{"text": B["sub_tg_web"], "url": wb}])
            _bot_send_message(chat_id,
                              B["sub_tg_hdr"] % _html.escape(str(u.get("name") or "")),
                              "HTML", {"inline_keyboard": rows})
            sent += 1
        if not sent:
            _bot_send_message(chat_id, B["sub_tg_none"], "HTML", _bot_sub_keyboard(B))
        return
    if data == "sub_renew":
        if not subs:
            return _bot_send_message(chat_id, B["sub_renew_none"], "HTML",
                                     _bot_sub_keyboard(B))
        plans = []
        try:
            if _pay_cfg()["enabled"]:
                plans = _pay_pub_plans()[:8]
        except Exception:
            plans = []
        if plans:
            base = _pay_base()
            for u in subs[:3]:
                ex = int(u.get("expiry") or 0)
                try:
                    exp_txt = (time.strftime("%d.%m.%Y", time.localtime(ex))
                               if ex else B["noexp"])
                except Exception:
                    exp_txt = B["noexp"]
                rows = []
                cur = []
                for pl in plans:
                    lbl = str(pl.get("title") or "")
                    cost = ("%g %s" % (float(pl.get("price") or 0),
                                       pl.get("currency") or "RUB")).strip()
                    rows.append([{"text": (lbl + " · " + cost)[:64],
                                  "url": base + "/pay/buy/" + urllib.parse.quote(u["sub_token"])
                                         + "/" + urllib.parse.quote(str(pl["id"]))}])
                _bot_send_message(chat_id,
                                  B["sub_renew_hdr"] % (_html.escape(str(u.get("name") or "")),
                                                        exp_txt),
                                  "HTML", {"inline_keyboard": rows})
            return
        # платежи выключены → низкосервисный путь: запрос администраторам
        last = _BOT_RENEW_TS.get(str(chat_id), 0)
        if time.time() - last < 600:
            return _bot_send_message(chat_id, B["sub_renew_wait"], "HTML")
        ids = [str(x) for x in (CFG_CACHE.get("bot_chat_ids") or [])]
        if not ids:
            return _bot_send_message(chat_id, B["sub_renew_wait"], "HTML")
        _BOT_RENEW_TS[str(chat_id)] = time.time()
        if len(_BOT_RENEW_TS) > 500:
            for k in sorted(_BOT_RENEW_TS, key=_BOT_RENEW_TS.get)[:-400]:
                _BOT_RENEW_TS.pop(k, None)
        lines = []
        for u in subs[:5]:
            ex = int(u.get("expiry") or 0)
            exp_txt = (time.strftime("%d.%m.%Y", time.localtime(ex) if ex else time.localtime()))
            lines.append("• %s — %s" % (u.get("name") or "?",
                                        exp_txt if ex else B["noexp"]))
        msg = B["sub_renew_admin"] % (_html.escape(", ".join(
            str(u.get("name") or "?") for u in subs[:5])), str(chat_id),
            "\n".join(lines))
        kb = {"inline_keyboard": [[{"text": B["m_sub_page"],
                                    "url": _bot_sub_urls(subs[0])[1]}]]}
        for aid in ids[:8]:
            try:
                _bot_send_message(aid, msg, "HTML", kb)
            except Exception:
                pass
        return _bot_send_message(chat_id, B["sub_renew_sent"], "HTML")
    if data == "sub_unbind":
        _bot_unbind(chat_id)
        return _bot_send_message(chat_id, B["sub_unbound"], "HTML", _bot_sub_keyboard(B))

def _bot_sub_msg(chat_id, text, B):
    """Сообщения подписчика (не-администратора): привязка по ссылке и команды."""
    t = (text or "").strip()
    low = t.lower()
    if not t.startswith("/"):
        tok = _bot_sub_link_tok(t)
        name = _bot_bind(chat_id, tok) if tok else ""
        if not name:
            return _bot_send_message(chat_id, B["sub_badlink"], "HTML", _bot_sub_keyboard(B))
        return _bot_send_message(chat_id, B["sub_bound"] % _html.escape(name), "HTML",
                                 _bot_sub_keyboard(B))
    if low == "/lang":
        return _bot_send_message(chat_id, B["lang_q"], "HTML", _lang_keyboard())
    cmds = {"/status": "sub_status", "/link": "sub_link", "/apps": "sub_apps",
            "/proxy": "sub_tg", "/renew": "sub_renew",
            "/unsubscribe": "sub_unbind"}
    if low in cmds:
        return _bot_sub_cb(chat_id, cmds[low], B)
    if low == "/menu" and _bot_subs_of(chat_id):
        return _bot_send_message(chat_id, B["sub_menu_q"], "HTML", _bot_sub_keyboard(B))
    if low in ("/start", "/help"):
        return _bot_send_message(chat_id, B["sub_welcome"], "HTML", _bot_sub_keyboard(B))
    return _bot_send_message(chat_id, B["sub_none"], "HTML", _bot_sub_keyboard(B))

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
        B = _bot_B(ids[0])
        if pct <= 50.0 and not _GP_LOW_ALERT_ACTIVE:
            _GP_LOW_ALERT_ACTIVE = True
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%d.%m %H:%M")
            _bot_send_message(ids[0],
                B["gp_low"] % (ok, total, f"{pct:.0f}", ts, B["m_status"]),
                "HTML")
        elif pct > 50.0 and _GP_LOW_ALERT_ACTIVE:
            _GP_LOW_ALERT_ACTIVE = False
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%d.%m %H:%M")
            _bot_send_message(ids[0],
                B["gp_recover"] % (ok, total, f"{pct:.0f}", ts),
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

# ================= PAYMENTS =================
# Подключаемые платежи: тарифы → счета → провайдер (manual/generic/cryptobot/yookassa)
# → автопродление подписки + уведомление админу в Telegram.
PAYMENTS_F = f"{BASE}/payments.json"
PAY_LOCK = threading.Lock()
_PAY_PROVIDERS = ("manual", "generic", "cryptobot", "yookassa")
_PAY_LABELS = {"manual": "Вручную", "generic": "Своя касса (HMAC API)",
               "cryptobot": "CryptoBot (крипта)", "yookassa": "ЮKassa (карты)"}

# --- дополняем словари /p-страниц и бота ключами платежей ---
_SUB_TXT_RU.update({
    "pay_hd": "Оплата и продление", "pay_days": "%d дн.", "pay_gb": "%s ГБ",
    "pay_unl": "безлимит", "pay_btn": "Продлить",
    "ch_ttl": "Оплата подписки", "ch_plan": "Тариф", "ch_sum": "К оплате",
    "ch_paybtn": "Перейти к оплате", "ch_wait": "Ожидаем подтверждение платежа…",
    "ch_manual": "Как оплатить: свяжись с владельцем сервиса (способ оплаты он указал при выдаче). Как только оплата подтвердится, срок продлится автоматически.",
    "ch_paid": "Оплата получена — подписка продлена",
    "ch_back": "Вернуться к подписке", "ch_err": "Счёт не найден или недействителен",
    "ch_exp": "Срок до", "ch_cli": "Клиент", "ch_inv": "Счёт",
    "sh_ttl": "Тарифы VPN", "sh_hd": "Выбери тариф — доступ придёт сразу после оплаты",
    "sh_buy": "Купить", "sh_tg": "Telegram @username",
    "sh_tg_hint": "необязательно: напиши — и после оплаты бот пришлёт ссылку в этот чат",
    "sh_go": "Перейти к оплате", "sh_err": "Не удалось создать счёт — попробуй позже",
    "sh_empty": "Тарифы временно недоступны — загляни позже",
    "ch_link": "Твоя ссылка-подписка (сохрани её):",
})
for _pk, _pv in {
    "en": {
        "pay_hd": "Payment & renewal", "pay_days": "%d days", "pay_gb": "%s GB",
        "pay_unl": "unlimited", "pay_btn": "Renew",
        "ch_ttl": "Subscription payment", "ch_plan": "Plan", "ch_sum": "Amount due",
        "ch_paybtn": "Go to payment", "ch_wait": "Waiting for payment confirmation…",
        "ch_manual": "How to pay: contact the service owner (payment method is the one they gave you). Once the payment is confirmed, the expiry extends automatically.",
        "ch_paid": "Payment received — subscription extended",
        "ch_back": "Back to subscription", "ch_err": "Invoice not found or invalid",
        "ch_exp": "Valid until", "ch_cli": "Client", "ch_inv": "Invoice",
        "sh_ttl": "VPN plans", "sh_hd": "Pick a plan — access arrives right after payment",
        "sh_buy": "Buy", "sh_tg": "Telegram @username",
        "sh_tg_hint": "optional: add it and the bot will send the link to this chat after payment",
        "sh_go": "Proceed to payment", "sh_err": "Could not create the invoice — try again later",
        "sh_empty": "Plans are temporarily unavailable — check back later",
        "ch_link": "Your subscription link (save it):",
    },
    "fa": {
        "pay_hd": "پرداخت و تمدید", "pay_days": "%d روز", "pay_gb": "%s گیگ",
        "pay_unl": "نامحدود", "pay_btn": "تمدید",
        "ch_ttl": "پرداخت اشتراک", "ch_plan": "پلن", "ch_sum": "مبلغ قابل پرداخت",
        "ch_paybtn": "رفتن به پرداخت", "ch_wait": "در انتظار تأیید پرداخت…",
        "ch_manual": "نحوه پرداخت: با صاحب سرویس تماس بگیرید. پس از تأیید پرداخت، اعتبار اشتراک به‌طور خودکار تمدید می‌شود.",
        "ch_paid": "پرداخت دریافت شد — اشتراک تمدید شد",
        "ch_back": "بازگشت به اشتراک", "ch_err": "فاکتور یافت نشد یا نامعتبر است",
        "ch_exp": "اعتبار تا", "ch_cli": "مشتری", "ch_inv": "فاکتور",
        "sh_ttl": "پلن‌های VPN", "sh_hd": "یک پلن انتخاب کنید — دسترسی بلافاصله پس از پرداخت فعال می‌شود",
        "sh_buy": "خرید", "sh_tg": "نام کاربری تلگرام",
        "sh_tg_hint": "اختیاری: آن را بنویسید تا ربات پس از پرداخت لینک را در همین چات بفرستد",
        "sh_go": "رفتن به پرداخت", "sh_err": "ایجاد فاکتور ممکن نشد — بعداً تلاش کنید",
        "sh_empty": "پلن‌ها موقتاً در دسترس نیستند — بعداً سر بزنید",
        "ch_link": "لینک اشتراک شما (آن را ذخیره کنید):",
    },
    "zh": {
        "pay_hd": "付款与续订", "pay_days": "%d 天", "pay_gb": "%s GB",
        "pay_unl": "无限制", "pay_btn": "续订",
        "ch_ttl": "订阅付款", "ch_plan": "套餐", "ch_sum": "应付金额",
        "ch_paybtn": "前往付款", "ch_wait": "等待付款确认…",
        "ch_manual": "付款方式：请联系服务提供者。付款确认后，订阅时长将自动延长。",
        "ch_paid": "已收到付款——订阅已延长",
        "ch_back": "返回订阅页", "ch_err": "未找到账单或账单无效",
        "ch_exp": "有效期至", "ch_cli": "客户", "ch_inv": "账单",
        "sh_ttl": "VPN 套餐", "sh_hd": "选择套餐——付款成功后立即开通",
        "sh_buy": "购买", "sh_tg": "Telegram 用户名",
        "sh_tg_hint": "可选：填写后机器人将在付款完成后把链接发到该聊天",
        "sh_go": "前往付款", "sh_err": "无法创建账单——请稍后重试",
        "sh_empty": "套餐暂时不可用——请稍后再来",
        "ch_link": "你的订阅链接（请保存）：",
    },
}.items():
    _SUB_TXT.setdefault(_pk, {}).update(_pv)

_BOT_RU.update({
    "pay_paid": "💰 <b>Оплата прошла</b>\nКлиент: <code>%s</code>\nТариф: %s · %s\nПодписка продлена автоматически.",
    "pay_paid_na": "⚠️ Оплата %s: подписка не найдена (клиент удалён?), продлить нечем.",
    "pay_paid_shop": "🛒 <b>Покупка с витрины</b>\nПокупатель: <code>%s</code>\nТариф: %s · %s\nНовая подписка создана и выдана.",
    "shop_found": "🛒 <b>Нашла твою покупку с витрины!</b>\nТариф: <b>%s</b> — подписка привязана к этому чату.\n🔑 Ссылка: <code>%s</code>\n📱 Страница: %s\nДальше — кнопки меню: статус, ссылка, приложения.",
})
_BOT_TXT["en"].update({
    "pay_paid": "💰 <b>Payment received</b>\nClient: <code>%s</code>\nPlan: %s · %s\nSubscription extended automatically.",
    "pay_paid_na": "⚠️ Payment %s: subscription not found (client deleted?), nothing to extend.",
    "pay_paid_shop": "🛒 <b>Storefront purchase</b>\nBuyer: <code>%s</code>\nPlan: %s · %s\nNew subscription created and delivered.",
    "shop_found": "🛒 <b>Found your storefront purchase!</b>\nPlan: <b>%s</b> — the subscription is now linked to this chat.\n🔑 Link: <code>%s</code>\n📱 Page: %s\nUse the menu buttons: status, link, apps.",
})
_BOT_TXT["fa"].update({
    "pay_paid": "💰 <b>پرداخت دریافت شد</b>\nمشتری: <code>%s</code>\nپلن: %s · %s\nاعتبار اشتراک خودکار تمدید شد.",
    "pay_paid_na": "⚠️ پرداخت %s: اشتراک یافت نشد، تمدید انجام نشد.",
    "pay_paid_shop": "🛒 <b>خرید از ویترین</b>\nخریدار: <code>%s</code>\nپلن: %s · %s\nاشتراک جدید ساخته و تحویل شد.",
    "shop_found": "🛒 <b>خرید شما از ویترین پیدا شد!</b>\nپلن: <b>%s</b> — اشتراک به این چات متصل شد.\n🔑 لینک: <code>%s</code>\n📱 صفحه: %s\nدکمه‌های منو: وضعیت، لینک، برنامه‌ها.",
})
_BOT_TXT["zh"].update({
    "pay_paid": "💰 <b>已收到付款</b>\n客户：<code>%s</code>\n套餐：%s · %s\n订阅已自动延长。",
    "pay_paid_na": "⚠️ 付款 %s：未找到订阅，无法延长。",
    "pay_paid_shop": "🛒 <b>商店购买</b>\n买家：<code>%s</code>\n套餐：%s · %s\n已创建并交付新订阅。",
    "shop_found": "🛒 <b>找到你的商店订单！</b>\n套餐：<b>%s</b> — 订阅已绑定到此聊天。\n🔑 链接：<code>%s</code>\n📱 页面：%s\n使用菜单按钮：状态、链接、应用。",
})

def _pay_load():
    d = _load(PAYMENTS_F, None)
    if not isinstance(d, dict):
        d = {}
    if not isinstance(d.get("plans"), list):
        d["plans"] = []
    if not isinstance(d.get("invoices"), dict):
        d["invoices"] = {}
    try:
        d["seq"] = int(d.get("seq") or 0)
    except Exception:
        d["seq"] = 0
    return d

def _pay_save(d):
    _save(PAYMENTS_F, d, 0o600)

def _pay_cfg():
    return {
        "enabled": bool(CFG_CACHE.get("pay_enabled")),
        "provider": CFG_CACHE.get("pay_provider") if CFG_CACHE.get("pay_provider") in _PAY_PROVIDERS else "manual",
        "secret": CFG_CACHE.get("pay_secret") or "",
        "cb_token": CFG_CACHE.get("pay_cb_token") or "",
        "yoo_shop": CFG_CACHE.get("pay_yoo_shop") or "",
        "yoo_secret": CFG_CACHE.get("pay_yoo_secret") or "",
        "notify": CFG_CACHE.get("pay_notify", True) is not False,
    }

def _pay_base():
    host = _hop_pub_host()
    host = host if "://" not in host else urllib.parse.urlparse(host).netloc
    return _pb(host, CFG_CACHE.get("panel_port", 8444))

def _pay_pub_plans():
    d = _pay_load()
    out = []
    for pl in d["plans"]:
        try:
            if float(pl.get("price") or 0) > 0 and int(pl.get("days") or 0) >= 0 and pl.get("id"):
                out.append(pl)
        except Exception:
            pass
    return out

def _pay_shop_plans():
    """Витрина /shop: только при включённых платежах и у тарифов с флагом shop."""
    try:
        if not _pay_cfg()["enabled"]:
            return []
    except Exception:
        return []
    return [pl for pl in _pay_pub_plans() if pl.get("shop")][:24]

def _pay_sub_find(tok):
    if not tok:
        return None
    st = _load(STATE) or {}
    return next((x for x in _subs_summary(st)
                 if x["sub_token"] == tok or x["uuid"] == tok), None)

# ---------- провайдеры ----------
def _pay_cb_api(method, params):
    pc = _pay_cfg()
    if not pc["cb_token"]:
        raise ValueError("CryptoBot: не задан API-токен")
    body = json.dumps(params).encode()
    req = urllib.request.Request("https://pay.crypt.bot/api/" + method, data=body,
        headers={"Content-Type": "application/json", "Crypto-Pay-API-Token": pc["cb_token"]})
    with urllib.request.urlopen(req, timeout=15) as r:
        j = json.loads(r.read().decode("utf-8", "replace") or "{}")
    if not j.get("ok"):
        raise ValueError("CryptoBot: " + str((j.get("error") or {}).get("name") or "ошибка API"))
    return j.get("result")

def _pay_cb_sig_ok(raw, sig):
    tok = _pay_cfg()["cb_token"]
    if not tok or not sig:
        return False
    mac = hmac.new(tok.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, str(sig).lower())

def _pay_cb_create(inv):
    r = _pay_cb_api("createInvoice", {
        "currencies": ["RUB"], "amount": "%.2f" % inv["price"],
        "payload": inv["id"], "description": ("Veil: " + (inv["title"] or ""))[:1024]})
    url = r.get("bot_invoice_url") or r.get("pay_url") or ""
    return url, str(r.get("invoice_id") or "")

def _pay_yoo_api(path, body=None, idem=None):
    pc = _pay_cfg()
    if not pc["yoo_shop"] or not pc["yoo_secret"]:
        raise ValueError("ЮKassa: не заданы shopId/secret")
    auth = base64.b64encode((pc["yoo_shop"] + ":" + pc["yoo_secret"]).encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request("https://api.yookassa.ru/v3" + path, data=data,
        headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"})
    if idem:
        req.add_header("Idempotence-Key", idem)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode("utf-8", "replace") or "{}")

def _pay_yoo_create(inv):
    r = _pay_yoo_api("/payments", {
        "amount": {"value": "%.2f" % inv["price"], "currency": inv["currency"] or "RUB"},
        "capture": True,
        "confirmation": {"type": "redirect", "return_url": _pay_base() + "/p/" + inv["sub_token"]},
        "description": "Veil: " + (inv["title"] or inv["id"])[:128],
        "metadata": {"veil_inv": inv["id"]}}, idem=inv["id"])
    url = ((r.get("confirmation") or {}).get("confirmation_url")) or ""
    return url, str(r.get("id") or "")

def _pay_pay_sig_ok(raw, sig, secret):
    if not secret or not sig:
        return False
    mac = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, str(sig).lower())

# ---------- продление ----------
def _pay_shop_deliver(inv):
    """Покупка с витрины оплачена -> создать новую подписку."""
    if inv.get("delivered"):
        return True
    name = (str(inv.get("tg") or "").lstrip("@") or ("куплено-" + inv["id"]))[:40]
    try:
        r = _create_subscription(name, limit_gb=float(inv.get("gb") or 0),
                                 expiry_days=int(inv.get("days") or 0))
    except Exception as e:
        print("[pay] shop deliver " + str(inv.get("id")) + ": " + str(e), flush=True)
        return False
    inv["delivered"] = {"sub_token": r["sub_token"], "name": r["name"]}
    _audit("pay_shop_deliver", inv=inv["id"], client=r["name"])
    return True

def _shop_try_bind(username, chat_id, B):
    """Покупатель с витрины написал в бота и совпал по @username — привязать подписку к чату."""
    uname = str(username or "").lower().lstrip("@")
    if not uname or len(uname) < 3:
        return
    try:
        cands = [v for v in _pay_load()["invoices"].values()
                 if v.get("kind") == "shop" and v.get("applied") and v.get("delivered")
                 and not v.get("tg_chat")
                 and str(v.get("tg") or "").lower().lstrip("@") == uname]
    except Exception:
        return
    for inv in cands:
        tok = str((inv.get("delivered") or {}).get("sub_token") or "")
        if not tok:
            continue
        try:
            st = _load(STATE) or {}
            hit = 0
            for inb in (st.get("inbounds") or {}).values():
                for c in inb.get("clients", []):
                    if c.get("sub_token") == tok:
                        c["tg_chat"] = str(chat_id)
                        hit += 1
            if hit:
                _save(STATE, st)
            with PAY_LOCK:
                d = _pay_load()
                v = d["invoices"].get(inv["id"])
                if v:
                    v["tg_chat"] = str(chat_id)
                    _pay_save(d)
            base = _pay_base()
            _bot_send_message(chat_id,
                              (B.get("shop_found") or _BOT_RU["shop_found"]) %
                              ((inv.get("delivered") or {}).get("name") or "?",
                               base + "/sub/" + tok, base + "/p/" + tok),
                              "HTML", _bot_sub_keyboard(B))
            _audit("shop_tg_bind", inv=inv["id"], chat=str(chat_id))
        except Exception as e:
            print("[pay] shop bind " + str(e), flush=True)

def _pay_extend(inv):
    if inv.get("kind") == "shop":
        return _pay_shop_deliver(inv)
    st = _load(STATE)
    if st is None:
        return False
    _migrate_state(st)
    now = int(time.time())
    grp = []
    for proto, inb in (st.get("inbounds") or {}).items():
        for c in inb.get("clients", []):
            if c.get("sub_token") == inv.get("sub_token"):
                grp.append(c)
    if not grp:
        return False
    days = int(inv.get("days") or 0)
    gb = float(inv.get("gb") or 0)
    for c in grp:
        if days > 0:
            ex = int(c.get("expiry") or 0)
            c["expiry"] = (max(now, ex) if ex else now) + days * 86400
            c["warned_days"] = []
            c["blocked"] = False
            c["blocked_reason"] = ""
        if gb > 0:
            c["limit_gb"] = gb
            c["warned_80"] = False
    if gb > 0 and inv.get("reset"):
        uid = grp[0].get("uuid")
        for c in grp:
            c["up"] = 0; c["down"] = 0; c["last_up"] = 0; c["last_down"] = 0
        if uid:
            try:
                subprocess.run(["xray", "api", "statsreset",
                                "--server", f"127.0.0.1:{_STATS_PORT}",
                                "--pattern", f"user>>>{uid}>>>"],
                               capture_output=True, text=True, timeout=8)
            except Exception:
                pass
    _awg_sync(st); _wg_sync(st)
    _write_xray(st); _save(STATE, st)
    _restart_xray()
    _audit("pay_extend", inv=inv["id"], sub=inv.get("sub_token"), days=days, gb=gb)
    return True

def _pay_notify_paid(inv, ok):
    pc = _pay_cfg()
    if not pc["notify"]:
        return
    ids = CFG_CACHE.get("bot_chat_ids") or []
    if not ids:
        return
    try:
        B = _bot_B(ids[0])
        price = ("%g" % inv["price"]) + " " + (inv.get("currency") or "RUB")
        if ok:
            key = "pay_paid_shop" if inv.get("kind") == "shop" else "pay_paid"
            txt = (B.get(key) or B["pay_paid"]) % (inv.get("name") or "?",
                                                   inv.get("title") or inv["id"], price)
        else:
            txt = B["pay_paid_na"] % inv["id"]
        for cid in ids:
            _bot_send_message(cid, txt, "HTML")
    except Exception:
        pass

def _pay_mark_paid(inv_id, src=""):
    with PAY_LOCK:
        d = _pay_load()
        inv = d["invoices"].get(inv_id)
        if not inv:
            return None
        if inv.get("applied"):
            return inv
        inv["status"] = "paid"
        inv["paid_at"] = int(time.time())
        inv["paid_src"] = src
        ok = _pay_extend(inv)
        inv["applied"] = bool(ok)
        d["invoices"][inv_id] = inv
        _pay_save(d)
    _pay_notify_paid(inv, ok)
    return inv

def _pay_find_by_ext(provider, ext):
    ext = str(ext or "")
    if not ext:
        return None
    d = _pay_load()
    for v in d["invoices"].values():
        if v.get("provider") == provider and str(v.get("external_id") or "") == ext:
            return v
    return None

def _pay_mkv(tok, plan, src="page", kind="renew", tg=""):
    pc = _pay_cfg()
    u = None if kind == "shop" else _pay_sub_find(tok)
    if kind != "shop" and not u:
        raise ValueError("подписка не найдена")
    with PAY_LOCK:
        d = _pay_load()
        d["seq"] += 1
        now = int(time.time())
        for _try in range(50):
            iid = "V%06d" % ((now + d["seq"] * 7919) % 1000000)
            if iid not in d["invoices"]:
                break
            d["seq"] += 1
        inv = {"id": iid,
               "plan_id": plan.get("id") or "", "title": plan.get("title") or "",
               "price": float(plan.get("price") or 0),
               "currency": (plan.get("currency") or "RUB")[:8],
               "days": int(plan.get("days") or 0), "gb": float(plan.get("gb") or 0),
               "reset": bool(plan.get("reset")), "kind": kind, "tg": (tg or "")[:40],
               "sub_token": u["sub_token"] if u else "",
               "name": (u.get("name") if u else (tg or ("витрина-" + iid))) or "",
               "provider": pc["provider"],
               "status": "new", "external_id": "", "pay_url": "",
               "created": now, "paid_at": 0, "applied": False, "src": src}
        try:
            if pc["provider"] == "cryptobot":
                inv["pay_url"], inv["external_id"] = _pay_cb_create(inv)
            elif pc["provider"] == "yookassa":
                inv["pay_url"], inv["external_id"] = _pay_yoo_create(inv)
        except Exception as e:
            raise ValueError(str(e))
        d["invoices"][inv["id"]] = inv
        if len(d["invoices"]) > 2000:
            for k in sorted(d["invoices"], key=lambda x: d["invoices"][x].get("created") or 0)[:-1500]:
                if d["invoices"][k].get("applied"):
                    d["invoices"].pop(k, None)
        _pay_save(d)
    return inv

def _pay_check_ext(inv_id):
    """Опрос статуса у провайдера (для кнопки «Проверить» и dry-режима без webhook)."""
    d = _pay_load()
    inv = d["invoices"].get(inv_id)
    if not inv or inv.get("applied"):
        return inv
    try:
        if inv["provider"] == "cryptobot" and inv.get("external_id"):
            r = _pay_cb_api("getInvoices", {"invoice_ids": inv["external_id"]})
            items = r.get("items") or ([r] if isinstance(r, dict) else [])
            if any(str(x.get("invoice_id")) == str(inv["external_id"]) and x.get("status") == "paid"
                   for x in items):
                return _pay_mark_paid(inv_id, "poll")
        elif inv["provider"] == "yookassa" and inv.get("external_id"):
            r = _pay_yoo_api("/payments/" + urllib.parse.quote(inv["external_id"]))
            if r.get("status") == "succeeded":
                return _pay_mark_paid(inv_id, "poll")
    except Exception as e:
        print("[pay] check " + str(inv_id) + ": " + str(e), flush=True)
    return inv

# ---------- публичные страницы ----------
def _pay_block_html(tok, L):
    try:
        if not _pay_cfg()["enabled"]:
            return ""
        plans = _pay_pub_plans()
    except Exception:
        return ""
    if not plans:
        return ""
    rows = []
    for pl in plans[:12]:
        bits = []
        if int(pl.get("days") or 0) > 0:
            bits.append(L["pay_days"] % int(pl["days"]))
        gbv = float(pl.get("gb") or 0)
        bits.append(L["pay_gb"] % ("%g" % gbv) if gbv > 0 else L["pay_unl"])
        href = "/pay/buy/" + urllib.parse.quote(tok) + "/" + urllib.parse.quote(str(pl["id"]))
        rows.append(
            '<a href="' + _html.escape(href, quote=True) + '" '
            'style="display:flex;justify-content:space-between;gap:10px;align-items:center;'
            'padding:10px 12px;margin:6px 0;border:1px solid rgba(128,128,128,.35);'
            'border-radius:10px;text-decoration:none;color:inherit">'
            '<span><b>' + _html.escape(str(pl.get("title") or "")) + '</b><br>'
            '<span style="opacity:.65;font-size:12px">' + _html.escape(" · ".join(bits)) + '</span></span>'
            '<span style="white-space:nowrap;font-weight:700">' + _html.escape("%g" % float(pl["price"])) + " " +
            _html.escape(str(pl.get("currency") or "RUB")) + '</span></a>')
    return ('<div class="sec"><h2>' + _html.escape(L["pay_hd"]) + '</h2>' + "".join(rows) + '</div>')

def _pay_page_html(inv, L):
    esc = lambda s: _html.escape(str(s or ""), quote=True)
    tok = esc((inv.get("delivered") or {}).get("sub_token") or inv.get("sub_token") or "")
    state = "paid" if inv.get("applied") else ("wait" if inv.get("status") == "paid" else "new")
    if state == "paid":
        body = ('<div class="box ok">✅ ' + esc(L["ch_paid"]) + '</div>'
                '<a class="btn" href="/p/' + tok + '">' + esc(L["ch_back"]) + '</a>')
        if inv.get("kind") == "shop" and tok:
            body += ('<div class="box" style="text-align:center"><div style="font-size:12px;'
                     'opacity:.7;margin-bottom:6px">' + esc(L["ch_link"]) + '</div>'
                     '<code style="font-size:13px;word-break:break-all">' +
                     esc(_pay_base() + "/sub/" + tok) + '</code></div>')
    else:
        parts = ['<div class="box"><div class="row"><span>' + esc(L["ch_plan"]) +
                 '</span><b>' + esc(inv.get("title")) + '</b></div>',
                 '<div class="row"><span>' + esc(L["ch_inv"]) + '</span><b>' + esc(inv.get("id")) + '</b></div>',
                 '<div class="row"><span>' + esc(L["ch_sum"]) + '</span><b>' +
                 ("%g" % float(inv.get("price") or 0)) + " " + esc(inv.get("currency")) + '</b></div></div>']
        if inv.get("provider") == "manual":
            parts.append('<div class="box note">' + esc(L["ch_manual"]) + '</div>')
        elif inv.get("pay_url"):
            parts.append('<a class="btn big" target="_blank" rel="noopener" href="' +
                         esc(inv["pay_url"]) + '">' + esc(L["ch_paybtn"]) + '</a>')
        else:
            parts.append('<div class="box note">' + esc(L["ch_wait"]) + '</div>')
        parts.append('<p class="wait">' + esc(L["ch_wait"]) + '</p>'
                     '<a class="lnk" href="/p/' + tok + '">' + esc(L["ch_back"]) + '</a>')
        body = "".join(parts)
    meta = '<meta http-equiv="refresh" content="25">' if state == "new" else ""
    return ('<!doctype html><html lang="' + L.get("_code", "ru") + '" dir="' +
            ("rtl" if L.get("_code") == "fa" else "ltr") + '"><head><meta charset="utf-8">' + meta +
            '<meta name="viewport" content="width=device-width,initial-scale=1">' +
            '<title>' + esc(L["ch_ttl"]) + '</title><style>'
            'body{background:#0d1020;color:#e8eaf6;font-family:system-ui,sans-serif;display:flex;'
            'justify-content:center;padding:24px 14px;margin:0}'
            '.w{max-width:420px;width:100%}h1{font-size:19px;text-align:center}'
            '.box{background:#171b30;border:1px solid rgba(128,128,128,.35);border-radius:12px;padding:12px 14px;margin:10px 0}'
            '.box.ok{border-color:#3fb95066;text-align:center;padding:18px 14px}'
            '.row{display:flex;justify-content:space-between;gap:10px;padding:3px 0;font-size:14px}'
            '.btn{display:block;text-align:center;background:#3b6cf6;color:#fff;text-decoration:none;'
            'border-radius:12px;padding:12px;margin:10px 0;font-weight:700}'
            '.note{font-size:13px;opacity:.85}.wait{text-align:center;font-size:12px;opacity:.6}'
            '.lnk{display:block;text-align:center;color:#8fa3ff;font-size:13px}'
            '</style></head><body><div class="w"><h1>' + esc(L["ch_ttl"]) + '</h1>' + body +
            '</div></body></html>')

def _shop_page_html(L, plans):
    esc = lambda s: _html.escape(str(s or ""), quote=True)
    if plans:
        cards = []
        for pl in plans:
            bits = []
            if int(pl.get("days") or 0) > 0:
                bits.append(L["pay_days"] % int(pl["days"]))
            gbv = float(pl.get("gb") or 0)
            bits.append(L["pay_gb"] % ("%g" % gbv) if gbv > 0 else L["pay_unl"])
            cards.append(
                '<div class="pc"><div class="pt">' + esc(pl.get("title")) + '</div>'
                '<div class="pb">' + esc(" · ".join(bits)) + '</div>'
                '<div class="pp">' + ("%g" % float(pl.get("price") or 0)) + " " +
                esc(pl.get("currency") or "RUB") + '</div>'
                '<button class="btn" onclick="shopPick(\'' + esc(pl["id"]) + '\')">' +
                esc(L["sh_buy"]) + '</button></div>')
        body = ('<div class="grid">' + "".join(cards) + '</div>'
                '<div id="co" class="box" style="display:none">'
                '<div class="row"><span>' + esc(L["ch_plan"]) + '</span><b id="coT">—</b></div>'
                '<div class="tg"><label>' + esc(L["sh_tg"]) +
                '<input id="coTg" type="text" placeholder="@username" autocomplete="off"></label></div>'
                '<p class="wait">' + esc(L["sh_tg_hint"]) + '</p>'
                '<button class="btn big" id="coGo" onclick="shopGo()">' + esc(L["sh_go"]) + '</button>'
                '<p class="wait err" id="coErr"></p></div>')
    else:
        body = '<div class="box note">' + esc(L["sh_empty"]) + '</div>'
    pj = json.dumps([{"id": str(pl["id"]), "title": str(pl.get("title") or "")}
                     for pl in plans], ensure_ascii=True).replace("<", "\\u003c")
    js = ('<script>var _P=' + pj + ';var _S=null;'
          'function shopPick(id){_S=id;'
          'var p=_P.filter(function(x){return x.id==id})[0];'
          'document.getElementById("coT").textContent=p?p.title:"";'
          'document.getElementById("coErr").textContent="";'
          'var c=document.getElementById("co");c.style.display="block";'
          'c.scrollIntoView({behavior:"smooth"});}'
          'function shopGo(){if(!_S)return;'
          'var g=document.getElementById("coTg").value.trim();'
          'var b=document.getElementById("coGo");b.disabled=true;'
          'fetch("/pay/shop/buy",{method:"POST",headers:{"Content-Type":"application/json"},'
          'body:JSON.stringify({plan_id:_S,tg:g})})'
          '.then(function(r){return r.json()})'
          '.then(function(j){b.disabled=false;if(j&&j.url){location.href=j.url;}'
          'else{document.getElementById("coErr").textContent=(j&&j.error)||'
          + json.dumps(L["sh_err"]) + ';}})'
          '.catch(function(){b.disabled=false;document.getElementById("coErr").textContent='
          + json.dumps(L["sh_err"]) + ';})}'
          '</script>')
    brand = str(CFG_CACHE.get("sub_brand") or "").strip()[:60]
    ttl = esc(L["sh_ttl"]) + ((" · " + esc(brand)) if brand else "")
    return ('<!doctype html><html lang="' + L.get("_code", "ru") + '" dir="' +
            ("rtl" if L.get("_code") == "fa" else "ltr") + '"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">' +
            '<title>' + ttl + '</title><style>'
            'body{background:#0d1020;color:#e8eaf6;font-family:system-ui,sans-serif;'
            'display:flex;justify-content:center;padding:24px 14px;margin:0}'
            '.w{max-width:680px;width:100%}h1{font-size:22px;text-align:center;margin:6px 0 2px}'
            '.hd{text-align:center;font-size:13px;opacity:.7;margin:0 0 18px}'
            '.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px}'
            '.pc{background:#171b30;border:1px solid rgba(128,128,128,.35);border-radius:14px;'
            'padding:14px;display:flex;flex-direction:column;gap:8px}'
            '.pt{font-weight:700;font-size:15px}.pb{font-size:12px;opacity:.65}'
            '.pp{font-size:20px;font-weight:800;margin-top:auto}'
            '.btn{display:block;text-align:center;background:#3b6cf6;color:#fff;text-decoration:none;'
            'border:0;border-radius:12px;padding:11px;font-weight:700;font-size:14px;cursor:pointer}'
            '.btn.big{width:100%;margin:8px 0 2px}.btn:disabled{opacity:.5}'
            '.box{background:#171b30;border:1px solid rgba(128,128,128,.35);border-radius:14px;'
            'padding:14px;margin:16px 0 0}'
            '.row{display:flex;justify-content:space-between;gap:10px;padding:3px 0;font-size:14px}'
            '.tg input{width:100%;box-sizing:border-box;margin-top:6px;background:#0d1020;'
            'color:inherit;border:1px solid rgba(128,128,128,.45);border-radius:10px;padding:9px 10px;'
            'font-size:14px}'
            '.note{font-size:13px;opacity:.85;text-align:center}.wait{font-size:12px;opacity:.6;text-align:center}'
            '.err{color:#ff8a8a;opacity:1}'
            '</style></head><body><div class="w"><h1>' + ttl + '</h1>'
            '<p class="hd">' + esc(L["sh_hd"]) + '</p>' + body + '</div>' + js + '</body></html>')

def _pay_lang_for(self):
    _q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query or "")
    _lq = (_q.get("lang") or [""])[0]
    _lck = ""
    for _c in (self.headers.get("Cookie") or "").split(";"):
        _c = _c.strip()
        if _c.startswith("veil_sub_lang="):
            _lck = _c[len("veil_sub_lang="):]
    lang = _sub_lang_pick(_lq, _lck, self.headers.get("Accept-Language", ""))
    L = _sub_L(lang)
    L["_code"] = lang
    return L

# ---------- сводка для админ-API ----------
def _pay_summary():
    pc = _pay_cfg()
    d = _pay_load()
    base = _pay_base()
    invs = sorted(d["invoices"].values(), key=lambda x: -(x.get("created") or 0))[:100]
    st = _load(STATE) or {}
    subs = [{"token": x["sub_token"], "name": x["name"], "expiry": x["expiry"],
             "limit_gb": x["limit_gb"]} for x in _subs_summary(st)][:400]
    return {"enabled": pc["enabled"], "provider": pc["provider"],
            "providers": [{"key": k, "label": _PAY_LABELS[k]} for k in _PAY_PROVIDERS],
            "labels": dict(_PAY_LABELS),
            "secret_set": bool(pc["secret"]), "cb_set": bool(pc["cb_token"]),
            "yoo_set": bool(pc["yoo_shop"] and pc["yoo_secret"]),
            "yoo_shop": pc["yoo_shop"], "notify": pc["notify"],
            "shop_url": base + "/shop",
            "hook_cb": base + "/pay/hook/cryptobot",
            "hook_yoo": base + "/pay/hook/yookassa",
            "api_url": base + "/pay/api/",
            "plans": d["plans"], "invoices": invs,
            "unpaid": sum(1 for v in d["invoices"].values() if not v.get("applied")),
            "paid_total": sum(float(v.get("price") or 0) for v in d["invoices"].values() if v.get("applied")),
            "subs": subs}

def _pay_plan_valid(pl):
    title = str(pl.get("title") or "").strip()[:60]
    if not title:
        raise ValueError("нужно название тарифа")
    try:
        price = float(pl.get("price") or 0)
        days = int(pl.get("days") or 0)
        gb = float(pl.get("gb") or 0)
    except Exception:
        raise ValueError("price/days/gb — числа")
    cur = str(pl.get("currency") or "RUB").strip().upper()[:8]
    if not re.fullmatch(r"[A-Z]{2,8}", cur):
        raise ValueError("валюта: 2-8 букв (RUB, USD…)")
    if price <= 0 or price > 10_000_000:
        raise ValueError("цена: 0…10 000 000")
    if days < 0 or days > 3650:
        raise ValueError("дни: 0…3650")
    if gb < 0 or gb > 100_000:
        raise ValueError("ГБ: 0…100000")
    if days == 0 and gb == 0:
        raise ValueError("тариф должен добавлять дни или ГБ")
    return {"title": title, "price": round(price, 2), "currency": cur,
            "days": days, "gb": round(gb, 3), "reset": bool(pl.get("reset")),
            "shop": bool(pl.get("shop"))}

_PAY_TL = {}
_PAY_TL_LK = threading.Lock()

def _pay_throttle(ip, limit=60):
    now = int(time.time())
    with _PAY_TL_LK:
        e = _PAY_TL.get(ip)
        if not e or now - e[0] > 60:
            _PAY_TL[ip] = [now, 1]
            return False
        e[1] += 1
        return e[1] > limit

def _pay_handle_public(self, p):
    """Публичные /pay/* маршруты. True — обработано."""
    ip = self.client_address[0]
    if _pay_throttle(ip):
        self._send(429, {"error": "too many requests"})
        return True
    pc = _pay_cfg()
    # GET /pay/buy/<tok>/<plan> — создать/взять счёт и показать страницу оплаты
    if p.startswith("/pay/buy/"):
        parts = p[len("/pay/buy/"):].strip("/").split("/")
        if len(parts) != 2:
            self._send(404, {"error": "not found"})
            return True
        tok, plan_id = parts
        if not pc["enabled"]:
            self._send(404, {"error": "платежи выключены"})
            return True
        plan = next((x for x in _pay_pub_plans() if str(x.get("id")) == plan_id), None)
        u = _pay_sub_find(tok)
        if not plan or not u:
            self._send(404, {"error": "тариф или подписка не найдены"})
            return True
        d = _pay_load()
        inv = next((v for v in d["invoices"].values()
                    if v.get("sub_token") == u["sub_token"] and str(v.get("plan_id")) == str(plan_id)
                    and not v.get("applied") and (v.get("created") or 0) > time.time() - 3 * 86400), None)
        if not inv:
            try:
                inv = _pay_mkv(u["sub_token"], plan, src="page")
            except Exception as e:
                self._send(502, {"error": "не удалось создать счёт: " + str(e)})
                return True
        self.send_response(302)
        self.send_header("Location", "/pay/i/" + urllib.parse.quote(inv["id"]))
        self.send_header("Content-Length", "0")
        self.end_headers()
        return True
    # GET /pay/i/<id> — страница счёта
    if p.startswith("/pay/i/"):
        inv_id = p[len("/pay/i/"):].strip("/")
        inv = _pay_load()["invoices"].get(inv_id) if re.fullmatch(r"V\d{6}", inv_id or "") else None
        if not inv:
            self._send(404, {"error": "not found"})
            return True
        L = _pay_lang_for(self)
        b = _pay_page_html(inv, L).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)
        return True
    # GET /shop — публичная витрина тарифов
    if p == "/shop":
        L = _pay_lang_for(self)
        b = _shop_page_html(L, _pay_shop_plans()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)
        return True
    # POST-маршруты ниже
    n = int(self.headers.get("Content-Length") or 0)
    if n < 0 or n > 262144:
        self._send(400, {"error": "bad body"})
        return True
    raw = self.rfile.read(n) if n else b""
    if p == "/pay/hook/cryptobot":
        if not pc["cb_token"]:
            self._send(404, {"error": "not found"})
            return True
        if not _pay_cb_sig_ok(raw, self.headers.get("Crypto-Pay-API-Signature", "")):
            _audit("pay_hook_bad_sig", provider="cryptobot", ip=ip)
            self._send(403, {"error": "bad signature"})
            return True
        try:
            upd = json.loads(raw.decode("utf-8", "replace") or "{}")
        except Exception:
            upd = {}
        cb_inv = upd.get("invoice") or {}
        if upd.get("update_type") == "pay_status_changed" and cb_inv.get("status") == "paid":
            mine = _pay_find_by_ext("cryptobot", cb_inv.get("invoice_id"))
            if mine:
                _pay_check_ext(mine["id"])
        self._send(200, {"ok": True})
        return True
    if p == "/pay/hook/yookassa":
        try:
            upd = json.loads(raw.decode("utf-8", "replace") or "{}")
        except Exception:
            upd = {}
        obj = upd.get("object") or {}
        if upd.get("event") == "payment.succeeded":
            mine = _pay_find_by_ext("yookassa", obj.get("id"))
            if mine:
                _pay_check_ext(mine["id"])  # повторный запрос к API — источник истины
        self._send(200, {"ok": True})
        return True
    if p in ("/pay/api/invoice", "/pay/api/paid"):
        if not pc["secret"]:
            self._send(404, {"error": "not found"})
            return True
        if not _pay_pay_sig_ok(raw, self.headers.get("X-Signature", ""), pc["secret"]):
            _audit("pay_hook_bad_sig", provider="generic", ip=ip)
            self._send(403, {"error": "bad signature"})
            return True
        try:
            b = json.loads(raw.decode("utf-8", "replace") or "{}")
        except Exception:
            self._send(400, {"error": "bad json"})
            return True
        if p == "/pay/api/invoice":
            plan = next((x for x in _pay_pub_plans() if str(x.get("id")) == str(b.get("plan_id") or "")), None)
            if not plan:
                self._send(404, {"error": "plan not found"})
                return True
            try:
                inv = _pay_mkv(str(b.get("sub_token") or ""), plan, src="api")
            except Exception as e:
                self._send(400, {"error": str(e)})
                return True
            self._send(200, {"invoice_id": inv["id"], "price": inv["price"],
                             "currency": inv["currency"], "pay_url": inv["pay_url"],
                             "status": "paid" if inv.get("applied") else "new"})
            return True
        inv = _pay_load()["invoices"].get(str(b.get("invoice_id") or ""))
        if not inv:
            self._send(404, {"error": "invoice not found"})
            return True
        inv = _pay_mark_paid(inv["id"], "api")
        self._send(200, {"invoice_id": inv["id"], "status": "paid" if inv.get("applied") else inv.get("status")})
        return True
    if p == "/pay/shop/buy":
        if not pc["enabled"]:
            self._send(404, {"error": "платежи выключены"})
            return True
        try:
            b = json.loads(raw.decode("utf-8", "replace") or "{}")
        except Exception:
            b = {}
        plan = next((x for x in _pay_shop_plans()
                     if str(x.get("id")) == str(b.get("plan_id") or "")), None)
        if not plan:
            self._send(404, {"error": "тариф не найден"})
            return True
        tg = str(b.get("tg") or "").strip()[:40]
        if tg and not re.fullmatch(r"@?[A-Za-z0-9_]{3,34}", tg):
            self._send(400, {"error": "telegram: @username без пробелов (3–34 символа)"})
            return True
        dd = _pay_load()
        inv = next((v for v in dd["invoices"].values()
                    if v.get("kind") == "shop" and not v.get("applied")
                    and str(v.get("plan_id")) == str(plan["id"])
                    and str(v.get("tg") or "").lower() == tg.lower()
                    and (v.get("created") or 0) > time.time() - 3 * 86400), None)
        try:
            if not inv:
                inv = _pay_mkv("", plan, src="shop", kind="shop", tg=tg)
        except Exception as e:
            self._send(502, {"error": "не удалось создать счёт: " + str(e)[:160]})
            return True
        _audit("shop_buy", inv=inv["id"], plan=plan["id"])
        self._send(200, {"ok": True, "invoice_id": inv["id"], "url": "/pay/i/" + inv["id"]})
        return True
    self._send(404, {"error": "not found"})
    return True


def _create_subscription(name, limit_gb=0, expiry_days=0):
    st = _load(STATE)
    if st is None:
        st = _new_state("reality")
    _migrate_state(st)
    sub_token = secrets.token_urlsafe(16)
    client_uuid = str(uuidlib.uuid4())
    expiry = (int(time.time()) + int(expiry_days) * 86400) if int(expiry_days) > 0 else 0
    host = _hop_pub_host()
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

_ONBOARD_LOCK = threading.Lock()

def _onboard_ensure():
    """Первый запуск «из коробки»: нет ни одного клиента — заводим личную подписку владельца.
    Возвращает True, если подписку создали сейчас (нужно оповестить в бот)."""
    try:
        if CFG_CACHE.get("onboarded"):
            return False
        with _ONBOARD_LOCK:
            if CFG_CACHE.get("onboarded"):
                return False
            st = _load(STATE)
            if _client_count(st or {}) > 0:
                CFG_CACHE["onboarded"] = "clients"
                _save(CFG, CFG_CACHE)
                return False
            r = _create_subscription("Я")
            CFG_CACHE["onboarded"] = r["sub_token"]
            _save(CFG, CFG_CACHE)
            try:
                _audit("onboard_first_sub", client=r["name"])
            except Exception:
                pass
            return True
    except Exception as e:
        print("onboard: " + str(e), flush=True)
        return False

def _onboard_info():
    """Данные карточки онбординга для дашборда или None (не показывать)."""
    tok = str(CFG_CACHE.get("onboarded") or "")
    if not tok or tok in ("clients", "seen"):
        return None
    st = _load(STATE) or {}
    if not any(c.get("sub_token") == tok
               for inb in (st.get("inbounds") or {}).values()
               for c in inb.get("clients", [])):
        return None
    host = _hop_pub_host()
    host = host if "://" not in host else urllib.parse.urlparse(host).netloc
    base = _pb(host, CFG_CACHE.get("panel_port", 8444))
    return {"sub_url": base + "/sub/" + tok, "page_url": base + "/p/" + tok}

def _onboard_notify():
    ids = CFG_CACHE.get("bot_chat_ids") or []
    if not ids:
        return
    try:
        info = _onboard_info()
        if not info:
            return
        B = _bot_B(ids[0])
        _bot_send_message(ids[0], B["onboard_msg"] % (info["sub_url"], info["page_url"]),
                          "HTML", _main_menu_keyboard(B))
    except Exception as e:
        print("onboard bot: " + str(e), flush=True)

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

def _lang_keyboard():
    return {"inline_keyboard": [[
        {"text": "Русский", "callback_data": "lang_ru"},
        {"text": "English", "callback_data": "lang_en"},
        {"text": "فارسی", "callback_data": "lang_fa"},
        {"text": "中文", "callback_data": "lang_zh"},
    ]]}

def _process_bot_update(update):
    message = update.get("message") or update.get("edited_message")
    callback_query = update.get("callback_query")
    
    if callback_query:
        callback_query_id = callback_query["id"]
        message = callback_query.get("message")
        tg_code = (callback_query.get("from") or {}).get("language_code") or ""
        if not message:
            # Answer callback query even if no message (shouldn't happen but safety)
            _bot_answer_callback(callback_query_id, _BOT_RU["nocallback"], show_alert=True)
            return
        chat_id = message["chat"]["id"]
        from_id = callback_query["from"]["id"]
        data = callback_query["data"]
        B = _bot_B(chat_id, tg_code)
        _cb_un = (callback_query.get("from") or {}).get("username") or ""
        if _cb_un:
            try:
                _shop_try_bind(_cb_un, chat_id, B)
            except Exception:
                pass
        if data.startswith("lang_"):
            _bot_answer_callback(callback_query_id)
            lg = data[5:]
            _bot_lang_set(chat_id, lg)
            B2 = _bot_B(chat_id)
            kb = _main_menu_keyboard(B2) if _is_admin(from_id) else _bot_sub_keyboard(B2)
            _bot_send_message(chat_id, B2["lang_saved"] % B2["m_lang"], reply_markup=kb)
            return
        if data.startswith("sub_"):
            _bot_answer_callback(callback_query_id)
            return _bot_sub_cb(chat_id, data, B)
        if not _is_admin(from_id):
            _bot_send_message(chat_id, B["norights"] % (from_id, CFG_CACHE.get('bot_chat_ids', [])))
            _bot_answer_callback(callback_query_id, B["norights_short"], show_alert=True)
            return
        # Answer callback query first (required by Telegram)
        _bot_answer_callback(callback_query_id)
        if data.startswith("bk"):
            try:
                _bot_backup_cb(chat_id, data, B)
            except Exception as e:
                _bot_send_message(chat_id, B["bk_err"] % str(e))
            return
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
        elif data == "cmd_pay":
            cmd = "/pay"
        elif data == "cmd_backup":
            cmd = "/backup"
        elif data == "cmd_lang":
            _bot_send_message(chat_id, B["lang_q"], reply_markup=_lang_keyboard())
            return
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
        tg_code = (message.get("from") or {}).get("language_code") or ""
        B = _bot_B(chat_id, tg_code)
        text = message.get("text", "").strip()
        _msg_un = (message.get("from") or {}).get("username") or ""
        if _msg_un:
            try:
                _shop_try_bind(_msg_un, chat_id, B)
            except Exception:
                pass
        if not text.startswith("/"):
            stp = BOT_NEW_SUB.get(chat_id)
            if stp and stp.get("step") and _is_admin(from_id):
                step = stp["step"]
                if step == "name":
                    name = text.strip()
                    if not name:
                        _bot_send_message(chat_id, B["add_nameempty"], "HTML")
                        return
                    stp["name"] = name[:40]
                    stp["step"] = "limit"
                    BOT_NEW_SUB[chat_id] = stp
                    _bot_send_message(chat_id,
                        B["add_limitq"] % _html.escape(stp["name"]), "HTML")
                elif step == "limit":
                    try:
                        limit_gb = float(text.replace(",", ".").strip())
                        if limit_gb < 0:
                            raise ValueError
                    except ValueError:
                        _bot_send_message(chat_id, B["add_num"], "HTML")
                        return
                    stp["limit_gb"] = limit_gb
                    stp["step"] = "days"
                    BOT_NEW_SUB[chat_id] = stp
                    _bot_send_message(chat_id,
                        B["add_daysq"] % str(limit_gb), "HTML")
                elif step == "days":
                    try:
                        days = int(text.strip())
                        if days < 0:
                            raise ValueError
                    except ValueError:
                        _bot_send_message(chat_id, B["add_intnum"], "HTML")
                        return
                    stp["days"] = days
                    BOT_NEW_SUB.pop(chat_id, None)
                    name = stp.get("name") or "Клиент"
                    try:
                        r = _create_subscription(name, limit_gb=stp.get("limit_gb", 0), expiry_days=days)
                    except Exception as e:
                        _bot_send_message(chat_id, B["add_err"] % str(e))
                        return
                    lim = B["unlim"] if r["limit_gb"] <= 0 else (B["gb"] % r["limit_gb"])
                    day = B["forever"] if r["expiry_days"] <= 0 else (B["daysu"] % r["expiry_days"])
                    _bot_send_message(chat_id,
                        B["created"] % (_html.escape(name), lim, day, r['sub_url']),
                        "HTML", _main_menu_keyboard(B))
                return
            if not _is_admin(from_id):
                return _bot_sub_msg(chat_id, text, B)
            return
    
    if not _is_admin(from_id):
        return _bot_sub_msg(chat_id, text, B)
    
    parts = text.split()
    cmd = parts[0].lower().split("@", 1)[0]
    args = parts[1:]
    try:
        if cmd == "/start":
            _bot_send_message(chat_id, B["start"] % chat_id,
                "HTML", _main_menu_keyboard(B))
        elif cmd == "/lang":
            _bot_send_message(chat_id, B["lang_q"], reply_markup=_lang_keyboard())
        elif cmd == "/clients":
            st = _load(STATE, {}) or {}
            lines = [B["clients_hdr"]]
            for proto, inb in (st.get("inbounds") or {}).items():
                for c in inb.get("clients", []):
                    online = "🟢" if c.get("online") else "⚪"
                    limit = (" (" + (B["gb"] % c.get('limit_gb', 0)) + ")") if c.get("limit_gb", 0) > 0 else ""
                    lines.append(f"{online} {_html.escape(str(c.get('name', '?')))} — {_html.escape(str(PROTO_LABELS.get(proto, proto)))}{limit}")
            _bot_send_message(chat_id, "\n".join(lines) if len(lines) > 1 else B["clients_empty"], "HTML", _main_menu_keyboard(B))
        elif cmd == "/restart":
            _restart_xray()
            _bot_send_message(chat_id, B["restarted"], reply_markup=_main_menu_keyboard(B))
        elif cmd == "/addsub":
            BOT_NEW_SUB[chat_id] = {"step": "name", "name": ""}
            _bot_send_message(chat_id, B["add_step1"], "HTML")
        elif cmd == "/cancel":
            BOT_NEW_SUB.pop(chat_id, None)
            _bot_send_message(chat_id, B["cancelled"], reply_markup=_main_menu_keyboard(B))
        elif cmd == "/help":
            _bot_send_message(chat_id, B["help"], "HTML", _main_menu_keyboard(B))
        elif cmd in ("/status", "/stats"):
            st = _load(STATE, {}) or {}
            running = subprocess.run(["systemctl", "is-active", "--quiet", "xray"]).returncode == 0
            clients = _client_count(st)
            uptime = _service_active_since("xray")
            gp = _gp_last_history()
            if gp:
                ok, total, pct, ts = gp
                gp_txt = B["gp_ok"] % ("🟢" if pct > 50 else "🔴", ok, total, f"{pct:.0f}", ts)
            else:
                gp_txt = B["gp_none"]
            cpu = mem = None
            try:
                m = get_system_metrics()
                cpu = m.get("cpu_usage"); mem = m.get("mem_usage")
            except Exception:
                pass
            disk = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=3).stdout
            _bot_send_message(chat_id,
                B["status_hdr"] % (B["xray_on"] if running else B["xray_off"],
                    uptime or '—', clients, len(_load_nodes()), gp_txt,
                    cpu if cpu is not None else '—', mem if mem is not None else '—',
                    disk.splitlines()[1] if len(disk.splitlines()) > 1 else '—'),
                "HTML", _main_menu_keyboard(B))
        elif cmd == "/2fa":
            _bot_send_message(chat_id, B["twofa"],
                "HTML", _main_menu_keyboard(B))
        elif cmd == "/pay":
            try:
                pc = _pay_cfg()
                if not pc["enabled"]:
                    _bot_send_message(chat_id, B["pay_off"], "HTML", _main_menu_keyboard(B))
                    return
                d = _pay_load()
                labels = dict(_PAY_LABELS)
                applied = [v for v in d["invoices"].values() if v.get("applied")]
                collected = sum(float(v.get("price") or 0) for v in applied)
                cur0 = (applied[0].get("currency") if applied and applied[0].get("currency") else "RUB")
                unpaid = sum(1 for v in d["invoices"].values() if not v.get("applied"))
                lines = [B["pay_hdr"] % (labels.get(pc["provider"], pc["provider"]),
                                         len(d["plans"]), unpaid, "%g" % collected, cur0)]
                invs = sorted(d["invoices"].values(), key=lambda x: -(x.get("created") or 0))[:6]
                if invs:
                    lines.append(B["pay_recent"])
                    for v in invs:
                        stt = B["pay_paidst"] if v.get("applied") else B["pay_wait"]
                        lines.append(B["pay_line"] % (v.get("id"),
                                                      _html.escape(str(v.get("name") or "?")),
                                                      "%g" % float(v.get("price") or 0),
                                                      v.get("currency") or "RUB", stt))
                else:
                    lines.append(B["pay_none"])
                _bot_send_message(chat_id, "\n".join(lines), "HTML", _main_menu_keyboard(B))
            except Exception as e:
                _bot_send_message(chat_id, B["err"] % str(e))
        elif cmd == "/paycheck":
            try:
                d = _pay_load()
                open_invs = [v["id"] for v in d["invoices"].values()
                             if not v.get("applied") and v.get("provider") in ("cryptobot", "yookassa")
                             and v.get("external_id")]
                if not open_invs:
                    _bot_send_message(chat_id, B["pay_none_open"], "HTML", _main_menu_keyboard(B))
                    return
                before = sum(1 for v in d["invoices"].values() if v.get("applied"))
                for iid in open_invs[:30]:
                    _pay_check_ext(iid)
                after = sum(1 for v in _pay_load()["invoices"].values() if v.get("applied"))
                _bot_send_message(chat_id, B["pay_checked"] % (len(open_invs), after - before),
                                  "HTML", _main_menu_keyboard(B))
            except Exception as e:
                _bot_send_message(chat_id, B["err"] % str(e))
        elif cmd == "/backup":
            _bot_backup_menu(chat_id, B)
        else:
            _bot_send_message(chat_id, B["unknown"], reply_markup=_main_menu_keyboard(B))
    except Exception as e:
        import traceback
        print("[bot] ошибка обработки " + str(text) + ": " + str(e), flush=True)
        traceback.print_exc()
        try:
            _bot_send_message(chat_id, B["err"] % str(e))
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

# ---------- роли: операторы с настраиваемыми правами ----------
PERM_KEYS = ["clients", "nodes", "hop", "proxy", "rotation", "site", "pay",
             "backups", "restore", "settings", "bot", "security", "logs", "appearance"]

def _clean_perms(d):
    d = d if isinstance(d, dict) else {}
    return {k: bool(d.get(k)) for k in PERM_KEYS}

# Логи служб (вкладка «Логи»): id, метка, источник (journal=имя юнита, file=путь), цель
LOG_SOURCES = [
    ("xray", "Xray (VPN-ядро)", "journal", "xray"),
    ("telemt", "telemt (Telegram-прокси)", "journal", "telemt"),
    ("vpnpanel", "Veil-панель", "journal", "vpnpanel"),
    ("nginx", "nginx (веб-фронт)", "journal", "nginx"),
    ("cloudflared", "Cloudflare Tunnel", "journal", "cloudflared"),
    ("zapret", "veil-zapret2 (обход DPI)", "journal", "veil-zapret2"),
    ("syslog", "Системный (syslog)", "file", "/var/log/syslog"),
]

def _tail_lines(path, count):
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        sz = f.tell()
        off = max(0, sz - 1500000)
        f.seek(off)
        data = f.read().decode("utf-8", "replace")
    ls = data.splitlines()
    if off > 0 and ls:
        ls = ls[1:]
    return ls[-count:]

# ================= Passkeys (WebAuthn): Face ID / Touch ID =================
# Самодостаточная реализация без внешних зависимостей: минимальный декодер CBOR
# и проверка ECDSA P-256 (ES256) на чистом Python. Регистрация — TOFU: ключ
# привязывается из уже аутентифицированной сессии и принимается как есть;
# вход доказывает владение приватным ключом подписью assertion'а (UV обязателен,
# т.е. биометрия/PIN на устройстве).
PASSKEYS_FILE = f"{BASE}/passkeys.json"
_PK_LOCK = threading.Lock()
_PK_PENDING = {}  # token -> {"ch": bytes, "exp": ts, "host": str}

def _b64u_dec(s):
    s = str(s or "")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _b64u_enc(b):
    return base64.urlsafe_b64encode(bytes(b)).decode().rstrip("=")

def _cbor_dec(d, i=0):
    v = d[i]; i += 1
    mt, ai = v >> 5, v & 31
    def ln():
        nonlocal i
        if ai < 24: return ai
        if ai == 24: n = d[i]; i += 1; return n
        if ai == 25: n = int.from_bytes(d[i:i + 2], "big"); i += 2; return n
        if ai == 26: n = int.from_bytes(d[i:i + 4], "big"); i += 4; return n
        if ai == 27: n = int.from_bytes(d[i:i + 8], "big"); i += 8; return n
        raise ValueError("cbor")
    if mt == 0: return ln(), i
    if mt == 1: return -1 - ln(), i
    if mt == 2:
        n = ln(); return bytes(d[i:i + n]), i + n
    if mt == 3:
        n = ln(); return d[i:i + n].decode("utf-8", "replace"), i + n
    if mt == 4:
        if ai == 31:
            out = []
            while d[i] != 0xFF:
                x, i = _cbor_dec(d, i); out.append(x)
            return out, i + 1
        n = ln(); out = []
        for _ in range(n):
            x, i = _cbor_dec(d, i); out.append(x)
        return out, i
    if mt == 5:
        if ai == 31:
            out = {}
            while d[i] != 0xFF:
                k, i = _cbor_dec(d, i); x, i = _cbor_dec(d, i); out[k] = x
            return out, i + 1
        n = ln(); out = {}
        for _ in range(n):
            k, i = _cbor_dec(d, i); x, i = _cbor_dec(d, i); out[k] = x
        return out, i
    if mt == 6:
        ln()
        return _cbor_dec(d, i)
    if mt == 7:
        if ai == 20: return False, i
        if ai == 21: return True, i
        if ai == 22: return None, i
        if ai == 24: return d[i], i + 1
        n = {25: 2, 26: 4, 27: 8}.get(ai)
        if n: return None, i + n
    raise ValueError("cbor")

_EC_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_EC_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_EC_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_EC_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

def _ec_inv(a, m):
    return pow(a % m, m - 2, m)

def _ec_add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % _EC_P == 0: return None
        s = (3 * p[0] * p[0] - 3) * _ec_inv(2 * p[1], _EC_P) % _EC_P
    else:
        s = (q[1] - p[1]) * _ec_inv(q[0] - p[0], _EC_P) % _EC_P
    x = (s * s - p[0] - q[0]) % _EC_P
    return (x, (s * (p[0] - x) - p[1]) % _EC_P)

def _ec_mul(k, p):
    r0, rp = None, p
    while k:
        if k & 1: r0 = _ec_add(r0, rp)
        rp = _ec_add(rp, rp); k >>= 1
    return r0

def _ecdsa_verify(msg_int, r, s, x, y):
    if not (1 <= r < _EC_N and 1 <= s < _EC_N): return False
    w = _ec_inv(s, _EC_N)
    pt = _ec_add(_ec_mul((msg_int * w) % _EC_N, (_EC_GX, _EC_GY)), _ec_mul((r * w) % _EC_N, (x, y)))
    return pt is not None and pt[0] % _EC_N == r

def _der_rs(b):
    try:
        if b[0] != 0x30: return None
        i = 2
        if b[1] & 0x80: i += (b[1] & 0x7F)
        if b[i] != 0x02: return None
        rl = b[i + 1]; r = int.from_bytes(b[i + 2:i + 2 + rl], "big"); i += 2 + rl
        if b[i] != 0x02: return None
        sl = b[i + 1]; s = int.from_bytes(b[i + 2:i + 2 + sl], "big")
        return r, s
    except Exception:
        return None

def _pk_authdata(ad):
    if len(ad) < 37: return None
    out = {"rp": ad[:32], "flags": ad[32], "counter": int.from_bytes(ad[33:37], "big"), "cred": None}
    if out["flags"] & 0x40:
        rest = ad[37:]
        if len(rest) < 19: return None
        cl = int.from_bytes(rest[16:18], "big")
        if len(rest) < 18 + cl: return None
        try:
            cose, _ = _cbor_dec(rest, 18 + cl)
        except Exception:
            return None
        out["cred"] = {"id": rest[18:18 + cl], "cose": cose}
    return out

def _pk_cose_es256(cose):
    try:
        if cose.get(1) != 2 or cose.get(3) != -7 or cose.get(-1) != 1: return None
        x, y = cose.get(-2), cose.get(-3)
        if isinstance(x, (bytes, bytearray)) and len(x) == 32 \
                and isinstance(y, (bytes, bytearray)) and len(y) == 32:
            return int.from_bytes(x, "big"), int.from_bytes(y, "big")
    except Exception:
        pass
    return None

def _pk_load():
    try:
        with open(PASSKEYS_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}

def _pk_host(self):
    h = (self.headers.get("Host") or "").strip()
    if h.startswith("["):
        try:
            return h[1:h.index("]")]
        except Exception:
            return h
    return h.split(":")[0]

def _pk_new_pending(host):
    with _PK_LOCK:
        now = time.time()
        for k in [k for k, v in _PK_PENDING.items() if v.get("exp", 0) < now]:
            _PK_PENDING.pop(k, None)
        tok = secrets.token_hex(8)
        _PK_PENDING[tok] = {"ch": secrets.token_bytes(32), "exp": now + 180, "host": host}
        return tok, _PK_PENDING[tok]["ch"]

def _pk_take_pending(tok):
    with _PK_LOCK:
        p = _PK_PENDING.pop(str(tok or ""), None)
    if not p or p["exp"] < time.time(): return None
    return p

def _pk_clientdata(rb, want_type, ch_b64, host):
    try:
        raw = _b64u_dec((rb or {}).get("clientDataJSON"))
        cd = json.loads(raw.decode("utf-8"))
    except Exception:
        return None, "clientDataJSON не разобран", None
    if cd.get("type") != want_type:
        return None, "не тот тип церемонии", None
    if cd.get("challenge") != ch_b64:
        return None, "challenge не совпал", None
    try:
        oh = urllib.parse.urlparse(str(cd.get("origin") or "")).hostname or ""
    except Exception:
        return None, "origin не разобран", None
    if oh.lower() != str(host or "").lower():
        return None, "origin не совпал с адресом панели", None
    return cd, None, raw

def _pk_uid(self):
    u = _auth_user(self)
    if u is None: return None
    return "" if u.get("owner") else u.get("login")

def _pk_reg_end(self, b, uid):
    p = _pk_take_pending(b.get("token"))
    if not p: return 400, {"error": "попытка истекла — начни заново"}
    rb = b.get("response") or b
    cd, err, raw = _pk_clientdata(rb, "webauthn.create", _b64u_enc(p["ch"]), p["host"])
    if cd is None: return 401, {"error": err}
    try:
        att = _b64u_dec(rb.get("attestationObject"))
        am, _ = _cbor_dec(att)
        ad = _pk_authdata(am.get("authData") or b"")
    except Exception:
        return 400, {"error": "attestationObject не разобран"}
    if not ad or not ad.get("cred"): return 400, {"error": "нет данных кредитенциала"}
    if not (ad["flags"] & 0x01): return 401, {"error": "UP не подтверждён"}
    if ad["rp"] != hashlib.sha256(p["host"].encode()).digest(): return 401, {"error": "rpIdHash не совпал"}
    xy = _pk_cose_es256(ad["cred"]["cose"])
    if not xy: return 400, {"error": "поддерживаются только ключи ES256 (P-256)"}
    if am.get("fmt") == "packed":
        st_ = am.get("attStmt") or {}
        sig = st_.get("sig")
        if sig and not st_.get("x5c"):
            try:
                cdh, i2 = _cbor_dec(att)
                blob = am.get("authData") + hashlib.sha256(raw).digest()
                rs = _der_rs(bytes(sig))
                if rs and not _ecdsa_verify(int.from_bytes(hashlib.sha256(blob).digest(), "big"),
                                            rs[0], rs[1], xy[0], xy[1]):
                    return 401, {"error": "подпись аттестации не прошла"}
            except Exception:
                return 400, {"error": "packed-аттестация не разобрана"}
    name = str(b.get("name") or "").strip()[:40] or \
        ((self.headers.get("User-Agent") or "ключ")[:40])
    db = _pk_load()
    lst = db.get(uid) or []
    if len(lst) >= 12: return 400, {"error": "слишком много ключей (макс. 12)"}
    cid = _b64u_enc(ad["cred"]["id"])
    if any(c.get("id") == cid for c in lst): return 409, {"error": "такой ключ уже привязан"}
    lst.append({"id": cid, "x": "%064x" % xy[0], "y": "%064x" % xy[1],
                "name": name, "rp": p["host"], "created": _now_iso(), "counter": 0})
    db[uid] = lst
    _save(PASSKEYS_FILE, db)
    _audit("passkey_add", user=uid or "owner", name=name)
    return 200, {"ok": True, "keys": _pk_public(lst)}

def _pk_public(lst):
    return [{"id": c.get("id"), "name": c.get("name"), "created": c.get("created")} for c in (lst or [])]

def _pk_login_end(self, b):
    cip = self.client_address[0]
    ua_h = (self.headers.get("User-Agent") or "")[:256]
    if _login_throttle(cip):
        return 429, {"error": "слишком много попыток. подожди 10 минут"}
    p = _pk_take_pending(b.get("token"))
    if not p: return 400, {"error": "попытка истекла — начни заново"}
    rb = b.get("response") or b
    found, fuid = None, None
    db = _pk_load()
    ckey = None
    try:
        ckey = _b64u_enc(_b64u_dec(b.get("id")))
    except Exception:
        pass
    for uid, lst in db.items():
        for c in lst:
            if ckey and c.get("id") == ckey:
                found, fuid = c, uid
    if not found:
        _login_fail(cip)
        _login_history("fail", ip=cip, ua=ua_h, err="passkey_unknown_cred")
        return 401, {"error": "ключ не привязан к этой панели"}
    cd, err, raw = _pk_clientdata(rb, "webauthn.get", _b64u_enc(p["ch"]), p["host"])
    if cd is None:
        _login_fail(cip)
        _login_history("fail", ip=cip, ua=ua_h, err="passkey_clientdata")
        return 401, {"error": err}
    try:
        ad_raw = _b64u_dec(rb.get("authenticatorData"))
        a = _pk_authdata(ad_raw)
        sig = _der_rs(_b64u_dec(rb.get("signature")))
    except Exception:
        a, sig = None, None
    if not a or not sig:
        return 400, {"error": "ответ устройства не разобран"}
    if not (a["flags"] & 0x01):
        return 401, {"error": "устройство не подтвердило присутствие (UP)"}
    if not (a["flags"] & 0x04):
        return 401, {"error": "биометрия не подтверждена (UV) — на устройстве должен быть настроен Face ID/Touch ID или PIN"}
    if a["rp"] != hashlib.sha256((found.get("rp") or "").encode()).digest():
        return 401, {"error": "ключ выпущен для другого адреса"}
    old = int(found.get("counter") or 0)
    if old and a["counter"] and a["counter"] <= old:
        return 401, {"error": "возможно клонирование ключа — привяжи заново"}
    blob = ad_raw + hashlib.sha256(raw).digest()
    if not _ecdsa_verify(int.from_bytes(hashlib.sha256(blob).digest(), "big"),
                         sig[0], sig[1], int(found["x"], 16), int(found["y"], 16)):
        _login_fail(cip)
        _login_history("fail", ip=cip, ua=ua_h, err="passkey_bad_sig")
        return 401, {"error": "подпись не прошла"}
    if fuid:
        x = next((u for u in (CFG_CACHE.get("users") or []) if u.get("login") == fuid), None)
        if not x or x.get("disabled"):
            return 403, {"error": "оператор удалён или заблокирован"}
    _login_ok(cip)
    t = secrets.token_hex(32)
    SESSIONS[t] = time.time() + 30 * 86400
    SESSIONS_META[t] = {"ip": cip, "ua": ua_h, "created": _now_iso(),
                        "last_seen": _now_iso(), "remember": True,
                        "user": fuid, "passkey": True}
    found["counter"] = a["counter"] or old
    _save(PASSKEYS_FILE, db)
    _login_history("ok", ip=cip, ua=ua_h, user=fuid or "owner")
    _audit("login_passkey", ip=cip, user=fuid or "owner", ok=True)
    _save_sessions()
    self._cookies = ["sid=" + t + "; Path=/; HttpOnly; Max-Age=2592000; SameSite=Lax"
                     + ("; Secure" if self._is_tls() else "")]
    return 200, {"ok": True, "sid": t}

def _auth_sid(self):
    t = _cookie(self)
    if t is None:
        t = (self.headers.get("X-Sid") or "").strip() or None
    if not t:
        return None
    e = SESSIONS.get(t)
    return t if (e and e > time.time()) else None

def _auth_user(self):
    sid = _auth_sid(self)
    if not sid:
        return None
    uname = (SESSIONS_META.get(sid) or {}).get("user") or ""
    if not uname:
        return {"owner": True, "login": str(CFG_CACHE.get("login") or "owner"), "perms": {}}
    for x in (CFG_CACHE.get("users") or []):
        if x.get("login") == uname:
            if x.get("disabled"):
                return None
            return {"owner": False, "login": uname, "perms": x.get("perms") or {}}
    return None

def _drop_user_sessions(login):
    drop = [t for t, mlist in SESSIONS_META.items() if (mlist or {}).get("user") == login]
    for t in drop:
        SESSIONS.pop(t, None)
        SESSIONS_META.pop(t, None)
    if drop:
        try:
            _save_sessions()
        except Exception:
            pass

def _perm_for(p, m):
    if not p.startswith("/api/"):
        return None
    if p in ("/api/login", "/api/logout", "/api/me", "/api/bot/webhook", "/api/hop/register",
             "/api/2fa/status"):
        return None
    if p.startswith("/api/ext/") or p.startswith("/pay/"):
        return None
    if p == "/api/theme" and m == "GET":
        return None
    if p == "/api/backup" or p.startswith("/api/backups"):
        return ["restore"] if p == "/api/backups/restore" else ["backups"]
    if p.startswith("/api/users"):
        return ["owner"]
    if p.startswith("/api/2fa/"):
        return ["owner"]
    if p.startswith("/api/nodes"):
        return ["nodes"]
    if p.startswith("/api/hop"):
        return ["hop"]
    if p.startswith("/api/migrate"):
        return ["owner"]
    if (p.startswith("/api/tg/") or p.startswith("/api/webproxy")
            or p.startswith("/api/webmux") or p.startswith("/api/front/")):
        return ["proxy"]
    if (p.startswith("/api/rotate") or p.startswith("/api/dynv6")
            or p.startswith("/api/globalping") or p.startswith("/api/fix/")):
        return ["rotation"]
    if p.startswith("/api/cert"):
        return ["site"]
    if p.startswith("/api/pay"):
        return ["pay"]
    if p.startswith("/api/bot/"):
        return ["bot"]
    if (p.startswith("/api/sessions") or p in ("/api/security", "/api/login/history", "/api/audit")
            or p.startswith("/api/journal")):
        return ["security"]
    if p.startswith("/api/logs"):
        return ["security", "logs"]
    if (p.startswith("/api/clients") or p.startswith("/api/subs") or p.startswith("/api/bans")
            or p.startswith("/api/sub/") or p.startswith("/api/wgconf") or p.startswith("/api/awgconf")
            or p in ("/api/favorite", "/api/extimport/apply", "/api/extimport/preview",
                     "/api/subscription/settings")):
        return ["clients"]
    if (p.startswith("/api/logo") or p.startswith("/api/wallpaper")
            or p == "/api/theme"):
        return ["appearance"]
    for pref in ("/api/settings", "/api/panel", "/api/xray", "/api/versions", "/api/update",
                 "/api/restart", "/api/port", "/api/inbound", "/api/network", "/api/vpn",
                 "/api/selftest"):
        if p.startswith(pref):
            return ["settings"]
    return None

def _perm_gate(self, p, m):
    need = _perm_for(p, m)
    if need is None:
        return None
    u = _auth_user(self)
    if u is None:
        return (401, {"error": "unauthorized"})
    if u["owner"]:
        return None
    if any(u["perms"].get(k) for k in need):
        return None
    return (403, {"error": "недостаточно прав", "need": need[0]})


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

EXT_CAPS = ["clients_add", "clients_update", "clients_delete", "traffic", "restart"]

def _node_restart(n):
    """Перезапуск ядра на ноде: veil -> /api/ext/restart, agent -> apply restart. Возвращает err или None."""
    if (n.get("type") or "agent") == "veil":
        _d, err, _fp = _node_call(n, "/api/ext/restart", {}, timeout=15)
    else:
        _d, err, _fp = _node_call(n, "/agent/apply", {"action": "restart"}, timeout=25)
    return err

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
            n["node_caps"] = data.get("caps") or []
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
        n["node_caps"] = data.get("caps") or []
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

_SSH_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}")
_SSH_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,252}")

def _ssh_target_ok(user, host):
    # «-» в начале уехал бы в getopt ssh как опция (-oProxyCommand=...) = RCE на бэке
    return bool(_SSH_USER_RE.fullmatch(user or "") and _SSH_HOST_RE.fullmatch(host or ""))

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
        if not _ssh_target_ok(user, host):
            return fail(0, "недопустимые SSH-логин или адрес")
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
                        "vmess-ws-tls", "vmess-tcp-tls", "vmess-ws",
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
    mp = _tg_mtproto_info()
    users = []
    for u in d.get("data", []):
        users.append({
            "username": u.get("username", ""),
            "enabled": bool(u.get("enabled")),
            "link": _tg_pick_tls_link((u.get("links") or {}).get("tls")),
            "web_link": web_links.get(u.get("username", ""), ""),
            "ad_tag": u.get("user_ad_tag") or "",
            "connections": u.get("active_unique_ips", 1 if u.get("current_connections", 0) else 0),
            "max_ips": int(u.get("max_unique_ips") or 0),
            "conns": int(u.get("current_connections") or 0),
            "total_octets": u.get("total_octets", 0),
        })
    for u in users:
        u["link"] = _tg_fix_mtproto_link(u.get("link") or "", mp.get("port"))
    res = {"installed": True, "users": users, "sni": _tg_sni(), "mtproto": mp}
    if web:
        res["web"] = web
    return res


def _tg_host_ok(link):
    host = (CFG_CACHE.get("hop_public_host") or "").strip() or \
           (CFG_CACHE.get("panel_domain") or "").strip()
    if not host or not link:
        return link
    return re.sub(r"(?i)(server=)[^&:]+", lambda m: m.group(1)+host, link)

def _tg_toml_server_port():
    """Устарело: см. _tg_toml_get_server_port. Оставлено как алиас для внешних потребителей."""
    return _tg_toml_get_server_port()

def _tg_mtproto_info():
    """Реальный публичный MTProto listener: тот порт, куда должны приходить tg://proxy-клиенты.
    В telemt 3.5+ массив [[server.listeners]] исчерпывающий: если в нём нет публичного
    transport=mtproxy блока, telemt не слушает [server] port, даже когда тот задан."""
    try:
        with open(TELEMT_CONF, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception:
        text = ""
    try:
        c = _tg_api("GET", "/v1/config").get("data", {}).get("censorship") or {}
    except Exception:
        c = {}
    mask = bool(c.get("mask"))
    try:
        mask_port = int(c.get("mask_port") or 0)
    except (TypeError, ValueError):
        mask_port = 0
    server_port = _tg_toml_get_server_port(text) if text else 0
    listeners = _tg_toml_listeners(text) if text else []
    pub = _tg_toml_public_mp_listener(text) if text else None
    if pub:
        port = pub["port"] or server_port
    elif not listeners:
        # Классический конфиг без listeners-массива — telemt сам биндит [server] port
        port = server_port
    else:
        # Listeners объявлены, но публичного mtproxy среди них нет — telemt MTProto не слушает
        port = server_port
    if not port:
        port = 443
    info = {"port": port, "mask": mask, "mask_port": mask_port, "server_port": server_port,
            "up": False, "proc": "", "note": "", "has_public_listener": bool(pub)}
    occ = _sock_occupant(port)
    info["proc"] = occ.get("proc", "")
    if occ.get("free"):
        info["note"] = ("на :%d никто не слушает — публичный MTProto listener не объявлен в "
                        "[[server.listeners]]" % port)
    elif "telemt" in (occ.get("proc") or ""):
        info["up"] = True
        info["note"] = "MTProto активен на :%d" % port
    else:
        info["note"] = ("порт :%d занят %s — не telemt; MTProto-клиенты туда не попадут"
                        % (port, occ.get("proc") or "другим процессом"))
    return info

def _tg_fix_mtproto_link(link, port):
    """Ссылка tg://proxy: подставить публичный домен и реальный порт MTProto
    (telemt иногда отдаёт порт своего loopback-веб-листенера вместо нативного)."""
    link = _tg_host_ok(link)
    if link and port:
        link = re.sub(r"(?i)(port=)\d+", lambda m: m.group(1)+str(port), link)
    return link

_TG_MP_MARK = "Veil:MTProtoListener"

def _tg_toml_get_server_port(text=None):
    """[server] port из telemt.toml (0 если не задан)."""
    if text is None:
        try:
            with open(TELEMT_CONF, "r", encoding="utf-8") as f: text = f.read()
        except Exception:
            return 0
    m = re.search(r"(?ms)^\s*\[server\]\s*$(.+?)(?=^\s*\[\[?|\Z)", text)
    if not m:
        return 0
    pm = re.search(r"(?m)^\s*port\s*=\s*(\d+)", m.group(1))
    return int(pm.group(1)) if pm else 0

def _tg_toml_set_server_port(text, port):
    """Вернуть текст с [server] port = port (вставить секцию, если её нет)."""
    port = int(port)
    m = re.search(r"(?ms)(^\s*\[server\]\s*$)(.+?)(?=^\s*\[\[?|\Z)", text)
    if not m:
        return text.rstrip("\n") + "\n\n[server]\nport = %d\n" % port
    body = m.group(2)
    if re.search(r"(?m)^\s*port\s*=", body):
        nb = re.sub(r"(?m)^(\s*port\s*=\s*)\d+", lambda mm: mm.group(1)+str(port), body, count=1)
    else:
        nb = body.rstrip("\n") + "\nport = %d\n" % port
    return text[:m.start(2)] + nb + text[m.end(2):]

def _tg_toml_listeners(text):
    """Список всех [[server.listeners]] блоков: [{ip, port, transport, span}].
    Transport по умолчанию — mtproxy; port по умолчанию наследует [server] port."""
    default_port = _tg_toml_get_server_port(text)
    out = []
    for m in re.finditer(r"(?ms)^\s*\[\[server\.listeners\]\]\s*$(.+?)(?=^\s*\[\[?|\Z)", text):
        body = m.group(1)
        ipm = re.search(r"(?m)^\s*ip\s*=\s*\"([^\"]*)\"", body)
        ptm = re.search(r"(?m)^\s*port\s*=\s*(\d+)", body)
        trm = re.search(r"(?m)^\s*transport\s*=\s*\"([^\"]*)\"", body)
        out.append({
            "ip": (ipm.group(1) if ipm else ""),
            "port": int(ptm.group(1)) if ptm else int(default_port or 0),
            "transport": (trm.group(1) if trm else "mtproxy").lower(),
            "span": (m.start(), m.end()),
        })
    return out

def _tg_toml_public_mp_listener(text):
    """True если в [[server.listeners]] есть mtproxy-блок, слушающий не-loopback IP."""
    for L in _tg_toml_listeners(text):
        if L["transport"] != "mtproxy":
            continue
        ip = L["ip"] or "0.0.0.0"
        if ip.startswith("127.") or ip in ("::1", ""):
            # ""=не задан; по доке это тоже любой интерфейс — считаем публичным
            if ip == "":
                return L
            continue
        return L
    return None

def _tg_toml_has_any_listener(text):
    return bool(_tg_toml_listeners(text))

def _tg_toml_ipv6_on(text):
    """Гарантировать [network] ipv6 = true — без этого флага (по умолчанию false)
    telemt молча НЕ биндит ни :: , ни v6-адрес: AAAA домен живёт, а слушателя нет,
    и iOS под VPN (где v6-маршрут появляется) теряет MTProto-прокси."""
    if re.search(r"(?m)^\s*ipv6\s*=\s*true", text):
        return text
    m = re.search(r"(?ms)^\s*\[network\]\s*$", text)
    if m:
        return text[:m.end()] + "\nipv6 = true\n" + text[m.end():]
    return text.replace("[server]\n", "[network]\nipv6 = true\n\n[server]\n", 1)

def _tg_toml_add_mp_listener(text, port):
    """Добавить публичные MTProto-listeners (v4 + v6) на port; вернуть (новый_текст, блок).
    Вставляем сразу после последнего существующего [[server.listeners]] (если есть) —
    тогда все listeners сгруппированы; иначе — в конец файла."""
    if _TG_MP_MARK in text:
        raise RuntimeError("VEIL-MTProto-listener уже добавлен — сначала откат")
    text = _tg_toml_ipv6_on(text)
    block = (
        "# "+_TG_MP_MARK+"\n"
        "[[server.listeners]]\n"
        "ip = \"0.0.0.0\"\n"
        "port = "+str(int(port))+"\n"
        "transport = \"mtproxy\"\n\n"
        "# "+_TG_MP_MARK+"\n"
        "[[server.listeners]]\n"
        "ip = \"::\"\n"
        "port = "+str(int(port))+"\n"
        "transport = \"mtproxy\"\n"
    )
    last = None
    for m in re.finditer(r"(?ms)^\s*\[\[server\.listeners\]\]\s*$(.+?)(?=^\s*\[\[?|\Z)", text):
        last = m
    if last:
        ins = last.end()
        return text[:ins].rstrip("\n") + "\n\n" + block + text[ins:].lstrip("\n"), block
    return text.rstrip("\n") + "\n\n" + block, block

def _tg_toml_remove_mp_listener(text):
    """Вырезать наши блоки-маркеры (v4+v6): строка-комментарий, заголовок [[server.listeners]]
    и тело до следующей секции/комментария."""
    pat = re.compile(r"(?m)^#[ \t]*" + re.escape(_TG_MP_MARK) + r"[ \t]*\n"
                     r"\[\[server\.listeners\]\][^\n]*\n(?:[^\[#\n][^\n]*\n)*")
    new, n = pat.subn("", text, count=2)
    if n == 0:
        raise RuntimeError("наш MTProto-listener не найден в telemt.toml — откатывать нечего")
    return new

def _tg_mp_preview():
    """Можно ли оживить MTProto: добавив публичный [[server.listeners]] (transport=mtproxy).
    Telemt 3.5+ рассматривает массив listeners как исчерпывающий: если задан только web-loopback,
    публичного MTProto-входа нет даже при корректном [server] port. Чиним это декларативно."""
    info = _tg_mtproto_info()
    telemt_up = _tg_available()
    try:
        with open(TELEMT_CONF, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception:
        text = ""
    cur_public = _tg_toml_public_mp_listener(text) if text else None
    any_listener = _tg_toml_has_any_listener(text) if text else False
    server_port = _tg_toml_get_server_port(text) if text else 0
    # Публичный порт, куда должны приходить MTProto-клиенты:
    public_port = (cur_public or {}).get("port") or info.get("port") or server_port or 0
    already_up = bool(info.get("up"))
    blockers, can_apply, cand = [], False, 0
    if not os.path.exists(TELEMT_CONF):
        blockers.append("нет %s — MTProto-прокси не установлен" % TELEMT_CONF)
    if not telemt_up:
        blockers.append("telemt не отвечает по API (не запущен?)")
    if already_up:
        blockers.append("MTProto уже активен на :%d — ничего делать не нужно" % public_port)
    elif cur_public is not None:
        # Публичный listener есть, но порт занят чужим или telemt не смог связаться
        occ = _sock_occupant(public_port)
        if not occ.get("free") and "telemt" not in (occ.get("proc") or ""):
            cand = _find_free_port(pref=[7443, 2443, 8843, 6443, 9443], avoid={public_port})
            if cand:
                can_apply = False   # перенос порта публичного listener'а — отдельная фича, не v2.7.7
                blockers.append("наш MTProto listener на :%d, но порт занят %s — освободите :%d или включите мюкс"
                                % (public_port, occ.get("proc") or "?", public_port))
            else:
                blockers.append("порт :%d занят и свободных альтернатив нет" % public_port)
        else:
            blockers.append("listener есть на :%d, но telemt его не слушает — перезапустите телеmt" % public_port)
    else:
        # Нет публичного MTProto listener'а → можно добавить на [server] port (или на free)
        want = server_port or 0
        occ = _sock_occupant(want) if want else {"free": True}
        if want and not occ.get("free") and "telemt" not in (occ.get("proc") or ""):
            cand = _find_free_port(pref=[7443, 2443, 8843, 6443, 9443], avoid={want})
        else:
            cand = want or _find_free_port(pref=[7443, 2443, 8843, 6443, 9443])
        if not cand:
            blockers.append("не нашёл свободный порт для MTProto listener'а")
        else:
            can_apply = bool(telemt_up)
    note = ""
    if can_apply:
        note = (" telemt держит массив [[server.listeners]] как исчерпывающий — добавим публичный "
                "MTProto-listener на :%d (nginx/Reality не трогаем). После применения ссылка tg://proxy "
                "указывает на :%d, fake-TLS-фронт работает как раньше." % (cand, cand))
    elif already_up:
        note = "MTProto активен на :%d — ничего делать не нужно." % public_port
    else:
        note = info.get("note") or ""
    return {"mask": bool(info.get("mask")), "public_port": public_port, "server_port": server_port,
            "up": already_up, "proc": info.get("proc") or "",
            "has_public_listener": bool(cur_public), "has_any_listener": any_listener,
            "candidate_port": cand, "can_apply": can_apply, "blockers": blockers, "note": note,
            "marked": bool(_TG_MP_MARK in text),
            "applied": bool((_load(_TGBP_STATE, {}) or {}).get("applied"))}

_MPST = {"ts": 0.0, "res": None}

def _tls_probe(ip, port, sni, timeout=6):
    """TLS-рукопожатие с SNI=фронт к ip:port (CERT_NONE — facade-сертификат не валиден
    по определению). Вернуть (ok, detail): detail содержит subject сервера при успехе."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(fam, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect((ip, port))
            s = ctx.wrap_socket(raw, server_hostname=sni)
            try:
                der = s.getpeercert(True)
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        if not der:
            return False, "handshake прошёл, но сертификата нет"
        fd, p = tempfile.mkstemp(suffix=".der")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(der)
            r = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject"],
                               capture_output=True, text=True, timeout=8)
            subj = re.sub(r"^subject=", "", (r.stdout or "").strip())[:90]
        finally:
            try:
                os.unlink(p)
            except Exception:
                pass
        return True, subj
    except Exception as e:
        return False, str(e)[:120]

def _tg_mp_selftest(force=False):
    """«MTProto под VPN» — самотест: помнит ли мир нашу беду (petlya-2026-09).
    1) facade-рукопожатие на свой публичный :7443 (v4 и v6) — путь клиента под VPN
       приходит в этот же порт, но через xray; 2) sniffing xray обязан исключать все
       фронты, иначе destination перезапишется SNI и сервер начнёт долбить чужой CDN
       на мёртвом порту (SYN-шторм); 3) synfix: свои SYN не должны упираться в лимит;
       4) сайт-маска (если настроена) — живой сертификат на :443. Кэш 60 с."""
    if not force and _MPST["res"] and time.time() - _MPST["ts"] < 60:
        return _MPST["res"]
    checks = []
    def add(id_, label, ok, detail="", warn=False):
        checks.append({"id": id_, "label": label, "ok": bool(ok),
                       "detail": (detail or "")[:200], "warn": bool(warn)})
    if not _tg_available():
        res = {"ok": False, "ran": int(time.time()),
               "checks": [{"id": "telemt", "label": "Прокси жив", "ok": False,
                           "detail": "telemt API не отвечает — сначала включи MTProto-прокси",
                           "warn": False}]}
        _MPST.update(ts=time.time(), res=res)
        return res
    add("telemt", "Прокси жив", True, "")
    try:
        port = int(_tg_mtproto_info().get("port") or 0)
    except Exception:
        port = 0
    add("listener", "Публичный MTProto-порт", bool(port),
        (":%d" % port) if port else "публичный listener не найден")
    if not port:
        res = {"ok": False, "ran": int(time.time()), "checks": checks}
        _MPST.update(ts=time.time(), res=res)
        return res
    fronts = _veil_front_domains()
    sni = (CFG_CACHE.get("front_domain") or "").strip().lower() or (fronts[0] if fronts else "www.microsoft.com")
    for ip, fam in ((_pub_ip4(), "IPv4"), (_pub_ip6(), "IPv6")):
        if not ip:
            add("tls_" + fam.lower(), "Facade-рукопожатие %s" % fam, True,
                "сервер без %s — пропускаем" % fam, warn=True)
            continue
        ok, detail = _tls_probe(ip, port, sni)
        add("tls_" + fam.lower(), "Facade-рукопожатие %s на %s:%d (SNI=%s)"
            % (fam, ip, port, sni), ok, detail)
    try:
        with open(XRAY, encoding="utf-8") as f:
            xc = json.load(f)
        need = set(fronts)
        bad = []
        n_inb = 0
        for ib in xc.get("inbounds", []):
            sn = ib.get("sniffing") or {}
            if not sn.get("enabled"):
                continue
            n_inb += 1
            miss = need - set(d.lower() for d in (sn.get("domainsExcluded") or []))
            if miss:
                bad.append("%s: нет %s" % (ib.get("tag") or ib.get("port"), ",".join(sorted(miss))))
        add("sniffing", "Xray: фронты исключены из подмены адресов", not bad and n_inb > 0,
            ("all %d inbound'ов в порядке" % n_inb) if not bad and n_inb else
            ("; ".join(bad[:4]) if bad else "ни одного inbound со sniffing — странно"))
    except Exception as e:
        add("sniffing", "Xray: фронты исключены из подмены адресов", False, str(e)[:160])
    try:
        t = subprocess.run(["nft", "list", "table", "inet", "veil_synfix"],
                           capture_output=True, text=True, timeout=10)
        txt = t.stdout or ""
        has_own = ("local_accept" in txt) and (("local6_accept" in txt) or not _pub_ip6())
        has_lim = ("other_accept" in txt) and (("other6_accept" in txt) or not _pub_ip6())
        add("synfix", "Защита SYN-лимитов: свои проходят, чужие нормируются",
            t.returncode == 0 and has_own and has_lim,
            "" if t.returncode == 0 and has_own and has_lim else
            "нет таблицы veil_synfix или правил (v4/v6) accept/лимит для своих и чужих")
    except Exception as e:
        add("synfix", "Защита SYN-лимитов", False, str(e)[:160])
    try:
        fs = _front_status()
        if fs.get("domain"):
            add("front", "Сайт-маска (свой фронт)", fs.get("active") and fs.get("https_ok"),
                "%s: cert %s, %s" % (fs["domain"], "ок" if fs.get("cert_ok") else "НЕТ",
                                      "отвечает на :443" if fs.get("https_ok") else "на :443 не отвечает"))
        else:
            add("front", "Сайт-маска (свой фронт)", True,
                "не настроена — прокси прячется за чужим фронтом; кнопка «Настроить сайт-маску» ниже",
                warn=True)
    except Exception:
        pass
    res = {"ok": all(c["ok"] for c in checks), "ran": int(time.time()), "checks": checks}
    _MPST.update(ts=time.time(), res=res)
    return res

def _tg_mp_firewall_open(port):
    """Best-effort: открыть порт в firewalld, если он активен. Молча игнорируем отсутствие."""
    try:
        if subprocess.run(["bash", "-c",
                           "command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1"],
                          capture_output=True, timeout=10).returncode == 0:
            subprocess.run(["firewall-cmd", "--permanent", "--add-port=%d/tcp" % port], capture_output=True, timeout=15)
            subprocess.run(["firewall-cmd", "--reload"], capture_output=True, timeout=15)
            return True
    except Exception:
        pass
    return False

def _tg_mp_apply(port=None, confirm=False):
    """Добавить публичный MTProto [[server.listeners]] в telemt.toml и перезапустить telemt."""
    if not confirm:
        raise RuntimeError("нужно подтверждение (confirm)")
    pv = _tg_mp_preview()
    if not pv["can_apply"]:
        raise RuntimeError("нельзя применить: " + "; ".join(pv["blockers"] or ["неизвестно"]))
    try:
        new_port = int(port) if port else int(pv["candidate_port"])
    except (TypeError, ValueError):
        new_port = int(pv["candidate_port"])
    if not (0 < new_port < 65536):
        raise RuntimeError("некорректный порт")
    occ = _sock_occupant(new_port)
    if not occ.get("free") and "telemt" not in (occ.get("proc") or ""):
        raise RuntimeError("порт :%d уже занят %s — выберите другой" % (new_port, occ.get("proc") or "?"))
    try:
        with open(TELEMT_CONF, "r", encoding="utf-8") as f:
            backup = f.read()
    except Exception as e:
        raise RuntimeError("не смог прочитать telemt.toml: %s" % e)
    prev_server_port = _tg_toml_get_server_port(backup)
    text = backup
    if prev_server_port != new_port:
        # Меняем [server] port, чтобы у ссылки и listener'а был один источник истины
        text = _tg_toml_set_server_port(text, new_port)
    text, block = _tg_toml_add_mp_listener(text, new_port)
    with open(TELEMT_CONF, "w", encoding="utf-8") as f:
        f.write(text)
    r = subprocess.run(["systemctl", "restart", "telemt"], capture_output=True, text=True, timeout=120)
    import time as _t
    up = False
    for _ in range(10):
        _t.sleep(1)
        ni = _tg_mtproto_info()
        if ni.get("up") and ni.get("port") == new_port:
            up = True
            break
    if not up:
        with open(TELEMT_CONF, "w", encoding="utf-8") as f:
            f.write(backup)
        subprocess.run(["systemctl", "restart", "telemt"], capture_output=True, timeout=120)
        raise RuntimeError("MTProto не поднялся на :%d (restart rc=%d) — конфиг откачен" % (new_port, r.returncode))
    selfw = _tg_mp_firewall_open(new_port)
    try:
        _synfix_apply()
    except Exception as e:
        print("synfix: " + str(e), flush=True)
    _save(_TGBP_STATE, {"applied": True, "port": new_port, "prev_server_port": prev_server_port,
                        "ts": _now_iso()}, 0o600)
    _audit("tg_mtproto_listen", port=new_port, prev=prev_server_port)
    return {"ok": True, "port": new_port, "prev_port": prev_server_port,
            "firewall": "open" if selfw else "skip",
            "note": "MTProto активен на :%d. Убедитесь, что облачный security group пропускает :%d." % (new_port, new_port)}

def _tg_mp_revert(confirm=False):
    """Убрать наш MTProto-listener (и вернуть прежний [server] port, если меняли)."""
    if not confirm:
        raise RuntimeError("нужно подтверждение (confirm)")
    st = _load(_TGBP_STATE, {}) or {}
    if not st.get("applied"):
        return {"ok": True, "already": True, "message": "VEIL-MTProto-listener не добавляли — откатывать нечего"}
    prev = int(st.get("prev_server_port") or 0)
    try:
        with open(TELEMT_CONF, "r", encoding="utf-8") as f:
            backup = f.read()
    except Exception as e:
        raise RuntimeError("не смог прочитать telemt.toml: %s" % e)
    try:
        text = _tg_toml_remove_mp_listener(backup)
    except Exception as e:
        raise RuntimeError(str(e))
    if prev:
        text = _tg_toml_set_server_port(text, prev)
    with open(TELEMT_CONF, "w", encoding="utf-8") as f:
        f.write(text)
    subprocess.run(["systemctl", "restart", "telemt"], capture_output=True, timeout=120)
    _save(_TGBP_STATE, {"applied": False, "port": prev, "ts": _now_iso()}, 0o600)
    try:
        _synfix_apply()
    except Exception as e:
        print("synfix: " + str(e), flush=True)
    ni = _tg_mtproto_info()
    _audit("tg_mtproto_revert", port=prev)
    if ni.get("up"):
        note = "VEIL-MTProto listener убран, но telemt всё ещё слушает :%s (значит у вас был свой публичный listener)." % prev
    elif not ni.get("proc"):
        note = "VEIL-MTProto listener убран; MTProto больше неактивен (никто не слушает :%s)." % prev
    else:
        note = "VEIL-MTProto listener убран; на :%s теперь сидит %s — MTProto-клиенты туда не попадут." % (prev, ni.get("proc"))
    return {"ok": True, "port": prev, "up": bool(ni.get("up")), "message": note, "note": note}


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
    return {"username": name, "secret": secret,
            "link": _tg_fix_mtproto_link(link, _tg_mtproto_info().get("port")),
            "web_link": web_link}

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

def _tg_set_max_ips(username, n):
    """Лимит одновременных адресов (устройств) на ссылку TG-прокси.

    Считает telemt: больше N живых IP с одним секретом — новым подключениям отказ.
    0/пусто = без лимита. Это тот же смысл, что max_devices у подписки VPN."""
    name = (username or "").strip()
    if not name:
        raise RuntimeError("имя пустое")
    try:
        n = int(n or 0)
    except Exception:
        raise RuntimeError("лимит — целое число")
    if n < 0 or n > 999:
        raise RuntimeError("лимит: 0..999 (0 — без ограничений)")
    _tg_api("PATCH", "/v1/users/" + urllib.parse.quote(name),
            {"max_unique_ips": n or None})
    return {"username": name, "max_ips": n}

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
            "link": _tg_fix_mtproto_link(_tg_pick_tls_link(links), _tg_mtproto_info().get("port")),
            "web_link": _tg_web_link(name)}

def _tg_sni():
    """SNI (маскировка) прокси: censorship.tls_domain + список tls_domains."""
    try:
        c = _tg_api("GET", "/v1/config").get("data", {}).get("censorship") or {}
    except Exception:
        return {"tls_domain": "", "tls_domains": [], "mlkem": None}
    return {"tls_domain": c.get("tls_domain") or "", "tls_domains": c.get("tls_domains") or [],
            "mlkem": _sni_mlkem_ok(c.get("tls_domain") or "")}

def _veil_front_domains():
    """Домены-фронты MTProto facade (SNI в ClientHello подделки TLS). Xray-сервер
    обязан исключать их из sniffing-override: туннельное соединение к прокси
    (hairpin: телефон под VPN → xray → свой же :7443) имеет изначальный dest
    = IP/домен панели, но внутри — TLS ClientHello с SNI=фронт. Если sniffing
    перезапишет dest этим SNI (docs telemt XRAY-SINGBOX-ROUTING, «Вариант B»),
    сервер начнёт долбить фронт (Akamai microsoft.com) на порту 7443 — там
    никто не слушает: шторм безответных SYN, а telemt не видит ни одного
    соединения. Отсюда и «прокси не работает под VPN» в клиентах без
    DirectIp-исключений (Incy)."""
    doms = []
    try:
        with open(TELEMT_CONF, "r", encoding="utf-8") as f:
            text = f.read()
        m = re.search(r'(?m)^\s*tls_domain\s*=\s*"([^"]+)"', text)
        if m:
            doms.append(m.group(1).strip().lower())
        m = re.search(r'(?m)^\s*tls_domains\s*=\s*\[([^\]]*)\]', text)
        if m:
            doms += [d.strip().strip(",").strip().strip('"').lower()
                     for d in m.group(1).split(",")]
    except Exception:
        pass
    # секреты facade: фронт зашит и в secret'ы пользователей:
    # ee + key(16B) + [первый байт SNI] + hex(остаток SNI)
    for mm in re.finditer(r'(?m)^\s*secret\s*=\s*"ee([0-9a-f]{64,})"', text or ""):
        try:
            hx = mm.group(1)
            if len(hx) < 68:
                continue
            host = chr(int(hx[64:66], 16)) + bytes.fromhex(hx[66:]).decode("ascii", "ignore")
            if re.fullmatch(r"[a-z0-9.-]+", host or ""):
                doms.append(host.lower())
        except Exception:
            pass
    if not doms:
        doms = ["www.microsoft.com", "my.aeza.ru"]
    return sorted({d for d in doms if d and "." in d})

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
    _SNI_PQ_CACHE.clear()
    _audit("tg_sni", **({"domain": dom} if dom is not None else {}))
    return _tg_sni()


FRONT_SITE_DIR = "/opt/vpnpanel/frontsite"
_NG_FRONT_CONF = "/etc/nginx/conf.d/veil-front.conf"

def _front_dns_ensure(domain):
    """Фронт обязан жить в зоне Cloudflare панели: серые A/AAAA на этот сервер.
    Создаёт записи, если их нет; пересоздаёт, если они облачные/уехали."""
    zid, zone = _cf_zone()
    if not (domain == zone or domain.endswith("." + zone)):
        raise RuntimeError("фронт " + domain + " не в Cloudflare-зоне " + (zone or "?") +
                           " — для своего фронта нужна зона с настроенным токеном (вкладка Сайт)")
    ip4, ip6 = _pub_ip4() or "", _pub_ip6() or ""
    rep = []
    for typ, ip in (("A", ip4), ("AAAA", ip6)):
        if not ip:
            continue
        q = "/zones/%s/dns_records?type=%s&name=%s&per_page=5" % (
            urllib.parse.quote(zid), typ, urllib.parse.quote(domain))
        res = _cf_api("GET", q) or []
        if len(res) == 1 and (res[0].get("content") or "").lower() == ip.lower() \
                and not res[0].get("proxied"):
            rep.append("%s %s уже указывает сюда" % (typ, domain))
            continue
        for r0 in res:
            _cf_api("DELETE", "/zones/%s/dns_records/%s" % (
                urllib.parse.quote(zid), urllib.parse.quote(r0.get("id") or "")))
        _cf_api("POST", "/zones/%s/dns_records" % urllib.parse.quote(zid),
                {"type": typ, "name": domain, "content": ip, "ttl": 60, "proxied": False})
        rep.append("%s %s → %s (создана/обновлена)" % (typ, domain, ip))
    return rep

def _front_cert_issue(domain):
    """LE-сертификата произвольного домена через DNS-01 (Cloudflare-хук панели).
    В отличие от _cert_issue — НЕ трогает настройки панели (cert_domain/panel_domain),
    продлевается общим циклом certbot renew (имя veil-<domain>)."""
    live = "%s/live/veil-%s" % (CERT_DIR, domain)
    certp, keyp = live + "/fullchain.pem", live + "/privkey.pem"
    if os.path.exists(certp) and os.path.exists(keyp):
        exp = _cert_expire(certp)
        if exp and exp > time.time() + 21 * 86400:
            return certp, keyp
    if _dns01_provider() != "cloudflare":
        raise RuntimeError("для своего фронта нужен Cloudflare (токен Zone→DNS:Edit) — "
                           "только он умеет выпускать TXT-записи для Let's Encrypt")
    if _CERT_STATE.get("busy"):
        raise RuntimeError("выпуск сертификата уже идёт — подожди минуту")
    import sys
    me = os.path.abspath(__file__)
    py = sys.executable or "python3"
    email = (CFG_CACHE.get("cert_email") or "").strip()
    args = ["certbot", "certonly", "--manual", "--preferred-challenges", "dns",
            "--manual-auth-hook", "%s %s --dns01-hook auth" % (py, me),
            "--manual-cleanup-hook", "%s %s --dns01-hook cleanup" % (py, me),
            "-d", domain, "--non-interactive", "--agree-tos",
            "--deploy-hook", "systemctl reload nginx"]
    args += ["--email", email] if email else ["--register-unsafely-without-email"]
    args += ["--config-dir", CERT_DIR, "--work-dir", CERT_DIR + "/work",
             "--logs-dir", CERT_DIR + "/logs", "--cert-name", "veil-" + domain]
    _CERT_STATE["busy"] = True
    try:
        os.makedirs(CERT_DIR, exist_ok=True)
        r = subprocess.run(args, capture_output=True, text=True, timeout=320)
        if r.returncode != 0:
            raise RuntimeError("certbot: " + (r.stderr or r.stdout)[-400:])
        subprocess.run(["chmod", "-R", "o+rX", CERT_DIR], capture_output=True)
        try:
            os.chmod(keyp, 0o600)
        except Exception:
            pass
    finally:
        _CERT_STATE["busy"] = False
    if not (os.path.exists(certp) and os.path.exists(keyp)):
        raise RuntimeError("certbot завершился, но fullchain/privkey не найдены")
    return certp, keyp

_FRONT_SITE_HTML = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Блокнот путешественника — заметки, маршруты, фотографии</title>
<style>
body{font-family:Georgia,'Times New Roman',serif;max-width:720px;margin:0 auto;padding:24px 16px;color:#2c2c2c;line-height:1.65;background:#fbfaf7}
header{border-bottom:1px solid #ddd;padding-bottom:16px;margin-bottom:24px}
h1{font-size:26px;margin:0}
.sub{color:#888;font-size:14px;margin-top:4px}
article{margin-bottom:28px}
h2{font-size:19px;margin:0 0 6px}
.d{color:#999;font-size:13px;margin-bottom:6px}
p{margin:6px 0}
a{color:#2b6cb0;text-decoration:none}
footer{margin-top:40px;padding-top:16px;border-top:1px solid #ddd;color:#999;font-size:13px}
</style>
</head>
<body>
<header>
<h1>Блокнот путешественника</h1>
<div class=sub>Заметки, маршруты и фотографии дорог</div>
</header>
<article>
<h2>Как мы пересекали Карелию на велосипедах</h2>
<div class=d>12 августа · маршруты</div>
<p>Сорок километров грунтовки, комары размером с воробья и озёра, в которых вода к полудню
прогревается ровно настолько, чтобы не захотелось плыть дальше. Рассказ о недельном веломаршруте
от Сортавалы до Ладожских шхер — с картами стоянок и списком того, что мы зря взяли с собой.</p>
</article>
<article>
<h2>Снимок дня: туман над поймой</h2>
<div class=d>29 июля · фотографии</div>
<p>Пять утра, минус по градуснику и ноль ожидания чуда: туман лёг над рекой ровно на те восемь
минут, которые нужны на три кадра. Разбираю настройки камеры, которые спасли сюжет,
и показываю исходники в RAW.</p>
</article>
<article>
<h2>Чек-лист перед первым походом</h2>
<div class=d>15 июля · снаряжение</div>
<p>Что действительно пригодилось за три сезона, а что только прибавило грамм на плечах.
Костюм от дождя, горелка, аптечка без мифической «на всякий случай» половины — и немного
математики веса, которая примиряет с компромиссами.</p>
</article>
<footer>
© 2026 Блокнот путешественника · письма на hello@localhost · ни один трекер не пострадал
</footer>
</body>
</html>
"""

def _front_site_write():
    os.makedirs(FRONT_SITE_DIR, exist_ok=True)
    p = FRONT_SITE_DIR + "/index.html"
    try:
        if os.path.exists(p) and open(p, encoding="utf-8").read() == _FRONT_SITE_HTML:
            return
    except Exception:
        pass
    with open(p, "w", encoding="utf-8") as f:
        f.write(_FRONT_SITE_HTML)

def _front_nginx_apply(domain, cert, key):
    conf = ("# Veil: сайт-маска для TLS-F (управляет панель — правка руками затрётся)\n"
            "server {\n"
            "    listen 443 ssl;\n"
            "    listen [::]:443 ssl;\n"
            "    http2 on;\n"
            "    server_name %s;\n"
            "    ssl_certificate     %s;\n"
            "    ssl_certificate_key %s;\n"
            "    root %s;\n"
            "    index index.html;\n"
            "    location / { try_files $uri $uri/ /index.html; }\n"
            "}\n"
            "server {\n"
            "    listen 80;\n"
            "    listen [::]:80;\n"
            "    server_name %s;\n"
            "    return 301 https://$host$request_uri;\n"
            "}\n" % (domain, cert, key, FRONT_SITE_DIR, domain))
    if os.path.exists(_NG_FRONT_CONF):
        try:
            if open(_NG_FRONT_CONF, encoding="utf-8").read() == conf:
                return
        except Exception:
            pass
    with open(_NG_FRONT_CONF, "w", encoding="utf-8") as f:
        f.write(conf)
    t = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=20)
    if t.returncode != 0:
        os.remove(_NG_FRONT_CONF)
        raise RuntimeError("nginx -t с фронтом: " + (t.stderr or t.stdout)[-300:])
    if subprocess.run(["systemctl", "is-active", "--quiet", "nginx"]).returncode == 0:
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, timeout=40)
    else:
        subprocess.run(["systemctl", "restart", "nginx"], capture_output=True, timeout=40)

def _front_apply(domain):
    """Свой фронт TLS-F: DNS → сертификат LE → сайт-заглушка на :443 → telemt
    tls_domain → xray (domainsExcluded подхватит новый фронт).
    Ротация секретов НЕ нужна: домен вшивается в tg://-ссылку в момент её выдачи
    telemt (список tls_domain + tls_domains), а не в момент создания клиента.
    Старые ссылки продолжают работать (старые фронты остаются в tls_domains),
    свежие выдачи /sub автоматически несут новый фронт — плавный перевод людей.
    Идемпотентно: повторный вызов с тем же доменом — починка недостающих кусков."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+",
                        domain or ""):
        raise RuntimeError("домен: например front.example.com — без протокола, порта и путей")
    if not shutil.which("nginx"):
        raise RuntimeError("nginx не установлен — свой фронт требует сайт на :443 "
                           "(установка во вкладке Сайт или apt install nginx)")
    if not _tg_available():
        raise RuntimeError("telemt не запущен — сначала включи MTProto-прокси")
    rep = _front_dns_ensure(domain)
    cert, key = _front_cert_issue(domain)
    _front_site_write()
    _front_nginx_apply(domain, cert, key)
    rep.append("сертификат Let's Encrypt + сайт-заглушка на :443 — готовы")
    cur = _tg_sni()
    olds = []
    for d0 in [cur.get("tls_domain") or ""] + list(cur.get("tls_domains") or []):
        if d0 and d0 != domain and d0 not in olds:
            olds.append(d0)
    _tg_sni_set(tls_domain=domain, tls_domains=olds)
    subprocess.run(["systemctl", "restart", "telemt"], capture_output=True, timeout=60)
    for _ in range(8):
        if _tg_available():
            break
        time.sleep(2)
    rep.append("telemt перезапущен — facade теперь притворяется фронтом " + domain)
    try:
        _write_xray(_load(STATE, {}) or {})
        _restart_xray()
        rep.append("xray обновлён: фронт исключён из подмены адресов (sniffing)")
    except Exception as e:
        rep.append("xray: " + str(e)[:140])
    if olds:
        rep.append("старые фронты (" + ", ".join(olds) + ") оставлены в tls_domains — "
                   "разданные ранее tg://-ссылки продолжают работать; свежие подписки "
                   "понесут новый фронт, перевод клиентов плавный")
    CFG_CACHE["front_domain"] = domain
    CFG_CACHE["front_enabled"] = True
    _save(CFG, CFG_CACHE)
    _audit("front_apply", domain=domain)
    return {"ok": True, "domain": domain, "report": rep}

def _front_status():
    dom = (CFG_CACHE.get("front_domain") or "").strip().lower()
    sni = _tg_sni()
    out = {"domain": dom, "tls_domain": sni.get("tls_domain") or "",
           "tls_domains": sni.get("tls_domains") or [],
           "active": bool(dom and sni.get("tls_domain") == dom),
           "enabled": bool(CFG_CACHE.get("front_enabled")),
           "cert_ok": False, "expire": 0, "nginx_ok": False, "https_ok": False,
           "dns01": _dns01_provider() == "cloudflare",
           "cf_zone": (CFG_CACHE.get("cf_zone") or "").strip().lower()}
    if dom:
        certp = CERT_DIR + "/live/veil-" + dom + "/fullchain.pem"
        out["cert_ok"] = os.path.exists(certp)
        out["expire"] = (_cert_expire(certp) or 0) if out["cert_ok"] else 0
        try:
            with open(_NG_FRONT_CONF, encoding="utf-8") as f:
                out["nginx_ok"] = ("server_name " + dom + ";") in f.read()
        except Exception:
            pass
        try:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            with socket.create_connection((dom, 443), timeout=6) as s0:
                with ctx.wrap_socket(s0, server_hostname=dom) as ss0:
                    out["https_ok"] = bool(ss0.getpeercert())
        except Exception:
            pass
    return out

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

_TGPL_PORT = {"ts": 0.0, "port": None}

def _tg_pub_port(ttl=30):
    """Публичный MTProto-порт с коротким кэшем (для частых выдач подписок)."""
    if time.time() - _TGPL_PORT["ts"] > ttl:
        try:
            p = _tg_mtproto_info().get("port")
        except Exception:
            p = None
        if p:
            _TGPL_PORT["ts"] = time.time()
            _TGPL_PORT["port"] = p
    return _TGPL_PORT["port"]

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
    mp_port = _tg_pub_port()
    return {"username": name,
            "link": _tg_fix_mtproto_link(
                _tg_host_ok(_tg_pick_tls_link((u.get("links") or {}).get("tls"))), mp_port),
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
            "tg_shared_user": CFG_CACHE.get("tg_shared_user") or "common",
            "support_url": CFG_CACHE.get("sub_support_url") or "",
            "brand": CFG_CACHE.get("sub_brand") or ""}

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
        # Раз мы завели listeners-массив, telemt перестанет сам биндить [server] port на 0.0.0.0 —
        # явно добавим публичный MTProto listener, иначе ссылка tg://proxy умрёт.
        if _tg_toml_public_mp_listener(text) is None:
            mp_port = _tg_toml_get_server_port(text) or 7443
            try:
                text, _ = _tg_toml_add_mp_listener(text, mp_port)
            except RuntimeError:
                pass

    web_block = ('[web]\n'
                 "enabled = true\n"
                 'carrier = "websocket"\n'
                 'carriers = ["websocket", "https"]\n'
                 "carrier_learning = true\n"
                 "\n[[web.vhosts]]\n"
                 'host = "%s"\n'
                 'public_addr = "%s:443"\n'
                 "\n[web.vhosts.decoy]\n"
                 'mode = "static_directory"\n'
                 'directory = "/opt/vpnpanel/decoy"\n'
                 'index = "index.html"\n' % (domain, (CFG_CACHE.get("hop_public_host") or "").strip() or ip4))
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
    # домен отдаёт AAAA, а при включённом VPN туннель добавляет маршрут ::/0 —
    # клиент идёт на IPv6 и без этого листенера получал refusal (webproxy «не работает с VPN»)
    listen [::]:443 ssl;
    http2 on;
    server_name {domain};
    # access_log выключен: в URL страницы-моста живёт bearer-секрет (?bridge=…),
    # а в логе — ещё и IP клиентов. Telemt рекомендует не светить это (WEB_PROXY docs).
    access_log off;

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

        # CSP НЕ переопределяем: страница-мост telemt — inline-скрипты с одноразовым
        # nonce, наша политика их блокирует (JS не стартует, /api/v1/ws не открывается).

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
    applied = bool((_load(_MUX_STATE, {}) or {}).get("applied"))
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
        avail, directive = _mux_stream_module_state()
        if not avail:
            warnings.append("stream-модуль динамический и НЕ установлен — выполните apt-get install -y libnginx-mod-stream (панель сама допишет load_module при применении).")
        elif directive:
            warnings.append("stream-модуль динамический (--with-stream=dynamic) — при применении панель автоматически добавит «%s» в nginx.conf (с бэкапом и авто-откатом)." % directive)
    return {"free443": o443["free"], "occupant443": o443, "free80": o80["free"], "occupant80": o80,
            "nginx": ng, "can_mux": can_mux, "xray_holds_443": xray_holds_443, "our_nginx_443": our_nginx_443,
            "reality_port": reality_port, "tls_ports": tls_ports, "domain": domain,
            "has_cert": has_cert, "cert_dns": cert_dns, "applied": applied,
            "plan": plan, "warnings": warnings}

# ─────────────────────────── #56 slice 2: opt-in SNI-mux (:443) ───────────────────────────
# Модель (решение пользователя): разные SNI-домены. Веб-фронт остаётся на домене панели,
# cert-TLS VPN получает собственный SNI-поддомен. nginx stream/ssl_preread на :443 разводит:
#   <vpn-sni>   → 127.0.0.1:<tls_port>  (xray cert-TLS inbound, слушает только loopback)
#   <веб-sni> / default → 127.0.0.1:<web_port> (веб-фронт / decoy, TLS-терминация у nginx)
# Reality НЕ mux-ится (общий SNI с реальным сайтом) — остаётся на своём порту.
_MUX_STATE = f"{BASE}/mux_state.json"
_NG_MAIN = "/etc/nginx/nginx.conf"
_NG_STREAM_INC = "/etc/nginx/veil-mux-stream.conf"
_NG_MUX_DEFAULT = "/etc/nginx/conf.d/veil-mux-default.conf"
_NG_MAIN_BAK = _NG_MAIN + ".veil-mux.bak"
_NG_WEB_BAK = _NG_CONF + ".veil-mux.bak"
_MUX_INBOUND = "vless-xhttp-tls"   # cert-TLS inbound, который мюкс переводит на loopback

_TGBP_STATE = f"{BASE}/tg_mp_port.json"   # помнит, на какой порт мы перенесли mask-фронт MTProto и прежний порт

_MUX_STREAM_TMPL = """# VEIL-MUX (generated) — не редактируйте вручную
stream {
    map $ssl_preread_server_name $veil_mux_backend {
        {vpn_domain}      127.0.0.1:{tls_port};
        {web_domain}      127.0.0.1:{web_port};
        default           127.0.0.1:{web_port};
    }
    server {
        listen 443 reuseport;
        listen [::]:443 reuseport;
        proxy_protocol off;
        ssl_preread on;
        proxy_timeout 3600s;
        proxy_pass $veil_mux_backend;
    }
}
"""

_MUX_DEFAULT_TMPL = """# VEIL-MUX default backend (generated)
server {
    listen 127.0.0.1:{web_port} ssl;
    server_name {web_domain};
    ssl_certificate     {cert};
    ssl_certificate_key {key};
    root /opt/vpnpanel/decoy;
    index index.html;
    location / { try_files $uri $uri/ /index.html; }
}
"""

def _mux_cert(web_domain, vpn_domain):
    """Сертификат для обеих сторон мюкса: рабочий LE-сертификат, иначе self-signed с SAN на
    оба SNI-имени. Возвращает (cert, key, kind)."""
    cp = _cert_pathes()
    if cp["cert"] and cp["key"] and os.path.exists(cp["cert"]) and os.path.exists(cp["key"]):
        exp = _cert_expire(cp["cert"])
        if exp and exp > time.time() + 86400:
            return cp["cert"], cp["key"], "le"
    names = []
    for n in (web_domain, vpn_domain):
        if n and n not in names:
            names.append(n)
    crt = f"{CERT_DIR}/veil-mux.crt"; key = f"{CERT_DIR}/veil-mux.key"
    san = ",".join("DNS:" + n for n in names)
    os.makedirs(CERT_DIR, exist_ok=True)
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
         "-keyout", key, "-out", crt, "-days", "825",
         "-subj", "/CN=" + (names[0] if names else "veil-mux"),
         "-addext", "subjectAltName=" + (san or "DNS:localhost")],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("openssl self-signed: " + (r.stderr or r.stdout)[-300:])
    os.chmod(key, 0o600)
    return crt, key, "self-signed"

def _mux_stream_module_state():
    """Можно ли nginx этого хоста реально использовать stream, и нужен ли явный load_module.
    Динамическая сборка (--with-stream=dynamic) НЕ гарантирует, что модуль установлен:
    на Ubuntu его даёт пакет libnginx-mod-stream, подключаемый через modules-enabled/*.conf.
    Возвращает (available, directive): directive=="" — грузится сам (built-in или modules-enabled);
    иначе — строка load_module для вставки."""
    try:
        v = subprocess.run(["nginx", "-V"], capture_output=True, text=True).stderr or ""
    except Exception:
        v = ""
    built_in = ("--with-stream" in v) and ("--with-stream=dynamic" not in v)
    if built_in:
        return True, ""
    try:
        linked = subprocess.run(
            ["grep", "-RliE", r"stream", "/etc/nginx/modules-enabled/"],
            capture_output=True, text=True).stdout.strip()
    except Exception:
        linked = ""
    if linked:
        return True, ""
    for nm in ("ngx_stream_module.so", "ngx_stream.so"):
        p = "/usr/lib/nginx/modules/" + nm
        if os.path.exists(p):
            return True, "load_module %s;" % p
    return False, ""

def _mux_ports_in_use():
    used = set()
    st = _load(STATE, {}) or {}
    for inb in (st.get("inbounds") or {}).values():
        if isinstance(inb, dict) and isinstance(inb.get("port"), int):
            used.add(inb["port"])
    return used

def _mux_stream_conf(web_port, tls_port, web_domain, vpn_domain):
    return (_MUX_STREAM_TMPL.replace("{vpn_domain}", vpn_domain)
            .replace("{web_domain}", web_domain)
            .replace("{tls_port}", str(tls_port)).replace("{web_port}", str(web_port)))

def _mux_nginx_block_installed():
    try:
        return "veil-mux-stream.conf" in open(_NG_MAIN).read()
    except Exception:
        return False

# ========== ДВОЙНОЙ ПРЫЖОК: RU-фронт (nft-релей) + зарубежный бэк ==========
# ФРОНТ — тонкий L4-релей: DNAT портов на БЭК + MASQUERADE (бэк видит IP фронта,
# клиенту наружу отдаётся IP бэка). Агент на фронте не ставится — поэтому отдельный
# hops.json (nodes.json предполагает агентский токен у каждой записи).

HOPS_FILE = f"{BASE}/hops.json"
_HOP_MAX_PORTS = 64   # предельное число портов на один фронт (и потолок автозаполнения)
HOP_LOCK = threading.Lock()
HOP_JOBS = {}   # состояние SSH-буста; пароли SSH живут только в памяти воркера

def _hop_load():
    try:
        v = _load(HOPS_FILE, [])
        return v if isinstance(v, list) else []
    except Exception:
        return []

def _hop_save(hops):
    _save(HOPS_FILE, hops)  # содержит токены регистрации — 0600

def _hop_pub_host():
    """Хост для пользовательских ссылок: ФРОНТ (если двойной прыжок включён),
    иначе домен/IP бэка. SNI/server_name/сертификаты здесь НЕ меняются —
    TLS по-прежнему терминируется на бэке."""
    h = (CFG_CACHE.get("hop_public_host") or "").strip()
    if h and ":" not in h and "/" not in h:
        return h
    return (CFG_CACHE.get("panel_domain") or "").strip() or (_my_ip() or "127.0.0.1")

def _hop_is_ip4(s):
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except Exception:
        return False

def _hop_valid_ports(ports):
    out = []
    for x in (ports or []):
        try:
            p = int(x)
        except Exception:
            return None
        if not (1 <= p <= 65535) or p in out:
            return None
        out.append(p)
    if not out or len(out) > _HOP_MAX_PORTS:
        return None
    return out

def _hop_back_ip():
    return _pub_ip4() or (_my_ip() or "")

def _hop_suggest_ports():
    ports = []
    try:
        pp = int(CFG_CACHE.get("panel_port", 8444) or 8444)
        if pp:
            ports.append(pp)   # иначе подписки /sub по адресу фронта не откроются
    except Exception:
        pass
    try:
        mp = _tg_mtproto_info()
        if mp.get("up") and mp.get("port"):
            ports.append(int(mp["port"]))
    except Exception:
        pass
    st = _load(STATE, {}) or {}
    for _proto, inb in (st.get("inbounds") or {}).items():
        try:
            pt = int(inb.get("port") or 0)
            if pt and pt not in ports:
                ports.append(pt)
        except Exception:
            pass
    if 443 not in ports:
        ports.append(443)
    return sorted(ports)[:_HOP_MAX_PORTS]

_RELAY_APPLY_SH = """#!/bin/bash
# Veil double-hop: применяет nft-правила релея (идемпотентно).
set -euo pipefail
. /etc/veil-relay/relay.env
els=$(printf '%s ' $RELAY_PORTS | tr ' ' ','); els=${els%,}
cat > /etc/veil-relay/relay.nft <<EOF
table ip veil_relay {
  set ports {
    type inet_service
    elements = { $els }
  }
  chain pr {
    type nat hook prerouting priority dstnat; policy accept;
    iifname != "lo" fib daddr type local tcp dport @ports dnat to $BACK_IP
    iifname != "lo" fib daddr type local udp dport @ports dnat to $BACK_IP
  }
  chain po {
    type nat hook postrouting priority srcnat; policy accept;
    ip daddr $BACK_IP masquerade
  }
}
EOF
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
nft delete table ip veil_relay 2>/dev/null || true
nft -f /etc/veil-relay/relay.nft
"""

_RELAY_UNIT = """[Unit]
Description=Veil double-hop relay (DNAT to BACK)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/veil-relay-apply.sh
ExecStop=-/bin/sh -c 'nft delete table ip veil_relay 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
"""

# Универсальный установщик фронта: одинаково исполняется по SSH и через curl|sh.
_RELAY_INSTALL_TMPL = """#!/bin/bash
# Veil double-hop FRONT: L4-релей (nft DNAT+MASQUERADE) на __BACK_IP__. Повторно запускаемо.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "VEILERR: нужен root (sudo -s или curl ... | sudo bash)"; exit 1; }
if ! command -v nft >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then dnf -y -q install nftables >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then yum -y -q install nftables >/dev/null 2>&1 || true
  fi
fi
command -v nft >/dev/null 2>&1 || { echo "VEILERR: nftables не установлен и ставить нечем — установите вручную (apt/dnf install nftables)"; exit 2; }
busy=""
for p in __PORTS_SP__; do
  if ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$p$"; then
    owner=$(ss -H -ltnp "sport = :$p" 2>/dev/null | grep -oE '\\("[a-zA-Z0-9_.-]+' | head -1 | tr -d '("')
    busy="${busy:+$busy, }:$p${owner:+ ($owner)}"
  fi
done
if [ -n "$busy" ]; then
  echo "VEILERR: на этом сервере уже СЛУШАЮТСЯ порты$busy — релей по ним не сработает. Останови их держателей (например: systemctl stop xray nginx telemt) или укажи в панели только свободные порты, и запусти установку снова"
  exit 3
fi
mkdir -p /etc/veil-relay
printf 'BACK_IP=%s\\nRELAY_PORTS="%s"\\n' "__BACK_IP__" "__PORTS_SP__" > /etc/veil-relay/relay.env
cat > /usr/local/bin/veil-relay-apply.sh <<'VEILEOF'
__APPLY_SH__VEILEOF
chmod 0755 /usr/local/bin/veil-relay-apply.sh
printf 'net.ipv4.ip_forward = 1\\n' > /etc/sysctl.d/99-veil-relay.conf
sysctl -p /etc/sysctl.d/99-veil-relay.conf >/dev/null 2>&1 || true
cat > /etc/systemd/system/veil-relay.service <<'VEILEOF'
__UNIT__VEILEOF
systemctl daemon-reload
systemctl enable veil-relay >/dev/null 2>&1 || true
systemctl restart veil-relay
sleep 1
systemctl is-active --quiet veil-relay || { echo "VEILERR: служба veil-relay не активна"; exit 4; }
nft list table ip veil_relay >/dev/null 2>&1 || { echo "VEILERR: таблица veil_relay не видна в nft"; exit 5; }
echo "VEILOK: релей активен, порты __PORTS_SP__ -> __BACK_IP__"
if [ -n "__TOK__" ]; then
  RESP=$(curl -sk -m 20 -X POST "__REG_URL__" -H 'Content-Type: application/json' \\
         -d '{"tok":"__TOK__"}' 2>/dev/null || true)
  case "$RESP" in
    *'"ok": true'*|*'"ok":true'*) echo "VEILREG: фронт зарегистрирован в панели" ;;
    *) echo "VEILREGW: правила работают, но панель не приняла регистрацию: ${RESP:-нет ответа} (открой порт панели в фаерволе фронта)" ;;
  esac
fi
exit 0
"""

def _relay_installer(hop, with_register=False):
    ports = " ".join(str(p) for p in hop["ports"])
    panel_port = int(CFG_CACHE.get("panel_port", 8444) or 8444)
    reg_url = "https://%s:%d/api/hop/register" % (hop.get("back_ip"), panel_port)
    tok = (hop.get("tok") or "") if with_register else ""
    body = (_RELAY_INSTALL_TMPL
            .replace("__APPLY_SH__", _RELAY_APPLY_SH)
            .replace("__UNIT__", _RELAY_UNIT)
            .replace("__BACK_IP__", hop["back_ip"])
            .replace("__PORTS_SP__", ports)
            .replace("__TOK__", tok)
            .replace("__REG_URL__", reg_url))
    return body

def _hop_find_tok(tok):
    if not re.fullmatch(r"[A-Za-z0-9_\-]{10,64}", tok or ""):
        return None
    for h in _hop_load():
        if (h.get("tok") or "") == tok:
            return h
    return None

def _hop_preview(front_ip, ports):
    front_ip = (front_ip or "").strip()
    ports = [x for x in re.split(r"[,\s]+", str(ports or "").strip()) if x] if isinstance(ports, str) else list(ports or [])
    blockers = []
    back = _hop_back_ip()
    pl = _hop_valid_ports(ports)
    if not _hop_is_ip4(front_ip):
        blockers.append("адрес ФРОНТа — не IPv4 (релей работает по IPv4)")
    if pl is None:
        blockers.append("порты: от 1 до %d значений 1..65535, без повторов" % _HOP_MAX_PORTS)
        pl = []
    if not _hop_is_ip4(back or ""):
        blockers.append("не удаётся определить публичный IPv4 этого сервера (БЭКа)")
    elif front_ip and front_ip == back:
        blockers.append("адрес ФРОНТа совпадает с этим сервером — бэк не может релеежить сам себя")
    panel_port = int(CFG_CACHE.get("panel_port", 8444) or 8444)
    if 22 in pl:
        blockers.append("порт 22 не релееят — отключи SSH фронта от бэка")
    note = ("На ФРОНТе будет создана nft-таблица veil_relay: DNAT портов [%s] на %s и "
            "MASQUERADE. Бэк будет видеть IP фронта вместо IP клиента (учёт по IP "
            "устройств на бэке перестанет различать подписчиков фронта — это ожидаемо). "
            "Установка обратима: кнопка «Удалить» снимает службу и правила."
            % (", ".join(map(str, pl)) or "—", back or "?"))
    return {"front_ip": front_ip, "ports": pl, "back_ip": back,
            "blockers": blockers, "can_apply": not blockers,
            "panel_port": panel_port, "note": note}

def _hop_add(name, front_ip, ports):
    pv = _hop_preview(front_ip, ports)
    if not pv["can_apply"]:
        raise RuntimeError("; ".join(pv["blockers"]))
    hops = _hop_load()
    if any((h.get("front_ip") == pv["front_ip"]) for h in hops):
        raise RuntimeError("фронт с таким адресом уже добавлен — обнови его или удали")
    hid = uuidlib.uuid4().hex[:12]
    hop = {"id": hid, "name": (name or "Фронт")[:40], "front_ip": pv["front_ip"],
           "ports": pv["ports"], "back_ip": pv["back_ip"], "state": "pending",
           "tok": secrets.token_urlsafe(24), "tok_exp": int(time.time()) + 1800,
           "added": int(time.time()), "last_check": None}
    hops.append(hop)
    _hop_save(hops)
    _audit("hop_add", id=hid, front_ip=pv["front_ip"], ports=pv["ports"])
    panel_port = pv["panel_port"]
    curl = ("curl -sk https://%s:%s/relay.sh?tok=%s | sudo bash"
            % (pv["back_ip"], panel_port, hop["tok"]))
    return {"id": hid, "state": "pending", "curl": curl, "ttl_sec": 1800}

def _hop_public(ip, port, timeout=1.6):
    try:
        s = socket.create_connection((ip, int(port)), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False

def _hop_check(hid=None):
    hops = _hop_load()
    targets = [h for h in hops if (hid is None or h.get("id") == hid)]
    if hid is not None and not targets:
        raise RuntimeError("хоп не найден")
    out = []
    for h in targets:
        res = [{"port": p, "tcp": _hop_public(h["front_ip"], p)} for p in (h.get("ports") or [])]
        h["last_check"] = {"ts": int(time.time()), "tcp_up": [r["port"] for r in res if r["tcp"]],
                           "tcp_down": [r["port"] for r in res if not r["tcp"]]}
        if h["state"] == "pending" and not any(r["tcp"] for r in res):
            pass
        out.append({"id": h["id"], "front_ip": h["front_ip"], "state": h["state"], "check": res})
    _hop_save(hops)
    return {"hops": out,
            "note": "Проба идёт с бэка через фронт: успех = весь путь DNAT+MASQUERADE работает "
                    "(для портов, где сам бэк что-то слушает, это кольцо бэк→фронт→бэк). "
                    "UDP-порты (WireGuard/Hysteria2) этой пробой не проверяются. "
                    "Не забудь открыть порты в security group облака фронта."}

def _hop_ssh_job(hid, user, password, ssh_port):
    jid = uuidlib.uuid4().hex[:12]
    steps = ["SSH-доступ", "Права root", "Установка релея", "Проверка"]
    job = {"id": jid, "hop": hid,
           "steps": [{"name": s, "state": "pending", "detail": ""} for s in steps],
           "done": False, "ok": False, "error": None, "created": int(time.time()),
           "params": {"user": user, "password": password, "ssh_port": ssh_port}}
    with HOP_LOCK:
        HOP_JOBS[jid] = job
        if len(HOP_JOBS) > 30:
            old = sorted(HOP_JOBS, key=lambda k: HOP_JOBS[k]["created"])[:-20]
            for k in [x for x in old if HOP_JOBS[x]["done"]]:
                HOP_JOBS.pop(k, None)
    threading.Thread(target=_hop_ssh_worker, args=(jid,), daemon=True).start()
    return jid

def _hop_ssh_worker(jid):
    import shlex
    with HOP_LOCK:
        job = HOP_JOBS.get(jid) or {}
        prm = dict(job.get("params") or {})
    def st(i, s, d=""):
        with HOP_LOCK:
            j = HOP_JOBS.get(jid)
            if j:
                j["steps"][i]["state"] = s
                if d:
                    j["steps"][i]["detail"] = str(d)[:300]
    def finish(ok, err=None):
        with HOP_LOCK:
            job["done"] = True
            job["ok"] = bool(ok)
            job["error"] = err
            jp = job.get("params") or {}
            jp["password"] = ""
    def fail(i, msg):
        st(i, "failed", msg)
        finish(False, msg)
        try:
            _audit("hop_bootstrap_fail", id=job.get("hop"), step=i, error=str(msg)[:200])
        except Exception:
            pass
    hid = job.get("hop") or ""
    hop = next((h for h in _hop_load() if h.get("id") == hid), None)
    if not hop:
        return fail(0, "хоп не найден")
    host = hop.get("front_ip") or ""
    user = prm.get("user") or "root"
    password = prm.get("password") or ""
    sport = int(prm.get("ssh_port") or 22)
    try:
        st(0, "running")
        keyfile, pubkey = _boot_host_key("hop:" + host + ":" + str(sport))
        base = ["/usr/bin/ssh", "-p", str(sport)] + _ssh_opts(keyfile)
        target = "%s@%s" % (user, host)

        def key_run(cmd, timeout=60, input=None):
            return subprocess.run(base + [target, cmd], capture_output=True, text=True,
                                  timeout=timeout, input=input,
                                  stdin=subprocess.DEVNULL if input is None else None)
        try:
            ok_key = key_run("true", timeout=20).returncode == 0
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
            try:
                pubtxt = open(pubkey).read().strip().replace("'", "'\\''")
            except Exception:
                pubtxt = ""
            if not pubtxt:
                return fail(0, "не читается публичный ключ панели")
            r = _boot_askpass_run(password, base + [target,
                  "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; "
                  "grep -qxF '%s' ~/.ssh/authorized_keys || printf '%%s\\n' '%s' "
                  ">> ~/.ssh/authorized_keys" % (pubtxt, pubtxt)], timeout=45)
            if r.returncode != 0:
                return fail(0, "установка ключа: " + (r.stderr or b"").decode("utf-8", "ignore")[:200])
            try:
                ok_key = key_run("true", timeout=20).returncode == 0
            except Exception:
                ok_key = False
            if not ok_key:
                return fail(0, "ключ панели не принимается после установки")
        st(0, "done", "вход по ключу панели")

        st(1, "running")
        r = key_run('u=$(id -u); p=$(command -v sudo || true); '
                    'if [ "$u" = 0 ]; then m=root; elif [ -n "$p" ] && sudo -n true 2>/dev/null; '
                    'then m=sudo_n; elif [ -n "$p" ]; then m=s_s; else m=none; fi; '
                    'if command -v ss >/dev/null 2>&1; then s=ss; else s=noss; fi; echo "$m $s"', timeout=30)
        if r.returncode != 0:
            return fail(1, "SSH-команда не прошла: " + (r.stderr or r.stdout or "")[:150])
        parts = (r.stdout or "").split()
        mode = parts[0] if parts else "none"
        if len(parts) > 1 and parts[1] == "noss":
            return fail(1, "на фронте нет ss (iproute2) — не проверить занятость портов")
        if mode == "s_s":
            try:
                if key_run("sudo -S -p '' true", timeout=30,
                           input=password.rstrip("\n") + "\n").returncode == 0:
                    mode = "sudo_s"
            except Exception:
                pass
        if mode not in ("root", "sudo_n", "sudo_s"):
            return fail(1, "нужны root или sudo (парольный или без пароля)")
        st(1, "done", {"root": "root", "sudo_n": "sudo без пароля", "sudo_s": "sudo с паролем"}[mode])

        st(2, "running")
        script = _relay_installer(hop, with_register=True)
        shell = "bash -euo pipefail -s"
        stdin_txt = script
        if mode == "sudo_n":
            shell = "sudo -n bash -euo pipefail -s"
        elif mode == "sudo_s":
            shell = "sudo -S -p '' bash -euo pipefail -s"
            stdin_txt = password.rstrip("\n") + "\n" + script
        r = subprocess.run(base + [target, shell], capture_output=True, text=True,
                           timeout=240, input=stdin_txt)
        out = (r.stdout or "") + (r.stderr or "")
        errline = ""
        for ln in out.splitlines():
            if ln.startswith("VEILERR:"):
                errline = ln[len("VEILERR:"):].strip()
        if r.returncode != 0 or "VEILOK" not in out:
            return fail(2, errline or ("установка не подтверждена: " + out[-200:]))
        st(2, "done", errline or "veil-relay: active")

        st(3, "running")
        hops = _hop_load()
        h = next((x for x in hops if x.get("id") == hid), None)
        if h is None:
            return fail(3, "хоп исчез из hops.json")
        h["state"] = "active"
        h["ssh_user"] = user
        h["ssh_port"] = sport
        h["ssh_key"] = keyfile
        registered = "VEILREG:" in out
        h["registered"] = registered
        _hop_save(hops)
        tcp = [{"port": p, "tcp": _hop_public(host, p)} for p in hop["ports"]]
        h["last_check"] = {"ts": int(time.time()),
                           "tcp_up": [c["port"] for c in tcp if c["tcp"]],
                           "tcp_down": [c["port"] for c in tcp if not c["tcp"]]}
        _hop_save(hops)
        st(3, "done", "TCP открыт: " + (", ".join(str(c["port"]) for c in tcp if c["tcp"]) or "нет (проверь security group)"))
        finish(True)
        _audit("hop_bootstrap_ok", id=hid, front_ip=host, ports=hop["ports"])
    except Exception as e:
        fail(2, "исключение: " + str(e)[:200])

def _hop_register(tok, peer_ip):
    hop = _hop_find_tok(tok)
    if hop is None:
        raise RuntimeError("ссылка не найдена или уже использована")
    if int(hop.get("tok_exp") or 0) < time.time():
        raise RuntimeError("срок жизни токена истёк — создай фронт заново")
    hops = _hop_load()
    h = next((x for x in hops if x.get("id") == hop["id"]), None)
    if h is None:
        raise RuntimeError("хоп удалён из панели")
    already = h.get("state") == "active"
    h["state"] = "active"
    h["peer_seen"] = peer_ip
    h["registered_ts"] = int(time.time())
    _hop_save(hops)
    if not already:
        _audit("hop_register", id=h["id"], front_ip=h.get("front_ip"), peer=peer_ip)
    return {"ok": True, "note": "уже было активно" if already else "фронт активирован"}

def _hop_remove(hid, confirm=False):
    if not confirm:
        raise RuntimeError("нужно подтверждение (confirm): удаляет релей с ФРОНТа и запись")
    hops = _hop_load()
    h = next((x for x in hops if x.get("id") == hid), None)
    if not h:
        raise RuntimeError("хоп не найден")
    note = ""
    key = h.get("ssh_key") or ""
    if key and os.path.exists(key) and _ssh_target_ok(h.get("ssh_user") or "root", h.get("front_ip")):
        try:
            base = ["/usr/bin/ssh", "-p", str(int(h.get("ssh_port") or 22))] + _ssh_opts(key)
            target = "%s@%s" % (h.get("ssh_user") or "root", h.get("front_ip"))
            r = subprocess.run(base + [target,
                "systemctl disable --now veil-relay >/dev/null 2>&1 || true; "
                "nft delete table ip veil_relay 2>/dev/null || true; "
                "rm -f /etc/veil-relay/relay.env /etc/veil-relay/relay.nft "
                "/etc/veil-relay/relay.nft /etc/systemd/system/veil-relay.service "
                "/usr/local/bin/veil-relay-apply.sh /etc/sysctl.d/99-veil-relay.conf; "
                "systemctl daemon-reload; rmdir /etc/veil-relay 2>/dev/null || true; echo VEILPURGED"],
                capture_output=True, text=True, timeout=45, stdin=subprocess.DEVNULL)
            note = ("очистка на фронте выполнена" if "VEILPURGED" in (r.stdout or "")
                    else "фронт не ответил на очистку — удалил только запись")
        except Exception:
            note = "фронт недоступен по SSH — удалил только запись"
    else:
        note = ("ключа SSH нет (установка была через curl) — на фронте останься: "
                "systemctl disable --now veil-relay && nft delete table ip veil_relay && "
                "rm -rf /etc/veil-relay /usr/local/bin/veil-relay-apply.sh /etc/sysctl.d/99-veil-relay.conf")
    hops = [x for x in hops if x.get("id") != hid]
    _hop_save(hops)
    if (CFG_CACHE.get("hop_public_host") or "").strip() == (h.get("front_ip") or ""):
        CFG_CACHE.pop("hop_public_host", None)
        _save(CFG, CFG_CACHE)
        note += "; публичный адрес сброшен (он принадлежал этому фронту)"
    _audit("hop_remove", id=hid, front_ip=h.get("front_ip"))
    return {"ok": True, "note": note}

def _hop_set_public(host):
    host = (host or "").strip().lower()
    warn = ""
    if host:
        if any(c in host for c in ":/ @\\") or len(host) > 253 or not re.fullmatch(r"[a-z0-9._\-]+", host):
            raise RuntimeError("адрес — домен или IPv4, без протокола, слэшей и порта")
        hops = _hop_load()
        known = [x.get("front_ip") for x in hops if x.get("front_ip")]
        if host not in known:
            warn = "ни один добавленный фронт не имеет этот адрес — ссылки могут вести в никуда"
        CFG_CACHE["hop_public_host"] = host
    else:
        CFG_CACHE.pop("hop_public_host", None)
    _save(CFG, CFG_CACHE)
    _audit("hop_public_set", host=host or "(reset)")
    return {"hop_public_host": host, "warn": warn,
            "note": "ссылки подписок и прокси пересоберутся на новый адрес; подписчикам с Telegram "
                    "панель отправит уведомление в течение минуты, на /p появится подсказка"}

def _hop_relink(hid):
    hops = _hop_load()
    h = next((x for x in hops if x.get("id") == hid), None)
    if not h:
        raise RuntimeError("хоп не найден")
    if h.get("state") == "active":
        raise RuntimeError("фронт уже активен — новая ссылка не требуется")
    h["tok"] = secrets.token_urlsafe(24)
    h["tok_exp"] = int(time.time()) + 1800
    _hop_save(hops)
    _audit("hop_relink", id=hid, front_ip=h.get("front_ip"))
    return {"curl": "curl -sk https://%s:%s/relay.sh?tok=%s | sudo bash"
                    % (h.get("back_ip"), int(CFG_CACHE.get("panel_port", 8444) or 8444), h["tok"]),
            "ttl_sec": 1800}

def _hop_public_view():
    hops = []
    now = int(time.time())
    for h in _hop_load():
        d = {k: v for k, v in h.items() if k not in ("tok", "tok_exp")}
        alive = h.get("state") == "pending" and int(h.get("tok_exp") or 0) > now
        d["tok_alive"] = alive
        d["tok_left"] = max(0, int(h.get("tok_exp") or 0) - now) if h.get("state") == "pending" else 0
        hops.append(d)
    return {"hops": hops,
            "hop_public_host": (CFG_CACHE.get("hop_public_host") or "").strip(),
            "back_ip": _hop_back_ip(),
            "panel_port": int(CFG_CACHE.get("panel_port", 8444) or 8444),
            "suggest_ports": _hop_suggest_ports(),
            "addr_prev": str(CFG_CACHE.get("addr_prev") or ""),
            "addr_changed": int(CFG_CACHE.get("addr_changed") or 0)}

def _addr_watch_tick():
    """Присмотр за адресом сервера в ссылках подписок (ddns/hop/переезд/смена IP):
    хост изменился — пометка addr_changed (баннер на /p неделю), push подписчикам
    с tg_chat и отчёт администраторам. Ссылки /sub пересобираются сами при каждой
    выдаче, поэтому клиенту нужно лишь обновить подписку или взять ссылку заново.
    Кулдаун 10 мин — адрес может «моргнуть» при переезде, не заспамить клиентов."""
    try:
        cur = (_hop_pub_host() or "").strip().lower()
    except Exception:
        return
    if not cur or cur == "127.0.0.1":
        return
    last = str(CFG_CACHE.get("addr_host") or "")
    if not last:
        CFG_CACHE["addr_host"] = cur
        _save(CFG, CFG_CACHE)
        return
    if last == cur:
        return
    now = int(time.time())
    CFG_CACHE["addr_host"] = cur
    if now - int(CFG_CACHE.get("addr_changed") or 0) < 600:
        _save(CFG, CFG_CACHE)
        return
    CFG_CACHE["addr_changed"] = now
    CFG_CACHE["addr_prev"] = last
    _save(CFG, CFG_CACHE)
    _audit("addr_change", old=last, new=cur)
    print("[addr] адрес подписок изменён: %s → %s" % (last, cur), flush=True)
    try:
        subs = [x for x in _subs_summary(_load(STATE) or {})
                if str(x.get("tg_chat") or "")]
    except Exception:
        subs = []
    chats = {}
    for x in subs:
        chats.setdefault(str(x["tg_chat"]), x)
    notified = 0
    for cid, x in list(chats.items())[:500]:
        try:
            Bc = _bot_B(cid)
            kb = {"inline_keyboard": [
                [{"text": Bc["m_sub_link"], "callback_data": "sub_link"}],
                [{"text": Bc["m_sub_page"], "url": _bot_sub_urls(x)[1]}]]}
            _bot_send_message(cid, Bc["addr_moved"] % _html.escape(cur), "HTML", kb)
            notified += 1
            time.sleep(0.05)
        except Exception:
            pass
    ids = [str(v) for v in (CFG_CACHE.get("bot_chat_ids") or [])][:8]
    if ids:
        try:
            Ba = _bot_B(ids[0])
            msg = Ba["addr_admin"] % (_html.escape(last), _html.escape(cur), notified)
            for aid in ids:
                try:
                    _bot_send_message(aid, msg, "HTML")
                except Exception:
                    pass
        except Exception as e:
            print("[addr] admin: " + str(e)[:120], flush=True)

def _mux_preview(vpn_domain=None):
    web_domain = (CFG_CACHE.get("panel_domain") or "").strip()
    vpn_domain = (vpn_domain or (("vpn." + web_domain) if web_domain else "")).strip().lower()
    ms = _mux_status()
    ng = ms["nginx"]
    blockers = []
    if not ng["installed"]:
        blockers.append("nginx не установлен")
    elif not (ng["stream"] and ng["ssl_preread"]):
        blockers.append("nginx собран без stream/ssl_preread — SNI-mux невозможен")
    elif not _mux_stream_module_state()[0]:
        blockers.append("stream-модуль не установлен (сборка динамическая): выполните apt-get install -y libnginx-mod-stream")
    if not web_domain:
        blockers.append("не задан домен панели (веб-SNI)")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,252}[a-z0-9])?", vpn_domain or ""):
        blockers.append("некорректный SNI-домен VPN")
    st = _load(STATE, {}) or {}
    inb = (st.get("inbounds") or {}).get(_MUX_INBOUND)
    if inb is None:
        blockers.append("нет inbound «%s» — включите любой cert-TLS inbound" % _MUX_INBOUND)
    if ms["reality_port"] == 443 or (ms["xray_holds_443"] and not ms["our_nginx_443"]):
        blockers.append("xray/Reality держит :443 — сначала перенесите Reality на другой порт (мюкс не трогает Reality)")
    web_held = ms["our_nginx_443"]
    foreign = (not ms["free443"]) and (not web_held) and ("xray" not in (ms["occupant443"].get("proc") or ""))
    if ms["applied"]:
        note = "Мюкс уже применён — apply перепишет конфигурацию (идемпотентно)."
    else:
        note = ("nginx stream на :443 разведёт SNI: %s→xray(loopback :%s), %s/default→веб(:%s). "
                "Reality остаётся на :%s. Сертификат: %s."
                % (vpn_domain or "?", 4443, web_domain or "?", 8445,
                   ms["reality_port"] or "—", "LE" if ms["has_cert"] else "self-signed (SAN на оба имени)"))
    return {"web_domain": web_domain, "vpn_domain": vpn_domain, "can_apply": not blockers,
            "blockers": blockers, "reality_port": ms["reality_port"],
            "web_front_on443": web_held, "foreign443": (ms["occupant443"] if foreign else None),
            "cert_kind": ("le" if ms["has_cert"] else "self-signed"), "note": note}

def _mux_apply(vpn_domain=None, confirm=False, force=False):
    if not confirm:
        raise RuntimeError("нужно подтверждение (confirm): apply меняет nginx.conf и xray")
    pv = _mux_preview(vpn_domain)
    if not pv["can_apply"]:
        raise RuntimeError("нельзя применить: " + "; ".join(pv["blockers"]))
    web_domain, vpn_domain = pv["web_domain"], pv["vpn_domain"]
    occ = _sock_occupant(443)
    web_held = ("nginx" in (occ.get("proc") or "")) and os.path.exists(_NG_CONF)
    if not occ["free"] and not web_held:
        if not force:
            raise RuntimeError("на :443 процесс %s — передайте force, чтобы остановить (с бэкапом unit)"
                               % (occ.get("proc") or "?"))
        for pid in occ.get("pids") or []:
            try:
                unit = _proc_unit(pid)
                if unit and unit not in ("nginx.service", "xray.service", "vpnpanel.service"):
                    subprocess.run(["systemctl", "stop", unit], capture_output=True, timeout=30)
            except Exception:
                pass
    cert, key, kind = _mux_cert(web_domain, vpn_domain)
    avail, mod_directive = _mux_stream_module_state()
    if not avail:
        raise RuntimeError("stream-модуль nginx не установлен — выполните apt-get install -y libnginx-mod-stream")
    used = _mux_ports_in_use()
    web_port = _find_free_port(pref=[8445], avoid=used)
    tls_port = _find_free_port(pref=[4443], avoid=used | {web_port})

    if not os.path.exists(_NG_MAIN_BAK):
        shutil.copy2(_NG_MAIN, _NG_MAIN_BAK)
    with open(_NG_STREAM_INC, "w") as f:
        f.write(_mux_stream_conf(web_port, tls_port, web_domain, vpn_domain))
    # подключаем stream-вставку в nginx.conf (топ-левел); load_module — только если модуль не грузится сам
    main = open(_NG_MAIN_BAK).read()
    changed = False
    if mod_directive and mod_directive not in main:
        main = mod_directive + "\n" + main
        changed = True
    if "veil-mux-stream.conf" not in main:
        main = main.rstrip("\n") + "\n\n# VEIL-MUX BEGIN\ninclude %s;\n# VEIL-MUX END\n" % _NG_STREAM_INC
        changed = True
    if changed:
        with open(_NG_MAIN, "w") as f:
            f.write(main)

    moved_web = False
    if web_held:
        if not os.path.exists(_NG_WEB_BAK):
            shutil.copy2(_NG_CONF, _NG_WEB_BAK)
        conf = open(_NG_WEB_BAK).read()
        conf = re.sub(r"(?m)^(\s*listen\s+)443(\s+ssl\b)", r"\g<1>%d\g<2>" % web_port, conf)
        conf = re.sub(r"(?m)^(\s*listen\s+)\[::\]:443(\s+ssl\b)", lambda m: m.group(0), conf)
        with open(_NG_CONF, "w") as f:
            f.write(conf)
        moved_web = True
    else:
        with open(_NG_MUX_DEFAULT, "w") as f:
            f.write(_MUX_DEFAULT_TMPL.replace("{web_port}", str(web_port))
                    .replace("{web_domain}", web_domain).replace("{cert}", cert).replace("{key}", key))

    # xray: переводим cert-TLS inbound на loopback:tls_port с нашим сертификатом
    st = _load(STATE, {}) or {}
    inb = st["inbounds"][_MUX_INBOUND]
    prev = {k: inb.get(k) for k in ("listen", "port", "cert", "key")}
    inb["listen"] = "127.0.0.1"; inb["port"] = tls_port; inb["cert"] = cert; inb["key"] = key
    inb["_mux_enabled"] = True
    ok, err = _validate_and_apply(st)
    if not ok:
        inb.update(prev); inb.pop("_mux_enabled", None)
        _revert_nginx_files(web_held)
        _save(STATE, st)
        raise RuntimeError("xray-валидация не пройдена, откатили: " + (err or ""))

    t = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=25)
    if t.returncode != 0:
        inb.update(prev); inb.pop("_mux_enabled", None)
        _save(STATE, st)
        _save(XRAY, _build_xray_cfg(st), 0o644); subprocess.run(["systemctl", "restart", "xray"], capture_output=True)
        _revert_nginx_files(web_held)
        raise RuntimeError("nginx -t упал, откатили: " + (t.stderr or t.stdout)[-400:])
    subprocess.run(["systemctl", "enable", "nginx"], capture_output=True)
    if subprocess.run(["systemctl", "is-active", "--quiet", "nginx"]).returncode == 0:
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, timeout=40)
    else:
        subprocess.run(["systemctl", "restart", "nginx"], capture_output=True, timeout=40)

    _save(_MUX_STATE, {"applied": True, "web_domain": web_domain, "vpn_domain": vpn_domain,
                       "web_port": web_port, "tls_port": tls_port, "cert_kind": kind,
                       "inbound": _MUX_INBOUND, "prev": prev, "moved_web": moved_web,
                       "ts": _now_iso()}, 0o600)
    return {"ok": True, "vpn_domain": vpn_domain, "web_domain": web_domain,
            "web_port": web_port, "tls_port": tls_port, "cert_kind": kind}

def _revert_nginx_files(web_held):
    try: os.remove(_NG_STREAM_INC)
    except Exception: pass
    try: os.remove(_NG_MUX_DEFAULT)
    except Exception: pass
    if os.path.exists(_NG_MAIN_BAK):
        shutil.copy2(_NG_MAIN_BAK, _NG_MAIN)
    if web_held and os.path.exists(_NG_WEB_BAK):
        shutil.copy2(_NG_WEB_BAK, _NG_CONF)

def _proc_unit(pid):
    try:
        c = open("/proc/%d/cgroup" % int(pid)).read()
    except Exception:
        return ""
    m = re.search(r"/([^/]+\.service)", c)
    return m.group(1) if m else ""

def _mux_revert(confirm=False):
    if not confirm:
        raise RuntimeError("нужно подтверждение (confirm)")
    ms = _load(_MUX_STATE, {}) or {}
    if not ms.get("applied"):
        return {"ok": True, "already": True, "message": "Мюкс не применён — откатывать нечего"}
    web_held = bool(ms.get("moved_web"))
    st = _load(STATE, {}) or {}
    inb = (st.get("inbounds") or {}).get(ms.get("inbound") or _MUX_INBOUND)
    if inb is not None:
        for k, v in (ms.get("prev") or {}).items():
            if v is None:
                inb.pop(k, None)
            else:
                inb[k] = v
        inb.pop("_mux_enabled", None)
        ok, err = _validate_and_apply(st)
        if not ok:
            return {"ok": False, "message": "xray после отката невалиден: " + (err or "")}
    _revert_nginx_files(web_held)
    subprocess.run(["nginx", "-t"], capture_output=True, timeout=25)
    if subprocess.run(["systemctl", "is-active", "--quiet", "nginx"]).returncode == 0:
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, timeout=40)
    else:
        subprocess.run(["systemctl", "restart", "nginx"], capture_output=True, timeout=40)
    for p in (_NG_MAIN_BAK, _NG_WEB_BAK):
        try: os.remove(p)
        except Exception: pass
    _save(_MUX_STATE, {"applied": False, "ts": _now_iso()}, 0o600)
    return {"ok": True, "message": "Мюкс откачен: nginx и xray возвращены к прежнему виду"}


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

# ---------- MTProto SYN-защита (nftables; порт логики MTPROTO_FIX_By_MEKO v3) ----------
# Публичный MTProto-порт круглосуточно сканируют каталогизаторы Telegram-прокси.
# Ограничить SYN-флуд просто — ломается Telegram iOS: он агрессивно шлёт дубли
# SYN (retransmit быстрее лимита). Поэтому три слоя, как в MEKO:
#  1) SYN с TCP-опциями iOS (отпечаток в заголовке) — accept без лимита;
#  2) все остальные — 54 SYN/мин на IP (реальному клиенту хватает с запасом);
#  3) сверх — reject «хост недоступен»: сканер видит фильтруемый порт.
# Таблица inet veil_synfix пересобирается панелью при старте, при смене порта
# MTProto и раз в минуту при дрейфе. После ребута ОС таблицы нет до старта
# панели — ok, окнами в 1 минуту защищаемся и сами не ломаемся.

_SYNFIX_LOCK = threading.Lock()

def _synfix_port():
    """Порт, который надо защищать: публичный MTProto listener telemt (0 = нечего)."""
    try:
        info = _tg_mtproto_info()
    except Exception:
        return 0
    try:
        port = int(info.get("port") or 0)
    except (TypeError, ValueError, AttributeError):
        port = 0
    return port if port and (info.get("up") or info.get("has_public_listener")) else 0

def _synfix_live():
    """(порт, число правил) живой таблицы veil_synfix; (0, 0) если таблицы нет."""
    try:
        r = subprocess.run(["nft", "list", "table", "inet", "veil_synfix"],
                           capture_output=True, text=True, timeout=5)
    except Exception:
        return (0, 0)
    if r.returncode != 0:
        return (0, 0)
    m = re.search(r"dport (\d+)", r.stdout or "")
    return (int(m.group(1)) if m else 0, (r.stdout or "").count("counter"))

def _synfix_apply():
    """Пересобрать inet/veil_synfix под текущий порт MTProto. Возвращает защищённый порт.
    _limits_loop стартует ещё на импорте модуля — его тик может совпасть со стартовым
    apply, поэтому пересборка таблицы под локом (иначе правила задвоятся)."""
    port = _synfix_port() if CFG_CACHE.get("synfix_enabled", True) else 0
    with _SYNFIX_LOCK:
        _f2b_nft("delete", "table", "inet", "veil_synfix")
        if not port:
            return 0
        _f2b_nft("add", "table", "inet", "veil_synfix")
        _f2b_nft("add", "chain", "inet", "veil_synfix", "input",
                 "{ type filter hook input priority 0; policy accept; }")
        # своя служебная проверка порта с loopback/из локальных сетей лимиту не
        # подлежит; туда же собственные публичные адреса — это hairpin-петля
        # (клиент под VPN → туннель → xray звонит на свой же :7443): её SYN
        # приходят с IP сервера и под лимит 54/мин попадать не должны.
        try:
            own = _own_ip_cidrs()
        except Exception:
            own = []
        v4 = ["0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
              "172.16.0.0/12", "192.168.0.0/16"] + [c for c in own if ":" not in c]
        v6 = ["::1/128", "fc00::/7", "fe80::/10"] + [c for c in own if ":" in c]
        _f2b_nft("add", "rule", "inet", "veil_synfix", "input",
                 'tcp dport %d ip saddr { %s } counter accept comment "local_accept"'
                 % (port, ", ".join(v4)))
        _f2b_nft("add", "rule", "inet", "veil_synfix", "input",
                 'tcp dport %d ip6 saddr { %s } counter accept comment "local6_accept"'
                 % (port, ", ".join(v6)))
        _f2b_nft("add", "rule", "inet", "veil_synfix", "input",
                 'tcp dport %d tcp flags & (syn|ack) == syn '
                 '@th,108,20 0x2ffff @th,160,16 0x204 @th,192,16 0x103 '
                 '@th,224,24 0x10108 @th,320,32 0x4020000 counter accept comment "ios_accept"' % port)
        _f2b_nft("add", "rule", "inet", "veil_synfix", "input",
                 'tcp dport %d tcp flags & (syn|ack) == syn '
                 'meter veil_synfix { ip saddr timeout 60s limit rate 54/minute burst 1 packets } '
                 'counter accept comment "other_accept"' % port)
        _f2b_nft("add", "rule", "inet", "veil_synfix", "input",
                 'meta nfproto ipv4 tcp dport %d tcp flags & (syn|ack) == syn counter '
                 'reject with icmp type host-unreachable comment "other_reject"' % port)
        # IPv6 зеркало: без него v6-SYN проваливаются в policy accept — шторм без лимита.
        _f2b_nft("add", "rule", "inet", "veil_synfix", "input",
                 'meta nfproto ipv6 tcp dport %d tcp flags & (syn|ack) == syn '
                 'meter veil_synfix6 { ip6 saddr timeout 60s limit rate 54/minute burst 1 packets } '
                 'counter accept comment "other6_accept"' % port)
        # IPv6-аналог host-unreachable в ядре называется no-route (type1 code0);
        # administratively-prohibited/host-unreachable nft здесь не принимает.
        _f2b_nft("add", "rule", "inet", "veil_synfix", "input",
                 'meta nfproto ipv6 tcp dport %d tcp flags & (syn|ack) == syn counter '
                 'reject with icmpv6 type no-route comment "other6_reject"' % port)
    return port

def _synfix_tick():
    """Самоцелость: таблица ушла (ребут/вмешательство) или порт поменялся — пересобрать."""
    want = _synfix_port() if CFG_CACHE.get("synfix_enabled", True) else 0
    live, _ = _synfix_live()
    if live != want:
        _synfix_apply()

# ---------- лимит устройств на клиента (P3) ----------
# Источник — access-лог Xray (в нём email == uuid клиента). Окно активности 15 мин;
# при превышении max_devices самое «молодое» устройство банируется на 2ч через
# veil_bans. WireGuard/amneziawg идут мимо Xray — для них лимит не применяется.
# Роуминг: человек вышел из Wi-Fi в мобильную сеть — приложение сменило IP, но это
# то же устройство. Если новый IP появился, а прежний адрес этого же клиента только
# что «затих» (пауза 1.5–7 минут — типичная смена сети), новый IP записывается в
# то же устройство, а не считается отдельным. Бан только если превышение держится
# дольше 2 минут — одним всплеском не наказываем.

_XRAY_ACCESS = f"{BASE}/logs/xray-access.log"
_DEV_WIN_SEC = 900
_DEV_BAN_SEC = 2 * 3600
_DEV_IDLE_LO = 90
_DEV_IDLE_HI = 420
_DEV_OVER_SEC = 120
_DEVTRACK = {}          # uuid -> {gid: {"ips": {ip: last_seen_ts}}}  gid = первый IP группы
_DEV_OVER = {}          # uuid -> ts, когда заметили превышение
_DEV_POS = [0, 0]       # [offset чтения, последний размер файла]
_DEV_POS_FILE = f"{BASE}/logs/xray-access.pos"
_DEV_POS_INIT = [False]

def _devpos_init():
    # смещение переживало рестарт панели: иначе после каждого перезапуска
    # весь журнал перечитывается и счётчики «чем пользуется» удваиваются
    if _DEV_POS_INIT[0]:
        return
    _DEV_POS_INIT[0] = True
    try:
        p = json.load(open(_DEV_POS_FILE))
        if (isinstance(p, list) and len(p) == 2
                and os.path.getsize(_XRAY_ACCESS) >= int(p[1])):
            _DEV_POS[:] = [int(p[0]), int(p[1])]
    except Exception:
        pass

# Пример строки: `2026-09-22 12:56:32.927 from 1.2.3.4:5678 accepted vless:... [in] [uuid]`
_ACC_RE = re.compile(r"^\S+\s+\S+\s+(?:from\s+)?(\S+)\s+accepted\b")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# Xray 26.x пишет «... [vless-ws >> direct] email: <uuid>»; раньше uuid был в скобках.
_ACC_TAG_RE = re.compile(r"\[([a-z][a-z0-9_-]*)")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")
_ACC_MAIL_RE = re.compile(
    r"email:\s*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")

def _acc_email(line):
    m = _ACC_MAIL_RE.search(line)
    if m:
        return m.group(1)
    for b in re.findall(r"\[([^\]]*)\]", line):
        if _UUID_RE.match(b.strip()):
            return b.strip()
    return ""

def _acc_tag(line):
    """Тег инбаунда из «[vless-ws >> direct]» = какой протоколом воспользовались."""
    m = _ACC_TAG_RE.search(line)
    return m.group(1) if m else ""

# Кто чем пользуется: счётчик заходов (sub_token → тег инбаунда → дни).
_PROTOACT_FILE = f"{BASE}/proto_activity.json"
_PROTOACT_LOCK = threading.Lock()
_PROTOACT = None
_PA_DAYS = 7          # окно статистики на /p
_PA_KEEP = 30         # держать в файле (для «был N дней назад»)

def _protoact_load():
    global _PROTOACT
    if _PROTOACT is None:
        try:
            d = json.load(open(_PROTOACT_FILE))
            _PROTOACT = d if isinstance(d, dict) else {}
        except Exception:
            _PROTOACT = {}
    return _PROTOACT

def _protoact_merge(cnt, now):
    """cnt: {sub_token: {tag: {дата: n}}}. Сливает в постоянное хранилище,
    чистит старые дни/токены, сохраняет только при изменениях."""
    changed = False
    today = time.strftime("%Y-%m-%d", time.gmtime(now))
    with _PROTOACT_LOCK:
        pa = _protoact_load()
        cutoff = time.strftime("%Y-%m-%d", time.gmtime(now - _PA_KEEP * 86400))
        for tok, tags in cnt.items():
            e = pa.setdefault(tok, {})
            for tag, days in tags.items():
                d = e.setdefault(tag, {"last": 0, "d": {}})
                for k, n in days.items():
                    d["d"][k] = int(d["d"].get(k) or 0) + n
                    changed = True
                # «в последний раз» двигаем только если сегодня реально были строки
                # журнала: при отмотке файла назад (первый tick) вчерашние дни
                # не должны выглядеть как «только что».
                if today in days:
                    d["last"] = int(now)
                    changed = True
        for tok in list(pa):
            e = pa[tok]
            for tag in list(e):
                dd = e[tag].get("d") or {}
                for k in [k for k in dd if k < cutoff]:
                    dd.pop(k, None)
                    changed = True
                if not dd and now - int(e[tag].get("last") or 0) > _PA_KEEP * 86400:
                    e.pop(tag, None)
                    changed = True
            if not e:
                pa.pop(tok, None)
                changed = True
        if changed:
            _save(_PROTOACT_FILE, pa)
    return changed

def _protoact_view(token):
    """Последние 7 дней для подписчика: [{tag, n, today, last}] по убыванию."""
    with _PROTOACT_LOCK:
        pa = _protoact_load()
        ent = {k: v for k, v in (pa.get(str(token or "")) or {}).items()}
    today = time.strftime("%Y-%m-%d", time.gmtime())
    days = {time.strftime("%Y-%m-%d", time.gmtime(time.time() - i * 86400))
            for i in range(_PA_DAYS)}
    out = []
    for tag, e in ent.items():
        dd = e.get("d") or {}
        n = sum(int(v or 0) for k, v in dd.items() if k in days)
        if n <= 0:
            continue
        last = int(e.get("last") or 0)
        if not last and dd:
            try:
                last = int(datetime.datetime.strptime(max(dd), "%Y-%m-%d").replace(
                    tzinfo=datetime.timezone.utc).timestamp()) + 86399
            except Exception:
                last = 0
        out.append({"tag": tag, "n": n, "today": int(dd.get(today) or 0), "last": last})
    out.sort(key=lambda x: -x["n"])
    return out

def _access_log_lines():
    _devpos_init()
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

def _dev_seen(email, ip, now):
    """Отметить подключение IP у клиента. Новый IP попадает в «роуминг» к самому
    давно затихшему устройству того же клиента, если пауза похожа на смену сети."""
    d = _DEVTRACK.setdefault(email, {})
    for g in d.values():
        if ip in g["ips"]:
            g["ips"][ip] = now
            return
    cands = [(max(g["ips"].values()), g) for g in d.values()
             if _DEV_IDLE_LO <= now - max(g["ips"].values()) <= _DEV_IDLE_HI]
    if cands:
        min(cands, key=lambda x: x[0])[1]["ips"][ip] = now
        return
    d[ip] = {"ips": {ip: now}}

def _device_tick(st):
    limits = {}
    names = {}
    tok_of = {}
    for proto, inb in (st.get("inbounds") or {}).items():
        for c in inb.get("clients", []):
            names[c["uuid"]] = c.get("name") or str(c["uuid"])[:8]
            if c.get("sub_token"):
                tok_of[c["uuid"]] = c["sub_token"]
            if proto in ("wireguard", "amneziawg"):
                continue
            md = int(c.get("max_devices") or 0)
            if md > 0:
                limits[c["uuid"]] = max(limits.get(c["uuid"], 0), md)
    now = time.time()
    pact = {}
    for line in _access_log_lines():
        m = _ACC_RE.match(line)
        if not m:
            continue
        email = _acc_email(line)
        if not email:
            continue
        tok = tok_of.get(email)
        if tok:
            tag = _acc_tag(line)
            if tag and tag != "api":
                day = line[:10] if _DATE_RE.match(line[:10]) else \
                    time.strftime("%Y-%m-%d", time.gmtime(now))
                pact.setdefault(tok, {}).setdefault(tag, {}).setdefault(day, 0)
                pact[tok][tag][day] += 1
        if email not in limits:
            continue
        ip = _strip_port(m.group(1))
        if _f2b_public(ip):
            _dev_seen(email, ip, now)
    if pact:
        try:
            _protoact_merge(pact, now)
        except Exception as e:
            print("[protoact] " + str(e), flush=True)
    try:
        _save(_DEV_POS_FILE, list(_DEV_POS))
    except Exception:
        pass
    if not limits:
        _DEVTRACK.clear()
        _DEV_OVER.clear()
        return
    for email in list(_DEVTRACK):
        if email not in limits:
            _DEVTRACK.pop(email, None)
            _DEV_OVER.pop(email, None)
    for email, md in limits.items():
        d = _DEVTRACK.get(email)
        if not d:
            _DEV_OVER.pop(email, None)
            continue
        for gid in list(d):
            ips = d[gid]["ips"]
            for ip, ts in list(ips.items()):
                if now - ts > _DEV_WIN_SEC:
                    ips.pop(ip, None)
            if not ips:
                d.pop(gid, None)
        if len(d) <= md:
            _DEV_OVER.pop(email, None)
            continue
        since = _DEV_OVER.setdefault(email, now)
        if now - since < _DEV_OVER_SEC:
            continue     # превышение могло быть от роуминга — наказываем не сразу
        _DEV_OVER.pop(email, None)
        # «нарушитель» — самое молодое устройство (не тот, кто сидит давно)
        gid = max(d, key=lambda g: max(d[g]["ips"].values()))
        g = d.pop(gid)
        vip = max(g["ips"], key=lambda ip: g["ips"][ip])
        if _f2b_has_session(vip):
            continue
        if not _ban_ip(vip, _DEV_BAN_SEC, "devices:" + str(email)[:8]):
            break
        _audit("device_ban", ip=vip, uuid=email, name=names.get(email, ""),
               max_devices=md, roam=len(g["ips"]))
        print("[devices] бан " + vip + " (клиент " + names.get(email, "") + ")",
              flush=True)
        try:
            ids = CFG_CACHE.get("bot_chat_ids") or []
            if ids:
                _bot_send_message(ids[0],
                    f"📱 <b>Лимит устройств</b>\nКлиент: {names.get(email, '?')}\n"
                    f"Разрешено: {md}, новое устройство {vip} забанено на 2ч", "HTML")
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
_RULESET_FILES = {"geoip-ru.srs", "geosite-ru.srs", "geoip-ir.db", "geosite-ir.db",
                  "geoip-ru.dat", "geosite-ru.dat"}
_RULESET_STATE = {"updated": 0, "error": "", "tag_ru": "", "tag_ir": ""}

def _gh_release_latest(repo):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers=_gh_headers())
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)

def _geo_dat_trim(buf, keep):
    """Обрезка xray-дайджеста .dat до нужных кодов, чтобы мобильный клиент
    успевал скачать базу: зеркало runetfreedom весит 18/73 МБ, а Happ/INCY
    обрывают загрузку геофайлов дольше ~3 минут. Формат — GeoData: поток
    записей 0x0a <varint len> <GeoField>, имя кода — string-поле 1 (у
    зеркал оно ВЕРХНЕГО регистра; поиск xray регистронезависим). Возвращает
    new bytes или None (тогда пишем полный файл). Если хоть одного кода из
    keep нет — тоже None: лучше медленная полная база, чем битая."""
    n = len(buf)
    def rdv(b, o):
        v = 0; sh = 0
        while o < len(b):
            c = b[o]; o += 1
            v |= (c & 0x7F) << sh
            if not c & 0x80:
                return v, o
            sh += 7
        raise ValueError("varint")
    def varint_enc(k):
        out = bytearray()
        while True:
            c = k & 0x7F; k >>= 7
            out.append(c | (0x80 if k else 0))
            if not k:
                return bytes(out)
    def gtype(payload):
        o = 0
        while o < len(payload):
            key, o = rdv(payload, o)
            fn, wt = key >> 3, key & 7
            if wt == 2:
                ln, o = rdv(payload, o)
                if fn == 1:
                    return payload[o:o+ln].decode("ascii", "ignore")
                o += ln
            elif wt == 0:
                _, o = rdv(payload, o)
            elif wt == 5:
                o += 4
            elif wt == 1:
                o += 8
            else:
                return None
        return None
    out = bytearray(); found = set(); off = 0
    while off < n:
        if buf[off] != 0x0A:
            return None
        off += 1
        ln, off = rdv(buf, off)
        end = off + ln
        if end > n:
            return None
        payload = buf[off:end]; off = end
        t = gtype(payload)
        if t is None:
            return None
        if t.upper() in keep:
            found.add(t.upper())
            out += b"\x0a" + varint_enc(ln) + payload
    if found != {k.upper() for k in keep}:
        return None
    return bytes(out)

# Какие коды нужны профилю «Veil» из _routing_profile_b64 — остальное вырезаем.
_RULESET_TRIM = {"geoip-ru.dat": {"RU", "PRIVATE", "IR"},
                 "geosite-ru.dat": {"CATEGORY-RU"}}

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
            # Xray-формат (.dat) для INCY и других xray-клиентов — телефон не должен
            # тянуть GitHub сам (в РФ он без VPN недоступен).
            for src_name, dst_name in (("geoip.dat", "geoip-ru.dat"),
                                       ("geosite.dat", "geosite-ru.dat")):
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
                dstp = os.path.join(RULESET_DIR, dst_name)
                tb = None
                if dst_name in _RULESET_TRIM:
                    try:
                        with open(p, "rb") as f:
                            raw = f.read()
                        tb = _geo_dat_trim(raw, _RULESET_TRIM[dst_name])
                        if tb:
                            print(f"[rulesets] {dst_name}: {len(raw)} -> {len(tb)} Б (обрезка до нужных кодов)", flush=True)
                    except Exception as e:
                        tb = None
                        print(f"[rulesets] обрезка {dst_name} не удалась: {e}", flush=True)
                if tb:
                    with open(dstp, "wb") as f:
                        f.write(tb)
                else:
                    shutil.copy2(p, dstp)
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

_OWN_IP_CACHE = {"cidrs": [], "ts": 0.0}

def _own_ip_cidrs():
    """Публичные адреса самой панели (v4+v6, плюс IPv4-литерал хопа). Берутся ИЗ ДВУХ
    мест и объединяются: внешний эхо-сервис (_pub_ip4/_pub_ip6) и последний опубликованный
    в DDNS адрес — ровно то, что резолвит клиент. Под VPN эти адреса обязаны идти мимо
    туннеля (direct), иначе клиент петлёй заходит на тот же VPS и MTProto/webproxy
    не подключается. При смене IP панель перепроверяет сама: кэш короткий, а после
    обновления DDNS (_dynv6_update) он сбрасывается."""
    now = time.time()
    if _OWN_IP_CACHE["cidrs"] and now - _OWN_IP_CACHE["ts"] < 120:
        return _OWN_IP_CACHE["cidrs"]
    ips = []
    try:
        ip4 = _pub_ip4() or ""
    except Exception:
        ip4 = ""
    if ip4:
        ips.append(ip4)
    try:
        ip6 = _pub_ip6() or ""
    except Exception:
        ip6 = ""
    if ip6:
        ips.append(ip6)
    for k in ("ipv4", "ipv6"):
        v = _DDNS.get(k) or ""
        if v:
            ips.append(v)
    hop = (CFG_CACHE.get("hop_public_host") or "").strip()
    if re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", hop) or \
            (":" in hop and re.fullmatch(r"[0-9a-fA-F:]+", hop)):
        ips.append(hop)
    # Куда клиент реально стучится: A/AAAA собственного домена панели и wg-эндпоинта.
    for d in ((CFG_CACHE.get("panel_domain") or "").strip(), hop, _wg_auto_domain()):
        if d and not re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", d) and ":" not in d:
            try:
                for r in socket.getaddrinfo(d, None, proto=socket.IPPROTO_TCP):
                    ips.append(r[4][0])
            except Exception:
                pass
    out = [ip + ("/32" if ":" not in ip else "/128")
           for ip in dict.fromkeys(ips)
           if re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", ip) or
              (":" in ip and re.fullmatch(r"[0-9a-fA-F:.]+", ip))]
    if out:
        _OWN_IP_CACHE["cidrs"] = out
        _OWN_IP_CACHE["ts"] = now
    return out

def _own_direct_ips():
    """Те же адреса панели, но без маски (Xray DirectIp/INCY принимает чистые IP)."""
    return [c.split("/")[0] for c in _own_ip_cidrs()]

def _wg_full_tunnel_allowed_ips():
    """AllowedIPs полного туннеля, но ВНЕ его — адреса самого VPS (тот самый «IP в
    direct», только не руками в приложении, а в раздаваемом .conf): трафик к
    прокси панели под VPN идёт напрямую, а не петлёй через туннель на тот же VPS.
    WG не умеет exclude, поэтому 0.0.0.0/0 минус /32 = 32 парных префикса, а ::/0
    минус /128 = 128. IPv6 важен: iOS при наличии AAAA стучится на v6, а v6-петля
    через wg0 сервером не прокидывается — MTProto под VPN молча не коннектит."""
    own = _own_ip_cidrs()
    out = []
    ips4 = [c for c in own if c.endswith("/32")]
    if ips4:
        a, b, c, d = (int(x) for x in ips4[0][:-3].split("."))
        v = (a << 24) | (b << 16) | (c << 8) | d
        for depth in range(32):
            sib = (v ^ (1 << (31 - depth))) & ~((1 << (31 - depth)) - 1)
            out.append("%d.%d.%d.%d/%d" % ((sib >> 24) & 255, (sib >> 16) & 255,
                                           (sib >> 8) & 255, sib & 255, depth + 1))
    else:
        out.append("0.0.0.0/0")
    ips6 = [c for c in own if c.endswith("/128")]
    if ips6:
        seen = set()
        for cidr in ips6:
            raw = socket.inet_pton(socket.AF_INET6, cidr[:-4])
            v = int.from_bytes(raw, "big")
            for depth in range(128):
                sib = (v ^ (1 << (127 - depth))) & ~((1 << (127 - depth)) - 1)
                p = "%s/%d" % (socket.inet_ntop(socket.AF_INET6,
                                                sib.to_bytes(16, "big")), depth + 1)
                if p not in seen:
                    seen.add(p)
                    out.append(p)
    else:
        out.append("::/0")
    return ", ".join(out)

def _sb_config(st, sub_path, host, panel_port):
    """Полный standalone-конфиг sing-box для подписчика: tun + all outbounds
    + split-tunnel RU/IR через rule-sets, раздаваемые панелью. None = нет клиента."""
    outs = []
    tags = []
    split = (CFG_CACHE.get("split_tunnel") or "off").strip().lower()
    for proto, inb in (st.get("inbounds") or {}).items():
        if proto == "amneziawg":
            continue  # magic-амнезия в sing-box wireguard не импортируется
        if inb.get("disabled"):
            continue
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
    # Адреса самой панели — всегда мимо туннеля (тот самый «IP в direct»): под VPN
    # клиент иначе уходит туннелем на тот же VPS и MTProto/webproxy не подключается.
    own = _own_ip_cidrs()
    if own:
        rules.append({"ip_cidr": own, "outbound": "direct"})
    dom = (CFG_CACHE.get("panel_domain") or "").strip()
    if dom and ":" not in dom and not re.fullmatch(r"[0-9.]+", dom):
        rules.append({"domain": [dom], "outbound": "direct"})
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

def _panel_backup_now():
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    bdir = os.path.join(BASE, "backup-v%s-%s" % (VERSION, ts))
    os.makedirs(bdir, exist_ok=True)
    for fn in ("panel.py", "index.html"):
        src = os.path.join(BASE, fn)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(bdir, fn))
    for b in _panel_backups()[7:]:
        try:
            shutil.rmtree(os.path.join(BASE, b["dir"]))
        except Exception:
            pass
    _audit("panel_backup", version=VERSION)
    return {"ok": True, "version": VERSION, "dir": os.path.basename(bdir)}

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
    if not re.fullmatch(r"[0-9][0-9.]*", str(version or "")):
        raise RuntimeError("недопустимое имя версии")
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
    if not re.fullmatch(r"[0-9][0-9.]*", str(version or "")):
        raise RuntimeError("недопустимое имя версии")
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

def _wg_auto_domain():
    """Домен-эндпоинт WireGuard из того DDNS, что уже настроен у панели.
    У основного домена (dynv6 .v6.navy) есть AAAA, и телефон при резолве уйдёт
    в мобильный IPv6-транспорт, который рвёт WG-сессию. Для каждого хоста dynv6
    панель заводит A-only поддомен wg.<host> (AAAA у него физически нет) —
    это человекочитаемый эндпоинт, переживающий смену IP без реимпорта."""
    c = CFG_CACHE or {}
    prov = (c.get("rot_provider") or "dynv6").strip().lower()
    dh = (c.get("dynv6_host") or "").strip().lower()
    pd = (c.get("panel_domain") or "").strip().lower()
    if dh and dh == pd and prov in ("dynv6", "both"):
        return "wg." + dh
    z = (c.get("cf_zone") or "").strip().lower()
    if z and prov == "cloudflare":
        return "wg." + z
    return ""

_D6_WG = {"zid": None, "rid": None, "ts": 0.0}
_D6_LOCK = threading.Lock()

def _dynv6_api(method, path, body=None):
    token = _dynv6_conf()["token"]
    if not token:
        raise RuntimeError("dynv6 токен не задан")
    data = json.dumps(body).encode() if body is not None else None
    err = None
    for _ in range(2):
        req = urllib.request.Request("https://dynv6.com/api/v2" + path, data=data, method=method,
                                     headers={"Content-Type": "application/json",
                                              "Accept": "application/json",
                                              "Authorization": "Bearer " + token})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                t = r.read().decode("utf-8", "replace")
            return json.loads(t) if t.strip() else None
        except urllib.error.HTTPError as e:
            try:
                msg = e.read().decode("utf-8", "replace")[:150]
            except Exception:
                msg = ""
            raise RuntimeError("dynv6 HTTP %d %s" % (e.code, msg))
        except Exception as e:
            err = e
            time.sleep(2)
    raise RuntimeError("dynv6: %s" % str(err)[:150])

def _dynv6_ensure_wg(host, ip4):
    """Создать/починить A-only запись wg.<host> в зоне dynv6. Идемпотентно."""
    with _D6_LOCK:
        now = time.time()
        if _D6_WG["zid"] and now - _D6_WG["ts"] < 3600:
            zid = _D6_WG["zid"]
        else:
            zs = _dynv6_api("GET", "/zones") or []
            zid = next((z.get("id") for z in zs
                        if (z.get("name") or "").lower() == host.lower()), None)
            if not zid:
                raise RuntimeError("зона %s не найдена в dynv6" % host)
            _D6_WG["zid"], _D6_WG["ts"] = zid, now
        recs = _dynv6_api("GET", "/zones/%s/records" % zid) or []
        if isinstance(recs, dict):
            recs = recs.get("records") or []
        arec = next((r for r in recs if (r.get("type") or "").upper() == "A" and
                     str(r.get("name") or "").lower().rstrip(".") in ("wg", "wg." + host.lower())),
                    None)
        v6junk = [r for r in recs if (r.get("type") or "").upper() == "AAAA" and
                  str(r.get("name") or "").lower().rstrip(".") in ("wg", "wg." + host.lower())]
        for r in v6junk:  # AAAA у wg-поддомена быть не должно — вернёт баг мобильного v6
            try:
                _dynv6_api("DELETE", "/zones/%s/records/%s" % (zid, r.get("id")))
            except Exception:
                pass
        if arec and (arec.get("data") or "") == ip4 and not v6junk:
            _D6_WG["rid"] = arec.get("id")
            return False
        if arec:
            _dynv6_api("PUT", "/zones/%s/records/%s" % (zid, arec.get("id")), {"data": ip4})
            _D6_WG["rid"] = arec.get("id")
        else:
            r = _dynv6_api("POST", "/zones/%s/records" % zid,
                           {"name": "wg", "type": "A", "data": ip4})
            _D6_WG["rid"] = (r or {}).get("id") if isinstance(r, dict) else None
        return True

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

def _dynv6_update(force4=None, force6=None):
    if not force4 and not force6 and _mv_locked():
        raise RuntimeError("переезд: самопроизвольные DDNS-обновления приостановлены")
    conf = _dynv6_conf()
    host, token = conf["host"], conf["token"]
    if not host or not token:
        raise RuntimeError("dynv6 не настроен (нужны host и token)")
    if not re.fullmatch(r"(?i)[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", host):
        raise RuntimeError("некорректный dynv6-host")
    ip4, ip6 = _pub_ip4(), _pub_ip6()
    if force4:
        ip4 = str(force4)
    if force6:
        ip6 = str(force6)
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
        if ip4 and _wg_auto_domain() == "wg." + host.lower():
            try:
                _dynv6_ensure_wg(host, ip4)
            except Exception as e:
                _DDNS["wg_rec"] = "ошибка: " + str(e)[:120]
            else:
                _DDNS["wg_rec"] = "ok"
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


def _cf_ensure_wg(ip):
    """A-only серая запись wg.<cf_zone> — эндпоинт WireGuard (без AAAA)."""
    _, zone = _cf_zone()
    name = "wg." + zone
    zid, _ = _cf_zone()
    res = _cf_api("GET", "/zones/%s/dns_records?type=A&name=%s&per_page=5" %
                  (urllib.parse.quote(zid), urllib.parse.quote(name))) or []
    if not res:
        _cf_api("POST", "/zones/%s/dns_records" % urllib.parse.quote(zid),
                {"type": "A", "name": name, "content": ip, "ttl": 60, "proxied": False})
        return [{"name": name, "from": "нет записи", "to": ip, "proxied": False}]
    changed = []
    for rec in res:
        if (rec.get("content") or "") == ip and not rec.get("proxied"):
            continue
        _cf_api("PUT", "/zones/%s/dns_records/%s" % (urllib.parse.quote(zid),
                                                     urllib.parse.quote(rec.get("id") or "")),
                {"type": "A", "name": name, "content": ip, "ttl": 60, "proxied": False})
        changed.append({"name": name, "from": rec.get("content"), "to": ip,
                        "proxied": False})
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
    # A-only эндпоинт WireGuard обязан следовать за IP, иначе подписчики
    # останутся стучаться в старый адрес (dynv6-ветку чинит хук в _dynv6_update)
    wd = _wg_auto_domain()
    z = (CFG_CACHE.get("cf_zone") or "").strip().lower()
    if wd and z and wd == "wg." + z:
        try:
            _cf_ensure_wg(ip)
            rep.append("wg-эндпоинт: %s → %s" % (wd, ip))
        except Exception as e:
            rep.append("wg-эндпоинт: ошибка %s" % str(e)[:140])
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
            if cfg["enabled"] and not _mv_locked():
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
        # nginx читает ключ в master (root) — приватному ключу не нужен o+r, оставим только каталог проходимым
        try:
            os.chmod(keyp, 0o600)
        except Exception:
            pass
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
                    _synfix_tick()
                except Exception as e:
                    print("[synfix] " + str(e), flush=True)
                try:
                    _addr_watch_tick()
                except Exception as e:
                    print("[addr] " + str(e), flush=True)
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
            if _mv_load().get("pause_bot"):
                time.sleep(30)
                continue
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
        "payments": _load(PAYMENTS_F, {}),
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
    if isinstance(data.get("payments"), dict) and data["payments"]:
        _save(PAYMENTS_F, data["payments"], 0o600)
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
            os.chmod(p, 0o600 if fname.endswith(".key") else 0o644)
        except Exception:
            pass
    global CFG_CACHE
    CFG_CACHE = _load(CFG, {}) or {}
    try:
        _restart_xray()
    except Exception:
        pass
    return {"ok": True, "restored_at": ts, "clients": _client_count(st)}

# ---------- авто-резервные копии ----------
_AUTOBK_DIR = os.path.join(BASE, "backups", "auto")
_AUTOBK_RE = re.compile(r"veil-backup-\d{8}-\d{6}\.json\.gz")

def _autobk_settings():
    s = CFG_CACHE.get("auto_backup")
    if not isinstance(s, dict):
        s = {}
    try:
        every_h = int(s.get("every_h") or 24)
    except (TypeError, ValueError):
        every_h = 24
    try:
        keep = int(s.get("keep") or 7)
    except (TypeError, ValueError):
        keep = 7
    return {"enabled": bool(s.get("enabled")), "every_h": min(max(every_h, 1), 720),
            "keep": min(max(keep, 1), 60), "send_tg": bool(s.get("send_tg")),
            "last": int(s.get("last") or 0)}

def _autobk_files():
    try:
        names = [n for n in os.listdir(_AUTOBK_DIR) if _AUTOBK_RE.fullmatch(n)]
    except FileNotFoundError:
        return []
    out = []
    for n in names:
        try:
            fst = os.stat(os.path.join(_AUTOBK_DIR, n))
        except OSError:
            continue
        out.append({"name": n, "size": fst.st_size, "ts": int(fst.st_mtime)})
    out.sort(key=lambda x: x["name"], reverse=True)
    return out

def _autobk_make():
    data = _backup()
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    fname = f"veil-backup-{ts}.json.gz"
    os.makedirs(_AUTOBK_DIR, exist_ok=True)
    raw = gzip.compress(json.dumps(data, ensure_ascii=False).encode())
    fd = os.open(os.path.join(_AUTOBK_DIR, fname), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    keep = _autobk_settings()["keep"]
    for old in _autobk_files()[keep:]:
        try:
            os.remove(os.path.join(_AUTOBK_DIR, old["name"]))
        except OSError:
            pass
    return fname, raw

def _tg_send_document(chat_id, fname, raw, caption=""):
    token = CFG_CACHE.get("bot_token", "")
    if not token:
        return False
    boundary = "veilbk" + secrets.token_hex(8)
    def field(name, value):
        return (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").encode()
    body = field("chat_id", str(chat_id))
    if caption:
        body += field("caption", caption)
    body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"{fname}\"\r\n"
             "Content-Type: application/gzip\r\n\r\n").encode()
    body += raw + f"\r\n--{boundary}--\r\n".encode()
    try:
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendDocument",
                                     data=body,
                                     headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return bool(json.loads(r.read() or b"{}").get("ok"))
    except Exception as e:
        print("[autobk] sendDocument error: " + str(e), flush=True)
        return False

def _autobk_loop():
    while True:
        try:
            s = _autobk_settings()
            if s["enabled"] and time.time() - s["last"] >= s["every_h"] * 3600:
                CFG_CACHE["auto_backup"] = dict(CFG_CACHE.get("auto_backup") or {}, last=int(time.time()))
                _save(CFG, CFG_CACHE)
                fname, raw = _autobk_make()
                ids = CFG_CACHE.get("bot_chat_ids") or []
                if s["send_tg"] and ids:
                    if _tg_send_document(ids[0], fname, raw,
                                         caption=f"Автобэкап Veil v{VERSION} · клиентов: {_client_count(_load(STATE) or {})}"):
                        print("[autobk] отправлен в Telegram: " + fname, flush=True)
                    else:
                        print("[autobk] не удалось отправить в Telegram: " + fname, flush=True)
        except Exception as e:
            print("[autobk] " + str(e), flush=True)
        time.sleep(120)

threading.Thread(target=_autobk_loop, daemon=True).start()

# ---------- «Переезд» — автоматическая миграция на новый VPS ----------
# Старый хост по SSH ставит Veil на новый, переносит ВСЁ состояние (конфиги,
# подписчики, ключи, секреты telemt, сертификаты, nginx) порты-в-порты, поэтому
# ссылки подписчиков не меняются. Дальше — самопроверка, переключение DNS и
# «пенсионирование» старого хоста. Каждое действие пишется в mv_state.json:
# прерванный процесс продолжается с того же шага, а не с начала.
import io as _mv_io

MV_FILE = f"{BASE}/mv_state.json"
MV_JOBS = {}
MV_LOCK = threading.Lock()
MV_STEPS = ["Доступ по SSH", "Проверка нового хоста", "Передача файлов",
            "Установка Veil", "Перенос данных", "Проверка связности"]
# пока переезд не завершён, хосты сами DNS не трогают (иначе старый будет
# «тянуть домен назад» при каждом DDNS-цикле, а боты двух хостов — спорить)
_MV_LOCKED = {"prepared", "precheck", "applied", "verified", "dns_done", "retired", "arrived"}
_MV_BASE_FILES = ["panel.py", "index.html", "install.sh", "agent.py", "manifest.json",
                  "config.json", "state.json", "theme.json", "wallpaper.bin", "logo.bin",
                  "payments.json", "sessions.json", "sessions_meta.json", "passkeys.json",
                  "bans.json", "sub_devices.json", "sub_prefs.json", "proto_activity.json",
                  "bot_langs.json", "hops.json", "nodes.json", "mux_state.json",
                  "tg_mp_port.json", "globalping_history.json", "FIRST-LOGIN.txt",
                  "audit.json", "login_history.json", "github.token"]
_MV_BASE_DIRS = ["certs", "avatars", "node_keys", "rulesets", "frontsite", "decoy", "appicons"]
_MV_PRIVATE = {"config.json", "state.json", "sessions.json", "sessions_meta.json",
               "passkeys.json", "payments.json", "nodes.json", "hops.json", "bans.json",
               "sub_devices.json", "sub_prefs.json", "proto_activity.json", "bot_langs.json",
               "mux_state.json", "tg_mp_port.json", "mv_state.json", "github.token",
               "FIRST-LOGIN.txt", "audit.json", "login_history.json"}
_MV_SINGLE = "/tmp/veil-mv.tar.gz"


def _mv_load():
    v = _load(MV_FILE, {})
    return v if isinstance(v, dict) else {}


def _mv_save(st):
    st["updated"] = int(time.time())
    _save(MV_FILE, st, 0o600)


def _mv_note(msg):
    st = _mv_load()
    log = st.get("log")
    if not isinstance(log, list):
        log = []
    log.append({"ts": int(time.time()), "msg": str(msg)[:300]})
    st["log"] = log[-150:]
    _mv_save(st)
    return st


def _mv_setp(**kw):
    st = _mv_load()
    st.update(kw)
    _mv_save(st)
    return st


def _mv_step():
    return _mv_load().get("step") or ""


def _mv_locked():
    """Хост в середине переезда: не толкать свой IP в DNS и не крутить ротацию."""
    return _mv_step() in _MV_LOCKED


def _mv_notify(text):
    for cid in [str(x) for x in (CFG_CACHE.get("bot_chat_ids") or [])][:8]:
        try:
            _bot_send_message(cid, "📦 Переезд: " + text)
        except Exception:
            pass


def _mv_ports_plan():
    """Все публичные порты, которые панель займёт на новом хосте."""
    plan, seen = [], set()

    def add(proto, port):
        try:
            port = int(port)
        except (TypeError, ValueError):
            return
        if 1 <= port <= 65535 and (proto, port) not in seen:
            seen.add((proto, port))
            plan.append("%s:%d" % (proto, port))

    add("tcp", CFG_CACHE.get("panel_port") or 8443)
    st = _load(STATE) or {}
    for proto, ib in (st.get("inbounds") or {}).items():
        if not isinstance(ib, dict):
            continue
        add("udp" if proto in ("wireguard", "hysteria2", "amneziawg") else "tcp", ib.get("port"))
    tp = _tg_toml_get_server_port()
    if tp:
        add("tcp", tp)
    if shutil.which("nginx"):
        add("tcp", 80)
        add("tcp", 443)
    for f in ("/etc/wireguard/veilwg.conf", "/etc/amnezia/amneziawg/awg0.conf"):
        try:
            with open(f, encoding="utf-8", errors="ignore") as fh:
                m = re.search(r"(?mi)^ListenPort\s*=\s*(\d+)", fh.read())
            if m:
                add("udp", m.group(1))
        except Exception:
            pass
    return plan


def _mv_archive_bytes(manifest):
    buf = _mv_io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        raw = json.dumps(manifest, ensure_ascii=False).encode()
        ti = tarfile.TarInfo("manifest.json")
        ti.size = len(raw)
        ti.mode = 0o644
        ti.mtime = int(time.time())
        tar.addfile(ti, _mv_io.BytesIO(raw))
        for name in _MV_BASE_FILES:
            p = os.path.join(BASE, name)
            if os.path.isfile(p):
                tar.add(p, arcname="base/" + name)
        for d in _MV_BASE_DIRS:
            p = os.path.join(BASE, d)
            if os.path.isdir(p):
                tar.add(p, arcname="base/" + d)
        td = os.path.join(BASE, "logs", "traffic_days.json")
        if os.path.isfile(td):
            tar.add(td, arcname="base/logs/traffic_days.json")
        for src, arc in ((TELEMT_CONF, "etc/telemt/telemt.toml"),
                         ("/etc/nginx/nginx.conf", "etc/nginx/nginx.conf"),
                         ("/etc/nginx/conf.d/webproxy.conf", "etc/nginx/webproxy.conf"),
                         ("/etc/nginx/conf.d/veil-front.conf", "etc/nginx/veil-front.conf"),
                         ("/etc/nginx/conf.d/veil-mux-default.conf", "etc/nginx/veil-mux-default.conf"),
                         ("/etc/nginx/veil-mux-stream.conf", "etc/nginx/veil-mux-stream.conf"),
                         ("/etc/wireguard/veilwg.conf", "etc/wireguard/veilwg.conf"),
                         ("/etc/amnezia/amneziawg/awg0.conf", "etc/amnezia/awg0.conf"),
                         ("/etc/veil-zapret2/mtproto.conf", "etc/veil-zapret2/mtproto.conf")):
            if os.path.isfile(src):
                tar.add(src, arcname=arc)
        for d, arc in (("/usr/local/etc/xray", "etc/xray"), ("/var/lib/telemt", "var/telemt")):
            if os.path.isdir(d):
                tar.add(d, arcname=arc)
    return buf.getvalue()


_MV_PRECHECK_SH = r'''
set -u
echo "VHOST|$(hostname 2>/dev/null | tr -d "\r" || echo ?)"
( . /etc/os-release 2>/dev/null || true; echo "VID|${PRETTY_NAME:-?}|$(uname -m)" )
echo "VDISK|$(df -Pm / 2>/dev/null | awk 'NR==2{print $4}')"
echo "VPY|$(command -v python3 >/dev/null 2>&1 && echo yes || echo no)"
echo "VAPT|$(command -v apt-get >/dev/null 2>&1 && echo yes || echo no)"
for s in __PORTS_SP__; do
  p=${s#*:}; pr=${s%%:*}
  case "$pr" in
    udp) line=$(ss -H -lunp "sport = :$p" 2>/dev/null | head -1) ;;
    *)   line=$(ss -H -ltnp "sport = :$p" 2>/dev/null | head -1) ;;
  esac
  if [ -z "$line" ]; then echo "VPORT|$s|free"; continue; fi
  pid=$(printf '%s' "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
  proc=$(printf '%s' "$line" | grep -oE '\("[A-Za-z0-9_.-]+' | head -1 | tr -d '("')
  unit=""
  if [ -n "$pid" ] && [ -r "/proc/$pid/cgroup" ]; then
    unit=$(grep -m1 -oE '[A-Za-z0-9@:._-]+\.(service|socket)' "/proc/$pid/cgroup" | head -1)
  fi
  echo "VPORT|$s|taken|${proc:-?}|${unit:-none}|${pid:-0}"
done
for v in xray telemt nginx vpnpanel veil-zapret2; do
  echo "VSVC|$v|$(systemctl is-active $v 2>/dev/null || true)"
done
echo "VDATA|$( [ -f /opt/vpnpanel/config.json ] && echo yes || echo no )"
echo VEILPRE_DONE
'''

_MV_TAKEOVER_SH = r'''
set -u
for w in __SPECS_SP__; do
  IFS=, read -r spec unit pid rest <<EOF2
$w
EOF2
  case "$unit" in ssh*|sshd*) continue ;; esac
  if [ -n "$unit" ] && [ "$unit" != none ]; then
    systemctl stop "$unit" 2>/dev/null || true
    systemctl mask "$unit" 2>/dev/null || true
  fi
done
sleep 1
for w in __SPECS_SP__; do
  IFS=, read -r spec unit pid rest <<EOF2
$w
EOF2
  if [ -n "$pid" ] && [ "$pid" != 0 ] && kill -0 "$pid" 2>/dev/null; then kill -TERM "$pid" 2>/dev/null || true; fi
done
sleep 2
for w in __SPECS_SP__; do
  IFS=, read -r spec unit pid rest <<EOF2
$w
EOF2
  if [ -n "$pid" ] && [ "$pid" != 0 ] && kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
done
for w in __SPECS_SP__; do
  IFS=, read -r spec unit pid rest <<EOF2
$w
EOF2
  p=${spec#*:}; pr=${spec%%:*}
  case "$pr" in
    udp) line=$(ss -H -lunp "sport = :$p" 2>/dev/null | head -1) ;;
    *)   line=$(ss -H -ltnp "sport = :$p" 2>/dev/null | head -1) ;;
  esac
  if [ -n "$line" ]; then
    proc=$(printf '%s' "$line" | grep -oE '\("[A-Za-z0-9_.-]+' | head -1 | tr -d '("')
    echo "VSTILL|$spec|${proc:-?}"
  fi
done
echo VEILTAK_DONE
'''

_MV_INSTALL_SH = r'''
set -euo pipefail
mkdir -p /opt/vpnpanel
tar -xzf /tmp/veil-mv.tar.gz -C /opt/vpnpanel --strip-components=1 base/panel.py base/index.html
for s in 0 1 2 3 4; do bash /tmp/veil-install.sh --step $s; done
python3 /opt/vpnpanel/panel.py --migrate-apply /tmp/veil-mv.tar.gz
'''

_MV_PANEL_UNIT = """[Unit]
Description=VPN Panel
After=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/vpnpanel/panel.py
Restart=always
RestartSec=2
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
"""


def _mv_plan(dest_host, ssh_user, ssh_port):
    dest_host = (dest_host or "").strip()
    ssh_user = (ssh_user or "root").strip()
    try:
        ssh_port = int(ssh_port or 22)
    except (TypeError, ValueError):
        ssh_port = 22
    blockers = []
    if not dest_host or not _SSH_HOST_RE.fullmatch(dest_host):
        blockers.append("адрес нового хоста пустой или недопустимый")
    if not _SSH_USER_RE.fullmatch(ssh_user):
        blockers.append("SSH-логин содержит недопустимые символы")
    if not (1 <= ssh_port <= 65535):
        blockers.append("неверный SSH-порт")
    own = ""
    try:
        own = _pub_ip4() or ""
    except Exception:
        pass
    if own and dest_host == own:
        blockers.append("это адрес текущего хоста — переехать «в себя» нельзя")
    ports = _mv_ports_plan()
    note = ("На новом хосте будут заняты те же порты, что и здесь: " + ", ".join(ports) +
            ". Панель подключится по SSH, поставит Veil (нужны исходящие к github.com "
            "для Xray/telemt) и перенесёт всё состояние: подписчики, ссылки, секреты, "
            "сертификаты — без изменений. Пока ты не переключишь DNS, подписчики идут "
            "на старый хост; после переключения старый нужно «пенсионировать», иначе "
            "два хоста будут спорить из-за бота и DDNS. Пароль SSH сохраняется только "
            "в памяти задания и стирается по завершении.")
    _mv_setp(dest={"host": dest_host, "user": ssh_user, "ssh_port": ssh_port})
    return {"dest": {"host": dest_host, "user": ssh_user, "ssh_port": ssh_port},
            "ports": ports, "blockers": blockers, "can_apply": not blockers, "note": note}


def _mv_new_job(params):
    jid = uuidlib.uuid4().hex[:12]
    job = {"id": jid,
           "steps": [{"name": s, "state": "pending", "detail": ""} for s in MV_STEPS],
           "done": False, "ok": False, "error": None, "created": int(time.time()),
           "params": params}
    with MV_LOCK:
        MV_JOBS[jid] = job
        old = sorted(MV_JOBS, key=lambda k: MV_JOBS[k]["created"])[:-10]
        for k in old:
            if MV_JOBS[k].get("done"):
                MV_JOBS.pop(k, None)
    threading.Thread(target=_mv_worker, args=(jid,), daemon=True).start()
    return jid


def _mv_public_job(jid):
    with MV_LOCK:
        j = MV_JOBS.get(jid)
        if not j:
            return {"error": "задание не найдено"}
        j = json.loads(json.dumps(j, default=str))
    j.pop("params", None)
    return j


def _mv_worker(jid):
    with MV_LOCK:
        job = MV_JOBS.get(jid) or {}
        prm = dict(job.get("params") or {})
    host = (prm.get("host") or "").strip()
    user = (prm.get("user") or "root").strip()
    password = prm.get("password") or ""
    sport = int(prm.get("ssh_port") or 22)
    confirm_tk = bool(prm.get("confirm_takeover"))
    ports = _mv_ports_plan()

    def st(i, s, d=""):
        with MV_LOCK:
            j = MV_JOBS.get(jid)
            if j:
                j["steps"][i]["state"] = s
                if d:
                    j["steps"][i]["detail"] = str(d)[:400]
        if s in ("done", "failed"):
            _mv_note("шаг %s — %s%s" % (MV_STEPS[i], s, (": " + str(d)[:180]) if d else ""))

    def finish(okv, err=None):
        with MV_LOCK:
            job["done"] = True
            job["ok"] = bool(okv)
            job["error"] = err
            jp = job.get("params") or {}
            jp["password"] = ""
        stv = _mv_load()
        stv["finished"] = int(time.time())
        _mv_save(stv)

    def fail(i, msg):
        st(i, "failed", msg)
        finish(False, msg)
        _mv_setp(step="failed")
        _mv_notify("установка на %s не удалась: %s" % (host, str(msg)[:160]))
        try:
            _audit("mv_fail", host=host, step=i, error=str(msg)[:200])
        except Exception:
            pass

    try:
        # --- шаг 0: SSH (ключ панели, при отсутствии — пароль + установка ключа)
        st(0, "running")
        keyfile, pubkey = _boot_host_key("mv:" + host + ":" + str(sport))
        base = ["/usr/bin/ssh", "-p", str(sport)] + _ssh_opts(keyfile)
        target = "%s@%s" % (user, host)

        def key_run(cmd, timeout=60, input_txt=None):
            return subprocess.run(base + [target, cmd], capture_output=True, text=True,
                                  timeout=timeout, input=input_txt,
                                  stdin=None if input_txt is not None else subprocess.DEVNULL)
        try:
            ok_key = key_run("true", timeout=20).returncode == 0
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
            try:
                pubtxt = open(pubkey).read().strip().replace("'", "'\\''")
            except Exception:
                pubtxt = ""
            if not pubtxt:
                return fail(0, "не читается публичный ключ панели")
            r = _boot_askpass_run(password, base + [target,
                  "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; "
                  "grep -qxF '%s' ~/.ssh/authorized_keys || printf '%%s\\n' '%s' "
                  ">> ~/.ssh/authorized_keys" % (pubtxt, pubtxt)], timeout=45)
            if r.returncode != 0:
                return fail(0, "установка ключа: " + (r.stderr or b"").decode("utf-8", "ignore")[:200])
            try:
                ok_key = key_run("true", timeout=20).returncode == 0
            except Exception:
                ok_key = False
            if not ok_key:
                return fail(0, "ключ панели не принимается после установки")
        st(0, "done", "вход по ключу панели")

        r = key_run('u=$(id -u); p=$(command -v sudo || true); '
                    'if [ "$u" = 0 ]; then m=root; elif [ -n "$p" ] && sudo -n true 2>/dev/null; '
                    'then m=sudo_n; elif [ -n "$p" ]; then m=s_s; else m=none; fi; '
                    'if command -v ss >/dev/null 2>&1; then s=ss; else s=noss; fi; echo "$m $s"',
                    timeout=30)
        if r.returncode != 0:
            return fail(0, "SSH-команда не прошла: " + (r.stderr or r.stdout or "")[:150])
        parts = (r.stdout or "").split()
        mode = parts[0] if parts else "none"
        if len(parts) > 1 and parts[1] == "noss":
            return fail(0, "на новом хосте нет ss (iproute2) — не проверить порты")
        if mode == "s_s":
            try:
                if key_run("sudo -S -p '' true", timeout=30,
                           input_txt=password.rstrip("\n") + "\n").returncode == 0:
                    mode = "sudo_s"
            except Exception:
                pass
        if mode not in ("root", "sudo_n", "sudo_s"):
            return fail(0, "нужны root или sudo (парольный или без пароля)")

        def root_run(cmd, timeout=120, input_txt=None):
            if mode == "sudo_n":
                full = "sudo -n " + cmd
            elif mode == "sudo_s":
                full = "sudo -S -p '' " + cmd
                input_txt = (password.rstrip("\n") + "\n") + (input_txt or "")
            else:
                full = cmd
            return key_run(full, timeout=timeout, input_txt=input_txt)

        def bash_run(script, timeout=120, sudo=True):
            shell = "bash -s"
            if sudo and mode != "root":
                shell = ("sudo -n bash -s" if mode == "sudo_n"
                         else "sudo -S -p '' bash -s" if mode == "sudo_s" else shell)
            in_txt = script
            if sudo and mode == "sudo_s":
                in_txt = password.rstrip("\n") + "\n" + script
            return key_run(shell, timeout=timeout, input_txt=in_txt)

        # --- шаг 1: проверка нового хоста
        st(1, "running")
        pre = _MV_PRECHECK_SH.replace("__PORTS_SP__", " ".join(ports))
        r = bash_run(pre, timeout=90)
        out = (r.stdout or "") + (r.stderr or "")
        if "VEILPRE_DONE" not in out:
            return fail(1, "проверка не завершилась: " + out[-250:])
        occupied, svc, info = [], {}, {}
        for ln in out.splitlines():
            f = ln.split("|")
            if f[0] == "VPORT" and len(f) >= 3 and f[2] == "taken":
                occupied.append({"spec": f[1], "proc": f[3] if len(f) > 3 else "?",
                                 "unit": f[4] if len(f) > 4 else "none",
                                 "pid": f[5] if len(f) > 5 else "0"})
            elif f[0] == "VSVC":
                svc[f[1]] = f[2] if len(f) > 2 else ""
            elif f[0] == "VDATA":
                svc["data"] = f[1] if len(f) > 1 else "no"
            elif f[0] in ("VID", "VDISK", "VHOST", "VPY", "VAPT"):
                info[f[0]] = ln
        _mv_setp(precheck={"occupied": occupied, "services": svc, "env": info})
        if svc.get("data") == "yes" and svc.get("vpnpanel") == "active":
            return fail(1, "на этом хосте уже работает живая Veil-панель — переезд на неё "
                          "разрушил бы её данные; выбери чистый хост или удали Veil на нём")
        if occupied and not confirm_tk:
            who = ", ".join("%s (%s%s)" % (o["spec"], o["proc"],
                                           " · " + o["unit"] if o["unit"] not in ("", "none") else "")
                            for o in occupied)
            return fail(1, "порты заняты: " + who +
                        " — включи «забрать порты принудительно» и повтори")
        if occupied:
            st(1, "running", "забираю %d занятых порта(ов)" % len(occupied))
            specs = " ".join("%s,%s,%s" % (o["spec"], o["unit"] or "none", o["pid"] or "0")
                             for o in occupied)
            tk = _MV_TAKEOVER_SH.replace("__SPECS_SP__", specs)
            r = bash_run(tk, timeout=120)
            out = (r.stdout or "") + (r.stderr or "")
            still = [ln for ln in out.splitlines() if ln.startswith("VSTILL|")]
            if "VEILTAK_DONE" not in out or still:
                return fail(1, "порты остались заняты: " +
                            "; ".join(s.split("|")[1] + "(" + s.split("|")[2] + ")" for s in still)
                            if still else "захват не подтверждён: " + out[-200:])
            st(1, "done", "свободно после захвата")
        else:
            st(1, "done", "порты свободны: " + ", ".join(ports))

        # --- шаг 2: передача файлов
        st(2, "running")
        _mv_setp(step="prepared")
        manifest = {"app": "veil-mv", "version": VERSION, "created": int(time.time()),
                    "hostname": socket.gethostname(), "ports": ports,
                    "dest": _mv_load().get("dest") or {}}
        try:
            manifest["source_ip"] = _pub_ip4() or ""
        except Exception:
            pass
        raw = _mv_archive_bytes(manifest)
        if len(raw) > 200 * 1024 * 1024:
            return fail(2, "архив больше 200 МБ — так переезжать нельзя, разберись с логами")
        try:
            with open("/tmp/veil-mv-cache.tar.gz", "wb") as f:
                f.write(raw)
        except Exception:
            pass
        r = subprocess.run(base + [target, "cat > " + _MV_SINGLE],
                           input=raw, capture_output=True, timeout=1800)
        if r.returncode != 0:
            return fail(2, "загрузка архива: " +
                        (r.stderr or b"").decode("utf-8", "ignore")[:200])
        with open(os.path.join(BASE, "install.sh"), encoding="utf-8") as f:
            inst_sh = f.read()
        r = key_run("cat > /tmp/veil-install.sh", timeout=120, input_txt=inst_sh)
        if r.returncode != 0:
            return fail(2, "загрузка install.sh: " + (r.stderr or r.stdout or "")[:200])
        st(2, "done", "архив %d МБ + установщик переданы" % (max(1, len(raw) // (1024 * 1024))))

        # --- шаг 3: установка Veil на новый хост
        st(3, "running")
        r = bash_run(_MV_INSTALL_SH, timeout=2400)
        out = (r.stdout or "") + (r.stderr or "")
        st(3, "done", "инсталлятор отработал" if "VEILSUM|" in out or r.returncode == 0
           else "инсталлятор завершился с ошибкой")

        # --- шаг 4: перенос данных (сделал --migrate-apply, читаем VEILSUM)
        st(4, "running")
        summary = None
        for ln in out.splitlines():
            if ln.startswith("VEILSUM|"):
                try:
                    summary = json.loads(ln[len("VEILSUM|"):])
                except Exception:
                    summary = None
        if not summary:
            err = ""
            for ln in out.splitlines():
                if ln.startswith("VEILERR"):
                    err = ln
            return fail(4, (err or out)[-350:])
        _mv_setp(summary=summary, dest_ip=summary.get("dest_ip") or "",
                 step="applied")
        if not summary.get("ok"):
            return fail(4, "перенос применён, но самопроверка нового хоста не прошла: " +
                        str(summary.get("problems") or []) +
                        " | недоступные порты: " + str(summary.get("ports_missing") or []))
        st(4, "done", "данные перенесены, панель нового хоста: %s:%s" %
           (summary.get("dest_ip") or host, summary.get("panel_port")))

        # --- шаг 5: проверка связности со стороны старого хоста
        st(5, "running")
        dip = summary.get("dest_ip") or (host if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host or "") else "")
        pp = int(summary.get("panel_port") or CFG_CACHE.get("panel_port") or 8443)
        pub_up, pub_down = [], []
        if dip:
            for spec in ports:
                pr, pv = spec.split(":")
                if pr != "tcp":
                    continue
                if _hop_public(dip, int(pv), timeout=2.0):
                    pub_up.append(spec)
                else:
                    pub_down.append(spec)
            web_ok = _hop_public(dip, pp)
        else:
            web_ok = False
        ver = {"ip": dip, "web_ok": web_ok, "tcp_up": pub_up, "tcp_down": pub_down,
               "note_udp": "UDP-порты (WireGuard/Hysteria2) публичной пробой не проверяются",
               "ts": int(time.time())}
        _mv_setp(verify=ver, step="verified")
        detail = ("панель отвечает" if web_ok else "панель НЕ отвечает")
        if pub_down:
            detail += "; не открыто: " + ", ".join(pub_down[:8])
        _mv_note("проверка связности: " + detail)
        if not web_ok:
            st(5, "failed", detail + " — проверь security group / firewall нового хоста")
            finish(False, "новый хост недоступен снаружи: " + detail)
            _mv_notify("данные на %s перенесены, но снаружи он не виден (%s). "
                       "Открой порты в панели хостинга и нажми «Проверить ещё раз»." %
                       (dip or host, ", ".join(pub_down[:6]) or "порт панели"))
            return
        st(5, "done", detail)
        finish(True)
        _audit("mv_ok", host=dip or host, ports=ports)
        _mv_notify("новый хост %s готов: данные перенесены, связь есть. "
                   "Открой https://%s:%s — вход тот же. Дальше: переключить DNS." %
                   (dip or host, dip or host, pp))
    except Exception as e:
        fail(1, "исключение: " + str(e)[:200])


def _mv_verify_now():
    st = _mv_load()
    summ = st.get("summary") or {}
    dip = st.get("dest_ip") or summ.get("dest_ip") or ""
    if not dip:
        raise RuntimeError("сначала запусти переезд")
    ports = _mv_ports_plan()
    pp = int(summ.get("panel_port") or CFG_CACHE.get("panel_port") or 8443)
    pub_up, pub_down = [], []
    for spec in ports:
        pr, pv = spec.split(":")
        if pr != "tcp":
            continue
        (pub_up if _hop_public(dip, int(pv), timeout=2.0) else pub_down).append(spec)
    web_ok = _hop_public(dip, pp)
    ver = {"ip": dip, "web_ok": web_ok, "tcp_up": pub_up, "tcp_down": pub_down,
           "note_udp": "UDP-порты публичной пробой не проверяются", "ts": int(time.time())}
    _mv_setp(verify=ver, step="verified")
    _mv_note("повторная проверка: панель %s, tcp вверх %s, вниз %s" %
             ("ок" if web_ok else "НЕ ОТВЕЧАЕТ", pub_up or "—", pub_down or "—"))
    return ver


def _mv_dns(provider="auto", confirm=False):
    if not confirm:
        raise RuntimeError("нужно подтверждение: домен начнёт указывать на новый хост")
    st = _mv_load()
    if st.get("step") not in ("applied", "verified", "dns_done"):
        raise RuntimeError("сначала успешно заверши переезд (есть отчёт нового хоста)")
    ip4 = st.get("dest_ip") or (st.get("summary") or {}).get("dest_ip") or ""
    ip6 = (st.get("summary") or {}).get("dest_ip6") or ""
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip4 or ""):
        raise RuntimeError("не знаю публичный IPv4 нового хоста")
    c = CFG_CACHE
    if provider == "auto":
        provider = "cloudflare" if ((c.get("cf_token") or "").strip() and
                                    (c.get("cf_records") or c.get("cf_zone"))) else \
                   ("dynv6" if (c.get("dynv6_host") or "").strip() else "manual")
    report = []
    if provider == "cloudflare":
        try:
            ch = _cf_set_ip(ip4)
            report += ["cloudflare: " + (", ".join("%s %s→%s" % (x["name"], x["from"], x["to"])
                                                   for x in ch) if ch else "записи уже актуальны")]
        except Exception as e:
            raise RuntimeError("Cloudflare: " + str(e)[:200])
        try:
            wd = _wg_auto_domain()
            z = (c.get("cf_zone") or "").strip().lower()
            if wd and z and wd == "wg." + z:
                _cf_ensure_wg(ip4)
                report.append("wg-эндпоинт: wg.%s → %s" % (z, ip4))
        except Exception as e:
            report.append("wg-эндпоинт: ошибка " + str(e)[:140])
    elif provider == "dynv6":
        try:
            _dynv6_update(force4=ip4, force6=ip6 or None)
            report.append("dynv6: %s → %s%s" % (_dynv6_conf()["host"], ip4,
                                                (" (IPv6: %s)" % ip6) if ip6 else ""))
            if not ip6:
                report.append("внимание: IPv6 нового хоста не известен — AAAA-запись "
                              "не обновлена, убери её вручную, если у нового хоста нет v6")
        except Exception as e:
            raise RuntimeError("dynv6: " + str(e)[:200])
    else:
        report.append("авто-переключение недоступно (DNS-провайдер не настроен): "
                      "поменяй A-записи вручную на %s, затем нажми «пенсионировать»" % ip4)
    _mv_setp(step="dns_done", scheduled_ts=0, dns={"provider": provider, "ip": ip4,
                                                   "report": report, "ts": int(time.time())})
    _mv_note("DNS переключён на " + ip4 + " (" + provider + ")")
    _audit("mv_dns", ip=ip4, provider=provider)
    _mv_notify("домен переведён на %s. Проверь доступность и пенсионзируй старый хост." % ip4)
    return {"provider": provider, "ip": ip4, "report": report}


def _mv_retire(confirm=False):
    if not confirm:
        raise RuntimeError("нужно подтверждение: старый хост перестанет обслуживать подписчиков")
    st = _mv_load()
    if st.get("step") not in ("dns_done", "verified", "applied"):
        raise RuntimeError("сначала переключи DNS (или убедись, что новый хост живой)")
    stopped = []
    for svc in ("xray", "telemt", "veil-zapret2", "nginx"):
        try:
            subprocess.run(["systemctl", "stop", svc], capture_output=True, timeout=60)
            subprocess.run(["systemctl", "disable", svc], capture_output=True, timeout=60)
            stopped.append(svc)
        except Exception:
            pass
    for iface in (AWG_IFACE, WG_IFACE):
        try:
            subprocess.run(["systemctl", "stop", "wg-quick@" + iface], capture_output=True, timeout=30)
        except Exception:
            pass
    _mv_setp(step="retired", retired_ts=int(time.time()), stopped=stopped, pause_bot=True)
    _mv_note("старый хост пенсионирован: остановлено " + ", ".join(stopped))
    _audit("mv_retire", stopped=stopped)
    _mv_notify("этот хост pensionирован (остановлено: %s). Панель на :%s ещё доступна "
               "для осмотра; после проверки удали хост у хостинга." %
               (", ".join(stopped), CFG_CACHE.get("panel_port") or 8443))
    return {"stopped": stopped}


def _mv_finish_here():
    """Вызывается на НОВОМ хосте: переезд завершён, можно включать бота и DDNS."""
    st = _mv_load()
    if st.get("step") != "arrived":
        raise RuntimeError("этот хост не является результатом переезда")
    _mv_setp(step="idle", pause_bot=False)
    _mv_note("переезд завершён на новом хосте — DDNS и бот включены")
    return {"ok": True}


def _mv_cancel():
    with MV_LOCK:
        live = any((not j.get("done")) for j in MV_JOBS.values())
    if live:
        raise RuntimeError("задание ещё идёт — дождись его завершения или ошибки")
    _mv_setp(step="cancelled")
    _mv_note("переезд отменён")
    return {"ok": True}


def _mv_view():
    st = _mv_load()
    job = None
    jid = st.get("jid") or ""
    if jid:
        job = _mv_public_job(jid)
        if isinstance(job, dict) and job.get("error") == "задание не найдено":
            job = None
    return {"mv": st, "job": job, "ports": _mv_ports_plan(),
            "dns_provider": _dns01_provider() or ("dynv6" if _dynv6_conf()["host"] else ""),
            "locked": _mv_locked()}


def _mv_loop():
    time.sleep(20)
    while True:
        try:
            st = _mv_load()
            sch = int(st.get("scheduled_ts") or 0)
            if sch and st.get("step") == "verified" and time.time() >= sch:
                _mv_note("сработало расписание переезда")
                _mv_dns(provider=st.get("scheduled_provider") or "auto", confirm=True)
                if st.get("auto_retire"):
                    _mv_retire(confirm=True)
        except Exception as e:
            _mv_note("по расписанию: ошибка " + str(e)[:200])
        time.sleep(30)


threading.Thread(target=_mv_loop, daemon=True).start()


def _mv_unpack(tar, root="/"):
    """Раскладка архива переезда по местам. root — префикс (тест в песочнице)."""
    problems = []

    def place(m):
        n = m.name
        if n == "manifest.json" or "/" not in n:
            return None
        if n.startswith("base/"):
            dest = os.path.join(BASE, n[len("base/"):])
        elif n.startswith("etc/xray/") or n == "etc/xray":
            dest = "/usr/local/etc/xray/" + n[len("etc/xray/"):] if n != "etc/xray" \
                else "/usr/local/etc/xray"
        elif n.startswith("etc/telemt/"):
            dest = "/etc/telemt/" + n[len("etc/telemt/"):]
        elif n.startswith("etc/nginx/webproxy.conf"):
            dest = "/etc/nginx/conf.d/webproxy.conf"
        elif n.startswith("etc/nginx/veil-front.conf"):
            dest = "/etc/nginx/conf.d/veil-front.conf"
        elif n.startswith("etc/nginx/veil-mux-default.conf"):
            dest = "/etc/nginx/conf.d/veil-mux-default.conf"
        elif n.startswith("etc/nginx/veil-mux-stream.conf"):
            dest = "/etc/nginx/veil-mux-stream.conf"
        elif n.startswith("etc/nginx/nginx.conf"):
            dest = "/etc/nginx/nginx.conf"
        elif n.startswith("etc/wireguard/"):
            dest = "/etc/wireguard/" + n[len("etc/wireguard/"):]
        elif n.startswith("etc/amnezia/"):
            dest = "/etc/amnezia/amneziawg/" + n[len("etc/amnezia/"):]
        elif n.startswith("etc/veil-zapret2/"):
            dest = "/etc/veil-zapret2/" + n[len("etc/veil-zapret2/"):]
        elif n.startswith("var/telemt/") or n == "var/telemt":
            dest = "/var/lib/telemt/" + n[len("var/telemt/"):].lstrip("/") if n != "var/telemt" \
                else "/var/lib/telemt"
        else:
            return None
        if root != "/":
            dest = os.path.join(root, dest.lstrip("/"))
        if m.isdir():
            os.makedirs(dest, exist_ok=True)
            return None
        data = tar.extractfile(m).read()
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, m.mode & 0o777 or 0o644)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        return dest
    for m in tar.getmembers():
        try:
            place(m)
        except Exception as e:
            problems.append("раскладка %s: %s" % (m.name, str(e)[:100]))
    return problems


def _mv_apply_main():
    """На НОВОМ хосте: python3 /opt/vpnpanel/panel.py --migrate-apply /tmp/veil-mv.tar.gz"""
    argv = sys.argv
    try:
        path = argv[argv.index("--migrate-apply") + 1]
    except (ValueError, IndexError):
        raise RuntimeError("--migrate-apply <архив.tar.gz>")
    if os.geteuid() != 0:
        raise RuntimeError("нужен root")
    if not os.path.isfile(path):
        raise RuntimeError("нет архива: " + path)
    problems = []
    tar = tarfile.open(path, "r:gz")
    mf = tar.extractfile("manifest.json")
    manifest = json.loads(mf.read().decode()) if mf else {}
    if manifest.get("app") != "veil-mv":
        raise RuntimeError("это не архив переезда Veil")
    cur4 = ""
    try:
        cur4 = _pub_ip4() or ""
    except Exception:
        pass
    if cur4 and manifest.get("source_ip") and cur4 == manifest["source_ip"]:
        raise RuntimeError("этот хост видит тот же публичный IPv4, что и источник — "
                           "нельзя переехать «в себя»")
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    keep = f"{BASE}/pre-move-{ts}"
    os.makedirs(keep, exist_ok=True)
    for name in sorted(os.listdir(BASE)):
        if name.startswith("pre-move-"):
            continue
        try:
            shutil.move(os.path.join(BASE, name), os.path.join(keep, name))
        except Exception as e:
            problems.append("перенос %s: %s" % (name, str(e)[:80]))
    ng_orig = None
    if os.path.isfile("/etc/nginx/nginx.conf"):
        try:
            shutil.copy2("/etc/nginx/nginx.conf", keep + "/orig-nginx.conf")
            ng_orig = keep + "/orig-nginx.conf"
        except Exception:
            pass
    problems += _mv_unpack(tar)
    tar.close()
    for name in _MV_PRIVATE:
        try:
            os.chmod(os.path.join(BASE, name), 0o600)
        except Exception:
            pass
    try:
        os.chmod(os.path.join(BASE, "panel.py"), 0o755)
    except Exception:
        pass
    global CFG_CACHE
    CFG_CACHE = _load(CFG, {}) or {}
    try:
        import pwd as _pwd, grp as _grp
        pw = _pwd.getpwnam("telemt")
        gr = _grp.getgrgid(pw.pw_gid).gr_name
        for p in ("/etc/telemt", TELEMT_CONF, "/var/lib/telemt"):
            if not os.path.exists(p):
                continue
            if os.path.isdir(p):
                for root, dirs, files in os.walk(p):
                    for nm in [root] + dirs + files:
                        try:
                            shutil.chown(nm, user=pw.pw_name, group=gr)
                        except Exception:
                            pass
            else:
                shutil.chown(p, user=pw.pw_name, group=gr)
    except Exception:
        pass
    arrived = {"step": "arrived", "from": manifest.get("source_ip") or "",
               "from_hostname": manifest.get("hostname") or "",
               "arrived": int(time.time()), "pause_bot": True,
               "summary": {}, "log": [{"ts": int(time.time()),
                                       "msg": "хост получил данные переезда"}]}
    _mv_save(arrived)

    def unit_active(svc):
        try:
            return subprocess.run(["systemctl", "is-active", "--quiet", svc]).returncode == 0
        except Exception:
            return False

    def sysctl(*a, to=120):
        try:
            return subprocess.run(["systemctl"] + list(a), capture_output=True, timeout=to)
        except Exception:
            return None
    sysctl("daemon-reload", to=60)
    for svc in ("xray", "telemt"):
        sysctl("enable", "--now", svc)
    ng_ok = None
    if shutil.which("nginx"):
        t = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=30)
        if t.returncode == 0:
            sysctl("enable", "--now", "nginx")
            ng_ok = True
        else:
            ng_ok = False
            problems.append("nginx -t не прошёл — конфиг откатан к прежнему, "
                            "веб-фронт включи на новом хосте из панели заново")
            if ng_orig:
                try:
                    shutil.copy2(ng_orig, "/etc/nginx/nginx.conf")
                    os.remove("/etc/nginx/conf.d/webproxy.conf")
                    sysctl("restart", "nginx") if unit_active("nginx") else None
                except Exception:
                    pass
    if os.path.exists("/etc/systemd/system/veil-zapret2.service"):
        sysctl("enable", "--now", "veil-zapret2")
    for cmd in (("wg-quick@" + WG_IFACE,), ("awg-quick@" + AWG_IFACE,)):
        if os.path.exists("/etc/systemd/system/%s.service" % cmd[0]):
            sysctl("enable", "--now", cmd[0], to=60)
    with open("/etc/systemd/system/vpnpanel.service", "w") as f:
        f.write(_MV_PANEL_UNIT)
    sysctl("daemon-reload", to=60)
    sysctl("enable", "--now", "vpnpanel")
    time.sleep(3)
    pp = int(CFG_CACHE.get("panel_port") or 8443)
    web_ok = False
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen("https://127.0.0.1:%d/" % pp, timeout=8, context=ctx) as r:
            web_ok = r.status == 200
    except Exception:
        pass
    bound, missing = [], []
    for spec in (manifest.get("ports") or []):
        pr, pv = spec.split(":")
        try:
            out = subprocess.run(["ss", "-H", "-l" + ("un" if pr == "udp" else "tn"),
                                  "sport = :%s" % pv], capture_output=True, text=True,
                                 timeout=10).stdout or ""
        except Exception:
            out = ""
        (bound if out.strip() else missing).append(spec)
    cur6 = ""
    try:
        cur6 = _pub_ip6() or ""
    except Exception:
        pass
    ok = bool(web_ok) and not missing and unit_active("xray") and unit_active("telemt")
    summary = {"ok": ok, "dest_ip": cur4, "dest_ip6": cur6, "panel_port": pp,
               "services": {"xray": unit_active("xray"), "telemt": unit_active("telemt"),
                            "nginx": ng_ok, "vpnpanel": unit_active("vpnpanel")},
               "web_ok": web_ok, "ports_bound": bound, "ports_missing": missing,
               "problems": problems[:10], "kept": keep}
    _mv_setp(summary=summary)
    _mv_note("перенос применён: ok=%s, недоступно портов: %s" % (ok, missing or "нет"))
    print("VEILSUM|" + json.dumps(summary, ensure_ascii=False))
    if not ok:
        raise RuntimeError("самопроверка не прошла: " + str(summary)[:300])


# ---------- backup / restore через Telegram-бота ----------
BOT_BK_PENDING = {}

def _bot_bk_disp(name):
    # veil-backup-YYYYMMDD-HHMMSS.json.gz -> YYYY-MM-DD HH:MM
    t = name[12:26]
    return t[0:4] + "-" + t[4:6] + "-" + t[6:8] + " " + t[9:11] + ":" + t[11:13]

def _bot_backup_menu(chat_id, B):
    files = _autobk_files()[:8]
    rows = [[{"text": B["bk_file_btn"] % (_bot_bk_disp(f["name"]), f["size"] // 1024),
              "callback_data": "bkr|" + f["name"]}] for f in files]
    rows.append([{"text": B["bk_new_btn"], "callback_data": "bkw"},
                 {"text": B["bk_send_btn"], "callback_data": "bks"}])
    kb = {"inline_keyboard": rows}
    if files:
        _bot_send_message(chat_id, B["bk_hdr"] % len(files), "HTML", kb)
    else:
        _bot_send_message(chat_id, B["bk_none"], "HTML", kb)

def _bot_backup_cb(chat_id, data, B):
    if data == "bkw":
        fname, raw = _autobk_make()
        _audit("bot_backup_make", name=fname)
        _bot_send_message(chat_id, B["bk_created"] % (fname, len(raw) // 1024),
                          "HTML", _main_menu_keyboard(B))
    elif data == "bks":
        files = _autobk_files()
        if files:
            fname = files[0]["name"]
            with open(os.path.join(_AUTOBK_DIR, fname), "rb") as f:
                raw = f.read()
        else:
            fname, raw = _autobk_make()
        _bot_send_message(chat_id, B["bk_sent"])
        if not _tg_send_document(chat_id, fname, raw, caption="Veil backup " + fname):
            _bot_send_message(chat_id, B["bk_err"] % "sendDocument")
    elif data.startswith("bkr|"):
        name = data[4:]
        if not _AUTOBK_RE.fullmatch(name or ""):
            _bot_send_message(chat_id, B["bk_noent"] % name)
            return
        path = os.path.join(_AUTOBK_DIR, name)
        if not os.path.exists(path):
            _bot_send_message(chat_id, B["bk_noent"] % name)
            return
        with open(path, "rb") as f:
            data_ = json.loads(gzip.decompress(f.read()))
        ncl = _client_count(data_.get("state") or {})
        BOT_BK_PENDING[chat_id] = name
        _bot_send_message(chat_id, B["bk_ask"] % (name, _bot_bk_disp(name), ncl), "HTML",
                          {"inline_keyboard": [[{"text": B["bk_yes"], "callback_data": "bky|" + name},
                                                {"text": B["bk_no"], "callback_data": "bkn"}]]})
    elif data.startswith("bky|"):
        name = data[4:]
        if BOT_BK_PENDING.get(chat_id) != name or not _AUTOBK_RE.fullmatch(name or ""):
            _bot_send_message(chat_id, B["bk_noent"] % name)
            return
        BOT_BK_PENDING.pop(chat_id, None)
        path = os.path.join(_AUTOBK_DIR, name)
        if not os.path.exists(path):
            _bot_send_message(chat_id, B["bk_noent"] % name)
            return
        with open(path, "rb") as f:
            data_ = json.loads(gzip.decompress(f.read()))
        res = _restore(data_)
        _audit("bot_backup_restore", name=name, clients=res.get("clients"))
        _bot_send_message(chat_id, B["bk_done"] % (name, res.get("clients")),
                          "HTML", _main_menu_keyboard(B))
    elif data == "bkn":
        BOT_BK_PENDING.pop(chat_id, None)
        _bot_send_message(chat_id, B["bk_cancel"], "HTML", _main_menu_keyboard(B))

class H(http.server.BaseHTTPRequestHandler):
    # HTTP/1.1 = keep-alive: без него каждый <script>/<img>/fetch открывает
    # новое TCP+TLS соединение (3-4 RTT). На мобильной сети панель из-за этого
    # грузилась секундами. timeout освобождает зависшие потоки через 30 с.
    protocol_version = "HTTP/1.1"
    timeout = 30

    def log_message(self, *a): pass

    def handle_error(self, request, client_address):
        import sys as _sys
        et = _sys.exc_info()[0]
        if et and issubclass(et, (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                                  socket.timeout, TimeoutError)):
            return
        super().handle_error(request, client_address)

    def _is_tls(self):
        try:
            return isinstance(self.request, ssl.SSLSocket)
        except Exception:
            return False

    def _sec_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        if self._is_tls():
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def _send(self, code, obj, ctype="application/json"):
        if code == 200 and isinstance(obj, dict) and "ok" not in obj:
            obj = dict(obj)
            obj["ok"] = True
        b = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).replace(r'\/', '/').encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self._sec_headers()
        for c in getattr(self, "_cookies", []):
            self.send_header("Set-Cookie", c)
        self.end_headers(); self.wfile.write(b)

    def _api_pay(self, p):
        b = self._body()
        pc = _pay_cfg()
        if p == "/api/pay/settings":
            prov = (b.get("provider") or pc["provider"])
            if prov not in _PAY_PROVIDERS:
                return self._send(400, {"error": "неизвестный провайдер"})
            CFG_CACHE["pay_enabled"] = bool(b.get("enabled"))
            CFG_CACHE["pay_provider"] = prov
            CFG_CACHE["pay_notify"] = bool(b.get("notify", True))
            for key, field in (("pay_secret", "secret"), ("pay_cb_token", "cb_token"),
                               ("pay_yoo_shop", "yoo_shop"), ("pay_yoo_secret", "yoo_secret")):
                v = b.get(field)
                v = v.strip() if isinstance(v, str) else ""
                if v:
                    CFG_CACHE[key] = v[:256]
            _save(CFG, CFG_CACHE)
            _audit("pay_settings", provider=prov, enabled=bool(b.get("enabled")))
            return self._send(200, _pay_summary())
        if p == "/api/pay/plans":
            act = (b.get("action") or "").strip()
            try:
                with PAY_LOCK:
                    d = _pay_load()
                    if act in ("add", "edit"):
                        clean = _pay_plan_valid(b.get("plan") or {})
                        pid = str((b.get("plan") or {}).get("id") or "")
                        if act == "add":
                            d["seq"] += 1
                            clean["id"] = "P%d" % d["seq"]
                            d["plans"].append(clean)
                        else:
                            hit = False
                            for i, x in enumerate(d["plans"]):
                                if str(x.get("id")) == pid:
                                    clean["id"] = pid
                                    d["plans"][i] = clean
                                    hit = True
                                    break
                            if not hit:
                                raise LookupError("тариф не найден")
                    elif act == "del":
                        pid = str(b.get("id") or "")
                        d["plans"] = [x for x in d["plans"] if str(x.get("id")) != pid]
                    else:
                        raise ValueError("нужен action: add|edit|del")
                    _pay_save(d)
            except LookupError as e:
                return self._send(404, {"error": str(e)})
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            _audit("pay_plans", action=act)
            return self._send(200, _pay_summary())
        if p == "/api/pay/invoice":
            plan = next((x for x in _pay_load()["plans"]
                         if str(x.get("id")) == str(b.get("plan_id") or "")), None)
            if not plan:
                return self._send(404, {"error": "тариф не найден"})
            try:
                inv = _pay_mkv(str(b.get("sub_token") or ""), plan, src="panel")
            except Exception as e:
                return self._send(400, {"error": str(e)})
            _audit("pay_invoice", inv=inv["id"])
            return self._send(200, {"ok": True, "invoice": inv, "summary": _pay_summary()})
        if p == "/api/pay/confirm":
            iid = str(b.get("invoice_id") or "")
            if not re.fullmatch(r"V\d{6}", iid):
                return self._send(400, {"error": "неверный id счёта"})
            inv = _pay_mark_paid(iid, "panel")
            if not inv:
                return self._send(404, {"error": "счёт не найден"})
            _audit("pay_confirm", inv=iid)
            return self._send(200, {"ok": True, "applied": bool(inv.get("applied")),
                                    "summary": _pay_summary()})
        if p == "/api/pay/check":
            iid = str(b.get("invoice_id") or "")
            if re.fullmatch(r"V\d{6}", iid):
                _pay_check_ext(iid)
            else:
                for v in list(_pay_load()["invoices"].values()):
                    if not v.get("applied") and v.get("provider") in ("cryptobot", "yookassa"):
                        _pay_check_ext(v["id"])
            return self._send(200, _pay_summary())
        return self._send(404, {"error": "not found"})

    def _body(self, maxb=8 * 1024 * 1024):
        n = int(self.headers.get("Content-Length") or 0)
        if n < 0 or n > maxb:
            raise ValueError("тело запроса слишком большое")
        return json.loads(self.rfile.read(n) or b"{}")

    def _is_cur_pw(self, cur):
        return _pw_match(CFG_CACHE.get("salt", ""), cur, CFG_CACHE.get("pass_hash"))

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
                "caps": EXT_CAPS,
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
            host = _hop_pub_host()
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
        if p == "/api/ext/restart":
            _restart_xray()
            _audit("ext_restart", token=t.get("label"))
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})

    # ---- GET ----
    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        g = _perm_gate(self, p, "GET")
        if g:
            return self._send(*g)
        if p == "/api/me":
            u = _auth_user(self)
            if not u:
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, {"login": u["login"], "owner": bool(u["owner"]),
                                    "perms": ({"*": True} if u["owner"] else u["perms"])})
        if p == "/api/users":
            u = _auth_user(self)
            if not u:
                return self._send(401, {"error": "unauthorized"})
            if not u["owner"]:
                return self._send(403, {"error": "недостаточно прав"})
            us = [{"login": x.get("login"), "perms": x.get("perms") or {},
                   "disabled": bool(x.get("disabled")), "created": x.get("created")}
                  for x in (CFG_CACHE.get("users") or [])]
            return self._send(200, {"users": us, "perm_keys": PERM_KEYS})
        
        if p.startswith("/sub/") or p in ("/sub", "/sub/"):
            # Универсальная подписка (/sub) или личная подписка клиента (/sub/<subId>).
            # Как в 3x-ui: возвращается base64-список ссылок на ВСЕ протоколы, где есть клиент,
            # плюс заголовок subscription-userinfo (upload/download/total/expire) для v2rayNG и др.
            try:
                import base64
                sub_path = p[5:].strip("/") if p.startswith("/sub/") else ""
                st = _load(STATE) or {}
                host = _hop_pub_host()
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
                        if not inb.get("disabled"):
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
                xprof = None
                _ual = ua.lower()
                if sub_path and not use_sb and \
                        ("incy" in _ual or "happ" in _ual or _is_incy_client(ua, xc)):
                    try:
                        xprof = _routing_profile_b64(
                            _pb(host, CFG_CACHE.get("panel_port", 8444)))
                    except Exception:
                        xprof = None
                if use_sb:
                    payload = json.dumps(list(sb_objs.values()), ensure_ascii=False).replace(r'\/', '/')
                    b = payload.encode("utf-8")
                    ctype = "application/json; charset=utf-8"
                elif is_incy:
                    # Xray 26.7.11+ наотрез отказывается поднимать outbound
                    # «VLESS без TLS/Reality к публичному адресу» (шифрования
                    # нет — логин ушёл бы открытым текстом). Отдать незашифрованную
                    # vless-ссылку такому ядру нельзя, поэтому в подписку INCY
                    # plaintext-VLESS ноды не попадают: за WebSocket берёт
                    # соседняя нода «VLESS + WebSocket + TLS» (тот же uuid).
                    payload = "\n".join(list(tg_links) + [
                                        l for l in inc_links.values()
                                        if not (l.startswith("vless://") and
                                                "security=none" in l)])
                    if xprof:
                        # Incy понимает routing-профиль только диплинк-формой
                        # incy://routing/onadd/{b64} (схема обязательна, как happ:// у
                        # Happ). Без схемы строку ядро молча игнорировало — потому под
                        # VPN-туннелем Incy и терял MTProto: обходных DirectIp-исключений
                        # не применялось, телефон петлёй уходил на тот же VPS.
                        payload = ("incy://routing/onadd/" + xprof + "\n" + payload)
                    b = payload.encode("utf-8")
                    ctype = "text/plain; charset=utf-8"
                else:
                    # WG/AmneziaWG — однострочными ссылками wireguard:// и amneziawg://
                    # (тот же формат, что для INCY): Shadowrocket, Happ, NekoBox
                    # импортируют их из подписки. Многострочные [Interface]-блоки
                    # клиенты не разбирают и теряли эти протоколы молча.
                    links = [(inc_links.get(p) or l) if p in ("wireguard", "amneziawg") else l
                             for p, l in inb_links.items()]
                    # ссылки нод, куда клиент размещён мастером — в общий base64-список
                    links = links + list(node_links.values()) + tg_links
                    # Однострочные ссылки сначала, многострочные WG/AmneziaWG-блоки в конец:
                    # парсеры, спотыкающиеся о [Interface], всё равно импортируют остальное.
                    one = [l for l in links if l.startswith(("vless://", "vmess://", "trojan://", "ss://", "hy2://", "tg://"))]
                    if len(one) < len(links):
                        links = one + [l for l in links if l not in one]
                    # Happ (Xray-ядро) понимает профиль маршрутизации, приложенный
                    # к подписке строкой happ://routing/onadd/{base64} — тогда
                    # обход РФ включается сам, без «полного конфига» (который Happ
                    # всё равно не импортирует: у него Xray, а не sing-box).
                    # Прочим v2ray-клиентам (Shadowrocket/v2rayNG) строку не даём —
                    # они её не распознают.
                    if xprof and "happ" in _ual:
                        links.insert(0, "happ://routing/onadd/" + xprof)
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
                _pt = ((CFG_CACHE.get("sub_brand") or "").strip() or sub_name)[:25]
                if _pt:
                    pt = "base64:" + base64.b64encode(_pt.encode("utf-8")).decode()
                    self.send_header("profile-title", pt)
                _su = (CFG_CACHE.get("sub_support_url") or "").strip()
                if _su:
                    self.send_header("support-url", _su[:250])
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
            host = _hop_pub_host()
            host = host if "://" not in host else urllib.parse.urlparse(host).netloc
            panel_port = CFG_CACHE.get("panel_port", 8444)
            cfgj = _sb_config(st, tok, host, panel_port)
            if cfgj is None:
                return self._send(404, {"error": "клиент не найден"})
            # Отдаём как файл: браузер сохраняет veil.json (Happ импортирует его),
            # а _send добавил бы в JSON служебный ключ "ok" — конфиг с ним ломается.
            payload = json.dumps(cfgj, ensure_ascii=False, indent=1).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="veil.json"')
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers(); self.wfile.write(payload)
            return None

        if p.startswith("/pay/") or p == "/shop":
            return _pay_handle_public(self, p)

        if p.startswith("/p/") and p.endswith("/avatar"):
            # Аватар отдельным GET-файлом (токен = право доступа, как у POST-варианта).
            # Встроенный base64 делал каждую загрузку /p на ~95 КБ тяжелее и
            # гарантированно не кэшировался; здесь — public, max-age=1 день.
            tok = p[3:-len("/avatar")].strip("/")
            st = _load(STATE) or {}
            if _migrate_state(st):
                _save(STATE, st)
            if not any(x["sub_token"] == tok or x["uuid"] == tok
                       for x in _subs_summary(st)):
                return self._send(404, {"error": "подписка не найдена"})
            mime, raw = _avatar_serve(tok)
            if raw is None:
                return self._send(404, {"error": "аватара нет"})
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(raw)
            return None

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
            host = _hop_pub_host()
            host = host if "://" not in host else urllib.parse.urlparse(host).netloc
            panel_port = CFG_CACHE.get("panel_port", 8444)
            sub_url = f"{_pb(host, panel_port)}/sub/{u['sub_token']}"
            _q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query or "")
            _lq = (_q.get("lang") or [""])[0]
            _lck = ""
            for _c in (self.headers.get("Cookie") or "").split(";"):
                _c = _c.strip()
                if _c.startswith("veil_sub_lang="):
                    _lck = _c[len("veil_sub_lang="):]
            lang = _sub_lang_pick(_lq, _lck, self.headers.get("Accept-Language", ""))
            html = _sub_page_html(u, sub_url, host, panel_port,
                                  self.headers.get("User-Agent", "") or "",
                                  devs=_subdev_list(tok), lang=lang,
                                  pact=_protoact_view(tok))
            b = html.encode("utf-8")
            # страница весит ~135 КБ (все ссылки/иконки встроены): по мобильному
            # каналу gzip снимает ~85% трафика и секунды ожидания
            enc = None
            if "gzip" in (self.headers.get("Accept-Encoding") or "").lower():
                b, enc = gzip.compress(b, 6), "gzip"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Vary", "Accept-Encoding")
            if enc:
                self.send_header("Content-Encoding", enc)
            if _lq:
                self.send_header("Set-Cookie",
                                 "veil_sub_lang=" + lang + "; Path=/; Max-Age=31536000; SameSite=Lax")
            self.end_headers()
            self.wfile.write(b)
            return None


        if p.startswith("/api/wgconf/") or p.startswith("/api/awgconf/"):
            only_proto = "wireguard" if p.startswith("/api/wgconf/") else "amneziawg"
            tok = p[len("/api/wgconf/"):].strip("/") or p[len("/api/awgconf/"):].strip("/")
            st = _load(STATE, {}) or {}
            host = _hop_pub_host()
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

        if p.startswith("/appicons/"):
            # Логотипы приложений в каталоге личного кабинета (файлы лежат в BASE/appicons)
            fn = os.path.basename(p)
            if not re.match(r"^[a-z0-9][a-z0-9._-]{0,63}\.(?:jpg|png|webp|ico|svg)$", fn):
                return self._send(404, {"error": "not found"})
            fp = os.path.join(BASE, "appicons", fn)
            try:
                with open(fp, "rb") as f:
                    data = f.read()
            except Exception:
                return self._send(404, {"error": "not found"})
            mime = {"jpg": "image/jpeg", "png": "image/png", "webp": "image/webp",
                    "ico": "image/x-icon", "svg": "image/svg+xml"}[fn.rsplit(".", 1)[1]]
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Cache-Control", "public, max-age=604800")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return None

        if p == "/favicon.ico":
            # Happ и др. тянут логотип подписки из favicon-а домена подписки
            try:
                with open(_LOGO_PNG or os.path.join(BASE, "icon-veil.png"), "rb") as f:
                    data = f.read()
            except Exception:
                return self._send(404, {"error": "not found"})
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Cache-Control", "public, max-age=86400")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
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
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
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
            # отладочный артефакт: файл остаётся на диске, но наружу — только авторизованной сессии
            if not _authed(self):
                return self._send(404, {"error": "not found"})
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
            etag = '"' + hashlib.sha256(content).hexdigest()[:32] + '"'
            if (self.headers.get("If-None-Match") or "").strip() == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Vary", "Accept-Encoding")
                self._sec_headers()
                self.end_headers()
                return None
            body = content
            enc = None
            if "gzip" in (self.headers.get("Accept-Encoding") or "").lower():
                global _HTML_GZ
                if not (_HTML_GZ and _HTML_GZ[0] == etag):
                    _HTML_GZ = (etag, gzip.compress(content, 6))
                body, enc = _HTML_GZ[1], "gzip"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("ETag", etag)
            # no-cache = перепроверка по ETag каждый раз: файл ~1 МБ, но отдача
            # 304 или gzip снимает почти весь трафик повторных загрузок.
            self.send_header("Cache-Control", "no-cache")
            if enc: self.send_header("Content-Encoding", enc)
            self.send_header("Vary", "Accept-Encoding")
            self._sec_headers()
            self.end_headers()
            self.wfile.write(body)
            return None
        if p == "/api/state":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            just_born = _onboard_ensure()
            if just_born:
                _onboard_notify()
            st = _load(STATE)
            running = subprocess.run(["systemctl", "is-active", "--quiet", "xray"]).returncode == 0
            out = {"version": VERSION, "running": running, "login": CFG_CACHE.get("login", ""),
                   "configured": _client_count(st) > 0,
                   "proto": _proto_of(st),
                   "panel_port": CFG_CACHE.get("panel_port", 8443),
                   "ipv6": _my_ipv6(),
                   "onboarding": _onboard_info(),
                   "favorites": st.get("favorites", []) if st else []}
            return self._send(200, out)
        if p == "/api/vpn/protocols":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            st = _load(STATE) or {}
            inbs = st.get("inbounds") or {}
            return self._send(200, {"current": _proto_of(st),
                                    "configured": _client_count(st) > 0,
                                    "protocols": [dict(p, disabled=bool((inbs.get(p["id"]) or {}).get("disabled")),
                                                        has_inbound=bool(inbs.get(p["id"])))
                                                  for p in PROTOCOLS]})
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
            host = _hop_pub_host()
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
                try:
                    u["usage"] = _protoact_view(tok)
                except Exception:
                    u["usage"] = []
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
            b = json.dumps(_load(THEME, {})).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(b)
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
            cur = {"panel": VERSION}
            try: cur["xray"] = _xray_current_version()
            except Exception: cur["xray"] = "unknown"
            try: cur["telemt"] = _tg_current_version()
            except Exception: cur["telemt"] = "unknown"
            return self._send(200, {"panel": _panel_backups(), "xray": _xray_backups(),
                                    "telemt": _tg_backups(), "current": cur})
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
        if p == "/api/logs/services":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            out = []
            for sid, label, kind, tgt in LOG_SOURCES:
                if kind == "journal":
                    ok = (os.path.exists("/etc/systemd/system/%s.service" % tgt)
                          or os.path.exists("/lib/systemd/system/%s.service" % tgt))
                else:
                    ok = os.path.exists(tgt)
                out.append({"id": sid, "label": label, "available": ok})
            return self._send(200, {"services": out})
        if p == "/api/logs":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            svc = (qs.get("svc") or [""])[0].strip()
            src = next((s for s in LOG_SOURCES if s[0] == svc), None)
            if not src: return self._send(400, {"error": "unknown service"})
            try: lines = max(10, min(2000, int((qs.get("lines") or [""])[0] or "200")))
            except Exception: lines = 200
            grep = (qs.get("q") or [""])[0].strip()[:200]
            want = min(lines * 4, 8000) if grep else lines
            if src[2] == "journal":
                try:
                    r = subprocess.run(["journalctl", "-u", src[3], "-n", str(want),
                                        "--no-pager", "-q"], capture_output=True, text=True, timeout=10)
                    ls = (r.stdout or "").splitlines()
                except Exception:
                    return self._send(502, {"error": "journalctl unavailable"})
            else:
                try:
                    ls = _tail_lines(src[3], want)
                except Exception:
                    return self._send(502, {"error": "log file unavailable"})
            if grep:
                gl = grep.lower()
                ls = [x for x in ls if gl in x.lower()][:lines]
            else:
                ls = ls[-lines:]
            return self._send(200, {"text": "\n".join(ls), "count": len(ls), "svc": svc})
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
        if p == "/api/pay":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _pay_summary())
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
                "synfix_enabled": bool(CFG_CACHE.get("synfix_enabled", True)),
                "synfix_port_live": _synfix_live()[0],
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
                key = (grp, inb.get("port"))
                agg[key] = agg.get(key, 0) + n
            for (grp, port), n in sorted(agg.items(), key=lambda kv: -kv[1]):
                protos.append({"proto": grp, "label": _grp_lbl.get(grp, grp),
                               "clients": n, "port": port, "running": running})
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
                self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
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
                self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
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
        if p == "/api/front/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            try:
                return self._send(200, _front_status())
            except Exception as e:
                return self._send(200, {"error": str(e)[:200]})
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
        if p == "/api/webmux/preview":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            return self._send(200, _mux_preview((q.get("vpn_domain") or [""])[0] or None))
        if p == "/api/tg/mtproto/preview":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _tg_mp_preview())
        if p == "/api/hop/list":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _hop_public_view())
        if p == "/api/hop/preview":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            return self._send(200, _hop_preview((q.get("ip") or [""])[0],
                                                (q.get("ports") or [""])[0]))
        if p == "/api/hop/bootstatus":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            jid = (q.get("id") or [""])[0]
            with HOP_LOCK:
                j = HOP_JOBS.get(jid)
                return self._send(200, json.loads(json.dumps(j, default=str)) if j
                                  else {"error": "задание не найдено"})
        if p == "/api/migrate/status":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _mv_view())
        if p == "/api/migrate/job":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            return self._send(200, _mv_public_job((q.get("id") or [""])[0]))
        if p == "/relay.sh":
            # Публичный одноразовый установщик фронта: токен в query = право установки.
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            hop = _hop_find_tok((q.get("tok") or [""])[0])
            if hop is None or hop.get("state") != "pending":
                return self._send(404, "# ссылка неверна или уже использована — создай фронт в панели заново\n".encode(),
                                  "text/plain; charset=utf-8")
            if int(hop.get("tok_exp") or 0) < time.time():
                return self._send(404, "# срок жизни ссылки истёк — создай фронт в панели заново\n".encode(),
                                  "text/plain; charset=utf-8")
            return self._send(200, _relay_installer(hop, with_register=True).encode(),
                              "text/x-shellscript; charset=utf-8")
        if p == "/api/stats":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _stats())
        if p == "/api/backup":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            return self._send(200, _backup())
        if p == "/api/backups":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            s = _autobk_settings()
            nxt = s["last"] + s["every_h"] * 3600
            return self._send(200, {
                "settings": s, "files": _autobk_files(),
                "next_in": max(0, nxt - int(time.time())) if s["enabled"] else None,
                "tg_ready": bool(CFG_CACHE.get("bot_token") and (CFG_CACHE.get("bot_chat_ids") or []))})
        if p == "/api/backups/download":
            if not _authed(self): return self._send(401, {"error": "unauthorized"})
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = (qs.get("name") or [""])[0]
            if not _AUTOBK_RE.fullmatch(name):
                return self._send(400, {"error": "недопустимое имя файла"})
            try:
                with open(os.path.join(_AUTOBK_DIR, name), "rb") as f:
                    return self._send(200, f.read(), "application/gzip")
            except FileNotFoundError:
                return self._send(404, {"error": "файл не найден"})
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
                is_owner = (b.get("login") == CFG_CACHE.get("login") and
                            self._is_cur_pw(b.get("password", "")))
                op_user = None
                if not is_owner:
                    for x in (CFG_CACHE.get("users") or []):
                        if (x.get("login") == b.get("login") and not x.get("disabled") and
                                _pw_match(x.get("salt", ""), b.get("password", ""), x.get("pass_hash"))):
                            op_user = x
                            break
                if not (is_owner or op_user):
                    _login_fail(cip)
                    _login_history("fail", ip=cip, ua=ua_h, user=b.get("login"))
                    return self._send(401, {"error": "неверный логин или пароль"})
                if is_owner and CFG_CACHE.get("totp_enabled"):
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
                                    "last_seen": _now_iso(), "remember": bool(rem),
                                    "user": "" if is_owner else (op_user or {}).get("login", "")}
                _login_history("ok", ip=cip, ua=ua_h, user=b.get("login"))
                _audit("login", ip=cip, ua=ua_h, user=b.get("login"), ok=True)
                _save_sessions()
                ma = 2592000 if rem else 259200
                self._cookies = ["sid=" + t + "; Path=/; HttpOnly; Max-Age=" + str(ma) + "; SameSite=Lax"
                                 + ("; Secure" if self._is_tls() else "")]
                return self._send(200, {"ok": True, "sid": t, "remember": rem})
            if p == "/api/passkey/have":
                db = _pk_load()
                n = sum(len(v or []) for v in db.values())
                return self._send(200, {"have": n > 0, "n": n})
            if p == "/api/passkey/login/begin":
                db = _pk_load()
                ids = [k.get("id") for lst in db.values() for k in lst if k.get("id")]
                if not ids:
                    return self._send(400, {"error": "нет привязанных ключей входа"})
                tok, ch = _pk_new_pending(_pk_host(self))
                return self._send(200, {"token": tok, "challenge": _b64u_enc(ch), "ids": ids})
            if p == "/api/passkey/login/end":
                st, js = _pk_login_end(self, self._body() or {})
                return self._send(st, js)
            if (not _authed(self) and p != "/api/bot/webhook" and p != "/api/hop/register"
                    and not p.startswith("/api/ext/") and not p.startswith("/pay/")
                    and not (p.startswith("/p/") and (p.endswith("/forget") or p.endswith("/avatar")))):
                return self._send(401, {"error": "unauthorized"})
            g = _perm_gate(self, p, "POST")
            if g:
                return self._send(*g)
            if p == "/api/passkey/register/begin":
                b = self._body() or {}
                uid = _pk_uid(self)
                if uid is None:
                    return self._send(401, {"error": "unauthorized"})
                host = _pk_host(self)
                if not host or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                    return self._send(400, {"error": "для привязки ключа открой панель по домену и https"})
                tok, ch = _pk_new_pending(host)
                u = _auth_user(self) or {}
                db = _pk_load()
                exclude = [k.get("id") for k in db.get(uid, []) if k.get("id")]
                return self._send(200, {
                    "token": tok, "challenge": _b64u_enc(ch), "rp": host,
                    "exclude": exclude,
                    "user": ("" if uid == "" else uid) or (u.get("login") or CFG_CACHE.get("login") or "admin"),
                })
            if p == "/api/passkey/register/end":
                uid = _pk_uid(self)
                if uid is None:
                    return self._send(401, {"error": "unauthorized"})
                st, js = _pk_reg_end(self, self._body() or {}, uid)
                return self._send(st, js)
            if p == "/api/passkey/list":
                uid = _pk_uid(self)
                if uid is None:
                    return self._send(401, {"error": "unauthorized"})
                return self._send(200, {"keys": _pk_public(_pk_load().get(uid, []))})
            if p == "/api/passkey/delete":
                uid = _pk_uid(self)
                if uid is None:
                    return self._send(401, {"error": "unauthorized"})
                b = self._body() or {}
                kid = str(b.get("id") or "")
                db = _pk_load()
                lst = db.get(uid) or []
                left = [k for k in lst if k.get("id") != kid]
                if len(left) == len(lst):
                    return self._send(404, {"error": "ключ не найден"})
                removed = next(k for k in lst if k.get("id") == kid)
                db[uid] = left
                _save(PASSKEYS_FILE, db)
                _audit("passkey_del", id=kid, name=removed.get("name"))
                return self._send(200, {"ok": True})
            if p.startswith("/api/users/"):
                u = _auth_user(self)
                if not u or not u["owner"]:
                    return self._send(403, {"error": "только владелец"})
                b = self._body() or {}
                users = [dict(x) for x in (CFG_CACHE.get("users") or [])]
                lg = str(b.get("login") or "").strip().lower()
                if p == "/api/users/add":
                    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,31}", lg):
                        return self._send(400, {"error": "логин: 3–32 символа, латиница, цифры, . _ -"})
                    if lg == str(CFG_CACHE.get("login") or "").lower() or any(x.get("login") == lg for x in users):
                        return self._send(400, {"error": "такой логин уже занят"})
                    if len(users) >= 20:
                        return self._send(400, {"error": "не более 20 операторов"})
                    pw = str(b.get("password") or "")
                    if len(pw) < 8:
                        return self._send(400, {"error": "пароль минимум 8 символов"})
                    salt = secrets.token_hex(16)
                    users.append({"login": lg, "salt": salt, "pass_hash": _hash2(salt, pw),
                                  "perms": _clean_perms(b.get("perms")),
                                  "disabled": False, "created": _now_iso()})
                    CFG_CACHE["users"] = users
                    _save(CFG, CFG_CACHE)
                    _audit("user_add", login=lg)
                    return self._send(200, {"ok": True})
                tgt = next((x for x in users if x.get("login") == lg), None)
                if not tgt:
                    return self._send(404, {"error": "оператор не найден"})
                if p == "/api/users/update":
                    if "perms" in b:
                        tgt["perms"] = _clean_perms(b.get("perms"))
                    if "disabled" in b:
                        tgt["disabled"] = bool(b.get("disabled"))
                        if tgt["disabled"]:
                            _drop_user_sessions(lg)
                elif p == "/api/users/passwd":
                    pw = str(b.get("password") or "")
                    if len(pw) < 8:
                        return self._send(400, {"error": "пароль минимум 8 символов"})
                    tgt["salt"] = secrets.token_hex(16)
                    tgt["pass_hash"] = _hash2(tgt["salt"], pw)
                    _drop_user_sessions(lg)
                elif p == "/api/users/delete":
                    users = [x for x in users if x.get("login") != lg]
                    _drop_user_sessions(lg)
                else:
                    return self._send(404, {"error": "not found"})
                CFG_CACHE["users"] = users
                _save(CFG, CFG_CACHE)
                _audit("user_update", login=lg, action=p.rsplit("/", 1)[-1])
                return self._send(200, {"ok": True})
            if p.startswith("/pay/"):
                return _pay_handle_public(self, p)
            if p.startswith("/api/pay/"):
                return self._api_pay(p)
            if p.startswith("/p/") and p.endswith("/avatar"):
                # Публичная смена аватара со страницы /p/<tok>: токен = право доступа.
                tok = p[3:-len("/avatar")].strip("/")
                st = _load(STATE) or {}
                if _migrate_state(st): _save(STATE, st)
                ok_sub = any(x["sub_token"] == tok or x["uuid"] == tok
                             for x in _subs_summary(st))
                if not ok_sub:
                    return self._send(404, {"error": "подписка не найдена"})
                try:
                    b = self._body(maxb=260 * 1024)
                    if not isinstance(b, dict):
                        b = {}
                except Exception:
                    return self._send(400, {"error": "нечитаемое тело запроса"})
                img = str(b.get("img") or "")
                if not img:
                    _avatar_remove(tok)
                    return self._send(200, {"ok": True, "removed": True})
                m = re.match(r"^data:image/(png|jpeg|jpg|gif|webp);base64,([A-Za-z0-9+/=]{1,220000})$", img)
                if not m:
                    return self._send(400, {"error": "нужна картинка PNG/JPEG/GIF/WebP"})
                try:
                    raw = base64.b64decode(m.group(2))
                except Exception:
                    return self._send(400, {"error": "нужна картинка PNG/JPEG/GIF/WebP"})
                if not _avatar_save(tok, raw):
                    return self._send(400, {"error": "картинка не распознана или слишком большая"})
                return self._send(200, {"ok": True})
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
            if p == "/api/inbound/toggle":
                b = self._body()
                proto = (b.get("proto") or "").strip()
                if proto not in _VALID_PROTOCOLS:
                    return self._send(400, {"error": "неизвестный протокол"})
                st = _load(STATE) or {}
                inb = (st.get("inbounds") or {}).get(proto)
                if not inb:
                    return self._send(404, {"error": "inbound не найден: " + proto})
                want = bool(b.get("disabled"))
                was = bool(inb.get("disabled"))
                if want:
                    inb["disabled"] = True
                else:
                    inb.pop("disabled", None)
                _awg_sync(st); _wg_sync(st)
                ok, err = _validate_and_apply(st)
                if not ok:
                    if was:
                        inb["disabled"] = True
                    else:
                        inb.pop("disabled", None)
                    return self._send(400, {"error": err or "конфиг не принят"})
                _audit("proto_toggle", proto=proto, disabled=want)
                return self._send(200, {"ok": True, "proto": proto, "disabled": want})
            if p == "/api/bot/webhook":
                # Telegram webhook endpoint (no auth needed - called by Telegram)
                if self.command != "POST":
                    return self._send(405, {"error": "Method not allowed"})
                secret = CFG_CACHE.get("bot_webhook_secret") or ""
                if secret:
                    got = (self.headers.get("X-Telegram-Bot-Api-Secret-Token") or "").strip()
                    if not hmac.compare_digest(got, secret):
                        return self._send(403, {"error": "bad secret token"})
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
                
                host = _hop_pub_host()
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
            if p == "/api/nodes/restart":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                b = self._body()
                host = (b.get("host") or "").strip()
                nodes = get_nodes()
                node = next((n for n in nodes
                             if (n.get("host") or "").strip().lower() == host.lower()), None)
                if not node:
                    return self._send(404, {"error": "нода не найдена"})
                err = _node_restart(node)
                _node_poll_one(node)
                save_nodes(nodes)
                if err:
                    _audit("node_restart", host=host, ok=False, err=str(err)[:120])
                    return self._send(502, {"error": err})
                _audit("node_restart", host=host, ok=True)
                return self._send(200, {"ok": True, "nodes": _nodes_public()})
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
                if not _ssh_target_ok(user, host):
                    return self._send(400, {"error": "SSH-логин или адрес содержат недопустимые символы (разрешены буквы, цифры, . _ - :)"})
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
            if p == "/api/onboard/dismiss":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                if CFG_CACHE.get("onboarded") and CFG_CACHE.get("onboarded") != "clients":
                    CFG_CACHE["onboarded"] = "seen"
                    _save(CFG, CFG_CACHE)
                return self._send(200, {"ok": True})
            if p == "/api/extimport/preview":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                try:
                    b = self._body(maxb=40 * 1024 * 1024)
                except Exception as e:
                    return self._send(400, {"error": str(e)})
                raw = None
                b64 = str(b.get("db_b64") or "")
                if b64:
                    try:
                        raw = base64.b64decode(b64, validate=True)
                    except Exception:
                        return self._send(400, {"error": "файл повреждён (не корректный base64)"})
                else:
                    path = (b.get("db_path") or "").strip()
                    if not path:
                        return self._send(400, {"error": "не прислан файл базы"})
                    if not re.fullmatch(r"[A-Za-z0-9/_.\-]{2,512}", path) \
                            or not re.search(r"\.(db|sqlite3?|database)$", path, re.I):
                        return self._send(400, {"error": "разрешён только путь к файлу .db/.sqlite без специальных символов"})
                    try:
                        if not os.path.isfile(path) or os.path.getsize(path) > _EXTIMP_MAX_DB:
                            return self._send(400, {"error": "файл не найден или больше 16 МБ"})
                        with open(path, "rb") as f:
                            raw = f.read()
                    except Exception:
                        return self._send(400, {"error": "не могу прочитать файл"})
                if not raw or len(raw) > _EXTIMP_MAX_DB:
                    return self._send(400, {"error": "пустой файл или больше 16 МБ"})
                if raw[:16] != b"SQLite format 3\x00":
                    return self._send(400, {"error": "это не sqlite-база (ожидается файл .db панели)"})
                try:
                    source, items, warnings = _extimport_parse(raw)
                except Exception as e:
                    return self._send(400, {"error": "разбор базы не удался: " + str(e)[:160]})
                if not items:
                    return self._send(400, {"error": "подходящих клиентов не найдено" +
                                                   ("; " + "; ".join(warnings[:3]) if warnings else "")})
                groups = {}
                for it in items:
                    g = groups.setdefault(it["veil_proto"], {"proto": it["veil_proto"], "count": 0, "names": []})
                    g["count"] += 1
                    if len(g["names"]) < 8:
                        g["names"].append(it["name"])
                iid = uuidlib.uuid4().hex[:12]
                with EXTIMPORT_LOCK:
                    now = time.time()
                    for k in [k for k, v in EXTIMPORT.items() if now - v["created"] > 1800]:
                        EXTIMPORT.pop(k, None)
                    EXTIMPORT[iid] = {"created": int(now), "source": source,
                                      "items": items, "warnings": warnings}
                _audit("ext_import_preview", source=source, clients=len(items))
                return self._send(200, {"import_id": iid, "source": source, "total": len(items),
                                        "groups": sorted(groups.values(), key=lambda g: -g["count"]),
                                        "warnings": warnings[:50]})
            if p == "/api/extimport/apply":
                if not _authed(self):
                    return self._send(401, {"error": "unauthorized"})
                b = self._body()
                iid = (b.get("import_id") or "").strip()[:12]
                with EXTIMPORT_LOCK:
                    job = EXTIMPORT.get(iid)
                if not job:
                    return self._send(400, {"error": "превью устарело (30 минут) — приложи файл заново"})
                st = _load(STATE)
                if st is None:
                    st = _new_state()
                _migrate_state(st)
                imported, warns, per = _extimport_apply(st, job["items"])
                if not imported:
                    return self._send(400, {"error": "импортировать нечего (все дубликаты?)", "warnings": warns})
                _awg_sync(st); _wg_sync(st)
                ok, err = _validate_and_apply(st)
                if not ok:
                    return self._send(400, {"error": "конфиг не принят: " + str(err)[:200], "warnings": warns})
                with EXTIMPORT_LOCK:
                    EXTIMPORT.pop(iid, None)
                _audit("ext_import_apply", source=job.get("source"), imported=imported, per=per)
                return self._send(200, {"ok": True, "imported": imported, "per": per,
                                        "warnings": warns[:60], "subs": _subs_summary(st)})
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

                host = _hop_pub_host()
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

            if p == "/api/clients/expand":
                b = self._body() or {}
                u = (b.get("uuid") or "").strip()
                st = _load(STATE)
                if not st: return self._send(404, {"error": "нет состояния"})
                src, have = None, set()
                for proto, inb in (st.get("inbounds") or {}).items():
                    for c in (inb.get("clients") or []):
                        if c.get("uuid") == u:
                            if src is None: src = c
                            have.add(proto)
                if not src: return self._send(404, {"error": "клиент не найден"})
                added = []
                for proto, inb in (st.get("inbounds") or {}).items():
                    if proto in have: continue
                    c = _new_client(src.get("name") or "Клиент", proto, inb,
                                    limit_gb=src.get("limit_gb"), expiry=src.get("expiry") or 0,
                                    reset_cycle=src.get("reset_cycle"), max_devices=src.get("max_devices"))
                    c["uuid"] = u
                    if src.get("sub_token"): c["sub_token"] = src["sub_token"]
                    for k in ("tg_proxy", "tg_user"):
                        if src.get(k): c[k] = src[k]
                    inb.setdefault("clients", []).append(c)
                    added.append(proto)
                if not added:
                    return self._send(200, {"added": [], "note": "уже во всех протоколах"})
                try: _awg_sync(st)
                except Exception: pass
                try: _wg_sync(st)
                except Exception: pass
                _write_xray(st); _save(STATE, st)
                try: _restart_xray()
                except Exception: pass
                _audit("client_expand", uuid=u, protos=",".join(added))
                return self._send(200, {"added": added})

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
            if p == "/api/versions/backup":
                return self._send(200, _panel_backup_now())
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
            if p == "/api/webmux/apply":
                try:
                    b = self._body() or {}
                    return self._send(200, _mux_apply(b.get("vpn_domain"),
                                                      bool(b.get("confirm")), bool(b.get("force"))))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/webmux/revert":
                try:
                    b = self._body() or {}
                    return self._send(200, _mux_revert(bool(b.get("confirm"))))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/tg/mtproto/apply":
                try:
                    b = self._body() or {}
                    return self._send(200, _tg_mp_apply(b.get("port"), bool(b.get("confirm"))))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/tg/mtproto/revert":
                try:
                    b = self._body() or {}
                    return self._send(200, _tg_mp_revert(bool(b.get("confirm"))))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            # ---- двойной прыжок (RU-фронт + зарубежный бэк) ----
            if p == "/api/hop/add":
                try:
                    b = self._body() or {}
                    ports = b.get("ports") or []
                    if isinstance(ports, str):
                        ports = [x for x in re.split(r"[,\s]+", ports) if x]
                    return self._send(200, _hop_add(b.get("name"), b.get("front_ip"), ports))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/hop/ssh":
                try:
                    b = self._body() or {}
                    hid = (b.get("id") or "").strip()
                    hop = next((h for h in _hop_load() if h.get("id") == hid), None)
                    if not hop:
                        raise RuntimeError("хоп не найден")
                    user = (b.get("user") or "root").strip()
                    if not _SSH_USER_RE.fullmatch(user):
                        raise RuntimeError("SSH-логин содержит недопустимые символы")
                    sport = int(b.get("ssh_port") or 22)
                    if not (1 <= sport <= 65535):
                        raise RuntimeError("неверный SSH-порт")
                    with HOP_LOCK:
                        busy = any((not j["done"]) and j.get("hop") == hid for j in HOP_JOBS.values())
                    if busy:
                        raise RuntimeError("установка на этот фронт уже идёт")
                    jid = _hop_ssh_job(hid, user, str(b.get("password") or ""), sport)
                    _audit("hop_bootstrap_start", id=hid, front_ip=hop.get("front_ip"))
                    return self._send(200, {"id": jid})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/hop/relink":
                try:
                    b = self._body() or {}
                    return self._send(200, _hop_relink((b.get("id") or "").strip()))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/hop/status":
                try:
                    b = self._body() or {}
                    hid = (b.get("id") or "").strip() or None
                    return self._send(200, _hop_check(hid))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/hop/remove":
                try:
                    b = self._body() or {}
                    return self._send(200, _hop_remove((b.get("id") or "").strip(),
                                                       bool(b.get("confirm"))))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/hop/public":
                try:
                    b = self._body() or {}
                    return self._send(200, _hop_set_public(b.get("host")))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/migrate/plan":
                try:
                    b = self._body() or {}
                    return self._send(200, _mv_plan(b.get("host"), b.get("ssh_user"),
                                                    b.get("ssh_port")))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/migrate/start":
                try:
                    b = self._body() or {}
                    pl = _mv_plan(b.get("host"), b.get("ssh_user"), b.get("ssh_port"))
                    if not pl["can_apply"]:
                        raise RuntimeError("; ".join(pl["blockers"]))
                    with MV_LOCK:
                        busy = any((not j.get("done")) for j in MV_JOBS.values())
                    if busy:
                        raise RuntimeError("переезд уже устанавливается — дождись завершения")
                    password = str(b.get("password") or "")
                    jid = _mv_new_job({"host": pl["dest"]["host"], "user": pl["dest"]["user"],
                                       "ssh_port": pl["dest"]["ssh_port"], "password": password,
                                       "confirm_takeover": bool(b.get("confirm_takeover"))})
                    _mv_setp(jid=jid, step="precheck")
                    _mv_note("переезд начат: %s@%s:%s" % (pl["dest"]["user"], pl["dest"]["host"],
                                                          pl["dest"]["ssh_port"]))
                    _audit("mv_start", host=pl["dest"]["host"],
                           takeover=bool(b.get("confirm_takeover")))
                    return self._send(200, {"id": jid})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/migrate/verify":
                try:
                    return self._send(200, _mv_verify_now())
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/migrate/dns":
                try:
                    b = self._body() or {}
                    return self._send(200, _mv_dns((b.get("provider") or "auto"),
                                                   bool(b.get("confirm"))))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/migrate/schedule":
                try:
                    b = self._body() or {}
                    ts = int(b.get("scheduled_ts") or 0)
                    if ts and ts < time.time() + 30:
                        raise RuntimeError("расписание должно быть минимум через минуту")
                    if ts and _mv_step() not in ("verified", "applied"):
                        raise RuntimeError("расписание ставится после успешной переноски "
                                           "(шаг «проверка связности»)")
                    _mv_setp(scheduled_ts=ts, auto_retire=bool(b.get("auto_retire")),
                             scheduled_provider=b.get("provider") or "auto")
                    _mv_note("расписание: " + (time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
                                               if ts else "снято") +
                             (", авто-пенсия" if b.get("auto_retire") else ""))
                    return self._send(200, {"scheduled_ts": ts})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/migrate/retire":
                try:
                    b = self._body() or {}
                    return self._send(200, _mv_retire(bool(b.get("confirm"))))
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/migrate/finish":
                try:
                    return self._send(200, _mv_finish_here())
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/migrate/cancel":
                try:
                    _mv_cancel()
                    return self._send(200, {"ok": True})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if p == "/api/hop/register":
                # Публичный, но только по одноразовому токену фронт-скрипта.
                try:
                    b = self._body() or {}
                    return self._send(200, _hop_register((b.get("tok") or "").strip(),
                                                         self.client_address[0]))
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
                secret = CFG_CACHE.get("bot_webhook_secret") or secrets.token_urlsafe(24)
                CFG_CACHE["bot_webhook_secret"] = secret
                try:
                    q = urllib.parse.urlencode({"url": url, "secret_token": secret,
                                                "drop_pending_updates": "false"})
                    api = f"https://api.telegram.org/bot{token}/setWebhook?{q}"
                    with urllib.request.urlopen(api, timeout=10) as resp:
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
                    CFG_CACHE["pass_hash"] = _hash2(CFG_CACHE["salt"], np_)
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
                if domain and not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?", domain):
                    return self._send(400, {"error": "недопустимый домен (разрешены буквы, цифры, точка и дефис)"})
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
                self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length","11"); self.end_headers()
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
                    self.send_response(400); self.send_header("Content-Type","application/json"); self.send_header("Content-Length","17"); self.end_headers()
                    self.wfile.write(b'{"error":"empty"}'); return
                with open(WALL, "wb") as f: f.write(blob)
                t = _load(THEME, {}) or {}; t["wall_mime"] = mime; _save(THEME, t)
                self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length","11"); self.end_headers()
                self.wfile.write(b'{"ok":true}'); return
            if p == "/api/wallpaper/delete":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                try: os.remove(WALL)
                except FileNotFoundError: pass
                t = _load(THEME, {}) or {}; t.pop("wall_mime", None); _save(THEME, t)
                self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length","11"); self.end_headers()
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
                    self.send_response(400); self.send_header("Content-Type","application/json"); self.send_header("Content-Length","17"); self.end_headers()
                    self.wfile.write(b'{"error":"empty"}'); return
                with open(LOGO_FILE, "wb") as f: f.write(blob)
                t = _load(THEME, {}) or {}; t["logo_mime"] = mime; _save(THEME, t)
                self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length","11"); self.end_headers()
                self.wfile.write(b'{"ok":true}'); return
            if p == "/api/logo/delete":
                if not _authed(self): return self._send(401, {"error": "unauthorized"})
                try: os.remove(LOGO_FILE)
                except FileNotFoundError: pass
                t = _load(THEME, {}) or {}; t.pop("logo_mime", None); _save(THEME, t)
                self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length","11"); self.end_headers()
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
                if "synfix_enabled" in body:
                    CFG_CACHE["synfix_enabled"] = bool(body["synfix_enabled"])
                    try:
                        _synfix_apply()
                    except Exception as e:
                        return self._send(500, {"error": "synfix: " + str(e)})
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
            if p == "/api/tg/user/limit":
                b = self._body()
                try:
                    res = _tg_set_max_ips(b.get("username", ""), b.get("max_ips"))
                    _audit("tg_limit", username=res["username"], max_ips=res["max_ips"])
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
                if "support_url" in b:
                    su = (b.get("support_url") or "").strip()
                    if su and not re.match(r"^(https?://|tg://)", su):
                        return self._send(400, {"error": "support-url: нужен https:// или tg://"})
                    CFG_CACHE["sub_support_url"] = su[:250]
                if "brand" in b:
                    CFG_CACHE["sub_brand"] = (b.get("brand") or "").strip()[:25]
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
            if p == "/api/tg/mp/selftest":
                b = self._body()
                try:
                    return self._send(200, _tg_mp_selftest(force=bool(b.get("force"))))
                except Exception as e:
                    return self._send(400, {"error": str(e)[:300]})
            if p == "/api/front/apply":
                b = self._body()
                try:
                    return self._send(200, _front_apply(b.get("domain")))
                except Exception as e:
                    return self._send(400, {"error": str(e)[:300]})
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

            if p == "/api/backups/config":
                b = self._body()
                try:
                    every_h = int(b.get("every_h") or 24)
                    keep = int(b.get("keep") or 7)
                except (TypeError, ValueError):
                    return self._send(400, {"error": "интервал и количество копий — целые числа"})
                if not 1 <= every_h <= 720:
                    return self._send(400, {"error": "интервал: от 1 до 720 часов"})
                if not 1 <= keep <= 60:
                    return self._send(400, {"error": "хранить: от 1 до 60 копий"})
                cur = CFG_CACHE.get("auto_backup")
                cur = cur if isinstance(cur, dict) else {}
                CFG_CACHE["auto_backup"] = {"enabled": bool(b.get("enabled")), "every_h": every_h,
                                            "keep": keep, "send_tg": bool(b.get("send_tg")),
                                            "last": int(cur.get("last") or 0)}
                _save(CFG, CFG_CACHE)
                _audit("auto_backup_config", enabled=CFG_CACHE["auto_backup"]["enabled"],
                       every_h=every_h, keep=keep, send_tg=CFG_CACHE["auto_backup"]["send_tg"])
                return self._send(200, {"settings": _autobk_settings()})

            if p == "/api/backups/run":
                fname, _raw = _autobk_make()
                _audit("auto_backup_make", file=fname)
                return self._send(200, {"name": fname, "files": _autobk_files()})

            if p == "/api/backups/restore":
                b = self._body()
                name = b.get("name") or ""
                if not _AUTOBK_RE.fullmatch(name):
                    return self._send(400, {"error": "недопустимое имя файла"})
                try:
                    with open(os.path.join(_AUTOBK_DIR, name), "rb") as f:
                        data = json.loads(gzip.decompress(f.read()))
                except FileNotFoundError:
                    return self._send(404, {"error": "файл не найден"})
                except Exception:
                    return self._send(400, {"error": "файл повреждён или это не бэкап Veil"})
                res = _restore(data)
                _audit("auto_backup_restore", file=name, clients=res.get("clients"))
                return self._send(200, res)

            if p == "/api/backups/delete":
                b = self._body()
                name = b.get("name") or ""
                if not _AUTOBK_RE.fullmatch(name):
                    return self._send(400, {"error": "недопустимое имя файла"})
                try:
                    os.remove(os.path.join(_AUTOBK_DIR, name))
                except FileNotFoundError:
                    return self._send(404, {"error": "файл не найден"})
                _audit("auto_backup_delete", file=name)
                return self._send(200, {"files": _autobk_files()})

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
    if "--migrate-apply" in sys.argv:
        try:
            _mv_apply_main()
            sys.exit(0)
        except Exception as e:
            print("VEILERR: переезд(apply): " + str(e), file=sys.stderr)
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
        _synfix_apply()
    except Exception as e:
        print("synfix init: " + str(e), flush=True)
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

