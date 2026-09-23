#!/usr/bin/env bash
# Veil installer — https://github.com/GurovNA/Veil
# Usage: bash install.sh [--step N] [--dry-run] [--help]
set -euo pipefail

VERSION="2.4.3"
REPO="GurovNA/Veil"
LOG_FILE="/var/log/veil-install.log"
IPIFY="https://api.ipify.org"
XRAY_PORT=443
TELEMT_PORT=7443
PANEL_PORT=8443
TLS_DOMAIN="my.aeza.ru"

# ---------- colors ----------
if [ -t 1 ]; then
  C_R="\033[31m"; C_G="\033[32m"; C_Y="\033[33m"; C_B="\033[36m"; C_N="\033[0m"
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_N=""
fi

msg()   { printf "${C_B}[*]${C_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
ok()    { printf "${C_G}[✓]${C_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
warn()  { printf "${C_Y}[!]${C_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
err()   { printf "${C_R}[✗]${C_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
die()   { err "$*"; exit 1; }

# ---------- cli ----------
DRY_RUN=0
ONLY_STEP=""

usage() {
  cat <<EOF
Veil installer v$VERSION

Usage:
  bash install.sh                Интерактивное меню управления
  bash install.sh --step 1       Выполнить только шаг N
  bash install.sh --dry-run      Показать команды, не выполнять
  bash install.sh --help         Это сообщение
EOF
}

run() {
  if [ "$DRY_RUN" = "1" ]; then
    printf "${C_Y}[dry]${C_N} %s\n" "$*"
    return 0
  fi
  eval "$@" >>"$LOG_FILE" 2>&1
}

find_free_port() {
  python3 - "$1" <<'PYFP'
import socket, sys
start = int(sys.argv[1])
for p in range(start, start + 50):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("", p)); s.close()
        print(p); sys.exit(0)
    except OSError:
        s.close()
print("нет свободного порта рядом с " + str(start), file=sys.stderr)
sys.exit(1)
PYFP
}

step_0_preflight() {
  msg "Шаг 0: pre-flight checks"
  [ "$(id -u)" = "0" ] || die "нужен запуск от root"
  ok "root"
  # os-release задаёт собственную VERSION/ID и т.п. — читаем в подоболочке,
  # чтобы не перезатереть наш VERSION="..." (иначе меню и лог врют про версию).
  (. /etc/os-release) 2>/dev/null || true
  SERVER_IP="$(curl -fsSL --max-time 8 "$IPIFY" 2>/dev/null || true)"
  [ -n "$SERVER_IP" ] || die "не удалось определить внешний IP — проверь сеть"
  ok "внешний IP: $SERVER_IP"
  [ -d /etc/systemd/system ] || die "/etc/systemd/system не найден"
  ok "systemd на месте"
}

step_1_packages() {
  msg "Шаг 1: пакеты apt"
  export DEBIAN_FRONTEND=noninteractive
  run "apt-get update -y"
  PKGS="python3 curl openssl tar jq nftables qrencode ca-certificates unzip"
  run "apt-get install -y $PKGS"
  command -v python3 >/dev/null || die "python3 не поставился"
  command -v nft     >/dev/null || die "nftables не поставился"
  command -v curl    >/dev/null || die "curl не поставился"
  ok "пакеты установлены"
}

step_2_xray() {
  msg "Шаг 2: Xray (VLESS + Reality)"
  if [ -x /usr/local/bin/xray ]; then
    ok "Xray уже установлен: $(/usr/local/bin/xray version 2>/dev/null | head -1)"
  else
    run "curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/xray-install.sh"
    run "bash /tmp/xray-install.sh install"
  fi

  cat <<'UNITEOF' > /etc/systemd/system/xray.service
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
# CAP_DAC_OVERRIDE — панель отдаёт ключи/серты (hy2_key.pem и др.) с владельцем
# nobody:0600; без этой capability root-xray не может их прочитать и падает в
# crash-loop на чистом хосте (проверено на VPS).
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3
DynamicUser=false
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNITEOF
  systemctl daemon-reload
  systemctl enable xray
  ok "Xray service настроен"

  [ -x /usr/local/bin/xray ] || die "Xray не установился"
  if [ ! -f /usr/local/etc/xray/config.json ]; then
    run "mkdir -p /usr/local/etc/xray"
    run "echo '{\"log\":{\"loglevel\":\"warning\"},\"inbounds\":[],\"outbounds\":[{\"protocol\":\"freedom\"}]}' > /usr/local/etc/xray/config.json"
  fi
}

step_3_telemt() {
  msg "Шаг 3: telemt (Telegram MTProto)"
  if [ -x /usr/bin/telemt ]; then
    ok "telemt уже установлен"
    return 0
  fi
  if [ ! -f /etc/telemt/telemt.toml ]; then
    TELEMT_PORT="$(find_free_port "$TELEMT_PORT")"
  fi
  local arch variant asset_name tag url
  case "$(uname -m)" in
    x86_64)  arch="x86_64" ;;
    aarch64) arch="aarch64" ;;
    *) die "неподдерживаемая архитектура: $(uname -m)" ;;
  esac
  variant=""
  if [ "$arch" = "x86_64" ] && grep -qm1 avx2 /proc/cpuinfo 2>/dev/null; then
    variant="v3"
  fi
  asset_name="telemt-${arch}${variant:+-${variant}}-linux-gnu.tar.gz"
  tag="$(curl -fsSL https://api.github.com/repos/telemt/telemt/releases/latest 2>/dev/null \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null || true)"
  [ -n "$tag" ] || tag="v1.0.0"
  url="https://github.com/telemt/telemt/releases/download/${tag}/${asset_name}"
  run "curl -fsSL -o /tmp/telemt.tar.gz '$url' || curl -fsSL -o /tmp/telemt.tar.gz 'https://github.com/telemt/telemt/releases/latest/download/telemt-${arch}-linux-gnu.tar.gz'"
  run "tar -xzf /tmp/telemt.tar.gz -C /tmp 2>/dev/null || true"
  run "install -m 0755 /tmp/telemt /usr/bin/telemt 2>/dev/null || true"
  run "rm -f /tmp/telemt.tar.gz /tmp/telemt"
  if ! id telemt >/dev/null 2>&1; then
    run "useradd -r -s /usr/sbin/nologin -M telemt"
  fi
  run "mkdir -p /opt/telemt /etc/telemt /var/lib/telemt"
  run "chown telemt:telemt /opt/telemt /var/lib/telemt"
  local secret
  secret="$(openssl rand -hex 16)"
  if [ ! -f /etc/telemt/telemt.toml ]; then
    cat <<TOMLEOF > /etc/telemt/telemt.toml
[general]
use_middle_proxy = true
tg_connect = 30
[general.modes]
classic = false
secure = false
tls = true
[server]
port = ${TELEMT_PORT}
[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.1/32"]
[censorship]
tls_domain = "${TLS_DOMAIN}"
[access.users]
hello = "${secret}"
[timeouts]
client_handshake = 90
client_keepalive = 120
TOMLEOF
    chmod 0640 /etc/telemt/telemt.toml
    chown telemt:telemt /etc/telemt/telemt.toml
  fi
  if [ ! -f /etc/systemd/system/telemt.service ]; then
    cat <<'UNITEOF' > /etc/systemd/system/telemt.service
[Unit]
Description=Telemt
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=telemt
Group=telemt
WorkingDirectory=/opt/telemt
ExecStart=/usr/bin/telemt /etc/telemt/telemt.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
[Install]
WantedBy=multi-user.target
UNITEOF
  fi
  run "systemctl daemon-reload"
  run "systemctl enable --now telemt"
  ok "telemt готов"
}

step_4_zapret2() {
  msg "Шаг 4: veil-zapret2 (DPI bypass)"
  if [ -x /opt/veil-zapret2/bin/nfqws2 ]; then
    ok "veil-zapret2 уже установлен"
    run "systemctl enable --now veil-zapret2"
    return 0
  fi
  local ZV="v1.0.3"
  local ZURL="https://github.com/bol-van/zapret2/releases/download/${ZV}/zapret2-${ZV}.tar.gz"
  run "mkdir -p /opt/veil-zapret2/bin /opt/veil-zapret2/lua /etc/veil-zapret2"
  run "curl -fsSL -o /tmp/zapret2.tar.gz '$ZURL' || true"
  run "tar -xzf /tmp/zapret2.tar.gz -C /tmp --strip-components=1 2>/dev/null || true"
  if [ -f /tmp/binaries/linux-x86_64/nfqws2 ]; then
    install -m 0755 /tmp/binaries/linux-x86_64/nfqws2 /opt/veil-zapret2/bin/nfqws2 || true
  fi
  cat <<'LUA_VEIL_EOF' > /opt/veil-zapret2/lua/veil-mtproto.lua
function lets_resend(ctx, desync)
    return VERDICT_PASS
end
LUA_VEIL_EOF
  cat <<CONFEOF > /etc/veil-zapret2/mtproto.conf
--qnum 201 --fwmark=0x40000000 --server --uid=65534:65534 --filter-tcp=${TELEMT_PORT}
CONFEOF
  cat <<'STARTEOF' > /usr/local/sbin/veil-zapret2-start.sh
#!/bin/bash
exec /opt/veil-zapret2/bin/nfqws2 @/etc/veil-zapret2/mtproto.conf 2>/dev/null || true
STARTEOF
  chmod 0755 /usr/local/sbin/veil-zapret2-start.sh
  cat <<'UNITEOF' > /etc/systemd/system/veil-zapret2.service
[Unit]
Description=Veil Zapret2 MTProto fix
After=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/sbin/veil-zapret2-start.sh
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNITEOF
  run "systemctl daemon-reload"
  run "systemctl enable --now veil-zapret2 || true"
  ok "veil-zapret2 готов"
}

step_5_panel() {
  msg "Шаг 5: панель Veil v$VERSION"
  local TARBALL_URL="https://github.com/${REPO}/releases/latest/download/veil.tar.gz"
  if [ "$DRY_RUN" = "1" ]; then
    # Не трогаем диск: только показываем, что будет сделано.
    printf "${C_Y}[dry]${C_N} mkdir -p /opt/vpnpanel\n"
    printf "${C_Y}[dry]${C_N} curl -fsSL -o /tmp/veil.tar.gz '%s' && tar -xzf /tmp/veil.tar.gz -C /opt/vpnpanel\n" "$TARBALL_URL"
    if [ ! -f /opt/vpnpanel/config.json ]; then
      printf "${C_Y}[dry]${C_N} сгенерировать /opt/vpnpanel/config.json и FIRST-LOGIN.txt (порт из find_free_port %s)\n" "$PANEL_PORT"
    fi
    printf "${C_Y}[dry]${C_N} записать /etc/systemd/system/vpnpanel.service\n"
    run "systemctl daemon-reload"
    run "systemctl enable --now vpnpanel"
    ok "панель активна (dry-run)"
    return 0
  fi
  if [ ! -f /opt/vpnpanel/config.json ]; then
    PANEL_PORT="$(find_free_port "$PANEL_PORT")"
  fi
  run "mkdir -p /opt/vpnpanel"
  if curl -fsSL -o /tmp/veil.tar.gz "$TARBALL_URL" 2>/dev/null; then
    tar -xzf /tmp/veil.tar.gz -C /opt/vpnpanel 2>/dev/null || true
    rm -f /tmp/veil.tar.gz
  else
    warn "Не удалось скачать релиз с GitHub, используем локальные файлы"
  fi
  if [ ! -f /opt/vpnpanel/config.json ]; then
    python3 - "$PANEL_PORT" <<'PYCFG'
import json, hashlib, os, secrets, sys
CFG = "/opt/vpnpanel/config.json"
LOG = "/opt/vpnpanel/FIRST-LOGIN.txt"
panel_port = int(sys.argv[1])
login = "admin"
pw    = secrets.token_urlsafe(12)
salt  = secrets.token_hex(16)
h     = hashlib.sha256((salt + pw).encode()).hexdigest()
with open(CFG, "w") as f:
    json.dump({"login": login, "salt": salt, "pass_hash": h, "panel_port": panel_port}, f, indent=2)
os.chmod(CFG, 0o600)
with open(LOG, "w") as f:
    f.write(f"login:    {login}\npassword: {pw}\n")
os.chmod(LOG, 0o600)
PYCFG
  fi
  cat <<'UNITEOF' > /etc/systemd/system/vpnpanel.service
[Unit]
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
UNITEOF
  run "systemctl daemon-reload"
  run "systemctl enable --now vpnpanel"
  ok "панель активна"
}

step_6_finish() {
  msg "Шаг 6: итог"
  show_panel_info_internal
}

show_panel_info_internal() {
  local ip
  ip="${SERVER_IP:-$(curl -fsSL --max-time 5 "$IPIFY" 2>/dev/null || echo 'SERVER_IP')}"
  
  if [ -f /opt/vpnpanel/config.json ]; then
    _p="$(python3 -c 'import json;print(json.load(open("/opt/vpnpanel/config.json")).get("panel_port",8443))' 2>/dev/null)"
    [ -n "$_p" ] && PANEL_PORT="$_p"
  fi

  # Показываем РЕАЛЬную версию установленной панели, а не версию установщика:
  # установщик (VERSION выше) может отставать, и обычный человек путается,
  # когда карточка «Veil vX» не совпадает с версией в шапке самой панели.
  local _pv="$VERSION"
  if [ -f /opt/vpnpanel/panel.py ]; then
    _f="$(grep -m1 -oE '^VERSION[[:space:]]*=[[:space:]]*"[^"]+"' /opt/vpnpanel/panel.py | sed -E 's/.*"([^"]+)".*/\1/' 2>/dev/null)"
    [ -n "$_f" ] && _pv="$_f"
  fi

  echo
  echo -e "${C_B}================================================================${C_N}"
  echo -e "${C_B}          Veil v${_pv} - информация о панели                   ${C_N}"
  echo -e "${C_B}================================================================${C_N}"
  echo -e "  Адрес панели (URL):  ${C_B}http://${ip}:${PANEL_PORT}${C_N}"
  echo
  if [ -f /opt/vpnpanel/FIRST-LOGIN.txt ]; then
    local _L _P
    _L="$(awk '/^login:/    {print $2}' /opt/vpnpanel/FIRST-LOGIN.txt)"
    _P="$(awk '/^password:/ {print $2}' /opt/vpnpanel/FIRST-LOGIN.txt)"
    echo -e "  Логин:  ${C_G}${_L}${C_N}"
    echo -e "  Пароль: ${C_G}${_P}${C_N}"
    echo -e "  (первоначальный пароль из FIRST-LOGIN.txt)"
  else
    echo -e "  Логин:  ${C_G}admin${C_N}"
    echo -e "  Пароль: (используйте ваш текущий пароль от панели)"
  fi
  echo -e "${C_B}================================================================${C_N}"
  echo
}

show_panel_info() {
  show_panel_info_internal
  exit 0
}

run_install_steps() {
  for s in 0 1 2 3 4 5 6; do
    if [ -n "$ONLY_STEP" ] && [ "$ONLY_STEP" != "$s" ]; then
      continue
    fi
    "step_${s}_"$( case $s in
      0) echo preflight ;;
      1) echo packages ;;
      2) echo xray ;;
      3) echo telemt ;;
      4) echo zapret2 ;;
      5) echo panel ;;
      6) echo finish ;;
    esac )
  done
}

uninstall_completely() {
  msg "Удаление Veil и всех компонентов..."
  systemctl stop vpnpanel xray telemt veil-zapret2 nginx 2>/dev/null || true
  systemctl disable vpnpanel xray telemt veil-zapret2 nginx 2>/dev/null || true
  rm -f /etc/systemd/system/vpnpanel.service
  rm -f /etc/systemd/system/telemt.service
  rm -f /etc/systemd/system/veil-zapret2.service
  rm -f /etc/systemd/system/xray.service
  systemctl daemon-reload
  rm -rf /opt/vpnpanel /opt/telemt /etc/telemt /var/lib/telemt /opt/veil-zapret2 /etc/veil-zapret2 /usr/local/etc/xray
  nft delete table ip veil_mtproto 2>/dev/null || true
  ok "Veil полностью удален с сервера."
  exit 0
}

reinstall_keeping_data() {
  msg "Переустановка с сохранением данных..."
  local TARBALL_URL="https://github.com/${REPO}/releases/latest/download/veil.tar.gz"
  mkdir -p /opt/vpnpanel
  if curl -fsSL -o /tmp/veil.tar.gz "$TARBALL_URL" 2>/dev/null; then
    tar -xzf /tmp/veil.tar.gz -C /opt/vpnpanel 2>/dev/null || true
    rm -f /tmp/veil.tar.gz
    ok "Панель обновлена из релиза v$VERSION"
  else
    warn "Не удалось скачать релиз с GitHub, используем текущие файлы"
  fi

  # Восстанавливаем/проверяем systemd-юнит панели
  cat <<'UNITEOF' > /etc/systemd/system/vpnpanel.service
[Unit]
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
UNITEOF
  systemctl daemon-reload
  systemctl enable --now vpnpanel
  systemctl restart vpnpanel
  # telemt кэширует каталог заглушки (/opt/vpnpanel/decoy) при старте:
  # без перезапуска посетители продолжают видеть старый index.html и не видят новые .nes.
  systemctl is-active --quiet telemt && systemctl restart telemt
  ok "Переустановка с сохранением данных завершена."
  show_panel_info_internal
  exit 0
}

reinstall_deleting_data() {
  warn "Внимание: все данные будут удалены!"
  read -rp "Продолжить? [y/N]: " confirm
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    systemctl stop vpnpanel xray telemt veil-zapret2 2>/dev/null || true
    rm -rf /opt/vpnpanel
    run_install_steps
  else
    msg "Отменено."
    exit 0
  fi
}

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) DRY_RUN=1 ;;
      --step)    ONLY_STEP="${2:-}"; shift ;;
      --help|-h) usage; exit 0 ;;
      *) die "неизвестный аргумент: $1" ;;
    esac
    shift
  done

  [ -w /var/log ] || LOG_FILE="/tmp/veil-install.log"
  : >"$LOG_FILE"

  if [ -n "$ONLY_STEP" ]; then
    run_install_steps
    exit 0
  fi

  # Интерактивное меню управления
  echo -e "${C_B}================================================================${C_N}"
  echo -e "${C_B}            Veil Installer & Manager v$VERSION                  ${C_N}"
  echo -e "${C_B}================================================================${C_N}"
  echo -e "  1) Установить"
  echo -e "  2) Переустановить с сохранением данных"
  echo -e "  3) Переустановить с удалением данных"
  echo -e "  4) Удалить полностью панель"
  echo -e "  5) Показать адрес панели"
  echo -e "  0) Выход"
  echo -e "${C_B}================================================================${C_N}"
  read -rp "Выберите пункт [1-5]: " choice

  case "$choice" in
    1) run_install_steps ;;
    2) reinstall_keeping_data ;;
    3) reinstall_deleting_data ;;
    4) uninstall_completely ;;
    5) show_panel_info ;;
    0) exit 0 ;;
    *) err "Неверный выбор"; exit 1 ;;
  esac

  ok "Готово"
}

main "$@"
