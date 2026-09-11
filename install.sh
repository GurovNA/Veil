#!/usr/bin/env bash
# Veil installer — https://github.com/GurovNA/Veil
# Usage: bash install.sh [--step N] [--dry-run] [--help]
set -euo pipefail

VERSION="1.0.0"
REPO="GurovNA/Veil"
LOG_FILE="/var/log/veil-install.log"
IPIFY="https://api.ipify.org"
XRAY_PORT=443
TELEMT_PORT=7443
PANEL_PORT=8443

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
  bash install.sh                Установить всё (шаги 0-6)
  bash install.sh --step 1       Выполнить только шаг N
  bash install.sh --dry-run      Показать команды, не выполнять
  bash install.sh --help         Это сообщение

Steps:
  0  Pre-flight checks (root, Ubuntu, network)
  1  Install packages (apt)
  2  Install Xray (VLESS + Reality)
  3  Install telemt (Telegram MTProto)
  4  Install veil-zapret2 (DPI bypass fix)
  5  Install Veil panel
  6  Finish summary
EOF
}

# Обёртка: выполняет команду или печатает её при --dry-run
run() {
  if [ "$DRY_RUN" = "1" ]; then
    printf "${C_Y}[dry]${C_N} %s\n" "$*"
    return 0
  fi
  eval "$@" >>"$LOG_FILE" 2>&1
}

# ---------- step 0: pre-flight ----------
step_0_preflight() {
  msg "Шаг 0: pre-flight checks"

  [ "$(id -u)" = "0" ] || die "нужен запуск от root"
  ok "root"

  . /etc/os-release 2>/dev/null || true
  if [ "${ID:-}" != "ubuntu" ]; then
    warn "ОС не Ubuntu — продолжаем на свой риск (ID=${ID:-unknown})"
  else
    ok "Ubuntu ${VERSION_ID:-?}"
  fi

  if ! command -v curl >/dev/null 2>&1; then
    warn "curl отсутствует — поставим на шаге 1"
  fi

  SERVER_IP="$(curl -fsSL --max-time 8 "$IPIFY" 2>/dev/null || true)"
  [ -n "$SERVER_IP" ] || die "не удалось определить внешний IP — проверь сеть"
  ok "внешний IP: $SERVER_IP"

  [ -d /etc/systemd/system ] || die "/etc/systemd/system не найден — это не systemd-дистрибутив"
  ok "systemd на месте"
}

# ---------- step 1: packages ----------
step_1_packages() {
  msg "Шаг 1: пакеты apt"

  export DEBIAN_FRONTEND=noninteractive

  run "apt-get update -y"

  PKGS="python3 curl openssl tar jq nftables qrencode ca-certificates unzip"
  run "apt-get install -y $PKGS"

  command -v python3  >/dev/null || die "python3 не поставился"
  command -v nft      >/dev/null || die "nftables не поставился"
  command -v curl     >/dev/null || die "curl не поставился"
  ok "пакеты установлены"
}

# ---------- step 2-6 (заглушки) ----------
step_2_xray() {
  msg "Шаг 2: Xray (VLESS + Reality)"

  if [ -x /usr/local/bin/xray ]; then
    ok "Xray уже установлен: $(/usr/local/bin/xray version 2>/dev/null | head -1)"
    ok "конфиг оставляем панели — она запустит при активации"
    return 0
  fi

  msg "Скачиваем официальный установщик XTLS/Xray-install"
  run "curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/xray-install.sh"
  run "bash /tmp/xray-install.sh install"

  # Остановим — панель запустит при активации VPN
  run "systemctl stop xray 2>/dev/null || true"

  [ -x /usr/local/bin/xray ] || die "Xray не установился"
  ok "Xray готов: $(/usr/local/bin/xray version 2>/dev/null | head -1)"

  # Пустой конфиг-заглушка, панель перезапишет
  if [ ! -f /usr/local/etc/xray/config.json ]; then
    run "mkdir -p /usr/local/etc/xray"
    run "echo '{\"log\":{\"loglevel\":\"warning\"},\"inbounds\":[],\"outbounds\":[{\"protocol\":\"freedom\"}]}' > /usr/local/etc/xray/config.json"
    ok "создан пустой конфиг (панель заполнит при активации)"
  fi
}
step_3_telemt() {
  msg "Шаг 3: telemt (Telegram MTProto)"

  if [ -x /usr/bin/telemt ]; then
    ok "telemt уже установлен: $(/usr/bin/telemt --version 2>/dev/null | head -1)"
    return 0
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
  if [ -n "$variant" ]; then
    asset_name="telemt-${arch}-${variant}-linux-gnu.tar.gz"
  else
    asset_name="telemt-${arch}-linux-gnu.tar.gz"
  fi

  tag="$(curl -fsSL https://api.github.com/repos/telemt/telemt/releases/latest 2>/dev/null \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null || true)"
  [ -n "$tag" ] || die "не удалось получить последний релиз telemt"
  url="https://github.com/telemt/telemt/releases/download/${tag}/${asset_name}"
  msg "Качаю $asset_name ($tag)"

  run "curl -fsSL -o /tmp/telemt.tar.gz '$url'"
  run "tar -xzf /tmp/telemt.tar.gz -C /tmp"
  run "install -m 0755 /tmp/telemt /usr/bin/telemt"
  run "rm -f /tmp/telemt.tar.gz /tmp/telemt"

  if [ "$DRY_RUN" != "1" ] && [ ! -x /usr/bin/telemt ]; then
    die "telemt не установился"
  fi
  ok "бинарник: /usr/bin/telemt"

  if ! id telemt >/dev/null 2>&1; then
    run "useradd -r -s /usr/sbin/nologin -M telemt"
    ok "создан пользователь telemt"
  else
    ok "пользователь telemt уже есть"
  fi
  run "mkdir -p /opt/telemt /etc/telemt /var/lib/telemt"
  run "chown telemt:telemt /opt/telemt /var/lib/telemt"

  local secret
  secret="$(openssl rand -hex 16)"
  msg "секрет пользователя hello: $secret"

  local cfg
  cfg="$(cat <<TOMLEOF
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
)"

  if [ -f /etc/telemt/telemt.toml ]; then
    ok "конфиг уже есть: /etc/telemt/telemt.toml"
  else
    if [ "$DRY_RUN" = "1" ]; then
      printf "${C_Y}[dry]${C_N} write /etc/telemt/telemt.toml\n"
    else
      printf '%s\n' "$cfg" > /etc/telemt/telemt.toml
      chmod 0640 /etc/telemt/telemt.toml
      chown telemt:telemt /etc/telemt/telemt.toml
    fi
    ok "конфиг создан: /etc/telemt/telemt.toml"
  fi

  local unit
  unit="$(cat <<'UNITEOF'
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
)"

  if [ -f /etc/systemd/system/telemt.service ] || [ -f /lib/systemd/system/telemt.service ]; then
    ok "systemd-unit уже есть"
  else
    if [ "$DRY_RUN" = "1" ]; then
      printf "${C_Y}[dry]${C_N} write /etc/systemd/system/telemt.service\n"
    else
      printf '%s\n' "$unit" > /etc/systemd/system/telemt.service
    fi
    ok "systemd-unit создан"
  fi

  run "systemctl daemon-reload"
  run "systemctl enable --now telemt"

  if [ "$DRY_RUN" != "1" ]; then
    sleep 1
    systemctl is-active telemt >/dev/null 2>&1 || die "telemt не запустился — смотри $LOG_FILE"
    ok "telemt активен на :${TELEMT_PORT}"
  fi
}
step_4_zapret2() { warn "Шаг 4 (veil-zapret2) ещё не реализован"; }
step_5_panel()   { warn "Шаг 5 (панель) ещё не реализован"; }
step_6_finish()  { warn "Шаг 6 (финал) ещё не реализован"; }

# ---------- main ----------
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

  msg "Veil installer v$VERSION (log: $LOG_FILE)"
  [ "$DRY_RUN" = "1" ] && warn "DRY-RUN режим — команды НЕ выполняются"

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

  ok "Готово"
}

main "$@"
