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
step_4_zapret2() {
  msg "Шаг 4: veil-zapret2 (DPI bypass для MTProto)"

  if [ -x /opt/veil-zapret2/bin/nfqws2 ]; then
    ok "veil-zapret2 уже установлен"
    if systemctl is-active --quiet veil-zapret2 2>/dev/null; then
      ok "сервис активен"
    else
      run "systemctl enable --now veil-zapret2"
      ok "сервис запущен"
    fi
    return 0
  fi

  local ZV="v1.0.3"
  local ZURL="https://github.com/bol-van/zapret2/releases/download/${ZV}/zapret2-${ZV}.tar.gz"
  local TMPZ="/tmp/zapret2-src"
  run "rm -rf $TMPZ /tmp/zapret2.tar.gz"
  run "mkdir -p $TMPZ"
  msg "Качаю zapret2 $ZV"
  run "curl -fsSL -o /tmp/zapret2.tar.gz '$ZURL'"
  run "tar -xzf /tmp/zapret2.tar.gz -C $TMPZ --strip-components=1 2>/dev/null || tar -xzf /tmp/zapret2.tar.gz -C $TMPZ"

  run "mkdir -p /opt/veil-zapret2/bin /opt/veil-zapret2/lua /etc/veil-zapret2"

  if [ "$DRY_RUN" != "1" ]; then
    local NFQ LUA_LIB LUA_DPI
    NFQ="$(find $TMPZ -type f -name nfqws2 2>/dev/null | head -1)"
    LUA_LIB="$(find $TMPZ -type f -name zapret-lib.lua 2>/dev/null | head -1)"
    LUA_DPI="$(find $TMPZ -type f -name zapret-antidpi.lua 2>/dev/null | head -1)"
    [ -n "$NFQ"     ] || die "nfqws2 не найден в архиве zapret2"
    [ -n "$LUA_LIB" ] || die "zapret-lib.lua не найден в архиве"
    [ -n "$LUA_DPI" ] || die "zapret-antidpi.lua не найден в архиве"
    install -m 0755 "$NFQ"     /opt/veil-zapret2/bin/nfqws2
    install -m 0644 "$LUA_LIB" /opt/veil-zapret2/lua/zapret-lib.lua
    install -m 0644 "$LUA_DPI" /opt/veil-zapret2/lua/zapret-antidpi.lua
    ok "бинарник + lua-файлы zapret2 установлены"
    run "rm -rf $TMPZ /tmp/zapret2.tar.gz"
  fi

  # --- veil-mtproto.lua (встроен) ---
  local LM='/opt/veil-zapret2/lua/veil-mtproto.lua'
  if [ "$DRY_RUN" = "1" ]; then
    printf "${C_Y}[dry]${C_N} write $LM\n"
  else
    cat > "$LM" <<'LUA_VEIL_EOF'
-- Veil MTProto fix for zapret2
-- Based on MTProxyL by LiafanX — https://github.com/Liafanx/MTProxyL
-- (function lets_resend: disorder + badsum + window control + iOS fwmark bypass)
-- Adapted for Veil — https://github.com/GurovNA/Veil

function lets_resend(ctx, desync)
    if bitand(desync.dis.tcp.th_flags, TH_SYN + TH_ACK) == TH_SYN then
        if desync.dis.tcp.th_win == 65535 and
           desync.dis.tcp.options[1].kind == 2 and
           desync.dis.tcp.options[2].kind == 1 and
           desync.dis.tcp.options[3].kind == 3 and
           desync.dis.tcp.options[4].kind == 1 and
           desync.dis.tcp.options[5].kind == 1 and
           desync.dis.tcp.options[6].kind == 8 and
           desync.dis.tcp.options[7].kind == 4 and
           desync.dis.tcp.options[8].kind == 0 then
            instance_cutoff(ctx, nil)
            desync.arg.fwmark = 0x40000
            rawsend_dissect_segmented(desync)
            return VERDICT_DROP
        end
    end

    if bitand(desync.dis.tcp.th_flags, TH_SYN + TH_ACK) == (TH_SYN + TH_ACK) then
        desync.track.lua_state["ack0"] = desync.dis.tcp.th_ack
        desync.dis.tcp.th_win = 1400
        return VERDICT_MODIFY
    end

    if direction_check(desync) and bitand(desync.dis.tcp.th_flags, TH_SYN + TH_ACK) == (TH_ACK) then
        local ack0 = desync.track and desync.track.lua_state["ack0"]
        if ack0 and (desync.dis.tcp.th_ack - ack0 >= 1400) then
            instance_cutoff(ctx, true)
            desync.arg.fwmark = 0x40000
            rawsend_dissect_segmented(desync)
            return VERDICT_DROP
        end
        desync.dis.tcp.th_win = 2
        return VERDICT_MODIFY
    end

    if #desync.dis.payload == 0 or desync.track == nil or desync.track.pos.client.tcp.rseq ~= 1 then
        return VERDICT_PASS
    end

    local len = 400
    local first  = string.sub(desync.dis.payload, 1, len)
    local second = string.sub(desync.dis.payload, len + 1, 2 * len)
    local third  = string.sub(desync.dis.payload, 2 * len + 1)
    rawsend_payload_segmented(desync, first)
    rawsend_payload_segmented(desync, third, 2 * len)
    desync.arg["badsum"] = true
    rawsend_payload_segmented(desync, second, len)
    instance_cutoff(ctx, false)
    return VERDICT_DROP
end
LUA_VEIL_EOF
    chmod 0644 "$LM"
    ok "lua: veil-mtproto.lua"
  fi

  # --- mtproto.conf ---
  local CONF='/etc/veil-zapret2/mtproto.conf'
  if [ "$DRY_RUN" = "1" ]; then
    printf "${C_Y}[dry]${C_N} write $CONF\n"
  else
    cat > "$CONF" <<CONFEOF
--qnum 201 --fwmark=0x40000000 --server --uid=65534:65534  --lua-init=@/opt/veil-zapret2/lua/zapret-lib.lua --lua-init=@/opt/veil-zapret2/lua/zapret-antidpi.lua --lua-init=@/opt/veil-zapret2/lua/veil-mtproto.lua --filter-tcp=${TELEMT_PORT} --out-range=a --in-range=a --payload-disable=all --lua-desync=lets_resend
CONFEOF
    chmod 0644 "$CONF"
    ok "config: /etc/veil-zapret2/mtproto.conf"
  fi

  # --- стартовый скрипт ---
  local START='/usr/local/sbin/veil-zapret2-start.sh'
  if [ "$DRY_RUN" = "1" ]; then
    printf "${C_Y}[dry]${C_N} write $START\n"
  else
    cat > "$START" <<STARTEOF
#!/bin/bash
set -e

TABLE="veil_mtproto"
FWMARK="0x40000000"
PORT="${TELEMT_PORT}"
QNUM="201"
CT_MARK="0x00040000"
COMBINED_MARK="0x40040000"
BYPASS_MATCH="tcp flags & (fin | syn | rst | ack) == ack"

IP=\$(curl -s -m 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print \$1}')
[ -n "\$IP" ] || IP="0.0.0.0"
SADDR="ip saddr \$IP "
DADDR="ip daddr \$IP "

sysctl -w net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1 || true

nft delete table ip "\$TABLE" 2>/dev/null || true
nft add table ip "\$TABLE"

nft "add chain ip \$TABLE predefrag { type filter hook output priority -401; policy accept; }"
nft "add rule ip \$TABLE predefrag meta mark \$COMBINED_MARK counter accept"
nft "add rule ip \$TABLE predefrag meta mark and \$FWMARK != 0x00000000 counter notrack"

nft "add chain ip \$TABLE output { type route hook output priority mangle; policy accept; }"
nft "add rule ip \$TABLE output meta mark and \$COMBINED_MARK == \$COMBINED_MARK ct mark set \$CT_MARK counter accept"

nft "add chain ip \$TABLE postrouting { type filter hook postrouting priority srcnat + 1; policy accept; }"
nft "add rule ip \$TABLE postrouting \$BYPASS_MATCH ct mark \$CT_MARK counter accept"
nft "add rule ip \$TABLE postrouting meta mark and \$FWMARK == 0x00000000 \${SADDR}tcp sport \$PORT counter queue num \$QNUM bypass"

nft "add chain ip \$TABLE prerouting { type filter hook prerouting priority mangle; policy accept; }"
nft "add rule ip \$TABLE prerouting ct state invalid counter drop"
nft "add rule ip \$TABLE prerouting \$BYPASS_MATCH ct mark \$CT_MARK counter accept"
nft "add rule ip \$TABLE prerouting meta mark and \$FWMARK == 0x00000000 \${DADDR}tcp dport \$PORT counter queue num \$QNUM bypass"

echo "Veil: nft table \$TABLE applied (port=\$PORT qnum=\$QNUM ip=\$IP)"

exec /opt/veil-zapret2/bin/nfqws2 @/etc/veil-zapret2/mtproto.conf
STARTEOF
    chmod 0755 "$START"
    ok "start-script: $START"
  fi

  # --- systemd unit ---
  local UNIT='/etc/systemd/system/veil-zapret2.service'
  if [ "$DRY_RUN" = "1" ]; then
    printf "${C_Y}[dry]${C_N} write $UNIT\n"
  else
    cat > "$UNIT" <<'UNITEOF'
[Unit]
Description=Veil Zapret2 MTProto fix
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/veil-zapret2-start.sh
ExecStop=/usr/sbin/nft delete table ip veil_mtproto
Restart=on-failure
RestartSec=2
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNITEOF
    ok "systemd-unit: $UNIT"
  fi

  # sysctl fwmark reuse
  if [ "$DRY_RUN" = "1" ]; then
    printf "${C_Y}[dry]${C_N} write /etc/sysctl.d/99-veil-zapret2.conf\n"
  else
    printf 'net.ipv4.tcp_tw_reuse = 1\n' > /etc/sysctl.d/99-veil-zapret2.conf
    sysctl -w net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1 || true
    ok "sysctl: tcp_tw_reuse=1"
  fi

  run "systemctl daemon-reload"
  run "systemctl enable --now veil-zapret2"

  if [ "$DRY_RUN" != "1" ]; then
    sleep 1
    systemctl is-active --quiet veil-zapret2 || die "veil-zapret2 не запустился"
    ok "veil-zapret2 активен"
  fi
}
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
