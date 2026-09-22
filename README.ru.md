<div align="center">
  <img src="icon-veil.png" width="128" height="128" alt="Veil Logo">
  <h1>Veil Panel</h1>
  <p><strong>Универсальная панель управления VPN: 18 протоколов Xray и WireGuard, Telegram MTProto-прокси, обход DPI, подписки для всех популярных клиентов — из одного веб-интерфейса.</strong></p>
  <p>
    <a href="README.md">🇬🇧 English</a> |
    <a href="README.ru.md">🇷🇺 Русский</a>
  </p>
  <p>
    <a href="https://github.com/GurovNA/Veil/releases/latest"><img src="https://img.shields.io/github/v/release/GurovNA/Veil?label=release&color=blue" alt="Release"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
    <a href="https://ubuntu.com/download/server"><img src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-orange.svg" alt="Ubuntu"></a>
  </p>
</div>

---

## Быстрая установка

Установите панель на Ubuntu одной командой:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/GurovNA/Veil/main/install.sh)
```

> Панель запускается как `vpnpanel.service` (управляется через `systemctl`),
> веб-интерфейс доступен по HTTPS: `https://<IP-сервера>:8443`.
> Первоначальные логин и пароль выводятся при установке (файл `FIRST-LOGIN.txt`).

---

## Возможности

### Протоколы (18 из коробки)
- **VLESS**: Reality, XHTTP+Reality, WS, WS+TLS, TCP+TLS, gRPC+TLS, XHTTP+TLS
- **VMess** и **Trojan**: WS / TCP / gRPC + TLS
- **Shadowsocks** AEAD, **Hysteria2**
- **WireGuard** на kernel-модуле (`veilwg`) и **AmneziaWG** (`awg0`) — с PSK и генерацией личных `.conf`
- REALITY с SNI-валидацией, настраиваемые TLS-отпечатки (Firefox/Chrome/Safari/iOS/Android)

### Подписки и клиенты
- Единый URL `/sub/<token>`: base64-список для v2rayNG/NekoBox/Hiddify, sing-box JSON, формат для **INCY** — по UA или `?format=`
- Публичная страница подписки `/p/<token>`: статус, трафик, QR-коды, каталог приложений с deep-link'ами, скачивание `WireGuard.conf` / `AmneziaWG.conf`
- Заголовки `subscription-userinfo` (трафик/остаток/срок) с корректными единицами для каждого клиента
- Лимиты трафика и срок действия с автоблокировкой; онлайн и расход трафика через Xray Stats API

### Безопасность
- 2FA (TOTP), смена логина/пароля, троттлинг входов
- Управление сессиями: список (IP, user-agent, последний визит), отзыв одной или всех кроме текущей
- Журналы: аудит API-действий и история входов прямо в UI
- Собственный ACME-клиент Let's Encrypt с автореневалом; dynv6 DDNS с проверкой домена через DoH

### Обход блокировок и Telegram
- **Zapret2** (DPI-bypass) одним переключателем, веб-прокси на Nginx, **decoy-сайт** (встроенный NES-эмулятор) для обфускации
- **Telegram-бот**: создание подписок с лимитами, список клиентов, перезапуск, алерты
- **telemt**: MTProto-прокси с web-настройками и переключением версий

### Диагностика и администрирование
- Вкладка «Диагностика»: метрики CPU/RAM/load, статус служб и портов, протокол-осознанный self-test (TCP/UDP), замеры **Globalping** из точек по всему миру с алертами в Telegram
- Центр обновлений: панель / Xray / telemt с откатом на предыдущую версию; экспорт и импорт состояния (бэкап)
- PWA, темы, обои и логотип настраиваются из UI; мульти-ноды (бета)

## Документация

- Полная история версий — [`CHANGELOG.md`](CHANGELOG.md)
- Заметки: [SNI vs FakeTLS](docs/SNI_vs_FakeTLS.md)
- Форматы подписок и deep-link'ов клиентов: [INCY docs](https://incy.gitbook.io), [sing-box docs](https://sing-box.sagernet.org)

## Лицензия

Распространяется по лицензии MIT ([`LICENSE`](LICENSE)). Отдельные сетевые фиксы заимствованы из открытых наработок MEKO ([`LICENSE-MEKO`](LICENSE-MEKO)).
