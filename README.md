<div align="center">
  <img src="icon-veil.png" width="128" height="128" alt="Veil Logo">
  <h1>Veil Panel</h1>
  <p><strong>Универсальная панель управления VPN: Xray (VLESS-Reality, Shadowsocks-2022, Trojan, VMess, gRPC/XHTTP) + Telegram MTProto Proxy. Обход DPI, REALITY SNI-валидация, встроенный веб-прокси.</strong></p>
  <p><em>Основано на разработке <a href="https://github.com/Mekotofeuka/MTPROTO_FIX_By_MEKO">MEKO (MTPROTO_FIX)</a> · Лицензия MEKO: <a href="LICENSE-MEKO">LICENSE-MEKO</a></em></p>
  <p>
    <a href="README.ru.md">🇷🇺 Русский</a> •
    <a href="README.en.md">🇬🇧 English</a>
  </p>
  <p>
    <img src="https://img.shields.io/badge/version-2.1.0-blue.svg" alt="Version">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
    <img src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-orange.svg" alt="Ubuntu">
  </p>
</div>

---

## Возможности

- **Быстрая установка**: развёртывание одной командой на Ubuntu.
- **Несколько протоколов из коробки**: Xray (VLESS-Reality, Shadowsocks-2022, Trojan, VMess, gRPC/XHTTP) и Telegram MTProto Proxy.
- **Обход DPI**: тонкая настройка TLS-отпечатков (Firefox, Chrome, Safari, iOS, Android) и проверка доступности SNI.
- **Универсальная подписка**: единый URL, который отдаёт клиентам base64-список ссылок всех протоколов — работает с v2rayNG / Hiddify / Streisand / NekoBox.
- **REALITY**: всё настроено под обход блокировок и недетектируемый TLS-хендшейк (SNI-валидация перед применением).
- **Встроенный веб-прокси**: автоматическая настройка Nginx HTTPS reverse proxy прямо из панели.
- **Современный интерфейс**: адаптивная тёмная тема, QR-коды, метрики сервера в реальном времени, зелёный селф-тест в один клик.

## Быстрая установка

```bash
bash <(curl -fsSL <ваш raw-URL>/install.sh)
```

> Панель запускается как `vpnpanel.service` (управляется через `systemctl`),
> веб-интерфейс доступен по HTTPS: `https://<IP-сервера>:<порт панели>`.

## Документация и история версий

- Полная история версий — в [`CHANGELOG.md`](CHANGELOG.md).
- Русская версия — [`README.ru.md`](README.ru.md).
- Английская версия — [`README.en.md`](README.en.md).

## Лицензия

Распространяется по лицензии MIT ([`LICENSE`](LICENSE)).

Проект создан на основе разработки **[MEKO](https://github.com/Mekotofeuka/MTPROTO_FIX_By_MEKO)** и лицензируется по Публичной лицензии MEKO v3 — см. [`LICENSE-MEKO`](LICENSE-MEKO).

---

## Дорожная карта

- [ ] Мультисерверность (одна панель → несколько нод).
- [ ] Роли пользователей панели (админ / наблюдатель).
- [ ] API-токены для автоматизации.
- [ ] 2FA (TOTP) для входа в панель.
- [ ] Живые графики нагрузки в реальном времени.
