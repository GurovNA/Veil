# Veil

VPN-панель + Telegram MTProto прокси с DPI-фиксом.
Установка одной строкой на Ubuntu 22.04 / 24.04 / 26.04.

## Установка

  bash <(curl -fsSL https://raw.githubusercontent.com/GurovNA/Veil/main/install.sh)

В конце скрипт выведет URL панели, логин и пароль (сгенерирован автоматически).
Логин и пароль можно сменить в разделе Безопасность панели.

## Что ставится

| Компонент | Что делает |
|---|---|
| Xray | VLESS + Reality VPN, активируется кнопкой из панели |
| telemt | Telegram MTProto прокси с FakeTLS |
| veil-zapret2 | DPI-bypass для MTProto (nfqws2 + nft + lua) |
| vpnpanel | Веб-панель управления на порту 8443 |

## Что умеет панель

- VPN: включить/выключить Xray, VLESS-ссылка и QR для Happ, v2rayNG, Hiddify
- Telegram: MTProto-ссылка и QR, кнопка Отключить fix (zapret2)
- Несколько клиентов: добавлять, переименовывать, удалять
- Безопасность: смена логина и пароля панели
- Обновления: проверка новых версий из GitHub

## Стек

- Backend: Python 3 (стандартная библиотека)
- Frontend: один HTML-файл
- VPN-ядро: Xray-core (VLESS + Reality, xtls-rprx-vision)
- Прокси: telemt (MTProto + FakeTLS)
- DPI-fix: zapret2 + veil-mtproto.lua (nfqws2 + nftables)
- Управление: systemd

## Рабочая конфигурация

| Параметр | Значение |
|---|---|
| Порт Xray | 443 |
| SNI / dest | www.samsung.com:443 |
| Fingerprint | firefox |
| Flow | xtls-rprx-vision |
| Порт Telegram | 7443 |
| FakeTLS домен | my.aeza.ru |

firefox — не случайность. С chrome Reality-рукопожатие падает на части клиентов.

## Диагностика

- Логи установки: /var/log/veil-install.log
- Статус сервисов: systemctl status xray telemt veil-zapret2 vpnpanel
- Перезапуск шага: bash install.sh --step 4

## Лицензия

Private.
