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

## Порты

install.sh сам находит свободные порты:

- Xray — панель ищет при первом включении VPN (443 → свободный)
- Telegram (telemt) — install.sh ищет при установке (7443 → свободный)
- Панель — install.sh ищет при установке (8443 → свободный)

Если 443 / 7443 / 8443 заняты — скрипт автоматически сдвинет на ближайший свободный и покажет актуальные порты в конце установки. Ничего настраивать вручную не надо.

## Опции install.sh

  --step N          только один шаг (0..6)
  --dry-run         показать команды, не выполнять
  --xray-port PORT  предпочитаемый порт Xray (по умолчанию 443)
  --tg-port PORT    предпочитаемый порт Telegram (по умолчанию 7443)
  --tls-domain NAME FakeTLS домен (по умолчанию my.aeza.ru)

## Логин и пароль панели

При первой установке install.sh генерирует случайный пароль.
Логин, пароль и порт сохраняются в /opt/vpnpanel/FIRST-LOGIN.txt и выводятся в конце установки.
Сменить — в панели, раздел Безопасность.
