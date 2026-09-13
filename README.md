# Veil

VPN-панель + Telegram MTProto прокси с DPI-фиксом.
Установка одной строкой на Ubuntu 22.04 / 24.04 / 26.04.

Актуальная версия: **v1.8.0**

## Установка

  bash <(curl -fsSL https://raw.githubusercontent.com/GurovNA/Veil/main/install.sh)

В конце скрипт выведет URL панели, логин и пароль (сгенерирован автоматически).
Логин и пароль можно сменить в разделе Безопасность панели.

## Что нового в v1.8.0

- dynv6: создание зоны прямо из панели через REST v2 API (account-token + имя) — zone token и host сохраняются автоматически, IP обновляется сразу
- DDNS везде: домен `xxxxxxx.v6.navy` подставляется в ссылки клиентов (VPN, Telegram MTProto, Telegram webproxy) вместо IP — при смене IP ничего не ломается, dynv6 сам обновляет A/AAAA
- Telegram MTProto: сохранённые клиенты показывают актуальные ссылки с DDNS-доменом (исправлено для существующих юзеров)
- Резервные копии панели перед каждым обновлением + скачивание/восстановление из файла
- Ядро Xray: просмотр версии, список доступных версий, смена с автооткатом (старый бинарь сохраняется)

## Web-прокси для Telegram (план)

Панель поднимает Telegram MTProto-прокси (MTProto + FakeTLS, порт 7443) и умеет встраивать DDNS-домен в ссылки. Есть два направления для full web-прокси:

1. **Web-proxy (обратный)**: nginx reverse-proxy на домене панели → `web.telegram.org`, с собственным LE-сертификатом. Позволяет заходить в Telegram Web из браузера даже при заблокированном web.telegram.org.
2. **MTProto web-proxy**: через js телеграм-клиента (webk/tg протокол) — панель уже генерирует прямые qr-ссылки, осталось подключить web-интерфейс.

Готовой полной реализации в v1.8.0 нет (обратный прокси с ws/wss и mtproto поверх — отдельный сервис). Предлагаю по шагам:
- [ ] nginx `proxy_pass https://web.telegram.org` на `web.<ddns>.v6.navy` (порт 8444), сертификат уже есть
- [ ] Проксирование WebSocket-сообщений (Telegram Web использует ws/wss)
- [ ] Кнопка «Открыть Telegram Web» в панели

## Что ставится

| Компонент | Что делает |
|---|---|
| Xray | VLESS + Reality VPN, активируется кнопкой из панели |
| telemt | Telegram MTProto прокси с FakeTLS |
| veil-zapret2 | DPI-bypass для MTProto (nfqws2 + nft + lua) |
| vpnpanel | Веб-панель управления на порту 8443 |

## Что умеет панель

- VPN: включить/выключить Xray, ссылка и QR для v2rayNG, Streisand, Hiddify
- 17 протоколов по группам (Reality / VLESS / VMess / Trojan / Shadowsocks): VLESS + Reality и XHTTP + Reality, VLESS на WS/TCP/gRPC/XHTTP/SplitHTTP (с TLS), VMess и Trojan на WS/TCP/gRPC (с TLS), Shadowsocks AEAD
- TLS-протоколы получают автоматический самоподписной сертификат, XHTTP поддерживает HTTP/2 / HTTP/3 streaming — домен не нужен
- Протоколы не конфликтуют: каждый живёт на своём порту, старые ссылки не ломаются; новая ссылка всегда добавляется отдельным клиентом
- Telegram: MTProto-ссылка и QR, кнопка Отключить fix (zapret2)
- Несколько клиентов: добавлять, переименовывать, удалять
- Безопасность: смена логина и пароля панели
- Обновления: проверка новых версий из GitHub
- Статистика: аптайм сервисов Xray и telemt, количество клиентов, загрузка диска и памяти

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
