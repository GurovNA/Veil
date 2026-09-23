# Changelog

All notable changes to Veil Panel will be documented in this file.

## [2.7.2] - 2026-09-23

**Страница подписчика стала «клиенто-понимающей»: устройства и форматы на подписке, экспорт/импорт подписчиков между панелями, точечная настройка каждого inbound, авто-ротация IP и Telegram-обёртки. Плюс чинки установки и федерации нод из теста на чистых VPS.**

- **Устройства подписчика и User-Agent (A3/A4)**: страница `/p/<token>` показывает список устройств, которые открывали подписку (IP, тип/модель из User-Agent, «был N назад»), с удалением лишнего и настройкой формата выдачи на устройство. Новый разбор UA (`_parse_client`) определяет приложение и ОС (v2rayNG, Happ, sing-box, Karing, Telegram-прокси и т. д.), тип/модель устройства; клиенто-зависимая сборка конфига. Очки устройств пишутся в `sub_devices.json`/`sub_prefs.json` (секреты, в `.gitignore`).
- **Чистка вкладки «Подписка» и своя кнопка прокси (A1/A2)**: персональные подписки отделены; для каждого вида — своя кнопка «Открыть прокси» (`tg://proxy?…`) вместо одной общей; адаптивная карточка подписки на мобиле.
- **Экспорт/импорт подписчиков между панелями (B2)**: `POST /api/subs/export` (JSON или ссылки) и импорт обратно — разбор `vmess://`/`vless://`/`trojan://` и подписочных blob'ов (`_import_from_links`/`_import_from_json`, `/api/ext/*`-формат). Позволяет перенести клиентскую базу с одной панели на другую.
- **Точечные настройки каждого inbound (B1)**: `GET /api/inbound/get` + `POST /api/inbound/settings` — правка параметров отдельного входящего (reality/xtls/flow и пр.) с deep-merge поверх базового шаблона; конфиг пересобирается и проходит `xray run -test` перед применением (`_validate_and_apply(force_proto=…)`).
- **Авто-ротация IP (через Globalping + Cloudflare)**: фоновый цикл `_rotate_loop` замеряет доступность текущего адреса из разных точек (`_gp_probe`), при деградации меняет A-запись на запасной публичный IPv4 через Cloudflare API (`_cf_set_ip`), с настраиваемыми порогами, историей и уведомлениями (`/api/rotate/status|settings|swap|check|cloudflare/test`). Работает только при явно включённых настройках и токенах.
- **Telegram: веб-прокси, adtag, SNI, ротация секрета**: управление MTProto/веб-обёртками прямо из панели — включение веб-прокси пользователю, установка `adtag`, смена TLS-SNI домена, ротация секрета прокси, ссылки на подписку (`/api/tg/user/adtag|rotate`, `/api/tg/sni`, `POST /api/bot/webhook`).
- **Исправления установки/рантайма (VPS-цикл, C)**: `install.sh` — `xray.service` получает `CAP_DAC_OVERRIDE` (иначе `nobody` не читает ключи hysteria2 `0600`); `/etc/os-release` больше не перезатирает переменную `VERSION` (`(. /etc/os-release)` в подоболочке); `step_5` теперь уважает `--dry-run`; Reality при свободном 443 занимает его автоматически (иначе — фолбэк на другой порт). `panel.py` — все генерируемые ссылки на панель следуют реальному протоколу через `_pb()` (`http`, когда сертификата нет; `https`, когда подключён) вместо жёсткого `https`.
- **Исправления федерации нод**: развёртывание клиента на ноду больше не зависит от порядка протоколов в записи — общий протокол выбирается по приоритету (`_NODE_PROTO_PRIORITY`), агент-нода принимает клиентов с Reality даже если он не первый в списке (#57); при удалении агент-ноды панель снимает с сервера осиротевший `veil-agent` по SSH (`_node_agent_purge`, с безопасным `pkill` через скобочный паттерн, чтобы не убить собственный сеанс) — чужая Veil-панель не демонтируется (#58).

## [2.7.1] - 2026-09-23

**Дата-центры Telegram во вкладке «Proxy» и автоподключение нод по SSH: нода поднимается в один клик — с установкой xray, агента и службы.**

- **Покрытие ДЦ Telegram** (вкладка «Proxy»): таблица «ДЦ · RTT · писатели · покрытие» по нативному API telemt (`/v1/stats/dcs`) — зелёная/жёлтая/красная подсветка по порогу, итоговое покрытие «в зачёт» (min(alive, required) от суммы required), живые счётчики writers и доступных эндпоинтов. Рядом — редактируемый **«Порог, %»** (`me_pool_min_fresh_ratio`, hot-reload telemt, диапазон 10–100).
- **⚡ Автоподключение ноды по SSH**: мастер «IP + логин + пароль» — панель сама: подключается (пароль используется **однократно** через SSH_ASKPASS, нигде не сохраняется; дальше — ed25519-ключ панели в `node_keys/` 0600), определяет root/sudo (включая `sudo -S` паролем), ставит xray (копия бинарника панели при совпадении архитектур, иначе официальный установщик), кладёт `agent.py` в `/opt/veil-agent`, пишет `agent.conf.json` с подбором свободных портов, поднимает systemd-службу `veil-agent` (Restart=always), best-effort открывает порты в ufw/firewalld, читает токен агента и регистрирует ноду с TOFU-закреплением отпечатка. Живой статус шагов в UI (`POST /api/nodes/bootstrap` + поллинг статуса); повторный пуск по существующей ноде — перезапровайдинг.
- **Исправления/безопасность**: обход сломанного `ssh-copy-id` в OpenSSH 10.2 (ключ дописывается напрямую в `authorized_keys` с правами 0700/0600); `node_keys/` добавлен в .gitignore; пароли SSH не попадают ни в audit, ни в argv процессов, ни в память задач после завершения.

## [2.7.0] - 2026-09-22

**Федерация нод: панель умеет принимать клиентов с других панелей Veil и сама размещает своих клиентов на удалённых серверах — как на панелях-нодах, так и на лёгких агентах (agent.py).**

- **Node API (входящие)**: скоуп-токены (чтение/запись) во вкладке «Ноды» — другие панели Veil могут размещать и вести **своих** клиентов на этом сервере через `/api/ext/*` (статус, входящие, добавление/правка/удаление клиентов). Константное сравнение токенов, rate-limit 30 запросов/10 с на IP, аудит каждого запроса; внешние клиенты помечаются `🌐` и доступны только создавшему их токену; отзыв токена отключает доступ мгновенно.
- **Нода-панель Veil (исходящие)**: мастер подключается по HTTPS к панели ноды, закрепляет отпечаток её сертификата (TOFU, MITM отсекается до отправки токена), опрашивает статус каждые 45 с. Кнопка «🖥» в карточке клиента создаёт его зеркало на ноде, а в подписку добавляется ссылка на ноду; правка лимита/срока и удаление прокидываются на ноды автоматически; снятие — кликом по бейджу «🖥 host».
- **Режим агента (agent.py)** — для серверов без панели: автономный single-file агент (stdlib + xray + openssl). Сам генерирует токен (`agent.py --token`), ставит self-signed TLS, поднимает vless+reality subprocess'ом с ключами `xray x25519`, ведёт **полный учёт трафика** (дельты статистики Xray, циклы день/неделя/месяц, автоблокировка по лимиту ≥95% и сроку) и перезапускает xray при падении. API: `/agent/hello` (параметры для сборки ссылок), `/agent/status`, `/agent/clients`, `POST /agent/apply` (add/remove/set_limits/unblock). Мастер размещает на агенте клиентов **с тем же uuid**, ссылка строится из параметров hello и попадает в подписку; лимиты/снятие синхронизируются.
- **Безопасность и исправления**: `GET /api/nodes` и ответы add/delete больше не отдают токены подключения (а GET /api/nodes был вообще без авторизации — закрыто); общий цикл опроса нод (`_node_poll_one`) для обоих типов; порты агента настраиваются в `agent.conf.json`.


## [2.6.0] - 2026-09-22

**Новый интерфейс панели + дашборд с живыми виджетами + прокачанная страница подписки.**

- **Новый интерфейс (включён по умолчанию)**: боковое меню вместо верхних табов, вертикальная навигация, компактный hero в сайдбаре. Переключатель «Новый / Классический» в «Оформлении» — выбор сохраняется на сервере (`ui_style` в `/api/network/settings`), классический интерфейс полностью сохранён. Тело страницы рендерится с нужным классом на сервере — вспышки старого дизайна при загрузке нет.
- **Дашборд-виджеты** (вкладка «Дашборд», автосвежение каждые 30 с только когда вкладка видима): карточка статуса Xray с аптаймом сервера, KPI «клиенты онлайн» (X/Y) и «трафик сегодня» с дельтой в % ко вчера, список активных протоколов (иконка, порт, число клиентов, статус; MTProto-прокси отдельной строкой), кольца CPU/RAM/disk + load, 30-дневный график трафика с осью Y и диапазоном дат, лента последних событий (аудит + входы, топ-6, ✓/✗), блок быстрых действий (добавить клиента, перезапустить Xray, диагностика, журналы, безопасность, подписка), статус «Сервер · Онлайн · vX.Y» внизу сайдбара.
- **Бэкенд дашборда**: новый `GET /api/dashboard` — история суточного трафика за 30 дней, сегодня/вчера/неделя/месяц, онлайн через Xray Stats API (с кэшем), протоколы с агрегацией по группам, активный протокол, версия и аптайм сервера. Дневная история пишется в `logs/traffic_days.json` (дельты из `_traffic_tick`, хранение 120 дней).
- **Полная причёска остальных вкладок**: единая типографика секций (h2/h3/hr), стилизованные спойлеры-инструкции, инлайн-`code` чипами, сообщения `.msg` плашками (красные/зелёные), под-вкладки журналов в контейнерах. **Исправлено**: карточки клиентов не имели базового стиля (рамка/фон/ховер висели в воздухе) — теперь аккуратные карточки с цветным акцентом по протоколу; 9 мест в Подписке/Нодах использовали несуществующую CSS-переменную `--brd` — рамки не рисовались, добавлен алиас.
- **Мобильная оптимизация нового интерфейса** (≤900px): вкладки — горизонтальная прокручиваемая лента, карточки компактнее, mini-stats в 2 колонки (≤420px — в одну), KPI/график/события в столбик, инпуты и кнопки форм на всю ширину, тосты на всю ширину (≤520px).
- **Страница подписчика `/p/<token>`**: палитра приведена к новому дизайну; десктоп-раскладка (колонка 680px, каталог приложений 3 колонки, статистика 4); строка под именем показывает лимиты клиента (цикл сброса, макс. устройств) вместо дубля срока; новый блок «Маршрутизация» — подсказки split-tunnel для RU/IR с конкретными правилами GEOSITE/GEOIP для Shadowrocket, v2rayNG и INCY (показывается только при включённом режиме); в каталоге приложений фильтруются приложения Hysteria2/WireGuard/AmneziaWG по наличию конфигов.
- **Каталог приложений подписки обновлён**: iOS — Happ (новое имя/URL App Store); Android — добавлены INCY, Happ, Karing, FlClash, Amnezia VPN, Hysteria2; Windows — Hiddify, sing-box (GUI); Android TV — INCY, sing-box (SFA).

## [2.5.0] - 2026-09-22

**Фаза 1 «Зрелость сервиса»** — то, чего не хватало панели относительно популярных VPL-панелей (3x-ui, Marzban, X-UI). Семь блоков, все проверены на живом сервере.

- **P1. Подписки /sub**: ответы теперь с заголовками `profile-title`, `profile-update-interval`, а в `subscription-userinfo` — накопленный трафик `upload`/`download`, `total` (лимит×ГБ, 0 = безлимит) и `expire` в мс. Клиенты (v2rayN, Happ, sing-box) показывают остаток трафика прямо в приложении. Плюс `sb_url` — ссылка на полный standalone-конфиг sing-box.
- **P2. Циклы сброса трафика**: у клиента появился `reset_cycle` (день/неделя/месяц; по умолчанию lifetime). Счётчики копятся дельтами из Xray-статистики (`_traffic_tick`) и обнуляются на границе цикла (в т.ч. `xray api statsreset` по uuid; пережил перезапуск Xray без потери накопанного). В UI — выбор цикла при создании и в новом ✏️-редакторе клиента, бейдж «Сброс: …» в списке. **Telegram-алерты**: один раз на 80% лимита (`warned_80`) и по порогам остатка дней до истечения (`warned_days`), плюс уведомление при автоблокировке.
- **P3. Лимит устройств**: `max_devices` на клиента. Панель тэйлит access-лог Xray (новый `log.access` в конфиге + logrotate `/etc/logrotate.d/veil-xray`), за 15-минутное окно считает публичные IP по uuid; лишних (новых последних) IP банит на 2 часа через `inet veil_bans`, WireGuard-kernel исключён (NAT ломаетSrcIP). В редакторе клиента и списке — «Устройств: N».
- **P4. fail2ban-lite для входа в панель**: `f2b_enabled` (по умолчанию вкл), `f2b_threshold` (5), `f2b_window_min` (10), `f2b_ban_hours` (24) — настраивается в сетевых настройках. Неудачные логчины (ip+user) копят нарушения; бан — добавление IP в nft-множество `b4`/`b6` с timeout. Защита от выстрела в ногу: никогда не баня приватные/loopback адреса и IP с активной сессией панели; баны переживают перезапуск (`bans.json`, `_f2b_bootstrap`), чистка протухших каждые 60 с. В UI — список активных банов и «Разбанить» по IP (`GET /api/bans`, `POST /api/bans/unban`).
- **P5. Prometheus `/metrics`**: port 8443, пре-авторизационный маршрут, 503 если токен не задан; доступ через `Authorization: Bearer` или `?token=` (constant-time сверка). Метрики `veil_*`: up, version_info, xray_active, clients_total, на клиента used/limit/expiry/blocked/devices (labels email+uuid8), login_fail_ips, bans_active, disk, mem, cert_expire/days_left, rulesets_updated, inbounds_total. Токен генерируется в один клик в UI (crypto.getRandomValues).
- **P6. Split-tunnel RU/IR в конфигах клиентов**: режим `off|ru|ir` в сетевых настройках. `ru` — российские домены/сети идут напрямую (final = прокси), DNS geosite-ru → Yandex DoH; `ir` — иранские сервисы через прокси (final = direct). Применяется и в подписках (share-link правья), и в standalone `/sb/<token>` конфигах sing-box (исправлен баг: `route.final` теперь реально зависит от режима). Панель каждую сутки зеркалит актуальные правила с GitHub-релизов (runetfreedom rules-dat → `geoip-ru.srs`/`geosite-ru.srs`; chocolate4u Iran-sing-box-rules → `geoip-ir.db`/`geosite-ir.db` с sha256-проверкой) и раздаёт их по `https://host:8443/rulesets/<name>`; статус зеркал — в UI.
- **P7. Откат релиза в один клик**: кнопка в UI откатывает `/opt/vpnpanel` на предыдущий GitHub-релиз (tarball+sha256), перезапускает панель.
- **Fix (latent)**: `/api/clients/unblock` вызывался из UI, но бэкенд-маршрута не существовало — реализован, с обнулением счётчиков при лимитной блокировке, чтобы автоблокировка не срабатывала повторно через 60 с. `POST /api/clients/update` — единая точка правки лимита/срока/цикла/устройств (применяется ко всей группе uuid).

## [2.4.4] - 2026-09-22

- **Главное: заглушка на 443 была полностью нерабочей из-за CSP.** `telemt` в своём static-хендлере жёстко отдаёт заголовок `Content-Security-Policy: default-src 'self' …` без `'wasm-unsafe-eval'` и без `'unsafe-inline'` — из-за этого блокировались инлайн-стили, инлайн-`<script>`, `onclick=`, data:-фавикон и сам WebAssembly. Ни CSS, ни JS, ни эмулятор не грузились. Nginx (фронт `telemt`) теперь переопределяет политику: `proxy_hide_header Content-Security-Policy` + своя `script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; …`. То же добавлено в шаблон nginx-конфига панели (`_NG_WEBPROXY_TEMPLATE`), чтобы чистые установки получали фикс сразу.
- **Страница вынесена во внешние файлы под строгую CSP**: `styles.css`, `app.js`, `favicon.svg`; убраны все инлайн-`<style>`/`<script>`, `onclick=`, `style=`-атрибуты и data:-фавикон. Карточки, оверлей и кнопки теперь на `addEventListener`.
- **Движок заменён на точный: FCEUmm (libretro-ядро) в WebAssembly** вместо JSNES. Написан минимальный браузерный libretro-хост (`nes-engine.js`, ~13 КБ): полный retro-цикл (environ, видео XRGB8888/RGB565/0RGB1555, пакетный аудио-выход, input-poll/bitmask, сохранение SRAM), поддержка `need_fullpath` (ром пишется в MEMFS), корректный blit 256×224 в canvas 256×240 с чёрными полями. Ядро — `romdev-core-fceumm` (GPL-2.0) с минимальным патчем glue под браузер; проприетарных зависимостей нет, исходящих запросов нет.
- **Точность и регион**: FCEUmm корректно обрабатывает тайминги, звук и мапперы. RoboRun требует PAL/Dendy — в реестре игр задан регион (`region:'Dendy'`), иначе игра показывает «WRONG VIDEO REGION». Регион задаётся через core-option `fceumm_region`.
- **Легальные домашние ромы**: `roborun.nes` (RoboRun 1.1, GPL-3.0, © heaven-hm) и `falling.nes` (Falling, MIT, © tragicmuffin) — обе NROM, 40976 B. В `decoy/` лежат `ROMS.md` (происхождение, лицензии, предложение исходников по GPL §3b) и тексты `LICENSE-ROBORUN` / `LICENSE-FALLING` / `LICENSE-FCEUMM`. Старые `jsnes.min.js`, `nestest.nes`, `LICENSE-JSNES` удалены.
- **Управление**: мультитач-геймпад на pointer-событиях (пер-элементный `held`-сет + `setPointerCapture`), клавиатура (стрелки/WASD, Z/X, Enter/Shift, P/M/C/F), Gamepad API с опросом в кадровом цикле, вибро-отклик, пауза/звук/CRT/фуллскрин, загрузка **своего** `.nes` локально в браузере (файл никуда не отправляется) с проверкой заголовка iNES `4E 45 53 1A`, автосохранение SRAM в localStorage.
- **Operational**: `telemt` кэширует каталог `decoy` при старте и не подхватывает добавленные файлы, поэтому `install.sh` перезапускает `telemt` после переустановки с сохранением данных (`systemctl is-active --quiet telemt && systemctl restart telemt`).
- **Проверено на живом 443** (headless Chrome по CDP против реального домена): 3 карточки, RoboRun (Dendy) и Falling (Auto) стартуют и рендерятся, CRT и геймпад работают, 0 CSP-нарушений в консоли.

## [2.4.3] - 2026-09-22

- **Fix: WireGuard-ссылки для INCY.** Выяснено, что парсер INCY percent-декодирует только userinfo ссылки, но **не** раскодирует query-параметры: в конфиг приложения уезжали `publicKey = "N%2FrePA...%3D"` и `address = "10.10.0.4%2F32/32"` (Incy добавлял свой `/32` к уже закодированному). Теперь `publickey` и `address` передаются плейнтекстом (base64 с `+ / =` как есть), `address` — без префикса `/32`, параметр `mtu` убран (его нет в поддерживаемом формате). `secretKey` в userinfo остаётся percent-encoded — Incy его раскодирует корректно. Формат сверен с официальной документацией INCY (incy.gitbook.io).
- **Установщик больше не «закостенел»**: `install.sh` скачивает `releases/latest/download/veil.tar.gz` вместо зашитого `v2.3.0`, так что свежие установки сразу получают актуальную панель.
- **Decoy** теперь полностью самодостаточен: `jsnes.min.js` и `nestest.nes` добавлены в репозиторий и релизный архив `veil.tar.gz`.
- **Документация наведена в порядок**: `README.md` переписан по-английски, `README.ru.md` — по-русски, описание возможностей приведено к фактическому (18 протоколов, подписки, 2FA, журналы, ACME/DDNS, диагностика); бейдж версии заменён на динамический (`shields.io/github/v/release`), битая ссылка на несуществующий `README.en.md` убрана; в CHANGELOG восстановлены пропущенные записи 2.3.9–2.4.2.

## [2.4.2] - 2026-09-22

- **Вкладка «Диагностика»**: `GET /api/metrics` (CPU, RAM, load, статус служб и портов) и `GET /api/selftest` — самотестирование всех inbound'ов. Проверки протокол-осознанные: TCP-connect для Xray-протоколов, UDP-bind для WireGuard/AmneziaWG/Hysteria2. В UI — сетка бейжей статуса портов.
- **Sanitization Xray WireGuard outbound JSON** для INCY: снятие лишнего url-кодирования с ключей/адреса, удаление `\/`-экранирования.

## [2.4.1] - 2026-09-21

- **Fix**: поле `ok` в ответах бэкенда; ошибка при отзыве сессии; адаптивность таблиц на мобильных экранах; `secretKey` в Xray WireGuard outbound для приложения INCY.

## [2.4.0] - 2026-09-21

- **Журналы безопасности**: read-only `GET /api/audit` и `GET /api/login/history` — журнал API-действий и история входов прямо в UI (вкладка «Журналы» со счётчиками).
- **Управление сессиями**: `GET /api/sessions`, `POST /api/sessions/revoke`, `POST /api/sessions/revoke_others` — список активных сессий (IP, user-agent, последний визит) и отзыв по одной/всех кроме текущей.
- **Оформление**: пресеты тем (`applyThemePreset`), обои, логотип — в отдельной вкладке.

## [2.3.9] - 2026-09-20

- **WireGuard переведён на kernel-интерфейс `veilwg`** (wg-quick) вместо userspace-Tun Xray: включение `ip_forward` + NAT-masquerade подсетей 10.10.0.0/24 и 10.20.0.0/24 через отдельную nft-таблицу `veil_wg`; PSK убран из peer-конфигов для совместимости с INCY; автозагрузка модуля AmneziaWG на новых ядрах.

## [2.3.8] - 2026-09-20

- **iOS: исправлены ссылки на приложения.**
  - **Happ Plus** — сломанный слэг `happ-plus/` → корректный `happ-plus-хапп-vpn/id6800274884`.
  - **WireGuard** — была macOS-версия (`id1451685025`, url-параметр `mt=12`), теперь iOS-версия `id1441195209`. Apple TV тоже больше не ссылается на macOS-версию.
  - **sing-box (SFI/SFM/SFT)** — ссылка на GitHub заменена на официальный раздел установки `sing-box.sagernet.org/clients/apple`: по данным самой команды sing-box приложения Apple-платформ временно убраны из App Store ревизором (TestFlight/GitHub) — рабочей App Store-страницы сейчас не существует (`id6451272673` отдаёт 404).

## [2.3.7] - 2026-09-20

- **AmneziaWG добавлен в iOS**: App Store `id6478942365` (официальное приложение Amnezia, free). На странице `/p/<token>` у подписчика с протоколом AmneziaWG теперь есть карточка и скачивание личного конфига; из Linux убран (официального клиента там нет).
- **Адаптивная сетка приложений**: карточки больше не вылезают за пределы страницы — сетка `auto-fill/minmax`, на узких экранах (<400px) переключается в одну колонку, длинные названия переносятся.
- **Настоящий логотип проекта**: вместо SVG-заглушки в шапке теперь используется штпатный файл `icon-veil.png` (отдаётся панелью по `GET /logo.png`), с лёгкой анимацией «парения» и градиентным wordmark «Veil»; добавлен favicon.

## [2.3.6] - 2026-09-20

- **Fix: Shadowrocket — неверная дата окончания.** Shadowrocket, как и Happ Plus/INCY, ждёт `expire` в секундах — теперь получает секунды; остальные клиенты (v2rayNG, NekoBox, Hiddify, Clash) — миллисекунды.
- **Проверен каталог приложений и ссылки магазинов:**
  - битые ссылки исправлены: sing-box для iOS/macOS больше не в App Store — ведёт на официальные релизы SagerNet/sing-box; v2rayNG не в Google Play — ведёт на GitHub; Foxray → новый `id6770070697`; v2rayM убран (репозиторий недоступен);
  - **платные** приложения (Shadowrocket, Stash, Loon) перенесены вниз списка и помечены тегом «платно»;
  - deep-link схемы приведены к актуальным: `sing-box://import-remote-profile?url=`, `hiddify://import/<url>`, `v2rayng://install-config/?url=`;
  - добавлены **Happ Plus**, **WireGuard** и **AmneziaWG** (официальные: Play `org.amnezia.awg`, iOS `id6478942365`, Windows GitHub `amneziawg-windows-client`).
- **Личные конфигурации**: на странице `/p/<token>` появился блок «Личные конфигурации» с кнопками скачивания личных `WireGuard.conf` и `AmneziaWG.conf` (`/api/wgconf/<token>`, `/api/awgconf/<token>`), а WireGuard-приложения импортируются одним тапом по `wgconf://`.
- **Анимационный логотип проекта Veil** (вращающееся кольцо, пульсирующая буква V, волна и анимированный градиентный wordmark) в шапке страницы подписки.

## [2.3.5] - 2026-09-20

- **Fix: Happ Plus — неверная дата окончания подписки.** В `subscription-userinfo` заголовок `expire` отправлялся в миллисекундах, а Happ Plus (и INCY по документации) ожидают **Unix-секунды** — итогом была фантомная дата. Теперь единицы зависят от клиента: Happ Plus и INCY получают секунды, остальные (v2rayNG, NekoBox, Hiddify и т.п.) — как раньше, миллисекунды.
- **Редизайн страницы подписки `/p/<token>`:** карточка с градиентной шапкой и аватаром, бейдж статуса (Активна/Отключена), сетка метрик (окончание со счётчиком «осталось N дней», трафик, онлайн, число протоколов) с иконками, прогресс-бар трафика с процентом, селект платформы с автоопределением, сетка карточек приложений с галочкой выбора, выделенная кнопка «+ Добавить подписку» и «Скопировать ссылку».

## [2.3.4] - 2026-09-20

- **Fix: INCY — неверный формат JSON.** INCY — Xray-клиент, sing-box outbound-объекты ему не подходят. По документации INCY (incy.gitbook.io) подписка теперь отдаётся как **открытые ссылки, по одной в строке**, со всеми 18 протоколами, включая однострочные `wireguard://<key>@host:port?publickey=&address=#` и `amneziawg://<base64url-conf>#` (ключ WireGuard URL-энкодится — содержит `/`, `+`). Определяется по UA `INCY/<ver>/<platform>` или заголовку `x-client: INCY`.
- sing-box JSON больше **не** отдаётся автоматически (только по явному `?format=sing-box`, отдаётся корректным массивом outbound'ов для настоящих sing-box клиентов). Остальные клиенты по умолчанию получают base64 v2ray-подписку; `?format=v2ray` форсирует её.
- Страница подписки `/p/<token>`: в каталог iOS добавлено приложение **INCY** (App Store) с deep-link `incy://import/<url>` для кнопки «+ Добавить подписку».

## [2.3.3] - 2026-09-20

- **Fix: INCY / Happ+ показывали только одно подключение (vless+reality).** Причина — многострочные WireGuard/AmneziaWG-блоки в base64-подписке не разбираются sing-box клиентами, импортировался только первый линк.
  - Добавлена **sing-box JSON-подписка**: `/sub/<token>?format=sing-box` отдаёт батарейку outbound'ов на все 18 протоколов; по User-Agent (INCY, Happ, Streisand, SFI/SFA/SFM, NekoBox, Foxray, Hiddify и др.) JSON отдаётся автоматически. `?format=v2ray` форсирует классический base64.
  - base64-подписка переупорядочена: однострочные ссылки (vless/vmess/trojan/ss/hy2) идут первыми, многострочные WG/AmneziaWG-конфиги — в конец.
- **Страница подписки `/p/<token>`.** Заголовок `profile-web-page-url` теперь ведёт на уникальную страницу каждой подписки (кнопка «i» в клиентах): имя подписки, статус (активна/отключена: блокировка, истёк срок, исчерпан лимит), дата окончания, использованный трафик. Ниже — выпадающий список платформ (iOS, Android, Windows, macOS, Apple TV, Android TV, Linux), ссылки на приложения (магазины/релизы) и кнопка «+ Добавить подписку», которая открывает приложение на устройстве напрямую (deep-link) либо через системный share/clipboard.

## [2.3.2] - 2026-09-20

- **Fix: удаление подписчика больше не раскидывает остальных** — `/api/clients/delete` вызывал `_ensure_all_protos()` после удаления, из-за чего все оставшиеся клиенты «получали» все 17 протоколов. Убрано: каждый клиент остаётся только в тех inbounds, где был создан (Reality-only остаются Reality-only).
- **Fix: bot `/addsub` больше не раскидывает существующих клиентов** — `_create_subscription()` раньше тоже вызывал `_ensure_all_protos()`; теперь создаётся недостающий inbound без распространения текущих клиентов.
- **Восстановлено live-состояние** — после инцидента подписчики Test/Test2 возвращены в Reality (удалено 34 клона), всепротокольный подписчик сохранён.

## [2.3.1] - 2026-09-20

- **Subscriptions: all protocols in one link** — when a subscriber is added from the Subscriptions tab, the client is now created in **all** protocol inbounds (VLESS/VMess/Trojan/Shadowsocks/Hysteria2/WireGuard/AmneziaWG variants), so the subscription URL immediately provides every transport; existing subscribers are left untouched. Per-protocol «Новый клиент» add now correctly targets the selected protocol (it was ignored before).
- **WebProxy fixed end-to-end** — stale nginx config that intercepted Telegram's handshake (`GET /?bridge=...`) replaced with a full proxy-all to the new telemt WEB listener (`127.0.0.1:18080`); carrier forced back to `https`; verified reachable from RU (6/6 Globalping probes) with a valid HTTP/2 cert.
- **telemt WEB mode** — new `_tg_web_ensure()` enables the telemt WEB listener, vhost on the panel domain (`926923.v6.navy`), public `tg://webproxy` link generation and nginx routing; `/etc/telemt` is chowned to the telemt user so config persists (fixes “Смена транспорта: HTTP Error 500”).
- **WebProxy retry/reinstall button** — «⚙ Повторить / Переустановить Web Proxy» regenerates the nginx config and re-applies WEB mode; free-port buttons for 80/443 added to the Proxy tab.
- **Decoy site** — Retro NES emulator decoy served as telemt's static vhost when the proxy isn't handed a valid bridge.
- **Globalping auto-check** — webproxy availability from RU is probed automatically every 15 minutes with alerting.
- **Installer v2.3.0 fixes** — install.sh menu shows the panel address on finish, `xray.service` naming compatibility for older distros, reinstall logic fixes.

## [2.2.9] - 2026-09-19

- **Critical JS fix** — restored missing `$` helper function (`const $ = (id) => document.getElementById(id)`) that was accidentally removed when fixing a duplicate declaration bug. This caused all UI interactions (login, buttons, tabs) to fail silently with "ReferenceError: $ is not defined".
- **dynv6 auth fix** — authentication checks on `/api/dynv6/create-zone`, `/api/dynv6/save`, `/api/dynv6/update`
- **Swipe removed** — removed swipe navigation toggle per user request
- **Timeout increased** — dynv6 API timeout 60s

## [2.2.8] - 2026-09-19

- **Swipe removed** — полностью убран свайп-навигация между вкладками (был источник багов на мобильных)
- **dynv6 auth fix** — добавлена проверка авторизации (`_authed`) ко всем эндпоинтам dynv6: `/api/dynv6/create-zone`, `/api/dynv6/save`, `/api/dynv6/update` — теперь кнопка «Создать зону» работает корректно
- **dynv6 zone creation fix** — автодополнение `.dynv6.net` (или выбранный домен), обработка `already taken`, account-token для DDNS
- **Quick install link restored** — `install.sh` в `main`
- **README: quick install at the top** — команда установки вверху

## [2.2.7] - 2026-09-19

- **Update check fix** — исправлена проверка обновлений (GitHub API: HTTP 401 → теперь работает с токеном из github.token)
- **Swipe checkbox persistence** — состояние чекбокса «Свайп между вкладками» в вкладке Оформление теперь корректно сохраняется и восстанавливается при загрузке
- **dynv6 zone creation fix** — кнопка «Создать зону через API» в вкладке Сайт: автодополнение `.dynv6.net` (или выбранный домен: dynv6.net, v6.navy, v6.army, dns.navy, dns.army, v6.rocks), обработка `already taken` (подключает существующую зону), account-token используется для DDNS.
- **Quick install link restored** — `install.sh` возвращён в `main`, работает `bash <(curl -fsSL https://raw.githubusercontent.com/GurovNA/Veil/main/install.sh)`.
- **README: quick install at the top** — команда быстрой установки вынесена в самый верх README.md и README.ru.md.

## [2.2.6] - 2026-09-19

- **Swipe navigation toggle** — в вкладке Оформление добавлен чекбокс «Свайп между вкладками» для включения/выключения навигации смахиванием пальцем (вкл/выкл). По умолчанию выключено, не мешает прокрутке и жестам браузера. Сохраняется в theme.json.
- **dynv6 zone creation fix** — кнопка «Создать зону через API» в вкладке Сайт: автодополнение `.dynv6.net` (или выбранный домен: dynv6.net, v6.navy, v6.army, dns.navy, dns.army, v6.rocks), обработка `already taken` (подключает существующую зону), account-token используется для DDNS.
- **Quick install link restored** — `install.sh` возвращён в `main`, работает `bash <(curl -fsSL https://raw.githubusercontent.com/GurovNA/Veil/main/install.sh)`.
- **README: quick install at the top** — команда быстрой установки вынесена в самый верх README.md и README.ru.md.

## [2.2.5] - 2026-09-19

- **dynv6: zone creation fixed + domain selector** — кнопка «Создать зону через API» в вкладке Сайт теперь работает: голые имена автодополняются `.dynv6.net` (или выбранный домен), ошибка \"already taken\" обрабатывается корректно (подключается существующая зона), account token используется для DDNS обновлений. UI разбит на поле имени + выпадающий список доменов (dynv6.net, v6.navy, v6.army, dns.navy, dns.army, v6.rocks).
- **Quick install link restored** — `install.sh` возвращён в ветку `main` (был только в feature-ветках), поэтому `bash <(curl -fsSL https://raw.githubusercontent.com/GurovNA/Veil/main/install.sh)` снова работает.
- **README: quick install at the top** — команда быстрой установки вынесена в самый верх README.md и README.ru.md.

## [2.2.4] - 2026-09-18
- **AmneziaWG: full server-side protocol** — the panel now manages a native `amneziawg` kernel interface (`awg0`, UDP 28444, 10.20.0.0/24) built from source: clients get their own `/32` address and keypair, configs include the AmneziaWG obfuscation parameters (`Jc`, `Jmin`, `Jmax`, `S1`, `S2`), and peers are synced to `awg0` on start, on subscription create, on unblock/block and after every boot (peers are written straight into `/etc/amnezia/amneziawg/awg0.conf` so the interface survives reboot without a gap).
- **AmneziaWG `.conf` for the Amnezia app** — public endpoint `GET /api/awgconf/<sub_token>` serves a ready-to-import AmneziaWG configuration for the AmneziaVPN client (attachment with RFC 5987 `filename*`); `conf_url` is exposed in `/api/subs`, `/api/clients` and as a «⬇ AmneziaWG» button on the subscription card and in the client card. Keys are generated in standard base64 (Xray's URL-safe X25519 keys are converted with `_wg_key_std`, otherwise the `awg` tools reject them with `Key is not the correct length or format`).
- **Subscription UX fixes** — the client card button row now wraps (`flex-wrap`) instead of overflowing the screen on every inbound; the «⬇» download button is also available for `amneziawg` inbounds and downloads the `.conf` through the server (correct filename).
- **Note for AmneziaVPN users**: the app has no v2ray-style base64 subscription support — it imports a single `.conf`/`.json`/`.vpn` file (or a `vpn://` key / QR). To get the AmneziaWG protocol in the app, use the direct «⬇ AmneziaWG» `.conf` download instead of the `/sub/<token>` link.

## [2.2.3] - 2026-09-18
- **Bot: multi-step subscription creation** — `/addsub` now walks through 3 steps in chat: client name → traffic limit in GB (`0` = unlimited, decimals allowed) → expiry in days (`0` = no expiry). The flow validates input, supports `/cancel` at any step, and calls `_create_subscription(name, limit_gb, expiry_days)`, which persists the limit/expiry on the client.
- **Bot: Status and Statistics merged** — `/status` now shows Xray state + uptime, client count, node count, RU availability from Globalping, CPU/RAM and disk. `/stats` is kept as a synonym; the «📈 Статистика» menu button was removed.
- **Bot: low-availability alerts** — when the RU availability probe drops to ≤50% (state transition, not every poll), the bot notifies the admin chat (🚨/✅), deduplicated via `_GP_LOW_ALERT_ACTIVE`.
- **Panel: WireGuard `.conf` download** — public endpoint `GET /api/wgconf/<sub_token>` serves the WG config as an attachment (RFC 5987 `filename*`, ASCII fallback); `conf_url` is added to `/api/subs` and `/api/clients` for WG subscriptions and shown as a «⬇ WireGuard» button on the subscription card.
- **Panel: restart button** — «⟳ Панель» button next to the version pill triggers a delayed `systemctl restart vpnpanel` via POST `/api/restart` (graceful, session survives).
- **Panel: VPS IP list in Settings** — `/api/settings` returns `addrs` (IPv4/IPv6 of every interface via `_all_iface_ips()`), rendered in the Settings block.

## [2.2.2] - 2026-09-18
- **Telegram Bot fixes**: added missing `_main_menu_keyboard`, removed double admin check that used the bot's own id (all commands fell into "no rights"), commands now accept the `/cmd@BotName` suffix, logging includes tracebacks + error messages sent to the chat, messages are capped at 4000 chars, and client names in `/clients` are HTML-escaped.
- **Globalping RU availability fixed**: the frontend relied on a non-existent `result.success` field; HTTP probes now use `status === "finished"` + `statusCode`, RTT comes from `timings.total`. Added the previously missing POST `/api/globalping/history` (GET-only before), so results are actually persisted (atomic write, ISO UTC `created_at`, last 50 kept). Probe target is derived from the subscription URL (host/protocol/port/path instead of a hardcoded path that returned 404) and HTTP 429 is handled with `Retry-After`.
- **Panel HTML nesting fixes**: `tab-security` pane is now inside `#panel` (two stray `</div>` tags removed) so Security no longer stays visible after logout; closed an unclosed `<p>`.
- **Swipe between tabs**: horizontal swipe on the active tab content switches to the previous/next tab (book-like), ignoring taps on buttons/inputs and vertical scroll.
- **Auto-check every 15 minutes now always runs**: replaced the `visibilityState === "visible"` guard (which skipped the check whenever the browser tab wasn't focused) with an overlap-protected `gpAutoCheck()`.
- **Log noise reduction**: Telegram long-poll read timeouts are no longer logged as errors (HTTP timeout raised to 40s), and `BrokenPipe`/`ConnectionReset` tracebacks from port scanners are suppressed.

## [2.2.1] - 2026-09-17
- **UI & Pane Nesting Fixes**: Resolved broken HTML nesting that caused proxy, site, and settings tabs to appear empty.
- **Add-User Modal Fix**: Fixed user creation modal to render correctly and function from any tab (including subscriptions).
- **Server Metrics Unification**: Unified CPU and RAM into clean circular gauges in mini-stats, with real-time load average and port status tracking via `/api/metrics`.
- **Appearance Modernization**: Removed redundant app/retro OS theme presets and added new stylish presets (Sakura, Matcha, Sunset, Cosmos).
- **README Cleanup**: Removed MEKO top attribution, made version/license/Ubuntu badges clickable, and updated attribution phrasing.

## [2.2.0] - 2026-09-17
- **Universal per-user subscription**: one `sub_token` and one `uuid` per user across every protocol; a single `/sub/<token>` URL returns base64 links for all enabled protocols (v2rayNG / Hiddify / Streisand / NekoBox / Happ / Shadowrocket).
- **3x-ui style subscription headers**: added `/api/subs`, `profile-title` (base64), `profile-web-page-url` and `subscription-userinfo` (upload/download/total/expire) headers.
- **Unique per-protocol link names**: each link now carries `<user> · <protocol>`, fixing clients that collapsed all entries with the same name into one.
- **Hysteria2 uses the real Let's Encrypt certificate**: dropped the self-signed cert and `insecure=1` from share links; Hysteria2 now works in Xray-based clients (Happ) that no longer honour `insecure`.
- **VMess + gRPC share link**: `type` is emitted as `gun` (v2rayN convention) so clients resolve the gRPC service name correctly.
- **Removed Shadowsocks-2022 (aes-256-gcm / chacha20)**: it handshook but did not pass traffic reliably through Russian mobile DPI; removed from protocols, ports and subscriptions.
- Fixed `profile-title` being sent as a Python `repr` of bytes, and a `panel_port` NameError in the `/sub` handler.

## [2.0.5] - 2026-09-15
- **Fingerprint configuration**: Moved TLS fingerprint setting from General Settings into inbound settings dialog (⋯ menu on protocol cards).
- **SNI Validation**: Added DNS resolution and TCP port 443 availability check before applying SNI changes to prevent breaking REALITY handshakes.
- **Protocol Cards UI Refinement**: Balanced action buttons, collapsible Shadowsocks-2022 cards by default.
- **Web Proxy (nginx)**: One-click installation of nginx HTTPS reverse proxy for telemt web directly from the panel.
- **Telemt Management**: Added version switcher, pre-release support, and rollback backup management directly from the Telegram proxy tab.
- **Default Firefox Fingerprint**: Changed default TLS fingerprint to firefox for improved REALITY handshake stability across various clients.

## [2.0.4] - 2026-09-14
- Initial release of modular Xray + Telemt integration.
- Added dark theme, system status metrics, and user management UI.
