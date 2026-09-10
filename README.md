# Veil

Однокнопочная веб-панель для управления Xray VLESS + Reality.

## Что умеет

- Установка одной командой
- Автоподбор свободного порта для панели и Xray
- Включение VPN одной кнопкой
- Генерация ссылки `vless://` для Happ, Shadowrocket, v2rayNG, Hiddify
- Три вкладки: VPN / Настройки / Безопасность
- Смена логина и пароля в отдельной вкладке
- Проверка обновлений с GitHub

## Стек

- Backend: Python 3 (стандартная библиотека)
- Frontend: один HTML-файл
- VPN-ядро: Xray-core (VLESS + Reality, xtls-rprx-vision)
- Управление: systemd

## Рабочая конфигурация

| Параметр | Значение |
|---|---|
| Порт Xray | 443 |
| SNI / dest | www.samsung.com:443 |
| Fingerprint | firefox |
| Flow | xtls-rprx-vision |
| Протокол | vless + reality |

firefox — не случайность. С chrome Reality-рукопожатие падает на части клиентов.

## Лицензия

Private.
