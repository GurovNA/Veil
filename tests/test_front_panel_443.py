"""Страница подписчика и раздача на стандартном :443 (#495).

Слово хозяина: «делай 2, выводи кнопку в настройки, но без меня не включай». Природа
беды названа числом: ссылки панели несут `:{panel_port}`, а сеть, где абоненту дали
только IPv6, добирается до IPv4-узла через переводчик (NAT64), который обычно пускает
80 и 443. Отсюда хозяйское наблюдение «при включённом VPN они заходят, при выключенном
нет». Переключатель ведёт credential-пути через тот же nginx-фронт, что держит :443.

Что нога обязана удержать словом:
  1) ни один credential-путь не записывается в журнал nginx (включено или выключено);
  2) включённый режим не может появиться без живого ответа панели;
  3) форма ссылки меняется только у СВЕЖИХ ссылок и только на подтверждённом имени —
     старые ссылки с портом продолжают работать (хозяйское «ссылки нельзя снимать»);
  4) на :80 раздача не появляется никогда (иначе токен уехал бы открытым http);
  5) вход в панель и её административная часть на :443 не ведутся.
"""
import inspect
import os
import re
import shutil
import tempfile
import types
import unittest

from _support import panel_module, read

panel = panel_module()

TOK = "veiltesttoken000000"
SERVE = ("127.0.0.1", 8443, True)
CLOSED = ("", 0, False)


class _CfgCase(unittest.TestCase):
    """Мутации `CFG_CACHE` — только с восстановлением прежних значений."""

    KEYS = ("front_panel", "front_panel_host", "panel_port", "panel_domain",
            "hop_public_host", "panel_bind")

    def setUp(self):
        self._saved = {k: panel.CFG_CACHE.get(k, "\0absent") for k in self.KEYS}
        self._tls = panel._WEB_CTX

    def tearDown(self):
        for k, v in self._saved.items():
            if v == "\0absent":
                panel.CFG_CACHE.pop(k, None)
            else:
                panel.CFG_CACHE[k] = v
        panel._WEB_CTX = self._tls


class Locations(_CfgCase):
    def test_every_credential_path_is_covered(self):
        # тот же список, что маскирует журнал (`_AUDIT_TOK_ROUTES`), плюс файлы правил:
        # до #495 они на фронте ловили ложный 200 маской
        rx = "".join(panel._FRONT_TOK_LOCATIONS)
        for path in ("/sub/x", "/sb/x", "/p/x", "/pay/x", "/api/wgconf/x",
                     "/api/awgconf/x", "/rulesets/geoip-ru.srs"):
            self.assertTrue(any(re.match(r, path) for r in panel._FRONT_TOK_LOCATIONS),
                            path)
        self.assertNotIn("/api/login", rx)
        self.assertNotIn("/api/settings", rx)

    def test_closed_mode_logs_nothing_and_proxies_nothing(self):
        block = panel._front_tok_block(serve=CLOSED)
        self.assertEqual(block.count("access_log off;"), len(panel._FRONT_TOK_LOCATIONS))
        self.assertEqual(block.count("return 404;"), len(panel._FRONT_TOK_LOCATIONS))
        self.assertNotIn("proxy_pass", block)

    def test_served_mode_keeps_the_log_closed_on_every_path(self):
        block = panel._front_tok_block(serve=SERVE)
        self.assertEqual(block.count("access_log off;"), len(panel._FRONT_TOK_LOCATIONS),
                         "credential-путь без `access_log off` уехал бы в /var/log/nginx")
        self.assertEqual(block.count("proxy_pass https://127.0.0.1:8443;"),
                         len(panel._FRONT_TOK_LOCATIONS))
        self.assertNotIn("return 404", block)
        self.assertIn("proxy_ssl_verify off;", block)
        # адрес клиента панель берёт из XFF только с петлевых сетей (см. #89)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", block)

    def test_http_server_is_never_marked(self):
        # сервер :80 обязан оставаться закрытым и немеченым: переключатель его не
        # трогает, иначе раздача пошла бы по прозрачному http
        src = inspect.getsource(panel._front_nginx_apply)
        self.assertIn("_loc80 = _front_tok_block(mark=False)", src)
        tail = src[src.find('listen 80'):]
        self.assertIn("+ _loc80 +", tail)
        self.assertNotIn("+ _loc +", tail)


class Upstream(_CfgCase):
    def test_flag_off_means_closed(self):
        panel.CFG_CACHE["front_panel"] = False
        panel._WEB_CTX = object()
        self.assertEqual(panel._front_panel_upstream(), CLOSED)

    def test_without_certificate_refuses(self):
        # токен подписки живёт в URL: открытый http на петле был бы раздачей секретом
        panel.CFG_CACHE["front_panel"] = True
        panel._WEB_CTX = None
        self.assertEqual(panel._front_panel_upstream(), CLOSED)

    def test_garbage_port_refuses(self):
        panel.CFG_CACHE["front_panel"] = True
        panel._WEB_CTX = object()
        for bad in ("abc", 0, 70000, None):
            panel.CFG_CACHE["panel_port"] = bad
            self.assertEqual(panel._front_panel_upstream(), CLOSED, bad)

    def test_panel_bind_is_honoured(self):
        panel.CFG_CACHE.update({"front_panel": True, "panel_port": 8443})
        panel._WEB_CTX = object()
        panel.CFG_CACHE["panel_bind"] = ""
        self.assertEqual(panel._front_panel_upstream(), SERVE)
        panel.CFG_CACHE["panel_bind"] = "0.0.0.0"
        self.assertEqual(panel._front_panel_upstream(), SERVE)
        panel.CFG_CACHE["panel_bind"] = "203.0.113.9"
        self.assertEqual(panel._front_panel_upstream(), ("203.0.113.9", 8443, True))
        panel.CFG_CACHE["panel_bind"] = "2001:db8::2"
        self.assertEqual(panel._front_panel_upstream(), ("[2001:db8::2]", 8443, True))


class Render(_CfgCase):
    FRONT = ("server {\n"
             "    listen 443 ssl;\n"
             "    server_name example.test;\n"
             "    location / { try_files $uri $uri/ /index.html; }\n"
             + panel._FRONT_TOK_LEGACY + "}\n")
    BRIDGE = ("server {\n"
              "    listen 8445 ssl;\n"
              "    location / {\n        proxy_pass http://telemt_web;\n    }\n}\n")

    def test_legacy_block_is_found_and_round_trips(self):
        served = panel._front_panel_render(self.FRONT, SERVE)
        self.assertIn("proxy_pass https://127.0.0.1:8443;", served)
        self.assertEqual(panel._front_panel_mode(served), "panel")
        back = panel._front_panel_render(served, CLOSED)
        self.assertEqual(panel._front_panel_mode(back), "closed")
        self.assertNotIn("proxy_pass", back)

    def test_render_is_idempotent_in_both_modes(self):
        for serve in (SERVE, CLOSED):
            once = panel._front_panel_render(self.FRONT, serve)
            self.assertEqual(panel._front_panel_render(once, serve), once)

    def test_bridge_without_block_gets_inserted_before_location_root(self):
        served = panel._front_panel_render(self.BRIDGE, SERVE)
        self.assertEqual(panel._front_panel_mode(served), "panel")
        self.assertLess(served.find(panel._FRONT_TOK_MARK + " begin"),
                        served.find("location / {"))

    def test_file_without_any_hook_is_named_not_guessed(self):
        self.assertIsNone(panel._front_panel_render("server {\n    listen 443;\n}\n", SERVE))

    def test_only_the_marked_region_moves(self):
        txt = self.FRONT + ("server {\n    listen 80;\n" + panel._FRONT_TOK_LEGACY + "}\n")
        served = panel._front_panel_render(txt, SERVE)
        self.assertEqual(served.count("proxy_pass https://127.0.0.1:8443;"),
                         len(panel._FRONT_TOK_LOCATIONS),
                         "под замену должен попадать только меченый кусок, не сервер :80")


class Name(_CfgCase):
    def test_plain_domain_is_accepted(self):
        panel.CFG_CACHE["panel_domain"] = "example.test"
        self.assertEqual(panel._front_panel_name(), "example.test")

    def test_ip_and_empty_are_refused_by_name(self):
        for bad in ("203.0.113.9", "", "127.0.0.1"):
            panel.CFG_CACHE["panel_domain"] = bad
            panel.CFG_CACHE.pop("hop_public_host", None)
            self.assertEqual(panel._front_panel_name(), "", bad)

    def test_double_hop_names_the_zone_base_not_the_front(self):
        # #635: со словом прыжка ссылки ведут на адрес фронта, но релей правится этой
        # машиной, TLS терминируется здесь (#572), а credential-куски лежат в наших
        # конфигах — имя раздачи берётся из базы домена, чья A-запись уже смотрит на
        # фронт (#502). Прежняя нога звала фронт «чужим» и отказывала: для самосборной
        # маски это верно, для релея под управлением этой машины — ошибочно.
        panel.CFG_CACHE["panel_domain"] = "example.test"
        panel.CFG_CACHE["hop_public_host"] = "front.other.test"
        self.assertEqual(panel._front_panel_name(), "example.test")

    def test_double_hop_refuses_address_empty_or_unnamed_base(self):
        # Слово «имя» значит то же, что и без прыжка: адрес сертификат не проверяется,
        # поэтому ссылка без порта была бы обещанием без доказательства.
        panel.CFG_CACHE["hop_public_host"] = "front.other.test"
        for bad in ("203.0.113.9", "", "127.0.0.1", "example.test:8443", "a/b"):
            panel.CFG_CACHE["panel_domain"] = bad
            self.assertEqual(panel._front_panel_name(), "", bad)


class LinkShape(_CfgCase):
    def test_portless_needs_the_confirmed_name(self):
        panel.CFG_CACHE.update({"front_panel": True, "panel_port": 8443,
                                "front_panel_host": "example.test"})
        panel._WEB_CTX = object()
        self.assertEqual(panel._pb_pub("example.test", 8443), "https://example.test")
        self.assertEqual(panel._pb_pub("other.test", 8443), "https://other.test:8443")

    def test_off_word_keeps_the_port(self):
        panel.CFG_CACHE.update({"front_panel": False, "panel_port": 8443,
                               "front_panel_host": "example.test"})
        panel._WEB_CTX = object()
        self.assertEqual(panel._pb_pub("example.test", 8443), "https://example.test:8443")

    def test_switch_never_invents_an_untrusted_scheme(self):
        panel.CFG_CACHE.update({"front_panel": True, "panel_port": 8443,
                                "front_panel_host": "example.test"})
        panel._WEB_CTX = object()
        self.assertTrue(panel._pb_pub("example.test", 8443).startswith("https://"))
        panel._WEB_CTX = None
        # без сертификата подтверждённое имя невозможна и выдача: `_pb` даёт http с портом
        self.assertEqual(panel._pb_pub("example.test", 8443), "http://example.test:8443")

    def test_only_the_port_part_can_differ(self):
        # хозяйское «ссылки нельзя снимать»: форма меняется у пути, токен остаётся
        panel.CFG_CACHE.update({"front_panel": True, "panel_port": 8443,
                                "front_panel_host": "example.test"})
        panel._WEB_CTX = object()
        for path in ("sub", "sb", "p"):
            off = panel._pb("example.test", 8443) + "/" + path + "/" + TOK
            on = panel._pb_pub("example.test", 8443) + "/" + path + "/" + TOK
            self.assertTrue(off.endswith("/" + path + "/" + TOK))
            self.assertTrue(on.endswith("/" + path + "/" + TOK))
            self.assertEqual(off.replace(":8443", ""), on)


class Sync(_CfgCase):
    """Живое тело `_front_panel_sync`: какие байты легли в файл и что бывает при красном `nginx -t`.

    `subprocess` и `_unit_active` подменяются заглушкой ровно на время ноги: судится
    ТЕЛО (перекладка куска, откат, молчание при отсутствии изменений), а машина не
    трогается. Поэтому ранний отказ `if SBX` в `_front_panel_sync` не стоит — он
    отрезал бы от прогонов ровно тот код, который эти ноги и проверяют.
    """

    FRONT = ("server {\n"
             "    listen 443 ssl;\n"
             "    server_name example.test;\n"
             "    location / { try_files $uri $uri/ /index.html; }\n"
             + panel._FRONT_TOK_LEGACY + "}\n")

    def setUp(self):
        super().setUp()
        self.dir = tempfile.mkdtemp(prefix="veil495sync")
        self.path = os.path.join(self.dir, "veil-front.conf")
        self._sub = panel.subprocess
        self._ua = panel._unit_active
        self._tg = panel._front_panel_targets
        self.calls = []
        panel._unit_active = lambda unit: True
        panel._front_panel_targets = lambda: (self.path,)
        self.nginx_rc = 0

    def tearDown(self):
        panel.subprocess = self._sub
        panel._unit_active = self._ua
        panel._front_panel_targets = self._tg
        shutil.rmtree(self.dir, ignore_errors=True)
        super().tearDown()

    def _stub(self, rc=None):
        outer = self

        class _P:
            def run(self, argv, **kw):
                outer.calls.append(list(argv))
                code = outer.nginx_rc if argv[0] == "nginx" else 0
                return types.SimpleNamespace(returncode=code, stdout="",
                                             stderr="проверка конфигурации nginx")

        panel.subprocess = _P()

    def _bytes(self, mode="r"):
        with open(self.path, mode, encoding=None if mode == "rb" else "utf-8") as f:
            return f.read()

    def _write(self, serve):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(panel._front_panel_render(self.FRONT, serve))

    def test_on_word_lays_the_proxy_and_reloads_without_restart(self):
        self._stub()
        self._write(CLOSED)
        panel.CFG_CACHE.update({"front_panel": True, "panel_port": 8443,
                                "panel_domain": "example.test"})
        panel._WEB_CTX = object()
        changed, refused = panel._front_panel_sync()
        self.assertEqual(refused, [])
        self.assertEqual(changed, [self.path])
        self.assertEqual(panel._front_panel_mode(self._bytes()), "panel")
        self.assertIn(["systemctl", "reload", "nginx"], self.calls)
        self.assertFalse([c for c in self.calls if "restart" in c],
                         "reload не рвёт живые соединения, restart — рвёт")

    def test_red_nginx_t_restores_previous_bytes_byte_for_byte(self):
        self._stub()
        self._write(CLOSED)
        before = self._bytes("rb")
        self.nginx_rc = 1
        panel.CFG_CACHE.update({"front_panel": True, "panel_port": 8443,
                                "panel_domain": "example.test"})
        panel._WEB_CTX = object()
        changed, refused = panel._front_panel_sync()
        self.assertEqual(self._bytes("rb"), before)
        self.assertEqual(changed, [])
        self.assertTrue(refused and refused[0].startswith("откат: nginx -t"), refused)
        self.assertFalse([c for c in self.calls if c[0] == "systemctl"],
                         "рабочий nginx не должен узнать о неудачной попытке")

    def test_second_pass_is_quiet(self):
        self._stub()
        self._write(CLOSED)
        panel.CFG_CACHE.update({"front_panel": True, "panel_port": 8443,
                                "panel_domain": "example.test"})
        panel._WEB_CTX = object()
        panel._front_panel_sync()
        self.calls = []
        changed, refused = panel._front_panel_sync()
        self.assertEqual((changed, refused), ([], []))
        self.assertEqual(self.calls, [], "нет изменений — нет и reload")

    def test_unmarked_legacy_form_is_the_previous_state_not_a_rewritten_one(self):
        # проигравшая попытка не имеет права оставить след: кусок 2.17.17 writes it
        # without markers, and the rollback must return exactly those bytes
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(self.FRONT)
        before = self._bytes("rb")
        snap = panel._front_panel_read()
        self._stub()
        panel.CFG_CACHE.update({"front_panel": True, "panel_port": 8443,
                                "panel_domain": "example.test"})
        panel._WEB_CTX = object()
        panel._front_panel_sync()
        self.assertNotEqual(self._bytes("rb"), before)
        panel._front_panel_sync(restore=snap)
        self.assertEqual(self._bytes("rb"), before)

    def test_restore_touches_only_files_the_snapshot_knows(self):
        # файл, появившийся ПОСЛЕ снимка: снимок ничего про него не обещал, и нога
        # смотрит, что к нему вернулся не снимок, а обычный перекладывающий проход
        self._stub()
        self._write(CLOSED)
        snap = panel._front_panel_read()
        other = os.path.join(self.dir, "veil-appeared.conf")
        with open(other, "w", encoding="utf-8") as f:
            f.write("server {\n    listen 443 ssl;\n    location / {\n    }\n}\n")
        with open(other, "rb") as f:
            keep = f.read()
        panel._front_panel_targets = lambda: (self.path, other)
        panel.CFG_CACHE.update({"front_panel": True, "panel_port": 8443,
                                "panel_domain": "example.test"})
        panel._WEB_CTX = object()
        panel._front_panel_sync()
        changed, refused = panel._front_panel_sync(restore=snap)
        self.assertEqual(changed, [self.path], "возврат известен только снятому файлу")
        with open(other, "rb") as f:
            self.assertNotEqual(f.read(), keep)

    def test_off_word_closes_the_paths_back(self):
        self._stub()
        panel.CFG_CACHE.update({"front_panel": False, "panel_port": 8443,
                                "panel_domain": "example.test"})
        self._write(SERVE)
        changed, refused = panel._front_panel_sync()
        self.assertEqual(changed, [self.path])
        self.assertEqual(panel._front_panel_mode(self._bytes()), "closed")
        self.assertNotIn("proxy_pass", self._bytes())

    def test_file_without_a_hook_is_named_not_guessed(self):
        self._stub()
        other = os.path.join(self.dir, "veil-strange.conf")
        with open(other, "w", encoding="utf-8") as f:
            f.write("server {\n    listen 443 ssl;\n}\n")
        self._write(CLOSED)
        panel._front_panel_targets = lambda: (other, self.path)
        panel.CFG_CACHE.update({"front_panel": True, "panel_port": 8443,
                                "panel_domain": "example.test"})
        panel._WEB_CTX = object()
        changed, refused = panel._front_panel_sync()
        self.assertIn("veil-strange.conf", " ".join(refused))
        self.assertEqual(changed, [self.path], "чужой файл не обязан принимать раздачу")


class Set(_CfgCase):
    """`_front_panel_set`: доказательство живой пробой и откат проигравшей попытки.

    Живой nginx, `systemd` и сеть заменены заглушками: нога судит ОБЕЩАНИЕ функции —
    «включено» только после ответа панели, а отказ не оставляет следа в конфигах.
    """

    FRONT = Sync.FRONT

    def setUp(self):
        super().setUp()
        self.dir = tempfile.mkdtemp(prefix="veil495set")
        self.path = os.path.join(self.dir, "veil-front.conf")
        self._saved = {}
        for name in ("subprocess", "_unit_active", "_front_panel_targets",
                     "_front_panel_probe", "_cfg_save", "_audit", "time",
                     "_front_443_blocker"):
            self._saved[name] = getattr(panel, name)
        panel._unit_active = lambda unit: True
        panel._front_panel_targets = lambda: (self.path,)
        panel._cfg_save = lambda *a, **k: None
        panel._audit = lambda *a, **k: None
        panel._front_443_blocker = lambda: ""

        class _P:
            def run(self, argv, **kw):
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        panel.subprocess = _P()

        class _T:
            def sleep(self, s):
                pass

        panel.time = _T()
        self._web = panel._WEB_CTX
        panel._WEB_CTX = object()
        panel.CFG_CACHE.update({"front_panel": False, "panel_port": 8443,
                                "panel_domain": "example.test"})
        panel.CFG_CACHE.pop("front_panel_host", None)
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(self.FRONT)

    def tearDown(self):
        for name, v in self._saved.items():
            setattr(panel, name, v)
        panel._WEB_CTX = self._web
        shutil.rmtree(self.dir, ignore_errors=True)
        super().tearDown()

    def _read(self):
        with open(self.path, "rb") as f:
            return f.read()

    def test_word_on_requires_a_live_answer(self):
        before = self._read()
        panel._front_panel_probe = lambda host, want=True: (False, "HTTP/1.1 404 Not Found")
        with self.assertRaises(RuntimeError) as ctx:
            panel._front_panel_set(True)
        self.assertIn("не довёл запрос", str(ctx.exception))
        self.assertFalse(panel.CFG_CACHE.get("front_panel"))
        self.assertNotIn("front_panel_host", panel.CFG_CACHE)
        self.assertEqual(self._read(), before,
                         "проигравший клик не оставляет следа в конфиге фронта")

    def test_reload_race_is_given_time_not_a_single_try(self):
        # замерено на живой коробке: первый запрос после `systemctl reload` получил
        # прежний `return 404` — рабочие процессы ещё не пересменились
        seen = []

        def probe(host, want=True):
            seen.append(1)
            return (len(seen) >= 3, "HTTP/1.1 404 Not Found")

        panel._front_panel_probe = probe
        v = panel._front_panel_set(True)
        self.assertTrue(v["on"], "проба дождалась пересмены — раздача включена")
        self.assertEqual(v["host"], "example.test")
        self.assertGreaterEqual(len(seen), 3)

    def test_confirmed_name_survives_and_files_stay_served(self):
        panel._front_panel_probe = lambda host, want=True: (True, "ok")
        v = panel._front_panel_set(True)
        self.assertEqual(v["host"], "example.test")
        with open(self.path, encoding="utf-8") as f:
            self.assertEqual(panel._front_panel_mode(f.read()), "panel")
        panel._front_panel_probe = lambda host, want=True: (False, "нет связи")
        v = panel._front_panel_set(False)
        self.assertFalse(v["on"])
        self.assertNotIn("front_panel_host", panel.CFG_CACHE)


    def test_boot_relays_the_word_after_a_restart(self):
        # мост и маски пишутся целиком из шаблонов; включённое слово не имеет права
        # после рестарта остаться закрытым — иначе свежие ссылки понесут порт
        panel._front_panel_probe = lambda host, want=True: (True, "ok")
        panel._front_panel_set(True)
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(panel._front_panel_render(self.FRONT, CLOSED))
        changed, refused = panel._front_panel_boot()
        self.assertEqual(changed, [self.path], refused)
        with open(self.path, encoding="utf-8") as f:
            self.assertEqual(panel._front_panel_mode(f.read()), "panel")

    def test_boot_is_quiet_when_word_and_deed_agree(self):
        panel.CFG_CACHE["front_panel"] = False
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(panel._front_panel_render(self.FRONT, CLOSED))
        self.assertEqual(panel._front_panel_boot(), ([], []))

    def test_boot_closes_a_front_left_served_by_hand(self):
        # выключенное слово обязано доехать до конфига и после ручной правки фронта
        panel.CFG_CACHE["front_panel"] = False
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(panel._front_panel_render(self.FRONT, SERVE))
        changed, _r = panel._front_panel_boot()
        self.assertEqual(changed, [self.path])
        with open(self.path, encoding="utf-8") as f:
            self.assertEqual(panel._front_panel_mode(f.read()), "closed")


class Wiring(_CfgCase):
    def test_perm_is_settings_not_proxy(self):
        # рубильник переписывает nginx и форму свежих ссылок — право настройки
        for m in ("GET", "POST"):
            self.assertEqual(panel._perm_for("/api/front/panel", m), ["settings"])
        self.assertEqual(panel._perm_for("/api/front/status", m), ["proxy"])

    def test_handlers_exist_for_both_genders(self):
        ui = read("index.html")
        self.assertIn('p == "/api/front/panel"', read("panel.py"))
        self.assertIn("id=setFront443", ui)
        self.assertIn("onchange=saveFrontPanel(this.checked)", ui)
        self.assertIn("setFront443:\"settings\"", ui)
        self.assertIn("loadFrontPanel()", ui)

    def test_startup_calls_the_boot_relay(self):
        # слово оператора живёт в `config.json`, а credential-куски — в конфигах
        # фронтов; без шага при старте включённый переключатель после рестарта
        # возвращал бы порт в ссылках, и самотест краснел бы на молча съехавшем деле
        boot = read("panel.py").split('if __name__ == "__main__":', 1)[1]
        self.assertLess(boot.find("_web_tls_ctx()"), boot.find("_front_panel_boot()"),
                        "перекладка обязана идти ПОСЛЕ сборки TLS-контекста панели")
        self.assertIn("front panel sync init", boot)

    def test_card_tells_the_truth_about_consequences(self):
        ui = read("index.html")
        card = ui[ui.find("id=setFront443"):ui.find('id=setWarpManual')]
        self.assertIn("разданные ранее ссылки с портом продолжают работать", card)
        self.assertIn("ни токена", card)          # журнал nginx не видит credential
        self.assertIn("административная часть", card)   # вход в панель наружу не ведётся
        self.assertIn("снимает обещание", card)   # названо следствие живой проверки
        for lie in ("работает всегда", "никаких рисков"):
            self.assertNotIn(lie, card)

    def test_panel_source_names_the_same_truth_as_the_card(self):
        # карточка про окно YouTube и про фикс TikTok обязана говорить замеренную
        # границу: правила смотрятся по адресу назначения, транзит подписчиков попадает
        ui = read("index.html")
        for cid in ("id=setYouTube", "id=setTikTok"):
            card = ui[ui.find(cid):ui.find(cid) + 6000]
            self.assertIn("пересылает подписчикам", card, cid)
            for lie in ("трафик самого сервера", "окно не замечают", "не замечают"):
                self.assertNotIn(lie, card, "%s: %s" % (cid, lie))


if __name__ == "__main__":
    unittest.main()
