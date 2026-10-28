"""`Gemini` в обход российского выхода окна «YouTube»: кольцо наружу с привязкой к штатному выходу.

Слово хозяина 22.10: «делай как считаешь нужным, главное что бы работало.
youtube-ru, gemini -не ru».

Почему не адресом. Окно «YouTube» (#493) ставит правила по АДРЕСУ НАЗНАЧЕНИЯ, а
`Gemini` отвечает из тех же сетей Google, что и `YouTube`. На живой коробке замерено
накрытие целиком: из 56 адресов сервиса под окном 56 — то есть весь `Gemini` читается
Россией. Адресом разделить нельзя, различим один признак — имя сервиса в начале
рукопожатия, и его ядро прокси уже читает на всех входах.

Почему привязкой, а не меткой. Метку сокета это ядро прокси наружу не передаёт (замерено
счётником на фильтре: контрольный сокет добавил 6 пакетов, кольца ядра с `sockopt.mark`
и с `sockSettings.mark` — ни одного). Привязка к интерфейсу из-под захваченной таблицы
выводит поток: неподвязанные попытки умерли по таймауту, привязанные дождались ответа —
и по четвёрке, и по шестёрке.

Что прибор судит по-настоящему. Форму кольца и правила, чтение штатного выхода, запрет
туннельных интерфейсов, порядок правила относительно `ru_bypass`, правду о живом файле
службы, темп пересборки при расхождении, перемычки морды и самопроверки — всё по живым
байтам панели. Ни одна нога не ставит правил, не поднимает звеньев и не перезапускает
служб: внешние вызовы подменены. Живая свёрка чисел сделана на тестовой коробке и
описана в теле релиза.

Честная граница, названная прибором: карточка обязана говорить, чего развод не умеет.
`veilwg` и `awg0` ядро пересылает мимо прокси, и по имени сервиса их развести нельзя в
принципе — карточка обязана называть число таких подписчиков, а не обещать невозможное.
"""
import inspect
import json
import os
import re
import shutil
import tempfile
import time
import unittest

from _support import panel_module, read

panel = panel_module()

TMP = tempfile.mkdtemp(prefix="veil-gd-split-")
RE_V4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


class Swap:
    """Подмена атрибута модуля с возвращением на место."""

    def __init__(self, obj, name, value):
        self.obj, self.name, self.value = obj, name, value
        self.old = getattr(obj, name, None)

    def __enter__(self):
        setattr(self.obj, self.name, self.value)
        return self

    def __exit__(self, *a):
        setattr(self.obj, self.name, self.old)


def route_line(text, rc=0, err=""):
    """Чем отвечает ядро на «покажи маршрут по умолчанию»."""
    return Swap(panel, "_tw_cmd", lambda *a, **k: (rc, text, err))


def words(**kw):
    """Слово оператора на время ноги, с возвратом к прежнему набору."""
    return Swap(panel, "CFG_CACHE", dict(kw))


def live_file(cfgobj):
    """Живой файл службы: свой файл, а не боевой."""
    path = os.path.join(TMP, "xray-%d.json" % (len(os.listdir(TMP)) + 1))
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(cfgobj))
    return path


def read_state(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def ring(dev=panel._GD_TAG):
    return {"protocol": "freedom", "tag": panel._GD_TAG,
            "streamSettings": {"sockopt": {"interface": dev if dev else "net0"}}}


def rule(outbound=panel._GD_TAG):
    return {"type": "field", "domain": ["keyword:gemini"], "outboundTag": outbound}


class Shape(unittest.TestCase):
    def test_split_has_its_own_home_and_creates_no_table_or_link(self):
        self.assertEqual(panel._GD_DIR, "/var/lib/veil-gemini-split")
        self.assertNotEqual(panel._GD_DIR, panel._YW_DIR)
        self.assertNotEqual(panel._GD_DIR, panel._TW_DIR)
        self.assertTrue(panel._GD_STATE.startswith(panel._GD_DIR + "/"))
        # Развод живёт в конфиге ядра прокси: ни своей таблицы, ни своего звена у него нет.
        for absent in ("_GD_TBL", "_GD_IF", "_GD_PRIO", "_GD_MARK", "_GD_KEY"):
            self.assertFalse(hasattr(panel, absent), absent)

    def test_ring_binds_interface_and_not_address(self):
        ob = panel._gd_outbound("net0")
        self.assertEqual(ob["protocol"], "freedom")
        self.assertEqual(ob["tag"], panel._GD_TAG)
        self.assertEqual(ob["streamSettings"]["sockopt"]["interface"], "net0")
        body = json.dumps(ob)
        self.assertNotIn("address", body)
        self.assertNotIn("mark", body, "меткой этот движок не выводит поток — замерено")

    def test_rule_is_domain_only_and_points_at_its_own_ring(self):
        r = panel._gd_rule()
        self.assertEqual(r["type"], "field")
        self.assertEqual(r["outboundTag"], panel._GD_TAG)
        self.assertNotIn("ip", r, "правило по адресу утащило бы поток обратно под окно")
        self.assertEqual(sorted(r["domain"]), sorted(panel._GD_DOMAINS))

    def test_domains_name_the_service_and_do_not_swallow_whole_google(self):
        for d in panel._GD_DOMAINS:
            self.assertIn(":", d, "домен без префикса формы: " + d)
            self.assertTrue(d.split(":", 1)[0] in ("keyword", "full", "domain", "suffix",
                                                   "regex", "regexp"), d)
        self.assertIn("keyword:gemini", panel._GD_DOMAINS)
        # #666: вершиной списка живьём названа форма `regexp` — `suffix:` эта сборка
        # ядра не матчит ни под чем, а голое имя без якоря матчится и как подстрока.
        self.assertIn("regexp:(^|\\.)generativelanguage\\.googleapis\\.com$",
                      panel._GD_DOMAINS)
        # Осиротевший слэш в литерале означал бы правило, которое не совпадает ни с чем.
        for d in panel._GD_DOMAINS:
            self.assertEqual(d.count("/"), 0, d)
            self.assertFalse(d.endswith("."), d)
        for wide in ("suffix:google.com", "keyword:google", "suffix:googleapis.com"):
            self.assertNotIn(wide, panel._GD_DOMAINS, "под этим правилом весь Google")
        self.assertLessEqual(len(panel._GD_DOMAINS), 16)

    def test_tunnel_interfaces_are_forbidden_by_name(self):
        for iface in (panel._TW_IF, panel._YW_IF, panel._MR_IF,
                      panel.WG_IFACE, panel.AWG_IFACE):
            self.assertIn(iface, panel._GD_FORBID, iface)

    def test_the_split_source_carries_no_address_literals(self):
        src = "".join(inspect.getsource(getattr(panel, n))
                      for n in ("_gd_egress_dev", "_gd_outbound", "_gd_rule", "_gd_split",
                                "_gd_applied", "_gd_pool", "_gd_region", "_gd_probe",
                                "_gd_reapply", "_gd_tick", "_gd_view"))
        src += repr(panel._GD_DOMAINS) + repr(panel._GD_HOSTS)
        self.assertEqual(RE_V4.findall(src), [], "в разводе записан адрес, а не имя")

    def test_pace_numbers(self):
        self.assertGreaterEqual(float(panel._GD_DRIFT_S), 60.0,
                                "расхождение обязано пережить хотя бы один тик")
        self.assertGreaterEqual(float(panel._GD_APPLY_GAP), float(panel._GD_DRIFT_S),
                                "пересборки чаще, чем допускается само расхождение")
        self.assertGreaterEqual(float(panel._GD_PROBE_TTL), float(panel._GD_DRIFT_S))
        self.assertLessEqual(int(panel._GD_POOL_CAP), 64, "пул щупов не должен разрастись")

    def test_desire_reads_only_its_own_word(self):
        with words(tiktok_warp=True, youtube_warp=True, ru_bypass=True):
            self.assertFalse(panel._gd_want(), "чужое слово не вправе включать развод")
        with words(gemini_direct=True):
            self.assertTrue(panel._gd_want())
        with words(gemini_direct="не число"):
            self.assertTrue(panel._gd_want(), "нечисловое слово — тоже включено, а не падение")
        with words():
            self.assertFalse(panel._gd_want(), "без слова развод выключен (заводской порядок)")


class Egress(unittest.TestCase):
    def test_reads_the_interface_of_the_default_route(self):
        with route_line("default via 192.0.2.1 dev net0 proto dhcp metric 100"):
            self.assertEqual(panel._gd_egress_dev(), ("net0", ""))

    def test_refuses_every_tunnel_interface_it_knows(self):
        for iface in panel._GD_FORBID:
            with route_line("default via 192.0.2.1 dev %s proto kernel" % iface):
                dev, why = panel._gd_egress_dev()
                self.assertEqual(dev, "", iface)
                self.assertTrue(why, iface)

    def test_refuses_loopback(self):
        with route_line("default via 192.0.2.1 dev lo"):
            dev, why = panel._gd_egress_dev()
            self.assertEqual(dev, "")
            self.assertTrue(why)

    def test_refuses_missing_default_route_and_names_the_reason(self):
        with route_line("", rc=1, err="RTNETLINK answers: Network is unreachable"):
            dev, why = panel._gd_egress_dev()
            self.assertEqual(dev, "")
            self.assertIn("маршрута по умолчанию", why)

    def test_refuses_route_without_interface(self):
        with route_line("10.0.0.0/8 via 10.0.0.1 proto kernel scope link src 10.0.0.2"):
            dev, why = panel._gd_egress_dev()
            self.assertEqual(dev, "")
            self.assertTrue(why)

    def test_never_raises_even_when_the_kernel_is_unreadable(self):
        def boom(*a, **k):
            raise OSError("netlink closed")
        with Swap(panel, "_tw_cmd", boom):
            dev, why = panel._gd_egress_dev()
        self.assertEqual(dev, "")
        self.assertTrue(why, "отказ обязан быть назван словом, а не исключением")


class Build(unittest.TestCase):
    """Что ложится в конфиг ядра прокси при сборке — и что не ложится без слова."""

    def test_word_off_leaves_the_build_untouched(self):
        with words(gemini_direct=False, ru_bypass=True), \
                route_line("default via 192.0.2.1 dev net0"), \
                Swap(panel, "_gd_split", lambda *a, **k: 1 / 0):
            cfg = panel._build_xray_cfg({"inbounds": {}})
        self.assertNotIn(panel._GD_TAG, [o["tag"] for o in cfg["outbounds"]])
        self.assertFalse([r for r in cfg["routing"]["rules"]
                          if r.get("outboundTag") == panel._GD_TAG])

    def test_word_on_adds_exactly_one_ring_and_one_rule(self):
        with words(gemini_direct=True), route_line("default via 192.0.2.1 dev net0"):
            cfg = panel._build_xray_cfg({"inbounds": {}})
        rings = [o for o in cfg["outbounds"] if o["tag"] == panel._GD_TAG]
        rules = [r for r in cfg["routing"]["rules"]
                 if r.get("outboundTag") == panel._GD_TAG]
        self.assertEqual(len(rings), 1, len(rings))
        self.assertEqual(len(rules), 1, len(rules))
        self.assertEqual(rings[0]["streamSettings"]["sockopt"]["interface"], "net0")

    def test_rule_stands_above_ru_bypass_because_xray_takes_the_first_match(self):
        with words(gemini_direct=True, ru_bypass=True), \
                route_line("default via 192.0.2.1 dev net0"):
            cfg = panel._build_xray_cfg({"inbounds": {}})
        tags = [r.get("outboundTag") for r in cfg["routing"]["rules"]]
        self.assertIn("direct", tags)
        self.assertLess(tags.index(panel._GD_TAG), tags.index("direct"),
                        "российская витрина не должна успеть первой")

    def test_general_ring_stays_the_fallback(self):
        with words(gemini_direct=True, ru_bypass=True), \
                route_line("default via 192.0.2.1 dev net0"):
            cfg = panel._build_xray_cfg({"inbounds": {}})
        self.assertIn("direct", [o["tag"] for o in cfg["outbounds"]])

    def test_no_egress_interface_builds_a_config_without_the_split(self):
        # Падение в `_build_xray_cfg` означает не «нет развода», а «нет никакого конфига».
        with words(gemini_direct=True, ru_bypass=True), route_line("", rc=1, err="нет пути"):
            cfg = panel._build_xray_cfg({"inbounds": {}})
        self.assertNotIn(panel._GD_TAG, [o["tag"] for o in cfg["outbounds"]])
        self.assertTrue([r for r in cfg["routing"]["rules"] if r.get("outboundTag") == "direct"],
                        "без штатного выхода должен хотя бы оставаться прежний путь")

    def test_split_helper_is_a_noop_without_interface(self):
        obs, rules = [], []
        self.assertFalse(panel._gd_split(obs, rules, ""))
        self.assertEqual((obs, rules), ([], []))
        self.assertTrue(panel._gd_split(obs, rules, "net0"))
        self.assertEqual((len(obs), len(rules)), (1, 1))

    def test_build_survives_an_unreadable_kernel(self):
        # Упадающий сборщик конфига стоил бы панели всякого конфига, а не одного развода.
        def boom(*a, **k):
            raise RuntimeError("ядро молчит")
        with words(gemini_direct=True, ru_bypass=True), Swap(panel, "_tw_cmd", boom):
            cfg = panel._build_xray_cfg({"inbounds": {}})
        self.assertNotIn(panel._GD_TAG, [o["tag"] for o in cfg["outbounds"]])
        self.assertTrue([r for r in cfg["routing"]["rules"] if r.get("outboundTag") == "direct"])


class AppliedTruth(unittest.TestCase):
    """Смотритель верит живому файлу службы, а не замыслу панели (урок #480)."""

    def setUp(self):
        panel._GD_APPLIED_CACHE[0] = 0.0
        panel._GD_APPLIED_CACHE[1] = None

    def tearDown(self):
        panel._GD_APPLIED_CACHE[0] = 0.0
        panel._GD_APPLIED_CACHE[1] = None

    def test_ring_and_rule_read_from_the_live_file(self):
        path = live_file({"outbounds": [ring("net0")], "routing": {"rules": [rule()]}})
        with Swap(panel, "XRAY", path):
            ap = panel._gd_applied(force=True)
        self.assertTrue(ap["read"], ap["error"])
        self.assertTrue(ap["tag"] and ap["rule"])
        self.assertEqual(ap["dev"], "net0")

    def test_ring_without_rule_is_not_applied(self):
        path = live_file({"outbounds": [ring("net0")], "routing": {"rules": []}})
        with Swap(panel, "XRAY", path):
            ap = panel._gd_applied(force=True)
        self.assertTrue(ap["read"])
        self.assertTrue(ap["tag"])
        self.assertFalse(ap["rule"])

    def test_missing_file_is_named_as_unreadable_not_as_absent_ring(self):
        with Swap(panel, "XRAY", os.path.join(TMP, "нет-такого-файла.json")):
            ap = panel._gd_applied(force=True)
        self.assertFalse(ap["read"])
        self.assertTrue(ap["error"])

    def test_broken_file_is_named_and_does_not_raise(self):
        path = os.path.join(TMP, "broken.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{ это не json")
        with Swap(panel, "XRAY", path):
            ap = panel._gd_applied(force=True)
        self.assertFalse(ap["read"])
        self.assertTrue(ap["error"])

    def test_state_without_fields_does_not_raise(self):
        # Ловушка `next()` без значения по умолчанию: StopIteration под `except Exception`
        # превращается в «файл не прочитан», то есть в ложь про живую службу.
        path = live_file({"outbounds": [], "routing": {}})
        with Swap(panel, "XRAY", path):
            ap = panel._gd_applied(force=True)
        self.assertTrue(ap["read"])
        self.assertFalse(ap["tag"])
        self.assertFalse(ap["rule"])

    def test_view_reports_the_file_not_the_memory(self):
        path = live_file({"outbounds": [{"protocol": "freedom", "tag": "direct"}],
                          "routing": {"rules": []}})
        st = os.path.join(TMP, "view-state.json")
        with Swap(panel, "XRAY", path), Swap(panel, "_GD_STATE", st), \
                route_line("default via 192.0.2.1 dev net0"), words(gemini_direct=True):
            v = panel._gd_view()
        self.assertTrue(v["want"], "слово оператора сказано")
        self.assertFalse(v["applied"], "а служба его не имеет — взгляд обязан сказать правду")

    def test_private_material_is_not_read(self):
        for name in ("_gd_applied", "_gd_view", "_gd_probe", "_gd_reapply"):
            src = inspect.getsource(getattr(panel, name))
            self.assertNotIn("private_key", src, name)
            self.assertNotIn("PRIVATE", src, name)


class Drift(unittest.TestCase):
    """Темп пересборки: первое расхождение службу не трогает, устойчивое — ровно одну."""

    def setUp(self):
        self.st = os.path.join(TMP, "drift-%d.json" % len(os.listdir(TMP)))
        self.calls = []
        self.saved_apply_at = panel._GD_APPLY_AT
        panel._GD_APPLY_AT = 0.0
        self.swaps = [Swap(panel, "_GD_STATE", self.st),
                      Swap(panel, "_load", lambda *a, **k: {}),
                      Swap(panel, "_apply_state", lambda s: self.calls.append(1))]
        for s in self.swaps:
            s.__enter__()

    def tearDown(self):
        for s in self.swaps:
            s.__exit__()
        panel._GD_APPLY_AT = self.saved_apply_at
        panel._GD_ERR = ""

    def test_first_observation_waits(self):
        with words(gemini_direct=True):
            msg = panel._gd_reapply({}, "net0", {"tag": False, "rule": False, "dev": ""})
        self.assertIn("жду подтверждения", msg)
        self.assertEqual(self.calls, [], "первое расхождение не вправе дёргать службу")
        st = read_state(self.st)
        self.assertTrue(st.get("drift"))

    def test_sustained_drift_rebuilds_exactly_once(self):
        with words(gemini_direct=True):
            panel._gd_reapply({}, "net0", {"tag": False, "rule": False, "dev": ""})
            st = read_state(self.st)
            st["drift_at"] = int(time.time()) - int(panel._GD_DRIFT_S) - 1
            with open(self.st, "w", encoding="utf-8") as f:
                f.write(json.dumps(st))
            msg = panel._gd_reapply(st, "net0", {"tag": False, "rule": False, "dev": ""})
        self.assertEqual(msg, "", msg)
        self.assertEqual(len(self.calls), 1, len(self.calls))
        self.assertFalse(read_state(self.st).get("drift"))

    def test_cooldown_holds_the_rebuild_back(self):
        panel._GD_APPLY_AT = time.time()          # пересобирали только что
        with words(gemini_direct=True):
            panel._gd_reapply({}, "net0", {"tag": False, "rule": False, "dev": ""})
            st = read_state(self.st)
            st["drift_at"] = int(time.time()) - int(panel._GD_DRIFT_S) - 1
            with open(self.st, "w", encoding="utf-8") as f:
                f.write(json.dumps(st))
            msg = panel._gd_reapply(st, "net0", {"tag": False, "rule": False, "dev": ""})
        self.assertIn("пересоберём на следующем тике", msg)
        self.assertEqual(self.calls, [], "чередь в пять минут не промах, а защита подписчиков")

    def test_sneaky_drift_change_starts_the_clock_again(self):
        with words(gemini_direct=True):
            panel._gd_reapply({}, "net0", {"tag": False, "rule": False, "dev": ""})
            st = read_state(self.st)
            st["drift_at"] = int(time.time()) - int(panel._GD_DRIFT_S) - 1
            # сменился штатный выход: старое расхождение пережито, новое — ещё нет
            msg = panel._gd_reapply(st, "net1", {"tag": False, "rule": False, "dev": ""})
        self.assertIn("жду подтверждения", msg)
        self.assertEqual(self.calls, [], "сменившееся расхождение не вправе пересобирать сразу")

    def test_orphan_ring_after_the_word_is_off(self):
        with words(gemini_direct=False):
            panel._gd_reapply({}, "", {"tag": True, "rule": True, "dev": "net0"})
            st = read_state(self.st)
            st["drift_at"] = int(time.time()) - int(panel._GD_DRIFT_S) - 1
            with open(self.st, "w", encoding="utf-8") as f:
                f.write(json.dumps(st))
            msg = panel._gd_reapply(st, "", {"tag": True, "rule": True, "dev": "net0"})
        self.assertEqual(msg, "", msg)
        self.assertEqual(len(self.calls), 1, "осиротевшее кольцо обязано быть снято")

    def test_agreement_needs_no_rebuild(self):
        with words(gemini_direct=True):
            msg = panel._gd_reapply({}, "net0", {"tag": True, "rule": True, "dev": "net0"})
        self.assertEqual(msg, "", msg)
        self.assertEqual(self.calls, [])

    def test_failed_rebuild_is_named_not_swallowed(self):
        def boom(s):
            raise RuntimeError("xray run -test отверг конфиг")
        with words(gemini_direct=True), Swap(panel, "_apply_state", boom):
            panel._gd_reapply({}, "net0", {"tag": False, "rule": False, "dev": ""})
            st = read_state(self.st)
            st["drift_at"] = int(time.time()) - int(panel._GD_DRIFT_S) - 1
            with open(self.st, "w", encoding="utf-8") as f:
                f.write(json.dumps(st))
            msg = panel._gd_reapply(st, "net0", {"tag": False, "rule": False, "dev": ""})
        self.assertIn("не пересобран", msg, msg)
        self.assertIn("xray", msg.lower(), msg)

    def test_the_split_never_touches_kernel_routing(self):
        for name in ("_gd_tick", "_gd_reapply", "_gd_probe", "_gd_probe_bg", "_gd_view"):
            src = inspect.getsource(getattr(panel, name))
            for banned in ("ip rule", "ip link", "systemctl", "nft ", "wg set",
                           'route add', "route replace", "_yw_up", "_tw_up"):
                self.assertNotIn(banned, src, "%s: %s" % (name, banned))


class Wiring(unittest.TestCase):
    def setUp(self):
        self.ui = read("index.html")
        self.py = read("panel.py")
        a, b = self.ui.find("id=setGemini"), self.ui.find("id=setFront443")
        self.card = self.ui[a:b] if a != -1 and b > a else ""

    def test_card_sits_between_the_youtube_window_and_the_front(self):
        self.assertTrue(self.card, "карточки развода нет")
        self.assertLess(self.ui.find("id=setYouTube"), self.ui.find("id=setGemini"))
        self.assertLess(self.ui.find("id=setGemini"), self.ui.find("id=setFront443"))

    def test_card_has_its_own_organs(self):
        for organ in ("id=gdState", "id=gdOn", "id=gdCheckBtn", "id=gdMsg"):
            self.assertIn(organ, self.card, organ)

    def test_card_is_reachable_and_guarded(self):
        self.assertIn("setJump('setGemini')", self.ui)
        self.assertIn('setGemini:"settings"', self.ui)
        self.assertIn("loadGemini()", self.ui[self.ui.find("dataset.tab==='settings'"):])

    def test_both_routes_exist_and_the_refusal_is_worded(self):
        self.assertEqual(self.py.count('p == "/api/gemini_direct"'), 2,
                         "ход только в одну сторону")
        # ход зовётся из скрипта, а не из разметки карточки: судим всю морду целиком
        self.assertGreaterEqual(self.ui.count("/api/gemini_direct"), 3,
                                "у карточки меньше ходов, чем у панели")
        post = self.py[self.py.rfind('p == "/api/gemini_direct"'):][:3000]
        self.assertIn("развод не включается", post,
                      "без штатного выхода отказ обязан быть назван")
        self.assertIn("нужно поле on или check", post)

    def test_the_word_stays_said_if_the_rebuild_fails(self):
        post = self.py[self.py.rfind('p == "/api/gemini_direct"'):][:3000]
        self.assertLess(post.find('CFG_CACHE["gemini_direct"] = want'),
                        post.find("_apply_state(_load(STATE))"),
                        "слово ставится до пересборки: отказ обязан быть пережит смотрителем")
        self.assertIn('"Xray: "', post, "отказ пересборки называется в этом же ответе")

    def test_watcher_and_selfcheck_are_wired(self):
        self.assertIn('(_gd_tick, "gemini-split")', self.py)
        self.assertGreaterEqual(self.py.count('add("gemini_direct"'), 5,
                                "нога самопроверки судит меньше веток, чем есть")
        self.assertIn("Gemini в обход окна YouTube", self.py)

    def test_selfcheck_does_not_call_a_half_measure_green(self):
        leg = self.py[self.py.find('add("gemini_direct"'):]
        leg = leg[:leg.find("\n    # #180")]
        self.assertIn('rs != "RU"', leg, "зелёным считается только ответ НЕ российской страны")
        self.assertIn('rs == "RU"', leg, "Россия при сказанном слове — красное, а не жёлтое")
        self.assertIn('gv["read"]', leg, "непрочитанный живой конфиг — не зелёный")
        self.assertIn('gv["applied"]', leg, "развод в памяти панели — не развод службы")

    def test_card_names_the_boundary_it_cannot_cross(self):
        self.assertIn("Веерные входы", self.card)
        self.assertIn("не могут в принципе", self.card)
        self.assertIn("число таких подписчиков", self.card)
        self.assertIn("kernel_clients", self.py)

    def test_card_tells_measured_numbers_and_pins_no_country(self):
        for phrase in ("56 адресов сервиса из 56", "переживёт два тика",
                       "живой файл конфигурации", "ни одного правила"):
            self.assertIn(phrase, self.card, phrase)
        for pinned in ("Финляндия", "Швеция", "Германия", "Нидерланды"):
            self.assertNotIn(pinned, self.card, pinned)

    def test_split_touches_no_subscriber_material(self):
        block = self.py[self.py.find("# ---------- #503"):self.py.find("# ---------- #384/#385")]
        self.assertTrue(block, "кусок развода не найден в файле")
        for banned in ("token", "password", "private_key", "_sub_", "qr"):
            self.assertNotIn(banned, block, banned)

    def test_window_its_untouched(self):
        # Развод не имеет права передвинуть ни одного числа окна «YouTube».
        self.assertEqual(panel._YW_IF, "ytw0")
        self.assertEqual(panel._YW_TBL, "205")
        self.assertEqual(int(panel._YW_PRIO_BASE), 600)
        self.assertEqual(panel._TW_TBL, "204")
        self.assertEqual(panel._GD_TAG, "gemini-direct")
        self.assertNotIn(panel._GD_TAG, str(panel._YW_AGG))


class DesireBoundary(unittest.TestCase):
    def test_kernel_clients_counts_live_clients_only(self):
        st = {"inbounds": {"wireguard": {"clients": [{"id": "a"}, {"id": "b"}]},
                           "amneziawg": {"clients": [{"id": "c"}]},
                           "vless-real": {"clients": [{"id": "d"}] * 9}}}
        with Swap(panel, "_load", lambda *a, **k: st):
            self.assertEqual(panel._gd_kernel_clients(), 3)
        st["inbounds"]["amneziawg"]["disabled"] = True
        with Swap(panel, "_load", lambda *a, **k: st):
            self.assertEqual(panel._gd_kernel_clients(), 2,
                             "снятый вход не вправе считаться живой дырой")

    def test_kernel_clients_falls_back_to_none_instead_of_lying(self):
        def boom(*a, **k):
            raise OSError("состояние не читается")
        with Swap(panel, "_load", boom):
            self.assertIsNone(panel._gd_kernel_clients())

    def test_probe_pool_is_capped(self):
        src = inspect.getsource(panel._gd_pool)
        self.assertIn("_GD_POOL_CAP", src)
        self.assertLessEqual(len(panel._GD_HOSTS), int(panel._GD_POOL_CAP))


if __name__ == "__main__":
    unittest.main(verbosity=2)
