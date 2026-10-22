# -*- coding: utf-8 -*-
"""Рубильник «Публиковать AAAA» дошёл до зоны Cloudflare, а не до решения панели.

Прежний хранитель выпушенных имён умел только dynv6. На машине, где DNS живёт в
Cloudflare, он не делал ровным счётом ничего: подъём рубильника менял РЕШЕНИЕ
панели, до зоны дело не доходило, и v6-клиенты продолжали ехать через NAT64
провайдера. Боевой промер 22.10 назвал число — нуль выпушенных записей из
тринадцати wanted имён. Цикл #499 добавляет ровно этот шаг.

Границы этого шага судятся прибором отдельно, потому что каждая из них стоила
кому-то связи: A-записи не трогаются (судиться с чужой A хранителю нечем), под
проксированием имя не трогается вовсе (адресата решает оператор-фронт), AAAA без
A не создаётся (имя повелось бы в семейство, где его нет), `wg`-эндпоинт обязан
оставаться A-only (мобильный IPv6 рвёт WG-сессию). Осиротевшая шестёрка у такого
имени снимается, а не оставляется.

Второй прибор судит локальную пробу семейства: строка `listen [::]:<порт>` на ядре
без IPv6 роняет ВЕСЬ nginx — вместе с v4-фасадом, маской и веб-фронтом, поэтому
право публиковать не может стоить работоспособности узла и решает только факт
привязки.

Настоящая зона не дёргается: весь ввод-вывод идёт через подменённые `_cf_api`,
`_cf_zone` и `_dynv6_*`.
"""
import types
import unittest

from _support import panel_module

ZONE = "example.test"
ZID = "zone-1"
IP4 = "198.51.100.10"        # TEST-NET-2 — документальный диапазон
IP6 = "2001:db8::1"          # RFC 3849 — наружу не маршрутизируется
STALE = "2001:db8::dead"
VPN = "vpn." + ZONE
TG = "tg." + ZONE
WG = "wg." + ZONE


def A(name, proxied=False):
    return {"id": "a-" + name, "type": "A", "name": name, "content": IP4,
            "proxied": proxied}


def SIX(name, content=IP6, rid=None):
    return {"id": rid or ("six-" + name), "type": "AAAA", "name": name,
            "content": content, "proxied": False}


class Zone:
    """Эмулятор зоны Cloudflare: держит записи и честно исполняет GET/POST/DELETE."""

    def __init__(self, recs, boom=None):
        self.recs = [dict(r) for r in recs]
        self.boom = boom
        self.calls = []

    def api(self, method, path, body=None):
        self.calls.append((method, path.split("?")[0], body))
        if self.boom:
            raise RuntimeError(self.boom)
        if method == "GET":
            return [dict(r) for r in self.recs]
        if method == "POST":
            row = dict(body)
            row["id"] = "made-%s-%s" % (row.get("type"), row.get("name"))
            self.recs.append(row)
            return row
        if method == "DELETE":
            rid = path.rstrip("/").rsplit("/", 1)[-1]
            self.recs = [r for r in self.recs if r.get("id") != rid]
            return {"id": rid}
        raise AssertionError("неожиданный метод %s" % method)

    def kinds(self, name):
        return sorted(r["type"] for r in self.recs if r["name"] == name)

    def content(self, name, typ):
        return [r["content"] for r in self.recs if r["name"] == name and r["type"] == typ]

    def writes(self):
        return [c for c in self.calls if c[0] in ("POST", "DELETE")]


class CfLegTest(unittest.TestCase):
    """Нога `_veil_ip6_guard_cf`: что ставится, что снимается, чего не трогают."""

    def setUp(self):
        self.panel = panel_module()
        p = self.panel
        self._saved = {}
        for name in ("_cf_api", "_cf_zone", "_ip6_to_publish", "_wg_auto_domain", "_audit"):
            self._saved[name] = getattr(p, name)
        self._guard = dict(p._VEIL_GUARD)
        self.audit = []
        p._cf_zone = lambda: (ZID, ZONE)
        p._wg_auto_domain = lambda: WG
        p._ip6_to_publish = lambda: IP6
        p._audit = lambda ev, **kw: self.audit.append((ev, kw))

    def tearDown(self):
        for name, v in self._saved.items():
            setattr(self.panel, name, v)
        self.panel._VEIL_GUARD.clear()
        self.panel._VEIL_GUARD.update(self._guard)

    def run_leg(self, recs, names, ip6=IP6, boom=None):
        z = Zone(recs, boom=boom)
        self.panel._cf_api = z.api
        self.panel._ip6_to_publish = lambda: ip6
        got = self.panel._veil_ip6_guard_cf(names)
        return z, got

    def test_aaaa_lives_beside_a(self):
        z, got = self.run_leg([A(VPN), A(TG)], [VPN, TG])
        self.assertEqual(sorted(got), sorted([VPN, TG]), got)
        self.assertEqual(z.content(VPN, "AAAA"), [IP6])
        self.assertEqual(z.content(TG, "AAAA"), [IP6])

    def test_a_records_never_touched(self):
        z, _ = self.run_leg([A(VPN), A(TG), SIX(TG, STALE)], [VPN, TG])
        for meth, path, body in z.calls:
            if meth == "DELETE":
                self.assertFalse(path.endswith("/a-" + VPN), "панель сняла чужую A-запись")
            if meth == "POST":
                self.assertNotEqual((body or {}).get("type"), "A", "панель выпускает A")
        self.assertEqual(z.content(VPN, "A"), [IP4])
        self.assertEqual(z.content(TG, "A"), [IP4])

    def test_stale_aaaa_is_replaced_not_doubled(self):
        # живая причина: адрес шестёрки меняется с ротацией, и если верную запись
        # ищут, но почерневшую не снимают, имя начинает нести два адреса
        z, got = self.run_leg([A(VPN), SIX(VPN, STALE)], [VPN])
        self.assertEqual(got, [VPN])
        self.assertEqual(z.content(VPN, "AAAA"), [IP6], z.recs)
        self.assertNotIn(STALE, [r["content"] for r in z.recs])

    def test_proxied_name_left_alone(self):
        z, got = self.run_leg([A(VPN, proxied=True), SIX(VPN, STALE)], [VPN])
        self.assertEqual(got, [], "под проксированием адресата решает фронт, не панель")
        self.assertEqual(z.writes(), [], "оранжевое имя тронули")
        self.assertIn(VPN, self.panel._VEIL_GUARD["ip6_skipped"])

    def test_aaaa_without_a_not_created(self):
        z, got = self.run_leg([], [VPN])
        self.assertEqual(got, [])
        self.assertEqual(z.writes(), [])
        self.assertIn(VPN, self.panel._VEIL_GUARD["ip6_skipped"],
                      "пропуск обязан быть назван, а не молча промолчан")

    def test_wg_endpoint_is_a_only(self):
        z, got = self.run_leg([A(WG), SIX(WG), A(VPN)], [WG, VPN])
        self.assertEqual(got, [VPN], "wg-эндпоинту не положена шестёрка")
        self.assertEqual(z.kinds(WG), ["A"], "мобильная WG-сессия под шестёркой рвётся")
        self.assertIn(WG, self.panel._VEIL_GUARD["ip6_dropped"])

    def test_second_pass_creates_nothing(self):
        z, _ = self.run_leg([A(VPN), A(TG)], [VPN, TG])
        writes = len(z.writes())
        self.assertTrue(writes)
        z2, got2 = self.run_leg(z.recs, [VPN, TG])
        self.assertEqual(got2, [], "повторный проход выпускает дубль")
        self.assertEqual(z2.writes(), [])
        self.assertEqual(len(z2.content(VPN, "AAAA")), 1)

    def test_duplicate_aaaa_cleaned_correct_kept(self):
        z, got = self.run_leg([A(VPN), SIX(VPN), SIX(VPN, STALE, rid="six-dup")], [VPN])
        self.assertEqual(got, [], "верная запись есть — выпускать нечего")
        self.assertEqual(z.content(VPN, "AAAA"), [IP6], z.recs)
        self.assertNotIn("six-dup", [r["id"] for r in z.recs])

    def test_lever_off_removes_every_aaaa(self):
        z, got = self.run_leg([A(VPN), SIX(VPN), A(TG)], [VPN, TG], ip6="")
        self.assertEqual(got, [])
        self.assertEqual(z.kinds(VPN), ["A"], "выключенный рубильник оставил шестёрку")
        self.assertIn(VPN, self.panel._VEIL_GUARD["ip6_dropped"])

    def test_zone_read_once_per_pass(self):
        z, _ = self.run_leg([A(VPN), A(TG)], [VPN, TG])
        gets = [c for c in z.calls if c[0] == "GET"]
        self.assertEqual(len(gets), 1, gets)

    def test_provider_failure_is_named_not_silent(self):
        z, got = self.run_leg([A(VPN)], [VPN], boom="HTTP 503")
        self.assertEqual(got, [])
        self.assertIn("503", self.panel._VEIL_GUARD["error"])
        self.assertEqual(self.panel._VEIL_GUARD["ip6_created"], "",
                         "панель рапортует о выпуске, которого не было")
        self.assertEqual(z.calls, [("GET", "/zones/%s/dns_records" % ZID, None)], z.calls)

    def test_state_and_audit_carry_the_provider(self):
        self.run_leg([A(VPN)], [VPN])
        self.assertEqual(self.panel._VEIL_GUARD["checked"], 1)
        self.assertIn(VPN, self.panel._VEIL_GUARD["ip6_created"])
        self.assertEqual(self.audit[0][0], "veil_names_guard")
        self.assertEqual(self.audit[0][1]["provider"], "cloudflare")


class GuardDispatchTest(unittest.TestCase):
    """Развилка хранителя: облачная зона не зовёт динамическую базу и наоборот."""

    def setUp(self):
        self.panel = panel_module()
        p = self.panel
        self._saved = {}
        for name in ("_cf_api", "_cf_zone", "_ip6_to_publish", "_wg_auto_domain", "_audit",
                     "_veil_provider", "_veil_base", "_veil_names_wanted", "_mv_locked",
                     "_dynv6_conf", "_dynv6_ensure_host", "_resolve_ips", "_DDNS",
                     "_our_ips"):
            self._saved[name] = getattr(p, name)
        self._guard = dict(p._VEIL_GUARD)
        self.d6 = []
        p._cf_zone = lambda: (ZID, ZONE)
        p._wg_auto_domain = lambda: WG
        p._ip6_to_publish = lambda: IP6
        p._audit = lambda *a, **k: None
        p._mv_locked = lambda: False
        p._veil_base = lambda: ZONE
        p._veil_names_wanted = lambda: [VPN, TG]
        p._dynv6_conf = lambda: {"token": "t", "host": ZONE}
        p._dynv6_ensure_host = lambda *a, **k: self.d6.append((a, k))

    def tearDown(self):
        for name, v in self._saved.items():
            setattr(self.panel, name, v)
        self.panel._VEIL_GUARD.clear()
        self.panel._VEIL_GUARD.update(self._guard)

    def test_cloudflare_zone_does_not_touch_dynv6(self):
        z = Zone([A(VPN), A(TG)])
        self.panel._cf_api = z.api
        self.panel._veil_provider = lambda base=None: "cloudflare"
        got = self.panel._veil_names_guard()
        self.assertEqual(sorted(got), sorted([VPN, TG]), got)
        self.assertEqual(self.d6, [], "облачная нога полезла в динамическую базу")
        self.assertEqual(self.panel._VEIL_GUARD["provider"], "cloudflare")

    def test_dynv6_zone_does_not_touch_cloudflare(self):
        self.panel._veil_provider = lambda base=None: "dynv6"
        self.panel._resolve_ips = lambda nm, **k: {IP4}
        self.panel._DDNS = {"ipv4": IP4, "ipv6": IP6}
        calls = []
        self.panel._cf_api = lambda m, pth, b=None: calls.append((m, pth))
        self.panel._dynv6_ensure_host = lambda *a, **k: (calls.append(("dynv6", a)), True)[1]
        self.panel._veil_names_guard()
        self.assertEqual([c for c in calls if c[0] in ("GET", "POST", "DELETE")], [])

    def test_nothing_wanted_reports_reason(self):
        self.panel._veil_provider = lambda base=None: "cloudflare"
        self.panel._veil_names_wanted = lambda: []
        z = Zone([])
        self.panel._cf_api = z.api
        self.assertEqual(self.panel._veil_names_guard(), [])
        self.assertIn("развилка", self.panel._VEIL_GUARD["skipped"])
        self.assertEqual(z.calls, [], "держать нечего, а зону всё равно дёрнули")


class V6BindableTest(unittest.TestCase):
    """Проба семейства (#499): решение кладёт в nginx факт привязки, а не мнение."""

    def setUp(self):
        self.panel = panel_module()
        self._saved = (self.panel.socket, dict(self.panel._V6_BIND))
        self.log = []

    def tearDown(self):
        self.panel.socket, snap = self._saved[0], self._saved[1]
        self.panel._V6_BIND.clear()
        self.panel._V6_BIND.update(snap)

    def fake_socket(self, boom=False):
        log = self.log

        class _S:
            def bind(self, addr):
                log.append(addr)

            def close(self):
                log.append("close")

        def make(fam, typ):
            log.append((fam, typ))
            if boom:
                raise OSError("семейство не поддерживается")
            return _S()

        return types.SimpleNamespace(AF_INET6=10, SOCK_DGRAM=2, socket=make)

    def test_probe_is_a_probe(self):
        self.panel.socket = self.fake_socket()
        self.panel._V6_BIND.update(ok=None, ts=0.0)
        self.assertIs(self.panel._v6_bindable(), True)
        self.assertIn(("::", 0), self.log, "привязки к `[::]` не было — это не проба")
        self.assertIn("close", self.log, "сокет не закрыт")
        self.assertIs(self.panel._V6_BIND["ok"], True)
        self.assertGreater(float(self.panel._V6_BIND["ts"] or 0), 0)

    def test_fresh_verdict_is_cached(self):
        self.panel.socket = self.fake_socket()
        self.panel._V6_BIND.update(ok=None, ts=0.0)
        self.panel._v6_bindable()
        n = len(self.log)
        self.panel._v6_bindable()
        self.assertEqual(len(self.log), n, "свежий вердикт перемеряется на каждый проход")

    def test_kernel_without_family_refuses_quietly(self):
        self.panel.socket = self.fake_socket(boom=True)
        self.panel._V6_BIND.update(ok=None, ts=0.0)
        self.assertIs(self.panel._v6_bindable(), False,
                      "отказ ядра обязан быть назван отказом, а не исключением")
        self.assertIs(self.panel._V6_BIND["ok"], False)

    def test_stale_cache_is_remeasured(self):
        self.panel.socket = self.fake_socket()
        self.panel._V6_BIND.update(ok=True, ts=self.panel.time.time() - 3600)
        self.assertIs(self.panel._v6_bindable(), True)
        self.assertIn(("::", 0), self.log, "протухший вердикт принят без перемера")

    def test_real_kernel_gives_a_bool(self):
        # на живой машине проба обязана отвечать числом-да/нет, а не формой
        self.panel._V6_BIND.update(ok=None, ts=0.0)
        self.assertIsInstance(self.panel._v6_bindable(), bool)


if __name__ == "__main__":
    unittest.main()
