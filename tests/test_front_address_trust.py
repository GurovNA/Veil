"""Два стоп-крана, которых в панели не было: память сетей абонента и адрес фронта.

`#500`. Широкий автобан наблюдателя (`/24` сеткой и веером) резал живых людей: по
узору полуоткрытых соединений абонент оператора связи неотличим от фермы ключей, а
ферма ключей не имеет ни одной подписки. Панель теперь помнит СЕТЬ каждого принятого
сеанса (`/24` для четвёрки, `/64` для шестёрки) и умеет спросить, сколько сетей
подписчика попадает в префикс: ноль — банить нечего, больше нуля — широкого бана не
будет, а более узкие останутся своими ногами.

`#501`. За добавленный фронт (RU-вход, через который подписчики доходят до бэка)
панель не отвечала ничем: один адрес фронта попадал под `SYN`-лимит и под баны всех
ступеней, а перепись устройств заводила на него строку «устройство» — то есть за
весь пул подписчиков судил один человек. Адрес фронта стал доверенным источником:
он «свой» (не лимитируется и обслуживается мимо туннеля), не банится ни одиночным
адресом, ни префиксом, который его накрывает, и не заводит строк в переписи.

Прибор судит НАСТОЯЩИЙ код панели. Боевые файлы прогон не трогает: каждый путь
перенесён в песочницу, а в `tearDown` сверяется, что живые `hops.json`,
`subs_seen.json` и `bans.json` остались теми же байтами, что и до ноги.
"""
import ipaddress
import io
import datetime
import json
import os
import contextlib
import tempfile
import time
import unittest

from _support import panel_module

panel = panel_module()

FRONT = "192.0.2.44"             # адрес добавленного фронта
FRONT_GRID = "192.0.2.0/24"      # сетка наблюдателя, внутри которой сидит фронт
FRONT_WIDE = "192.0.2.0/23"      # шире сетки: тот же фронт накрывается и ею
FRONT6 = "2001:db8::5"
OTHER_GRID = "198.51.100.0/24"   # соседняя сетка — фронта в ней нет
NEIGHBOR = "192.0.2.86"          # сосед фронта по сетке — самый обычный абонент
HOST_FRONT = "192.0.2.61"        # то, во что разрезолвился публичный хост ссылок
SUB4 = "203.0.113.77"            # сеть абонента (TEST-NET-3)
SUB4_NET = "203.0.113.0/24"      # та же сеть целиком — именно её и помнит память
SUB4_WIDE = "203.0.113.0/16"     # предок сети: бан по нему резал бы того же абонента
SUB6 = "2001:db8:abcd:12::9"
STRAY = "192.0.2.9"              # адрес вне всякого фронта
UA = "v2rayNG/1.11.28"

# живые файлы коробки, которым прогон не имеет права менять байты
LIVE = ["/opt/vpnpanel/hops.json", "/opt/vpnpanel/subs_seen.json",
        "/opt/vpnpanel/bans.json", "/opt/vpnpanel/sub_devices.json"]


def _iso(ts):
    """Метка переписи устройств: тот же почерк UTC, что пишет панель."""
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat(
        timespec="seconds")


def stamp(path):
    try:
        with open(path, "rb") as f:
            return (os.path.getsize(path), hash(f.read()))
    except Exception:
        return None


class Sandbox(unittest.TestCase):
    """Общее: песочница вместо боевых путей и сверка, что боевое не тронуто."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.before = {p: stamp(p) for p in LIVE}
        self.saved = {}

    def keep(self, name, value=None):
        self.saved.setdefault(name, getattr(panel, name))
        if value is not None:
            setattr(panel, name, value)

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(panel, name, value)
        self.tmp.cleanup()
        for path, was in self.before.items():
            self.assertEqual(stamp(path), was,
                             "нога тронула живой файл: " + path)


class LedgerOfSubscriberNets(Sandbox):
    def setUp(self):
        super().setUp()
        self.keep("_SUBS_SEEN_FILE", os.path.join(self.tmp.name, "subs_seen.json"))
        self.keep("_SUBDEV_FILE", os.path.join(self.tmp.name, "sub_devices.json"))
        self.keep("_SUBS_SEEN", None)
        self.keep("_SUBDEV", {})

    def test_setka_chetvyorki_i_shestyorki(self):
        self.assertEqual(panel._subs_seen_net(SUB4), "203.0.113.0/24")
        self.assertEqual(panel._subs_seen_net("203.0.113.1"), "203.0.113.0/24")
        # шестёрка судится ЗНАЧЕНИЕМ, а не почерком: размер префикса — вот мера
        self.assertEqual(ipaddress.ip_network(panel._subs_seen_net(SUB6)),
                         ipaddress.ip_network("2001:db8:abcd:12::/64"))
        self.assertTrue(panel._subs_seen_net(SUB6).endswith("/64"))

    def test_derazbiramyj_adres_ne_setka(self):
        for bad in ("", None, "не адрес", "203.0.113.999", SUB4 + "/24"):
            self.assertEqual(panel._subs_seen_net(bad), "", bad)

    def test_setka_pomnitsya_odin_raz_za_minutu(self):
        now = time.time()
        self.assertTrue(panel._subs_seen_note(SUB4, now))
        self.assertFalse(panel._subs_seen_note(SUB4, now + 5))
        self.assertTrue(panel._subs_seen_note(SUB4, now + 61))
        self.assertEqual(list(panel._subs_seen_load()), ["203.0.113.0/24"])

    def test_semji_ne_slivayutsya(self):
        panel._subs_seen_note(SUB4)
        panel._subs_seen_note(SUB6)
        self.assertEqual({ipaddress.ip_network(k) for k in panel._subs_seen_load()},
                         {ipaddress.ip_network("203.0.113.0/24"),
                          ipaddress.ip_network("2001:db8:abcd:12::/64")})

    def test_odinakovy_set_raznym_pocherkom(self):
        # один и тот же адрес, записанный по-разному, — одна сеть и одна отметка:
        # на разном почерке стоп-кран не плодит дублей и не считает сеть дважды
        panel._subs_seen_note("2001:DB8:abcd:12::9", time.time())
        panel._subs_seen_note("2001:0db8:abcd:0012::9", time.time())
        self.assertEqual(len(panel._subs_seen_load()), 1)
        self.assertEqual(panel._subs_live_in("2001:db8:abcd:12::/64"), 1)
        self.assertEqual(panel._subs_live_in("2001:db8::/32"), 1)

    def test_mera_popadaet_v_set_i_v_predok(self):
        panel._subs_seen_note(SUB4)
        panel._subs_seen_note("203.0.113.8")
        panel._subs_seen_note("198.51.100.4")
        self.assertEqual(panel._subs_live_in(SUB4_NET), 1)
        self.assertEqual(panel._subs_live_in(SUB4_WIDE), 1)
        self.assertEqual(panel._subs_live_in(OTHER_GRID), 1)
        # часть сети — не предок: мерить бан по /25, когда абонент сидит в /24, нечем
        self.assertEqual(panel._subs_live_in("203.0.113.128/25"), 0)
        self.assertEqual(panel._subs_live_in(FRONT_GRID), 0)
        # самый широкий предок — весь мир — считает обе сети отдельно, а не одну строку
        self.assertEqual(panel._subs_live_in("0.0.0.0/0"), 2)

    def test_okno_zhivosti_korchestoka(self):
        panel._SUBS_SEEN = {"203.0.113.0/24": time.time() - 31 * 86400}
        self.assertEqual(panel._subs_live_in("203.0.113.0/24"), 0)
        self.assertEqual(panel._subs_live_in("203.0.113.0/24", 32 * 86400), 1)

    def test_pervogo_zapuska_hvataet_perepisi(self):
        # перепись ленивая: на первом обращении её в памяти нет вовсе, поэтому
        # загрузка памяти сетей обязана звать ЗАГРУЗЧИК, а не глобальный словарь.
        # Полумера — читать память — на живой коробке и провалилась: файл памяти
        # завёлся с одной сетью вместо трёх десятков переписанных
        self.keep("_SUBPREF_FILE", os.path.join(self.tmp.name, "sub_prefs.json"))
        panel._SUBDEV = None
        panel._SUBPREF = None
        with open(panel._SUBDEV_FILE, "w", encoding="utf-8") as f:
            json.dump({"tok": [{"ip": SUB4, "last_ts": _iso(time.time()),
                               "ips": [NEIGHBOR, "мусор"]}]}, f)
        panel._SUBS_SEEN = None
        nets = sorted(panel._subs_seen_load())
        self.assertEqual(nets, ["192.0.2.0/24", SUB4_NET])

    def test_nepolnyj_fayl_dolivayet_perepisi(self):
        # боевая природа: файл памяти завёлся ОДНОЙ сетью, а перепись несла три
        # десятка. Доливка только при пустом файле означала, что неполная память
        # остаётся неполной навсегда и стоп-кран судит по одному свидетелю
        self.keep("_SUBPREF_FILE", os.path.join(self.tmp.name, "sub_prefs.json"))
        file_ts = time.time() - 10
        with open(panel._SUBS_SEEN_FILE, "w", encoding="utf-8") as f:
            json.dump({SUB4_NET: file_ts}, f)
        with open(panel._SUBDEV_FILE, "w", encoding="utf-8") as f:
            json.dump({"tok": [{"ip": SUB4, "last_ts": _iso(time.time() - 5 * 86400)},
                               {"ip": NEIGHBOR, "last_ts": _iso(time.time() - 2 * 86400)}]},
                      f)
        panel._SUBDEV = None
        panel._SUBPREF = None
        panel._SUBS_SEEN = None
        d = panel._subs_seen_load()
        self.assertEqual(sorted(d), ["192.0.2.0/24", SUB4_NET])
        # метка файла свежее метки переписи — черстветь ей не от чего
        self.assertAlmostEqual(d[SUB4_NET], file_ts, places=3)
        self.assertEqual(panel._subs_live_in(FRONT_GRID), 1)

    def test_stroka_perepisi_ne_ozhivaet_mertvuyu_set(self):
        # перепись не вправе врать о свежести: сеть, откуда последний сеанс был
        # дольше квартала назад, остаётся забытой, а не рождается заново
        self.keep("_SUBPREF_FILE", os.path.join(self.tmp.name, "sub_prefs.json"))
        with open(panel._SUBDEV_FILE, "w", encoding="utf-8") as f:
            json.dump({"tok": [{"ip": SUB4, "last_ts": _iso(time.time() - 91 * 86400)}]}, f)
        panel._SUBDEV = None
        panel._SUBPREF = None
        panel._SUBS_SEEN = None
        self.assertEqual(panel._subs_seen_load(), {})
        self.assertEqual(panel._subs_live_in(SUB4_NET), 0)

    def test_fayl_pamyati_chitaemyj(self):
        panel._subs_seen_note(SUB4)
        panel._subs_seen_save()
        with open(panel._SUBS_SEEN_FILE, encoding="utf-8") as f:
            self.assertEqual(list(json.load(f)), ["203.0.113.0/24"])
        panel._SUBS_SEEN = None
        self.assertEqual(panel._subs_live_in("203.0.113.0/24"), 1)

    def test_slomyj_fayl_ne_reshaet_za_stopkran(self):
        with open(panel._SUBS_SEEN_FILE, "w", encoding="utf-8") as f:
            f.write("{ не json")
        panel._SUBS_SEEN = None
        self.assertEqual(panel._subs_live_in("203.0.113.0/24"), 0)
        self.assertTrue(panel._subs_seen_note(SUB4))


class FrontIsTrustedSource(Sandbox):
    def setUp(self):
        super().setUp()
        self.keep("HOPS_FILE", os.path.join(self.tmp.name, "hops.json"))
        self.keep("_SUBS_SEEN_FILE", os.path.join(self.tmp.name, "subs_seen.json"))
        self.keep("_SUBDEV_FILE", os.path.join(self.tmp.name, "sub_devices.json"))
        self.keep("BANS_FILE", os.path.join(self.tmp.name, "bans.json"))
        self.keep("BANS", {})
        self.keep("_SUBS_SEEN", None)
        self.keep("_SUBDEV", {})
        self.keep("CFG_CACHE", dict(panel.CFG_CACHE))
        panel.CFG_CACHE["hop_public_host"] = ""
        panel.CFG_CACHE["panel_domain"] = ""
        self.nft = []
        self.audit = []
        self.keep("_f2b_nft", lambda *a: self.nft.append(a))
        self.keep("_bans_save", lambda: None)
        self.keep("_audit", lambda *a, **k: self.audit.append((a, k)))
        self.keep("_ssh_keep", lambda *a, **k: (True, set(), set()))
        self.keep("_pub_ip4", lambda: "203.0.113.7")
        self.keep("_pub_ip6", lambda: "")
        self.keep("_DDNS", {"ipv4": "", "ipv6": ""})
        self.keep("_wg_auto_domain", lambda: "")
        self.keep("_OWN_IP_CACHE", {"cidrs": None, "ts": 0.0})
        self.hop_cache = dict(panel._HOP_FRONT)
        self._front([{"front_ip": FRONT}])

    def tearDown(self):
        panel._HOP_FRONT["ips"] = self.hop_cache.get("ips")
        panel._HOP_FRONT["ts"] = self.hop_cache.get("ts")
        super().tearDown()

    def _front(self, hops):
        with open(panel.HOPS_FILE, "w", encoding="utf-8") as f:
            json.dump(hops, f)
        panel._hop_front_flush()

    def test_adres_i_setka_nakryvayut_front(self):
        self.assertEqual(panel._front_covered(FRONT), FRONT)
        self.assertEqual(panel._front_covered(FRONT + "/32"), FRONT)
        self.assertEqual(panel._front_covered(FRONT_GRID), FRONT)
        self.assertEqual(panel._front_covered(FRONT_WIDE), FRONT)
        self.assertEqual(panel._front_covered("2001:db8::/32"), "")

    def test_chuzhoj_adres_i_musor_molchat(self):
        for bad in (STRAY, "", None, "не адрес", "192.0.2.0/33", FRONT6,
                    OTHER_GRID):
            self.assertEqual(panel._front_covered(bad), "", repr(bad))

    def test_semji_adresov_ne_putayutsya(self):
        self._front([{"front_ip": FRONT6}])
        self.assertEqual(panel._front_covered("2001:db8::/64"), FRONT6)
        self.assertEqual(panel._front_covered(FRONT_GRID), "")

    def test_pubylicnyj_host_ssylok_tozhe_front(self):
        self._front([])
        panel.CFG_CACHE["hop_public_host"] = HOST_FRONT
        self.assertEqual(panel._front_covered(HOST_FRONT), HOST_FRONT)
        self.assertEqual(panel._front_covered(FRONT_GRID), HOST_FRONT)
        self.assertEqual(panel._front_covered(OTHER_GRID), "")

    def test_petlya_i_metadata_ne_stanovyatsya_frontom(self):
        self._front([{"front_ip": "127.0.0.1"}, {"front_ip": "169.254.169.254"},
                     {"front_ip": ""}, {"front_ip": {}}, {}])
        self.assertEqual(panel._hop_front_addrs(), [])
        self.assertEqual(panel._front_covered("127.0.0.1"), "")

    def test_nerazbiramoe_imya_ne_adres(self):
        # страж пропускает всё, что не разрешилось (в том числе явный мусор), а
        # доверенный список обязан состоять из адресов: иначе в нём жил бы «фронт»,
        # которого нет, и слова о неприкосновенности решались бы по опечатке
        self._front([{"front_ip": "не адрес"}, {"front_ip": "фронт.локаль"}])
        self.assertEqual(panel._hop_front_addrs(), [])
        self.assertFalse(panel._ban_ip(STRAY, 60, "тест") is False and
                         any(a[0] and a[0][0] == "front_ban_refused" for a in self.audit))

    def test_ban_fronta_otkazyvaetsya_bez_traceyora(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertFalse(panel._ban_ip(FRONT, 3600, "login fails"))
            self.assertFalse(panel._ban_ip(FRONT_GRID, 30 * 86400, "sweep farm grid"))
        self.assertEqual(panel.BANS, {})
        self.assertEqual(self.nft, [])
        refused = [k for a, k in self.audit if a and a[0] == "front_ban_refused"]
        self.assertEqual(len(refused), 2, refused)
        self.assertEqual(refused[0]["front"], FRONT)
        self.assertEqual(refused[1]["ip"], FRONT_GRID)
        self.assertIn("ОТКАЗ", out.getvalue())

    def test_chestnyj_ban_odstal_chestnym(self):
        self.assertTrue(panel._ban_ip(STRAY, 900, "sweep half-open"))
        self.assertEqual(panel.BANS[STRAY]["reason"], "sweep half-open")
        self.assertEqual(self.nft[-1][:5],
                         ("add", "element", "inet", "veil_bans", "b4"))
        self.assertIn("timeout 900s", self.nft[-1][5])

    def test_shestyorka_fronta_zakryta_tak_zhe(self):
        self._front([{"front_ip": FRONT6}])
        self.assertFalse(panel._ban_ip("2001:db8::/64", 30 * 86400, "sweep farm grid"))
        self.assertTrue(panel._ban_ip("2001:db8:4::9", 900, "sweep half-open"))
        self.assertEqual(self.nft[-1][4], "b6")

    def test_front_ne_zavodit_ustroystva(self):
        panel._subdev_note("tok", FRONT, UA)
        self.assertEqual(panel._SUBDEV, {})
        panel._subdev_note("tok", NEIGHBOR, UA)
        self.assertEqual([d["ip"] for d in panel._SUBDEV["tok"]], [NEIGHBOR])

    def test_front_svoj_dlya_sinimiti_i_marshruta(self):
        cidrs = panel._own_ip_cidrs()
        self.assertIn(FRONT + "/32", cidrs)
        self.assertIn("203.0.113.7/32", cidrs)
        self._front([{"front_ip": FRONT6}])
        # список «своих» кэшируется на две минуты: фронт, добавленный только что,
        # идёт туда на следующем тике, а не в эту секунду
        panel._OWN_IP_CACHE["cidrs"] = None
        panel._OWN_IP_CACHE["ts"] = 0.0
        self.assertIn(FRONT6 + "/128", panel._own_ip_cidrs())

    def test_vhozhdenie_meryaetsya_ne_udalennym_metodom(self):
        # метод `contains` у сети адресов удалён в Пифоне 3.13, а коробки на 3.14:
        # под `except Exception` он молча отвечал бы «фронта нет»
        with open(panel.__file__, encoding="utf-8") as f:
            src = f.read()
        start = src.index("def _front_covered(")
        seg = src[start:start + 1400]
        self.assertNotIn(".contains(", seg)
        self.assertIn(" in net", seg)


if __name__ == "__main__":
    unittest.main()
