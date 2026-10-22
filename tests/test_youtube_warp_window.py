"""Окно «YouTube»: адреса Google идут через своё звено WARP, отдельное от TikTok.

Слово хозяина: «можно как то сделать, что ютуб воспитнимал этот ip как русский?»
и «сделай отдельное окно около тикток ну и назови его ютуб». Звено своё: интерфейс
`ytw0`, таблица `205`, приоритеты от `600`, своя метка обхода — включать и выключать
его можно, не трогая TikTok. Покрытие судится агрегатами сетей Google целиком: `/24`
тут не работают, пул ротируется между сессиями, а плеер сам называет узлы потоков,
поэтому адрес нового потока мог бы остаться за туннелем.

Прибор судит форму и числа по настоящим байтам панели; живая свёрка сделана на
тестовой коробке и описана в теле релиза.
"""
import inspect
import ipaddress
import unittest

from _support import panel_module, read

panel = panel_module()

# По одному адресу с каждого /24-блока живого резолва десяти доменов меры
# (тестовая коробка, 21.10): 238 адресов, сорок четыре блока.
LIVE_SLICE = ["64.233.161.7", "64.233.162.7", "64.233.163.7", "64.233.164.7",
              "64.233.165.7", "74.125.131.7", "74.125.205.7", "108.177.14.7",
              "142.251.1.7", "142.251.38.7", "142.251.142.7", "142.251.143.7",
              "142.251.144.7", "142.251.145.7", "142.251.146.7", "142.251.147.7",
              "142.251.148.7", "142.251.149.7", "142.251.150.7", "142.251.151.7",
              "142.251.152.7", "142.251.153.7", "142.251.154.7", "142.251.155.7",
              "142.251.156.7", "142.251.157.7", "172.217.19.7", "172.217.20.7",
              "172.217.112.7", "172.217.113.7", "172.217.114.7", "172.217.115.7",
              "172.217.116.7", "172.217.117.7", "172.217.118.7", "172.217.119.7",
              "172.253.152.7", "173.194.73.7", "173.194.221.7", "173.194.222.7",
              "192.178.40.7", "192.178.41.7", "209.85.233.7", "216.58.201.7"]


def blocks_of(ips):
    return sorted({".".join(ip.split(".")[:3]) + ".0/24" for ip in ips})


def covers(nets, block):
    net = ipaddress.ip_network(block)
    return any(net.subnet_of(ipaddress.ip_network(n)) or
               net == ipaddress.ip_network(n) for n in nets)


class Numbers(unittest.TestCase):
    def test_link_its_own_and_does_not_collide_with_tiktok(self):
        self.assertEqual(panel._YW_IF, "ytw0")
        self.assertEqual(panel._YW_TBL, "205")
        self.assertNotEqual(panel._YW_TBL, panel._TW_TBL)
        self.assertNotEqual(panel._YW_IF, panel._TW_IF)
        self.assertEqual(panel._YW_BYPASS_MARK, 46)          # 0x2e, у TikTok 0x2d
        self.assertNotEqual(panel._YW_BYPASS_MARK, panel._TW_BYPASS_MARK)

    def test_priorities_named(self):
        self.assertEqual(int(panel._YW_PRIO_BASE), 600)      # выше чужих 200..456
        self.assertEqual(int(panel._YW_BYPASS_PRIO), 590)
        self.assertLess(int(panel._YW_BYPASS_PRIO), int(panel._YW_PRIO_BASE))
        self.assertGreater(int(panel._YW_BYPASS_PRIO), 456)
        self.assertEqual(panel._YW_MTU, "1280")
        self.assertEqual(panel._YW_KEEP, "25")

    def test_rotation_and_probe_pace_named_by_numbers(self):
        self.assertGreaterEqual(float(panel._YW_ROT), 900.0)
        # черед замера имеет смысл только у устоявшегося ответа: первый замер через
        # поднятое звено не ждёт `300` с (живая свёрка увидела прочерк длиннее минуты)
        self.assertEqual(float(panel._YW_PROBE_TTL), 300.0)
        self.assertEqual(float(panel._YW_PROBE_FRESH), 20.0)
        self.assertLess(float(panel._YW_PROBE_FRESH), float(panel._YW_PROBE_TTL))
        self.assertEqual(float(panel._TW_PROBE_FRESH), float(panel._YW_PROBE_FRESH))


class Coverage(unittest.TestCase):
    def test_live_slice_falls_inside_coverage(self):
        nets = panel._yw_blocks(LIVE_SLICE)
        outside = [b for b in blocks_of(LIVE_SLICE) if not covers(nets, b)]
        self.assertEqual(outside, [], "эти блоки живого резолва остались вне туннеля")

    def test_aggregates_present_and_are_google_front_nets(self):
        nets = panel._yw_blocks(LIVE_SLICE)
        for agg in panel._YW_AGG:
            self.assertIn(agg, nets, agg)
        self.assertEqual(len(panel._YW_AGG), 10)
        # `/15` — не опечатка: 142.250 и 142.251 куплены Google одной связкой
        self.assertIn("142.250.0.0/15", panel._YW_AGG)

    def test_tiktok_seeds_not_carried_over(self):
        nets = panel._yw_blocks(LIVE_SLICE)
        for seed in panel._TW_SEED:
            self.assertNotIn(seed, nets, seed)

    def test_cap_applies_to_picked_blocks_and_never_pushes_out_aggregates(self):
        many = ["10.%d.%d.7" % (i // 256, i % 256) for i in range(panel._YW_CAP + 40)]
        nets = panel._yw_blocks(many)
        picked = [n for n in nets if n not in panel._YW_AGG]
        self.assertLessEqual(len(picked), panel._YW_CAP, len(picked))
        for agg in panel._YW_AGG:
            self.assertIn(agg, nets, "потолок вытолкнул хозяйский агрегат")


class Desire(unittest.TestCase):
    def setUp(self):
        self.saved = dict(panel.CFG_CACHE)

    def tearDown(self):
        panel.CFG_CACHE.clear()
        panel.CFG_CACHE.update(self.saved)

    def test_reads_only_its_own_word(self):
        panel.CFG_CACHE.clear()
        panel.CFG_CACHE.update({"tiktok_warp": True, "warp_manual": {"domains": ["a.ru"],
                                                                     "ips": []}})
        self.assertFalse(panel._yw_want(), "чужое слово не вправе поднимать это звено")
        panel.CFG_CACHE["youtube_warp"] = True
        self.assertTrue(panel._yw_want())
        panel.CFG_CACHE["youtube_warp"] = "не число"
        self.assertTrue(panel._yw_want(), "нечисловое слово — тоже включено, а не падение")


class Snapshot(unittest.TestCase):
    def test_view_never_hands_out_private_key(self):
        src = inspect.getsource(panel._yw_view)
        self.assertNotIn("private_key", src)
        self.assertIn("_yw_registered()", src)
        self.assertTrue(panel._YW_REG.startswith(panel._YW_DIR + "/"))

    def test_registration_lives_in_its_own_directory(self):
        self.assertEqual(panel._YW_DIR, "/var/lib/veil-youtube-route")
        self.assertNotEqual(panel._YW_DIR, panel._TW_DIR)


class Card(unittest.TestCase):
    def setUp(self):
        ui = read("index.html")
        a, b = ui.find("id=setYouTube"), ui.find("id=setWarpManual")
        self.card = ui[a:b] if a != -1 and b > a else ""

    def test_card_exists_next_to_tiktok(self):
        ui = read("index.html")
        self.assertIn("id=setTikTok", ui)
        self.assertTrue(self.card, "карточки окна нет")
        self.assertLess(ui.find("id=setTikTok"), ui.find("id=setYouTube"))

    def test_card_names_its_own_endpoint_and_controls(self):
        self.assertIn("id=ywOn", self.card)
        self.assertIn("id=ywCheckBtn", self.card)
        self.assertIn("id=ywState", self.card)

    def test_card_tells_the_truth_about_scope_and_region(self):
        # страна прямого выхода живая: карточка обязана отвечать «Россия / не Россия»,
        # а не пересказывать чужую географию
        self.assertIn("не Россия", self.card)
        for pinned in ("Финляндия", "Швеция", "Германия"):
            self.assertNotIn(pinned, self.card, pinned)
        self.assertIn("раздельно", self.card)
        self.assertIn("трафик самого сервера", self.card)


if __name__ == "__main__":
    unittest.main()
