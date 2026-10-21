"""Журнал устройств подписки не принимает проверки самой панели за клиентов.

`sub_devices.json` панель ведёт по обращениям к `/sub/<токен>`: кто пришёл — тот
и устройство. Прежде запись ставилась на любой адрес, включая петлю и адреса,
назначенные этой же машине, — пробор выдачи, сделанный с сервера, выглядел как
живое устройство у каждого подписчика. Теперь такое обращение не заводит записи,
а уже накопленные строки снимаются при загрузке журнала. Подписчика, чей запрос
делает круг через его же туннель (адрес ВНУТРИ сети подписчиков, а не шлюз этой
сети), правка не трогает: судится именно «назначен ли адрес этой машине».
"""
import json
import os
import tempfile
import time
import unittest

from _support import panel_module

panel = panel_module()

ASSIGNED = "203.0.113.9"        # «адрес этой машины» — подставляется фикстурой
GUEST = "198.51.100.24"         # адрес подписчика снаружи
TUNNEL_PEER = "10.10.0.77"      # адрес подписчика внутри туннельной сети
TUNNEL_GW = "10.10.0.1"         # шлюз той же сети — он назначен машине
UA = "v2rayNG/1.11.28"          # версия без четвёртой группы: иначе литерал судится как IPv4


class SelfAddressLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (panel._SUBDEV, panel._SUBPREF, panel._SUBDEV_FILE,
                      panel._SUBPREF_FILE, panel._SELF_IPS, panel._SELF_IPS_TS)
        panel._SUBDEV_FILE = os.path.join(self.tmp.name, "sub_devices.json")
        panel._SUBPREF_FILE = os.path.join(self.tmp.name, "sub_prefs.json")
        panel._SUBDEV = None
        panel._SUBPREF = {}
        # без системных вызовов: набор адресов машины задан прямо здесь
        panel._SELF_IPS = {"127.0.0.1", "::1", ASSIGNED, TUNNEL_GW}
        panel._SELF_IPS_TS = time.time() + 3600

    def tearDown(self):
        (panel._SUBDEV, panel._SUBPREF, panel._SUBDEV_FILE,
         panel._SUBPREF_FILE, panel._SELF_IPS, panel._SELF_IPS_TS) = self.saved
        self.tmp.cleanup()

    def test_petlya_i_adresa_mashiny_svoj(self):
        for ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1", ASSIGNED, TUNNEL_GW):
            self.assertTrue(panel._is_self_ip(ip), ip)

    def test_chuzhie_adresa_i_musor_ne_svoj(self):
        for ip in (GUEST, TUNNEL_PEER, "", "не адрес", "999.1.1.1", "0"):
            self.assertFalse(panel._is_self_ip(ip), ip)

    def test_zapis_s_adresa_paneli_ne_zavodit_ustroystvo(self):
        for ip in ("127.0.0.1", "::1", ASSIGNED):
            panel._subdev_note("tok", ip, "INCY", "")
        self.assertEqual(panel._subdev_list("tok"), [])
        panel._subdev_note("tok", GUEST, UA, "")
        rows = panel._subdev_list("tok")
        self.assertEqual([r["ip"] for r in rows], [GUEST])

    def test_podpischik_v_nutri_tunnelnoj_seti_ostayetsya(self):
        panel._subdev_note("tok", TUNNEL_PEER, "INCY/3.7.9/android Dalvik", "")
        self.assertEqual([r["ip"] for r in panel._subdev_list("tok")], [TUNNEL_PEER])

    def test_zagruzka_snimayet_fantomy_i_pishet_fayl(self):
        seed = {
            "a": [
                {"ip": "127.0.0.1", "ips": [], "fp": "", "ua": "INCY", "client": "INCY",
                 "n": 18, "first_ts": "2026-10-10T12:48:25+00:00",
                 "last_ts": "2026-10-21T17:08:08+00:00"},
                {"ip": ASSIGNED, "ips": [], "fp": "", "ua": UA, "client": "v2rayNG",
                 "n": 5, "first_ts": "2026-10-11T00:29:42+00:00",
                 "last_ts": "2026-10-21T17:05:34+00:00"},
                {"ip": GUEST, "ips": ["127.0.0.1", TUNNEL_PEER], "fp": "", "ua": UA,
                 "client": "v2rayNG", "n": 4, "first_ts": "2026-10-12T06:00:00+00:00",
                 "last_ts": "2026-10-21T16:00:00+00:00"},
            ],
            "b": [{"ip": "127.0.0.1", "ips": [], "fp": "", "ua": "INCY", "client": "INCY",
                   "n": 9, "first_ts": "2026-10-20T09:00:00+00:00",
                   "last_ts": "2026-10-21T17:08:07+00:00"}],
            "c": [{"ip": TUNNEL_PEER, "ips": [], "fp": "", "ua": "INCY/3.7.9/android",
                   "client": "INCY", "n": 2, "first_ts": "2026-10-19T09:00:00+00:00",
                   "last_ts": "2026-10-21T15:00:00+00:00"}],
        }
        with open(panel._SUBDEV_FILE, "w", encoding="utf-8") as f:
            json.dump(seed, f)
        panel._SUBDEV = None
        panel._subdev_load()
        saved = json.load(open(panel._SUBDEV_FILE, encoding="utf-8"))
        self.assertEqual(sorted(saved), ["a", "c"])
        self.assertEqual([r["ip"] for r in saved["a"]], [GUEST])
        self.assertNotIn("127.0.0.1", saved["a"][0].get("ips") or [])
        self.assertIn(TUNNEL_PEER, saved["a"][0].get("ips") or [])
        self.assertEqual([r["ip"] for r in saved["c"]], [TUNNEL_PEER])

    def test_zivoe_ustroystvo_ne_izmeneno_vychistkoj(self):
        row = {"ip": GUEST, "ips": [TUNNEL_PEER], "fp": "ff" * 8, "ua": UA,
               "client": "v2rayNG", "n": 7, "first_ts": "2026-10-01T00:00:00+00:00",
               "last_ts": "2026-10-21T10:00:00+00:00"}
        with open(panel._SUBDEV_FILE, "w", encoding="utf-8") as f:
            json.dump({"a": [row]}, f)
        panel._SUBDEV = None
        panel._subdev_load()
        after = json.load(open(panel._SUBDEV_FILE, encoding="utf-8"))["a"]
        self.assertEqual(len(after), 1)
        self.assertEqual({k: v for k, v in after[0].items() if k in row}, row)


if __name__ == "__main__":
    unittest.main()
