# -*- coding: utf-8 -*-
"""Подписчику не отдают IPv6 внутрь туннеля, но захват шестёрки остаётся.

Окно TikTok и окно YouTube несут только четвёрку: шестое семейство у самих
туннельных окон отказано. Пока раздача выдавала клиенту адрес в `fd10:10::/64`
(`fd20:10::/64` для AmneziaWG) и `::/0`, YouTube-трафик по шестёрке уходил через
общее звено мимо окна, которое обещает «читает узел Россией». Снять же и `::/0` означало бы пустить
собственную шестёрку телефона мимо туннеля — утечка реального адреса подписчика.
Правило цикла #498: захват остаётся, адрес в раздаче гаснет. Нечем послать шестёрку
в интерфейс, пакеты чёрнеют, приложение само уходит на четвёрку.

Серверная приёмка и маскарад не тронуты: пиры продолжают знать v6-адрес клиента,
правила `ip6 masquerade` пишутся по-прежнему — рвать ссылки, по которым живут люди,
нельзя. Прибор судит настоящие `_link`, `_incy_link`, `_singbox_outbound` и `_tun6`.
"""
import json
import re
import unittest

from _support import panel_module

HOST = "198.51.100.10"      # TEST-NET-2 — документальный диапазон


def inbound():
    return {"port": 51820, "public_key": "SRVPUB", "private_key": "SRVPRIV",
            "address": "10.10.0.1/24", "psk": ""}


def client():
    return {"uuid": "u1", "name": "Тест", "address": "10.10.0.7/32",
            "client_private_key": "CLIPRIV", "client_public_key": "CLIPUB",
            "sub_token": "tok"}


class TestConfHandout(unittest.TestCase):
    """Раздаваемый .conf: адрес только по четвёрке, `::/0` на месте."""

    def conf(self, proto):
        panel = panel_module()
        inb = dict(inbound(), junk_on=True) if proto == "amneziawg" else inbound()
        return panel._link(inb, HOST, client(), proto)

    def test_interface_address_has_no_v6(self):
        for proto in ("wireguard", "amneziawg"):
            with self.subTest(proto=proto):
                lines = [l for l in self.conf(proto).splitlines()
                         if l.startswith("Address =")]
                self.assertTrue(lines, "секции Interface нет")
                self.assertNotIn(":", lines[0], lines[0])

    def test_allowed_ips_still_capture_ipv6(self):
        for proto in ("wireguard", "amneziawg"):
            with self.subTest(proto=proto):
                lines = [l for l in self.conf(proto).splitlines()
                         if l.startswith("AllowedIPs =")]
                self.assertTrue(lines, "peer-секции нет")
                self.assertTrue(any(":" in l for l in lines),
                                "шестёрка снята с захвата — это утечка адреса телефона")

    def test_conf_carries_no_tunnel_v6_address(self):
        for proto in ("wireguard", "amneziawg"):
            with self.subTest(proto=proto):
                self.assertIsNone(re.search(r"fd[0-9a-f]+:10::", self.conf(proto)))


class TestLinkAndCore(unittest.TestCase):
    """Ссылка INCY и объект sing-box — те же правила."""

    def test_incy_link_address_is_single_v4(self):
        panel = panel_module()
        link = panel._incy_link("wireguard", inbound(), client(), HOST)
        m = re.search(r"[?&]address=([^&#]*)", link)
        self.assertTrue(m, link[:120])
        value = m.group(1).replace("%2F", "/")
        self.assertTrue(value.startswith("10.10.0.7"), value)
        self.assertNotIn(",", value, "вторая (шестая) половина адреса вернулась")
        self.assertNotIn(":", value, value)

    def test_singbox_outbound_address_only_v4(self):
        panel = panel_module()
        for modern in (True, False):
            with self.subTest(modern=modern):
                ob = panel._singbox_outbound("wireguard", inbound(), client(), HOST, modern)
                addrs = ob.get("address") or ob.get("local_address") or []
                self.assertEqual(addrs, ["10.10.0.7/32"], addrs)
                self.assertIsNone(re.search(r"fd[0-9a-f]+:10::",
                                            json.dumps(ob, ensure_ascii=False)))

    def test_singbox_outbound_keeps_v6_capture(self):
        panel = panel_module()
        ob = panel._singbox_outbound("wireguard", inbound(), client(), HOST, True)
        # `::/0` здесь безусловен: это захват, а не адрес в туннеле (#498)
        self.assertIn("::/0", ob["peers"][0]["allowed_ips"], ob["peers"][0])


class TestServerSideUntouched(unittest.TestCase):
    """Сервер продолжает знать клиентскую шестёрку — ссылки живых не рвутся."""

    def test_tun6_still_derives_client_address(self):
        panel = panel_module()
        self.assertEqual(panel._tun6(client()), "fd10:10::7")
        self.assertEqual(panel._tun6(client(), "fd20:10::"), "fd20:10::7")

    def test_peer_side_still_derives_v6(self):
        panel = panel_module()
        # вход `veilwg`/`awg0` формируется этим же адресом: приёмка не тронута
        self.assertTrue(panel._tun6(client()).startswith("fd10:10::"))


if __name__ == "__main__":
    unittest.main()
