"""Разбор чужих ссылок и подписок: то, на чём держится импорт.

Здесь только тестовые адреса `example.*` и вымышленные ключи. Отдельно
прикреплено снятие shadowsocks: ссылка разбирается, но цель по ней не
назначается — молча склеить её в другой транспорт было бы хуже отказа.
"""
import base64
import json
import unittest

from _support import panel_module

panel = panel_module()

VLESS_REALITY = ("vless://11111111-2222-3333-4444-555555555555@example.com:443"
                "?type=xhttp&security=reality&pbk=pub&sni=example.com#Узел%20один")
VLESS_TLS_WS = ("vless://11111111-2222-3333-4444-555555555555@example.com:443"
                "?type=ws&security=tls#two")
VLESS_NO_SECURITY_WS = "vless://11111111-2222-3333-4444-555555555555@example.com:80?type=ws"
TROJAN_REALITY = "trojan://secret-password@example.com:443?type=tcp&security=reality#t"
HY2 = "hy2://topsecret@example.com:4433#h"
SS = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQx@example.com:8388#s"
VMESS = "vmess://" + base64.b64encode(json.dumps(
    {"v": "2", "ps": "узел вмес", "add": "example.com", "port": "443",
     "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "aid": "0", "net": "ws",
     "tls": "tls", "sni": "example.com"}).encode()).decode()


class TestSplitHostport(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(panel._split_hostport("example.com:443"), ("example.com", "443"))

    def test_bare_host(self):
        self.assertEqual(panel._split_hostport("example.com"), ("example.com", ""))

    def test_ipv6_literal_keeps_brackets(self):
        self.assertEqual(panel._split_hostport("[2001:db8::1]:443"), ("[2001:db8::1]", "443"))

    def test_ipv6_without_port(self):
        self.assertEqual(panel._split_hostport("[2001:db8::1]"), ("[2001:db8::1]", ""))


class TestParseLinkLine(unittest.TestCase):
    def test_vless_reality_xhttp(self):
        it = panel._parse_link_line(VLESS_REALITY)
        self.assertEqual(it["scheme"], "vless")
        self.assertEqual(it["proto"], "vless-xhttp-reality")
        self.assertEqual(it["uuid"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(it["host"], "example.com")
        self.assertEqual(it["name"], "Узел один")

    def test_vless_tls_ws(self):
        self.assertEqual(panel._parse_link_line(VLESS_TLS_WS)["proto"], "vless-ws-tls")

    def test_vless_reality_tcp_collapses_to_reality(self):
        line = VLESS_REALITY.replace("type=xhttp", "type=tcp")
        self.assertEqual(panel._parse_link_line(line)["proto"], "reality")

    def test_vless_plain_ws_has_proto(self):
        self.assertEqual(panel._parse_link_line(VLESS_NO_SECURITY_WS)["proto"], "vless-ws")

    def test_vless_plain_tcp_has_no_proto(self):
        line = VLESS_NO_SECURITY_WS.replace("type=ws", "type=tcp")
        self.assertIsNone(panel._parse_link_line(line)["proto"])

    def test_trojan_reality_keeps_its_own_proto(self):
        it = panel._parse_link_line(TROJAN_REALITY)
        self.assertEqual(it["proto"], "trojan-reality")
        self.assertEqual(it["password"], "secret-password")

    def test_hysteria2(self):
        it = panel._parse_link_line(HY2)
        self.assertEqual(it["proto"], "hysteria2")
        self.assertEqual(it["auth"], "topsecret")

    def test_vmess_ws_tls(self):
        it = panel._parse_link_line(VMESS)
        self.assertEqual(it["scheme"], "vmess")
        self.assertEqual(it["proto"], "vmess-ws-tls")
        self.assertEqual(it["uuid"], "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        self.assertEqual(it["name"], "узел вмес")

    def test_shadowsocks_is_parsed_but_not_assigned(self):
        it = panel._parse_link_line(SS)
        self.assertEqual(it["scheme"], "ss")
        self.assertIsNone(it["proto"], "shadowsocks снят с панели: цель назначать нечем")

    def test_junk_returns_none(self):
        for line in ("", "   ", "# комментарий", "http://example.com/", "vless://no-at-sign",
                     "vmess://not-base64-json", "hy2://nohost", "trojan://nohost"):
            with self.subTest(line=line):
                self.assertIsNone(panel._parse_link_line(line))

    def test_none_input(self):
        self.assertIsNone(panel._parse_link_line(None))


class TestSubscriptionBlob(unittest.TestCase):
    def test_plain_text_dedups(self):
        blob = "\n".join([VLESS_TLS_WS, "# комментарий", VLESS_TLS_WS, HY2, ""])
        out = panel._parse_subscription_blob(blob)
        self.assertEqual(len(out), 2, "дубль ссылки прошёл в разбор")
        self.assertEqual({i["scheme"] for i in out}, {"vless", "hy2"})

    def test_base64_body_is_decoded(self):
        blob = base64.b64encode(("\n".join([VLESS_TLS_WS, TROJAN_REALITY])).encode()).decode()
        out = panel._parse_subscription_blob(blob)
        self.assertEqual(len(out), 2)

    def test_empty_blob(self):
        self.assertEqual(panel._parse_subscription_blob(""), [])
        self.assertEqual(panel._parse_subscription_blob(None), [])

    def test_junk_blob_yields_nothing(self):
        self.assertEqual(panel._parse_subscription_blob("привет, тут нет ссылок"), [])


class TestFluxCleanLink(unittest.TestCase):
    def test_fragment_and_query_are_cut(self):
        self.assertEqual(panel._flux_clean_link("https://example.com/path?x=1#frag"),
                         "https://example.com/path")

    def test_trailing_slash_is_cut(self):
        self.assertEqual(panel._flux_clean_link("https://example.com/path/"),
                         "https://example.com/path")

    def test_keep_query_keeps_the_room_address(self):
        self.assertEqual(panel._flux_clean_link("https://example.com/wg?key=abc#frag",
                                                keep_query=True),
                         "https://example.com/wg?key=abc")

    def test_empty(self):
        self.assertEqual(panel._flux_clean_link(None), "")


if __name__ == "__main__":
    unittest.main()
