"""SSRF-граница импорта подписок: внутрь локальной сети панель не ходит.

Ручка `_fetch_subscription` берёт адрес, который ввёл оператор, и идёт по нему
сервером. Разрешены только внешние http/https, а каждый переход проверяется
тем же правилом — одна строчка `Location:` уводила бы запрос на метаданные
облака или на саму панель. Адреса в приборе — числовые литералы, чтобы не
зависеть от DNS.
"""
import unittest

from _support import panel_module

panel = panel_module()

INTERNAL = [
    "http://127.0.0.1:8443/sub",
    "http://localhost/sub",
    "http://10.0.0.5/x",
    "http://172.16.3.2/x",
    "http://192.168.1.1/x",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/x",
    "http://[fe80::1]/x",
    "http://0.0.0.0/x",
    "http://224.0.0.1/x",
]
EXTERNAL = [
    "https://8.8.8.8/sub",
    "http://8.8.4.4/sub",
]


class TestUrlHostIsPublic(unittest.TestCase):
    def test_internal_addresses_are_refused(self):
        for url in INTERNAL:
            with self.subTest(url=url):
                self.assertFalse(panel._url_host_is_public(url),
                                 "%r прошло внутрь сети" % url)

    def test_external_address_is_allowed(self):
        for url in EXTERNAL:
            with self.subTest(url=url):
                self.assertTrue(panel._url_host_is_public(url))

    def test_non_http_scheme_is_refused(self):
        for url in ("file:///etc/passwd", "gopher://8.8.8.8/", "http:///x", "http:///"):
            with self.subTest(url=url):
                self.assertFalse(panel._url_host_is_public(url))

    def test_unresolvable_host_is_refused(self):
        self.assertFalse(panel._url_host_is_public("http://этот-хост-не-существует.invalid/"))


class TestFetchRefusesInternal(unittest.TestCase):
    def test_fetch_raises_before_any_request(self):
        with self.assertRaises(ValueError):
            panel._fetch_subscription("http://127.0.0.1:8443/sub")

    def test_redirect_guard_refuses_internal_target(self):
        import urllib.request
        req = urllib.request.Request("http://8.8.8.8/sub")
        class _Resp:  # минимальная заглушка ответа, сеть не нужна
            def read(self, n=-1):
                return b""

            def close(self):
                pass
        handler = panel._SafeRedirect()
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(req, _Resp(), 302, "Found",
                                     {"Location": "http://169.254.169.254/"},
                                     "http://169.254.169.254/")


if __name__ == "__main__":
    unittest.main()
