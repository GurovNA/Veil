"""Мера самоподписи читает сам сертификат, а не каталог.

Панель хранит выпуск Let's Encrypt под тем же `CERT_DIR`, где живёт её
собственная заглушка `CN=Veil`, — каталог различить их не может. Этот прибор
не даёт мере вернуться к проверке по пути: на голом IP она отрезала подпискам
десять tls-транспортов.
"""
import os
import shutil
import subprocess
import tempfile
import unittest

from _support import panel_module

panel = panel_module()


def openssl(*args):
    return subprocess.run(["openssl", *args], capture_output=True, text=True, timeout=120)


@unittest.skipIf(shutil.which("openssl") is None, "нет openssl")
class TestCertSelfsigned(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        d = cls.dir.name
        cls.selfsigned = os.path.join(d, "selfsigned.pem")
        cls.leaf = os.path.join(d, "leaf.pem")
        cls.ca = os.path.join(d, "ca.pem")
        cls.junk = os.path.join(d, "junk.pem")
        r = openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
                    "-keyout", os.path.join(d, "self.key"), "-out", cls.selfsigned,
                    "-subj", "/CN=Veil")
        assert r.returncode == 0, r.stderr
        r = openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
                    "-keyout", os.path.join(d, "ca.key"), "-out", cls.ca,
                    "-subj", "/CN=Test CA")
        assert r.returncode == 0, r.stderr
        r = openssl("req", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", os.path.join(d, "leaf.key"), "-out", os.path.join(d, "leaf.csr"),
                    "-subj", "/CN=panel.example.org")
        assert r.returncode == 0, r.stderr
        r = openssl("x509", "-req", "-in", os.path.join(d, "leaf.csr"), "-CA", cls.ca,
                    "-CAkey", os.path.join(d, "ca.key"), "-CAcreateserial",
                    "-days", "3", "-out", cls.leaf)
        assert r.returncode == 0, r.stderr
        with open(cls.junk, "w", encoding="utf-8") as f:
            f.write("это не сертификат\n")

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def test_panel_stub_is_selfsigned(self):
        self.assertTrue(panel._cert_selfsigned(self.selfsigned))

    def test_issued_by_a_real_ca_is_not(self):
        self.assertFalse(panel._cert_selfsigned(self.leaf))

    def test_missing_file_counts_as_selfsigned(self):
        self.assertTrue(panel._cert_selfsigned(os.path.join(self.dir.name, "nope.pem")))

    def test_unparsable_file_counts_as_selfsigned(self):
        self.assertTrue(panel._cert_selfsigned(self.junk))


if __name__ == "__main__":
    unittest.main()
