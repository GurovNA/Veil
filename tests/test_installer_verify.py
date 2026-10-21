"""Сверка скачанного релизного архива: `verify_release_tarball` из install.sh.

Функция вырезается из установщика и вызывается в тех же условиях, в каких её
видит установка (`set -euo pipefail`), против локального сервера на 127.0.0.1.
Кода возврата три, и каждый проверяется отдельно: совпало, не совпало, сверить
нечем. Плюс структурная проверка — ни одна загрузка архива в установщике не
должна идти мимо сверки.
"""
import functools
import hashlib
import os
import re
import subprocess
import tempfile
import threading
import unittest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from _support import read

FUNC = "verify_release_tarball"


def installer_function(name):
    lines = read("install.sh").splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith(name + "() {"):
            start = i
            break
    if start is None:
        raise AssertionError("install.sh потерял функцию %s()" % name)
    body = []
    for line in lines[start:]:
        body.append(line)
        if line == "}":
            return "\n".join(body)
    raise AssertionError("функция %s не закрыта" % name)


class _Handler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class TestInstallerVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.root = cls.dir.name
        cls.payload = b"veil-release-archive-under-test\n"
        cls.digest = hashlib.sha256(cls.payload).hexdigest()
        with open(os.path.join(cls.root, "veil.tar.gz"), "wb") as f:
            f.write(cls.payload)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0),
                                         functools.partial(_Handler, directory=cls.root))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.script = os.path.join(cls.root, "driver.sh")
        with open(cls.script, "w", encoding="utf-8") as f:
            f.write("set -euo pipefail\n%s\n\nVRC=0\n%s \"$1\" \"$2\" || VRC=$?\nprintf '%%s\\n' \"$VRC\"\n"
                    % (installer_function(FUNC), FUNC))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.dir.cleanup()

    def write_digest(self, text):
        p = os.path.join(self.root, "veil.tar.gz.sha256")
        if text is None:
            if os.path.exists(p):
                os.unlink(p)
        else:
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)

    def run_verify(self, file_name="veil.tar.gz"):
        url = "http://127.0.0.1:%d/veil.tar.gz" % self.port
        target = os.path.join(self.root, file_name)
        r = subprocess.run(["bash", self.script, url, target],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, "драйвер умер: %s%s" % (r.stdout, r.stderr))
        return r.stdout.strip().splitlines()[-1]

    def test_matching_digest(self):
        self.write_digest("%s  veil.tar.gz\n" % self.digest)
        self.assertEqual(self.run_verify(), "0")

    def test_uppercase_digest_still_matches(self):
        self.write_digest("%s  veil.tar.gz\n" % self.digest.upper())
        self.assertEqual(self.run_verify(), "0")

    def test_short_digest_asset_name_also_works(self):
        self.write_digest(None)
        short = os.path.join(self.root, "veil.sha256")
        with open(short, "w", encoding="utf-8") as f:
            f.write("%s  veil.tar.gz\n" % self.digest)
        try:
            self.assertEqual(self.run_verify(), "0")
        finally:
            os.unlink(short)

    def test_mismatch_stops_the_install(self):
        self.write_digest("%s  veil.tar.gz\n" % ("0" * 64))
        self.assertEqual(self.run_verify(), "1")

    def test_missing_digest_cannot_verify(self):
        self.write_digest(None)
        self.assertEqual(self.run_verify(), "2")

    def test_empty_digest_cannot_verify(self):
        self.write_digest("")
        self.assertEqual(self.run_verify(), "2")

    def test_non_hex_digest_cannot_verify(self):
        self.write_digest("z" * 64 + "\n")
        self.assertEqual(self.run_verify(), "2")

    def test_short_digest_cannot_verify(self):
        self.write_digest(self.digest[:32] + "\n")
        self.assertEqual(self.run_verify(), "2")

    def test_absent_file_cannot_verify(self):
        self.write_digest("%s  veil.tar.gz\n" % self.digest)
        self.assertEqual(self.run_verify("no-such-file"), "2")

    def test_every_download_is_verified(self):
        lines = read("install.sh").splitlines()
        sites = [i for i, l in enumerate(lines) if re.search(r'-o /tmp/veil\.tar\.gz "\$TARBALL_URL"', l)]
        self.assertTrue(sites, "в установщике не осталось загрузки релизного архива")
        for i in sites:
            window = "\n".join(lines[i:i + 5])
            with self.subTest(line=i + 1):
                self.assertIn(FUNC, window,
                              "архив скачивается, но не сверяется (строка %d)" % (i + 1))

    def test_dry_run_shows_the_verification(self):
        dry = [l for l in read("install.sh").splitlines() if "[dry]" in l and "sha256" in l]
        self.assertTrue(dry, "dry-run не показывает шаг сверки дайджеста")


if __name__ == "__main__":
    unittest.main()
