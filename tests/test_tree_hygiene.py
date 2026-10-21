"""В дереве не остаётся приватного: ни ключей, ни рабочего состояния машины.

Панель хранит на сервере то, что нельзя показывать наружу: приватные ключи
TLS, подписочные идентификаторы, снимки состояния. Список таких файлов живёт в
`panel.py` (`_MV_PRIVATE`) и в `.gitignore`; этот прибор проверяет, что в
публичном дереве ни одного из них нет и что `.gitignore` их накрывает —
иначе следующий коммит унесёт их в историю навсегда.
"""
import os
import re
import unittest

from _support import ROOT, read

PRIVATE_NAMES = [
    "config.json", "state.json", "sessions.json", "audit.json", "login_history.json",
    "github.token", "FIRST-LOGIN.txt", "passkeys.json", "payments.json", "bans.json",
    "nodes.json", "hops.json", "media_route.json", "online_chain.json",
    "online_runs.json", "theme.json", "veil_private.py",
]
PRIVATE_SUFFIXES = (".pem", ".key", ".token", ".pcap", ".kdbx", ".env", ".db", ".sqlite")
PRIVATE_DIRS = ("certs", "avatars", "node_keys", "logs", "flux", "rulesets", "backups")
TEXT_EXTS = (".py", ".md", ".json", ".sh", ".html", ".js", ".css", ".txt", ".yml",
             ".yaml", ".toml", ".service", ".ini", ".conf")
RE_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
RE_SSH_PASS = re.compile(r"""sshpass\s+(-p|--password)\s+["']?\S""")


def walk_text_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", ".relwork")]
        for name in filenames:
            if os.path.splitext(name)[1] in TEXT_EXTS:
                yield os.path.join(dirpath, name)


def tree_entries():
    entries = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", ".relwork")]
        for name in dirnames + filenames:
            entries.append(os.path.relpath(os.path.join(dirpath, name), ROOT))
    return entries


class TestTreeHygiene(unittest.TestCase):
    def test_no_private_state_in_the_tree(self):
        names = {os.path.basename(e) for e in tree_entries()}
        for bad in PRIVATE_NAMES:
            with self.subTest(name=bad):
                self.assertNotIn(bad, names, "приватный файл попал в публичное дерево")

    def test_no_private_directories_in_the_tree(self):
        tops = {e.split(os.sep)[0] for e in tree_entries()}
        for bad in PRIVATE_DIRS:
            with self.subTest(dir=bad):
                self.assertNotIn(bad, tops, "приватный каталог попал в публичное дерево")

    def test_no_private_suffixes_in_the_tree(self):
        for entry in tree_entries():
            if entry.endswith(PRIVATE_SUFFIXES):
                self.fail("файл с приватным расширением в дереве: %s" % entry)

    def test_gitignore_covers_the_private_state(self):
        ignore = set(l.strip() for l in read(".gitignore").splitlines() if l.strip()
                     and not l.startswith("#"))
        for bad in PRIVATE_NAMES:
            with self.subTest(name=bad):
                self.assertIn(bad, ignore, ".gitignore разучился накрывать %s" % bad)

    def test_no_pem_private_keys_in_text_files(self):
        for f in walk_text_files():
            with open(f, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            with self.subTest(file=os.path.relpath(f, ROOT)):
                self.assertIsNone(RE_PEM.search(text), "в файле лежит приватный ключ")

    def test_no_password_literals_for_ssh(self):
        for f in walk_text_files():
            with open(f, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            with self.subTest(file=os.path.relpath(f, ROOT)):
                self.assertIsNone(RE_SSH_PASS.search(text),
                                  "в файл записан пароль ssh разворотом")


if __name__ == "__main__":
    unittest.main()
