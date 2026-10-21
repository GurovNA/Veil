"""Ссылки в наружных документах ведут на файлы, которые действительно лежат в дереве.

Отдельно — сироты: заметка в `docs/`, на которую никто снаружи не ссылается,
для читателя не существует. Прибор ловит и то, и другое, потому что обе беды
немые: битую ссылку видно только тому, кто по ней пошёл.
"""
import os
import re
import unittest

from _support import ROOT, path, read

DOC_FILES = ["README.md", "README.ru.md", "CONTRIBUTING.md", "SECURITY.md"]
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)")
SKIP_PREFIXES = ("http://", "https://", "mailto:", "tel:", "#", "data:")


def doc_files():
    files = list(DOC_FILES)
    d = os.path.join(ROOT, "docs")
    if os.path.isdir(d):
        files += ["docs/" + n for n in sorted(os.listdir(d)) if n.endswith(".md")]
    return [f for f in files if os.path.exists(path(f))]


class TestDocLinks(unittest.TestCase):
    def test_relative_links_resolve(self):
        checked = 0
        for rel in doc_files():
            base = os.path.dirname(rel)
            for target in LINK_RE.findall(read(rel)):
                if target.startswith(SKIP_PREFIXES):
                    continue
                checked += 1
                clean = target.split("#", 1)[0].split("?", 1)[0]
                if not clean:
                    continue
                self.assertFalse(clean.startswith("/"),
                                 "%s: локальный путь написан от корня диска — %r" % (rel, target))
                resolved = os.path.normpath(os.path.join(ROOT, base, clean))
                with self.subTest(doc=rel, link=target):
                    self.assertTrue(os.path.exists(resolved),
                                    "ссылка ведёт в никуда: %s → %s" % (rel, target))
        self.assertGreater(checked, 0, "ни одной наружной ссылки не разобрано")

    def test_no_orphan_notes(self):
        hub = "\n".join(read(f) for f in DOC_FILES)
        d = os.path.join(ROOT, "docs")
        if not os.path.isdir(d):
            self.skipTest("нет каталога docs")
        for name in sorted(os.listdir(d)):
            if not name.endswith(".md"):
                continue
            with self.subTest(note="docs/" + name):
                self.assertIn(name, hub,
                              "на заметку docs/%s нет ссылки ни в одном наружном документе" % name)


if __name__ == "__main__":
    unittest.main()
