"""Релизный архив и его контрольные суммы: сверься, что выложенное целое.

В репозитории лежат `veil.tar.gz` и два файла дайджеста к нему. Выпуск
устанавливается именно из этого архива, поэтому его целостность проверяется
приборе отдельно: дайджесты должны совпадать с байтами архива, оба файла —
быть равны между собой, а состав архива — не выносить за пределы дерева то,
чего в нём быть не должно.
"""
import hashlib
import os
import re
import tarfile
import unittest

from _support import path, read

DIGEST_NAME_RE = re.compile(r"^[0-9a-f]{64}  veil\.tar\.gz\n$")
FORBIDDEN_MEMBERS = ("config.json", "FIRST-LOGIN.txt", "tests/", ".github/", ".git/")
FORBIDDEN_SUFFIXES = (".pem", ".key", ".pyc", ".db", ".env")


def members():
    with tarfile.open(path("veil.tar.gz"), "r:gz") as t:
        return t.getnames()


class TestReleaseArchive(unittest.TestCase):
    def test_both_digest_files_exist_and_are_equal(self):
        a, b = read("veil.sha256"), read("veil.tar.gz.sha256")
        self.assertEqual(a, b, "два файла дайджеста разошлись")
        self.assertTrue(DIGEST_NAME_RE.match(a), "формат файла дайджеста съехал")

    def test_digest_matches_archive_bytes(self):
        want = read("veil.sha256").split()[0].lower()
        with open(path("veil.tar.gz"), "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(want, got, "выложенный дайджест не описывает выложенный архив")

    def test_archive_members_live_in_the_tree(self):
        for name in members():
            with self.subTest(member=name):
                self.assertTrue(os.path.exists(path(name)),
                                "архив несёт %r, которого нет в дереве" % name)

    def test_archive_carries_the_sources(self):
        got = set(members())
        for name in ("panel.py", "agent.py", "install.sh", "i18n.json", "CHANGELOG.md"):
            self.assertIn(name, got, "архив потерял %s" % name)

    def test_archive_carries_the_bytes_of_this_release(self):
        """Архив обязан нести байты ЭТОГО дерева, а не память прежнего выпуска (`#539`).

        Прежние ноги мерили только самоцелостность: дайджест совпадал с архивом,
        члены архива существовали в дереве — и всё это сходилось на архиве,
        отстававшем от дерева на сорок тегов. Здесь сравниваются байты двух
        исполняемых листов и литера в архивном журнале.
        """
        def blob_of(name):
            with open(path(name), "rb") as fh:
                return fh.read()

        want = {name: blob_of(name) for name in ("panel.py", "index.html")}
        with tarfile.open(path("veil.tar.gz"), "r:gz") as t:
            for name, blob in want.items():
                member = t.extractfile(name)
                self.assertIsNotNone(member, "архив потерял %s" % name)
                got = member.read()
                self.assertEqual(len(got), len(blob),
                                 "архив несёт %s другого размера: %d Б против %d Б в дереве"
                                 % (name, len(got), len(blob)))
                self.assertEqual(got, blob, "архив несёт %s не тех байтов, что в дереве" % name)
            changelog = t.extractfile("CHANGELOG.md").read().decode("utf-8")
        version = re.search(r'^VERSION = "([0-9.]+)"', read("panel.py"), re.M).group(1)
        self.assertIn("## [%s]" % version, changelog,
                      "архивный журнал не знает выпуску %s — архив отстал от дерева" % version)

    def test_archive_holds_nothing_forbidden(self):
        for name in members():
            with self.subTest(member=name):
                clean = True
                for bad in FORBIDDEN_MEMBERS:
                    if name == bad or name.startswith(bad):
                        clean = False
                        break
                self.assertTrue(clean, "архив несёт %r" % name)
                self.assertFalse(name.endswith(FORBIDDEN_SUFFIXES),
                                 "архив несёт %r" % name)
                self.assertFalse(name.startswith("/"), "абсолютный путь в архиве")
                self.assertNotIn("..", name.split("/"), "восходящий путь в архиве")


if __name__ == "__main__":
    unittest.main()
