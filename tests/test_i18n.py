"""Словарь интерфейса: три языка обязаны нести один и тот же набор строк.

Русская строка — ключ, переводы лежат в `en`, `fa`, `zh`. Разъехавшиеся
наборы ключей означают, что новую надпись перевели не во все языки: в панели
это молча показывает русский там, где человек ждёт своего языка.
"""
import json
import unittest

from _support import read

LANGS = ("en", "fa", "zh")


class TestI18n(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(read("i18n.json"))

    def test_top_level_is_language_map(self):
        self.assertIsInstance(self.data, dict)
        for lang in LANGS:
            self.assertIn(lang, self.data, "словарь потерял язык %r" % lang)

    def test_key_sets_are_identical(self):
        base = set(self.data[LANGS[0]])
        self.assertTrue(base, "пустой набор строк")
        for lang in LANGS[1:]:
            got = set(self.data[lang])
            self.assertEqual(base - got, set(), "%s недобран строк" % lang)
            self.assertEqual(got - base, set(), "%s несёт лишние строки" % lang)

    def test_no_empty_translations(self):
        for lang in LANGS:
            for key, value in self.data[lang].items():
                with self.subTest(lang=lang, key=key[:40]):
                    self.assertIsInstance(value, str)
                    self.assertTrue(value.strip(), "пустой перевод")

    def test_keys_are_non_empty_strings(self):
        for key in self.data[LANGS[0]]:
            self.assertTrue(key.strip(), "пустой ключ")


if __name__ == "__main__":
    unittest.main()
