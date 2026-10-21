"""Исходники собираются, наружных зависимостей панель не требует.

Панель ставится на голый сервер скриптом без pip, поэтому весь код обязан быть
внутри стандартной библиотеки. Три модуля выпадают из этого правила осознанно:
`cryptography` и `yaml` берутся на месте внутри `try`, каждая вызывающая функция
обязана иметь свой импорт (иначе отсутствие библиотеки уронит панель на старте),
а `veil_private` — приватный файл оператора, которого в публичном дереве нет: он
импортируется один раз на уровне модуля, внизу, тоже внутри `try`.
"""
import ast
import os
import subprocess
import sys
import unittest

from _support import ROOT, path, read

PY_SOURCES = ["panel.py", "agent.py", "teleconf_witness.py", "migrate_from_old_db.py"]
OPTIONAL = {"cryptography", "yaml", "veil_private"}
DEFERRED_ONLY = {"cryptography", "yaml"}
MIN_PYTHON = (3, 10)


def collect_imports(tree):
    pairs = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                pairs.append((alias.name.split(".")[0], node))
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            pairs.append((node.module.split(".")[0], node))
    return pairs


def ids_under(nodes):
    out = set()
    for node in nodes:
        for sub in ast.walk(node):
            if isinstance(sub, (ast.Import, ast.ImportFrom)):
                out.add(id(sub))
    return out


class TestSources(unittest.TestCase):
    def test_python_sources_compile(self):
        for rel in PY_SOURCES:
            with self.subTest(source=rel):
                compile(read(rel), rel, "exec")

    def test_python_sources_parse_under_declared_python(self):
        for rel in PY_SOURCES:
            with self.subTest(source=rel):
                ast.parse(read(rel), filename=rel, feature_version=MIN_PYTHON)

    def test_tests_compile_too(self):
        for name in sorted(os.listdir(os.path.join(ROOT, "tests"))):
            if not name.endswith(".py"):
                continue
            with self.subTest(source="tests/" + name):
                compile(read("tests", name), name, "exec")

    def test_installer_shell_syntax(self):
        r = subprocess.run(["bash", "-n", path("install.sh")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr.strip())

    def test_only_declared_optional_imports(self):
        for rel in PY_SOURCES:
            tree = ast.parse(read(rel), filename=rel)
            extra = {m for m, _ in collect_imports(tree)
                     if m not in sys.stdlib_module_names}
            with self.subTest(source=rel):
                if rel == "panel.py":
                    self.assertTrue(extra <= OPTIONAL,
                                    "панель потянула не-stdlib модуль %s" % sorted(extra - OPTIONAL))
                else:
                    self.assertEqual(extra, set(),
                                     "%s потянул не-stdlib модули %s" % (rel, sorted(extra)))

    def test_optional_imports_are_guarded_and_deferred(self):
        tree = ast.parse(read("panel.py"), filename="panel.py")
        guarded = ids_under([n for n in ast.walk(tree) if isinstance(n, ast.Try)])
        deferred = ids_under([n for n in ast.walk(tree)
                              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))])
        for mod, node in collect_imports(tree):
            if mod in sys.stdlib_module_names:
                continue
            with self.subTest(module=mod, line=node.lineno):
                self.assertIn(id(node), guarded,
                              "%s импортирован вне try: отсутствие библиотеки уронит панель" % mod)
                if mod in DEFERRED_ONLY:
                    self.assertIn(id(node), deferred,
                                  "%s импортирован на уровне модуля" % mod)


if __name__ == "__main__":
    unittest.main()
