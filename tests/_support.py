"""Общее для приборов: корень репозитория и бережная загрузка панели.

Панель — один файл без внешних зависимостей, и импортируется она без
конфигура: `config.json` читается в пустой словарь, если файла нет. Проверено
на чистой песочнице, поэтому приборы имеют право делать `import panel`.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def path(*rel):
    return os.path.join(ROOT, *rel)


def read(*rel, encoding="utf-8"):
    with open(path(*rel), encoding=encoding) as f:
        return f.read()


def panel_module():
    """panel.py из этого дерева, а не из установленного /opt/vpnpanel."""
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    import panel  # noqa: F401  (проверка живности импорта — часть прибора)
    return panel
