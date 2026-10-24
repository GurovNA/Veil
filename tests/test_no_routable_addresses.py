"""В публичных файлах не должно быть адресов наших хостов.

Значения приватных ворот (`cc38`) здесь не повторяются: этот прибор судит форму.
Любой литерал IPv4 или IPv6 в открытом дереве обязан быть либо адресом не для
маршрутизации (петлевой, внутренней сети, служебного или документального
диапазона), либо адресом сторонней службы, названной в `NAMED` ниже. Публичный
адрес вне списка означает одно: в репозиторий лег чей-то хост, и после push'а он
останется в истории навсегда.

`NAMED` — не лазейка, а реестр: у каждой сети подписано, чья она и почему она в
дереве. Новая чужая сеть попадает в список только вместе с объяснением; адресу,
который «просто пример», место в документальном диапазоне (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`).
"""
import ipaddress
import os
import re
import unittest

from _support import ROOT

TEXT_EXTS = (".py", ".md", ".json", ".sh", ".html", ".js", ".css", ".txt", ".yml",
             ".yaml", ".toml", ".service", ".ini", ".conf")
SKIP_DIRS = (".git", "__pycache__", ".relwork")
RE_V4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_V6 = re.compile(r"\b[0-9a-fA-F:]*:[0-9a-fA-F:]{2,}(?::[0-9a-fA-F:]+)*\b")

# чужие сети, названные намеренно: (кто это, зачем в дереве, сети)
NAMED = (
    ("Cloudflare DNS", "резолвер по умолчанию в подсказках и в проверках туннеля",
     ("1.1.1.0/24", "1.0.0.0/24")),
    ("Google DNS", "резолвер DoH-проверки и эталон сравнения",
     ("8.8.8.0/24", "8.8.4.0/24", "2001:4860:4860::/64")),
    ("Quad9 DNS", "упомянут в разборе закрытой зоны фильтров",
     ("9.9.9.0/24",)),
    ("Yandex DNS", "boot-резолвер в шаблоне конфига Xray",
     ("213.180.204.0/24",)),
    ("Cloudflare edge", "сети фронта WARP, по которым судят «это адрес Cloudflare или нет»",
     ("104.16.0.0/12", "172.64.0.0/13")),
    ("сеть TikTok и фронт Akamai", "семена проверки покрытия ДЦ региональным туннелем",
     ("71.18.0.0/16", "95.130.85.0/24")),
    ("сети Google (фронт YouTube, статика, пул потоков)",
     "агрегаты покрытия окна «YouTube»: адресно от других служб Google не отделяются",
     ("64.233.0.0/16", "74.125.0.0/16", "108.177.0.0/16", "142.250.0.0/15",
      "172.217.0.0/16", "172.253.0.0/16", "173.194.0.0/16", "192.178.0.0/16",
      "209.85.0.0/16", "216.58.0.0/16")),
    ("сети Amazon (`EC2` и `CloudFront`)",
     "пункты пробы, названные в журнале как наблюдаемые: окончание игры и фронт "
     "`CloudFront`, по которым меряли выборочность `ICMP` и затягивание /24",
     ("44.227.138.0/24", "3.165.190.0/24", "18.64.211.0/24")),
    ("сеть Akamai",
     "покрытый адрес окна «TikTok»: к нему TCP устанавливается сквозь звено, и журнал "
     "называет это числом",
     ("184.86.251.0/24",)),
)

# Слово, после которого адрес перестаёт быть чужим: адрес своей коробки нельзя
# зарегистрировать в чужом реестре, он обязан исчезнуть из дерева (#538).
OURS_WORDS = ("наш", "наших", "бэк", "коробк", "стенд", "moscow", "aeza", "myproxyru")

DOC_NETS = tuple(ipaddress.ip_network(n) for n in
                 ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
NAMED_NETS = tuple((label, reason, ipaddress.ip_network(net))
                   for label, reason, nets in NAMED for net in nets)
EXAMPLE_HINTS = ("Например", "например", "For example", "مثلاً", "例如")


def address(token):
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


def named_by(ip):
    """None — адрес открыт и не назван; иначе (кто, зачем)."""
    if ip.is_multicast or ip.is_private or ip.is_loopback or ip.is_link_local \
            or ip.is_unspecified or ip.is_reserved or any(ip in net for net in DOC_NETS):
        return ("служебный или документальный диапазон", "")
    for label, reason, net in NAMED_NETS:
        if ip.version == net.version and ip in net:
            return (label, reason)
    return None


def text_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1] in TEXT_EXTS:
                yield os.path.join(dirpath, name)


def candidates():
    for f in text_files():
        with open(f, encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                for token in RE_V4.findall(line):
                    yield f, lineno, token
                for token in RE_V6.findall(line):
                    if token.count(":") >= 2:
                        yield f, lineno, token


class TestNoRoutableAddresses(unittest.TestCase):
    def test_tree_has_no_unnamed_routable_literals(self):
        bad = []
        for f, lineno, token in candidates():
            ip = address(token)
            if ip is not None and not ip.is_multicast and named_by(ip) is None:
                bad.append("%s:%d" % (os.path.relpath(f, ROOT), lineno))
        self.assertEqual(bad, [], "не названные адреса хостов в дереве: %s"
                         % ", ".join(bad))

    def test_named_list_cannot_register_our_own_hosts(self):
        """Реестр чужих сетей не вправе приютить наш адрес: такое название и есть
        обход прибора, поэтому оно красное."""
        bad = ["%s · %s" % (label, net) for label, reason, net in NAMED_NETS
               if any(w in (label + " " + reason).lower() for w in OURS_WORDS)]
        self.assertEqual(bad, [], "в чужой реестр записан адрес нашей инфраструктуры: %s"
                         % ", ".join(bad))

    def test_named_list_has_no_dead_entries(self):
        """Сеть из NAMED без дела — мусор: её надо убрать из реестра."""
        seen = set()
        for _, _, token in candidates():
            ip = address(token)
            if ip is None:
                continue
            for label, reason, net in NAMED_NETS:
                if ip.version == net.version and ip in net:
                    seen.add(net)
        dead = sorted(str(net) for _, _, net in NAMED_NETS if net not in seen)
        self.assertEqual(dead, [], "в реестре остались сети, которых в дереве нет: %s"
                         % ", ".join(dead))

    def test_hint_examples_use_documentation_ranges(self):
        """Подсказка вида «например, адрес» не вправе называть чужой живой хост."""
        bad = []
        for f in text_files():
            if os.path.basename(f) not in ("index.html", "i18n.json"):
                continue
            with open(f, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    if not any(h in line for h in EXAMPLE_HINTS):
                        continue
                    for token in RE_V4.findall(line):
                        ip = address(token)
                        if ip is None or ip.is_multicast:
                            continue
                        if named_by(ip) == ("служебный или документальный диапазон", ""):
                            continue
                        if not any(ip in net for net in DOC_NETS):
                            bad.append("%s:%d" % (os.path.relpath(f, ROOT), lineno))
        self.assertEqual(bad, [], "пример в подсказке называет маршрутизируемый адрес: %s"
                         % ", ".join(bad))


if __name__ == "__main__":
    unittest.main()
