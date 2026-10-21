# -*- coding: utf-8 -*-
"""Ротация переставляет netplan, а ядро хранит порядок прежний.

`netplan apply` сверяет набор адресов, а не порядок: уже сидящие в интерфейсе
адреса он не переставляет. Пока нужный адрес не станет первым в ядре, машина
исходит прежним адресом — и внешний промер панели (`_pub_ip4` смотрит на
источник исходящего соединения) не видит перемены вовсе. Ровно так штатная
ротация оставила сервер исходившим снятым адресом, хотя файл netplan был
перевёрнут верно.

Прибор судит `_kernel_primary_sync`: цель не снимается никогда, перекладываются
только адреса того же семейства, что и цель, и только лежащие перед ней; IPv6
не трогается вовсе. Отказ возврата назван опасной веткой, а не молчанием.
Настоящие `ip` и `netplan` не вызываются: весь ввод-вывод идёт
через подменённый `subprocess` и временный каталог вместо `/etc/netplan`.
"""
import os
import shutil
import tempfile
import unittest

from _support import panel_module

TARGET = "8.8.8.8"        # Cloudflare DNS — назван в реестре адресной гигиены
BEFORE1 = "8.8.4.4"       # Google DNS-запасной
BEFORE2 = "1.0.0.1"       # Cloudflare DNS-запасной
V6 = "2001:db8::1"        # документальный IPv6 (RFC 3849) — наружу не маршрутизируется


class Run:
    """Эмулятор ядра: держит список cidr и честно исполняет del/add/list."""

    def __init__(self, addrs, apply_rc=0, fail_del="", fail_add=""):
        self.addrs = list(addrs)
        self.apply_rc = apply_rc
        self.fail_del = fail_del
        self.fail_add = fail_add
        self.calls = []

    def run(self, args, **kw):
        self.calls.append(list(args))
        a = list(args)
        r = type("R", (), {})()
        if a[:3] == ["ip", "-o", "addr"]:
            r.returncode = 0
            r.stdout = "\n".join(
                "%d: net0    %s %s scope global net0"
                % (i, "inet6" if ":" in c else "inet", c)
                for i, c in enumerate(self.addrs, start=2))
            return r
        if a[:3] == ["ip", "addr", "del"]:
            if a[3] == self.fail_del:
                r.returncode = 2
                return r
            if a[3] in self.addrs:
                self.addrs.remove(a[3])
            r.returncode = 0
            return r
        if a[:3] == ["ip", "addr", "add"]:
            if a[3] == self.fail_add:
                r.returncode = 2
                return r
            self.addrs.append(a[3])
            r.returncode = 0
            return r
        if a[:2] == ["netplan", "apply"]:
            r.returncode = self.apply_rc
            return r
        r.returncode = 1
        return r


class KernelPrimarySyncTest(unittest.TestCase):
    def setUp(self):
        self.panel = panel_module()
        self.box = tempfile.mkdtemp(prefix="veil-netplan-")
        self._sub = self.panel.subprocess
        self._dir = self.panel.NETPLAN_DIR

    def tearDown(self):
        self.panel.subprocess = self._sub
        self.panel.NETPLAN_DIR = self._dir
        shutil.rmtree(self.box, ignore_errors=True)

    def stub(self, kernel):
        self.panel.subprocess = type("S", (), {"run": staticmethod(kernel.run)})

    # ---------------------------------------------------------------- синхронизация
    def test_moves_ahead_addresses_behind_target(self):
        k = Run([BEFORE1 + "/32", BEFORE2 + "/32", TARGET + "/32"])
        self.stub(k)
        rep = self.panel._kernel_primary_sync(TARGET, "net0")
        self.assertEqual(k.addrs[0], TARGET + "/32")
        self.assertIn("переложено 2", rep)
        # цель не снималась ни разу: её снятие убило бы живые соединения
        self.assertFalse([c for c in k.calls
                          if c[:3] == ["ip", "addr", "del"] and c[3] == TARGET + "/32"])

    def test_already_first_touches_nothing(self):
        k = Run([TARGET + "/32", BEFORE1 + "/32"])
        self.stub(k)
        rep = self.panel._kernel_primary_sync(TARGET, "net0")
        self.assertIn("уже первый", rep)
        self.assertEqual(k.addrs, [TARGET + "/32", BEFORE1 + "/32"])

    def test_ipv6_before_target_is_never_touched(self):
        """Публичный `/48` лежит перед целью в списке ядра — и всё равно не
        снимается: порядок IPv4-адресов IPv6-строка не задерживает, а его снятие
        на секунду оборвало бы весь v6-трафик клиентов."""
        k = Run([V6 + "/48", BEFORE1 + "/32", TARGET + "/32"])
        self.stub(k)
        rep = self.panel._kernel_primary_sync(TARGET, "net0")
        self.assertEqual(k.addrs, [V6 + "/48", TARGET + "/32", BEFORE1 + "/32"])
        self.assertIn("переложено 1", rep)
        self.assertFalse([c for c in k.calls if c[3] == V6 + "/48"])

    def test_only_ipv6_ahead_means_already_first_of_family(self):
        k = Run([V6 + "/48", TARGET + "/32"])
        self.stub(k)
        rep = self.panel._kernel_primary_sync(TARGET, "net0")
        self.assertIn("уже первый", rep)
        self.assertEqual(k.calls, [["ip", "-o", "addr", "list", "net0", "scope", "global"]])
        self.assertEqual(k.addrs, [V6 + "/48", TARGET + "/32"])

    def test_target_absent_is_named(self):
        k = Run([BEFORE1 + "/32"])
        self.stub(k)
        rep = self.panel._kernel_primary_sync(TARGET, "net0")
        self.assertIn("не найден", rep)
        self.assertEqual(k.addrs, [BEFORE1 + "/32"])

    def test_del_refusal_stops_with_name(self):
        k = Run([BEFORE1 + "/32", TARGET + "/32"], fail_del=BEFORE1 + "/32")
        self.stub(k)
        rep = self.panel._kernel_primary_sync(TARGET, "net0")
        self.assertIn("не удалось", rep)

    def test_add_refusal_is_named_dangerous(self):
        k = Run([BEFORE1 + "/32", TARGET + "/32"], fail_add=BEFORE1 + "/32")
        self.stub(k)
        rep = self.panel._kernel_primary_sync(TARGET, "net0")
        self.assertIn("ОПАСНО", rep)

    # ------------------------------------------------------------- полный путь правки
    def setUpFull(self):
        try:
            import yaml  # noqa: F401
        except Exception:
            self.skipTest("парсер yaml недоступен оболочке — fuller-ветку судит приватный cc48")

    def write_yaml(self, addrs):
        import yaml
        body = {"network": {"version": 2, "ethernets": {"net0": {
            "match": {"macaddress": "52:54:00:f1:ef:2e"},
            "set-name": "net0",
            "dhcp4": False,
            "addresses": [a + "/32" for a in addrs]}}}}
        self.panel.NETPLAN_DIR = self.box + os.sep
        with open(os.path.join(self.box, "99-test.yaml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(body, f, sort_keys=False)

    def test_fix_of_yaml_order_also_fixes_kernel(self):
        self.setUpFull()
        k = Run([BEFORE1 + "/32", TARGET + "/32"])
        self.stub(k)
        self.write_yaml([BEFORE1, TARGET])
        rep = self.panel._netplan_primary_fix(TARGET)
        self.assertIn("главный адрес", rep)
        self.assertIn("стал первым", rep)
        self.assertEqual(k.addrs[0], TARGET + "/32")

    def test_correct_yaml_but_stale_kernel_is_still_fixed(self):
        self.setUpFull()
        """Ветка «yaml уже верен» раньше молчала — именно она и подвела на бою:
        перевёрнутый при прошлой ротации файл не значил ничего, пока порядок
        в ядре остался прежний."""
        k = Run([BEFORE1 + "/32", TARGET + "/32"])
        self.stub(k)
        self.write_yaml([TARGET, BEFORE1])
        rep = self.panel._netplan_primary_fix(TARGET)
        self.assertIn("уже", rep)
        self.assertEqual(k.addrs[0], TARGET + "/32")

    def test_apply_refusal_leaves_kernel_alone(self):
        self.setUpFull()
        k = Run([BEFORE1 + "/32", TARGET + "/32"], apply_rc=1)
        self.stub(k)
        self.write_yaml([BEFORE1, TARGET])
        rep = self.panel._netplan_primary_fix(TARGET)
        self.assertIn("отклонено", rep)
        self.assertEqual(k.addrs[0], BEFORE1 + "/32")


if __name__ == "__main__":
    unittest.main()
