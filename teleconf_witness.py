#!/usr/bin/env python3
"""Свидетель стирателя блока цензуры (#258, долг #176).

Опрашивает каждые ~150 мс файл /etc/telemt/telemt.toml (mtime, размер, sha256)
и mtime каталога /etc/telemt — каталог ловит атомарную замену через rename.
На каждое изменение перечисляет держателей файла/каталога по /proc/*/fd и
процессы, запущенные менее 120 с назад. В журнал пишутся только comm, exe,
pid, ppid — никогда cmdline (в аргументах бывают секреты).
"""
import hashlib
import os
import sys
import time

TARGET = "/etc/telemt/telemt.toml"
DIR = "/etc/telemt"
LOG = "/opt/vpnpanel/logs/teleconf-witness.log"
POLL_S = 0.15
RECENT_S = 120.0


def sha256(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()[:16]
    except FileNotFoundError:
        return "нет-файла"
    except OSError as exc:
        return "ошибка:%s" % exc.errno


def snap():
    st = None
    h = ""
    try:
        st = os.stat(TARGET)
        h = sha256(TARGET)
    except FileNotFoundError:
        pass
    try:
        d = os.stat(DIR)
        dm = d.st_mtime_ns
    except OSError:
        dm = -1
    key = (st.st_mtime_ns if st else -1, st.st_size if st else -1, h, dm)
    return key


def now_ms():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + \
        ".%03dZ" % int(time.time() % 1 * 1000)


def proc_start_secs(pid):
    try:
        with open("/proc/%s/stat" % pid) as fh:
            fields = fh.read().rsplit(")", 1)[1].split()
        starttime_ticks = int(fields[19])
        with open("/proc/uptime") as fh:
            uptime = float(fh.read().split()[0])
        return uptime - starttime_ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError, ValueError):
        return None


def read_comm(pid):
    try:
        with open("/proc/%s/comm" % pid) as fh:
            return fh.read().strip()
    except OSError:
        return "?"


def read_exe(pid):
    try:
        return os.readlink("/proc/%s/exe" % pid)
    except OSError:
        return "?"


def read_ppid(pid):
    try:
        with open("/proc/%s/stat" % pid) as fh:
            fields = fh.read().rsplit(")", 1)[1].split()
        return fields[1]
    except (OSError, IndexError):
        return "?"


def holders(target_paths):
    out = []
    tdir = DIR.encode()
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_dir = "/proc/%s/fd" % pid
        try:
            for fd in os.listdir(fd_dir):
                try:
                    link = os.readlink(os.path.join(fd_dir, fd)).encode()
                except OSError:
                    continue
                if link in target_paths or link.startswith(tdir + b"/"):
                    out.append((pid, fd, link.decode(errors="replace")))
                    break
        except OSError:
            continue
    return out


def recent_procs():
    out = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        age = proc_start_secs(pid)
        if age is not None and age < RECENT_S:
            out.append((pid, round(age, 1)))
    return out


def main():
    prev = None
    first = True
    with open(LOG, "a", encoding="utf-8") as log:
        log.write("%s witness старт pid=%d\n" % (now_ms(), os.getpid()))
        log.flush()
        while True:
            try:
                cur = snap()
            except Exception as exc:
                log.write("%s witness ошибка замера: %r\n" % (now_ms(), exc))
                log.flush()
                cur = None
            if cur is not None and not first and cur != prev:
                paths = set()
                try:
                    paths.add(os.readlink(TARGET))
                except OSError:
                    pass
                paths.add(TARGET)
                log.write("%s ИЗМЕНЕНИЕ prev=%s cur=%s\n" %
                          (now_ms(), prev, cur))
                for pid, fd, link in holders(paths):
                    log.write("  держатель pid=%s ppid=%s fd=%s link=%s "
                              "comm=%s exe=%s\n" %
                              (pid, read_ppid(pid), fd, link,
                               read_comm(pid), read_exe(pid)))
                for pid, age in recent_procs():
                    log.write("  свежий pid=%s ppid=%s возраст=%.1fs comm=%s "
                              "exe=%s\n" %
                              (pid, read_ppid(pid), age, read_comm(pid),
                               read_exe(pid)))
                log.flush()
            prev = cur
            first = False
            time.sleep(POLL_S)


if __name__ == "__main__":
    sys.exit(main())
