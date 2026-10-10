#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Переезд подписчиков со старой панели (sqlite .db) в state.json нашей.

Читает старую базу только-только, пишет результат в --out (в живой state.json
не пишет никогда). Наружу — имена подписчиков, коды, числа; секреты (uuid,
пароли, ключи) не печатаются. Поддержка постквантового mldsa65 в старой базе
снимается отдельной строкой отчёта: ключи переезжают без него, ссылки таких
клиентов меняются (ядро на приёмник обязано понимать формат).

Употребление:
    python3 migrate_from_old_db.py --db СТАРАЯ.db --state state.json --dry-run
    python3 migrate_from_old_db.py --db СТАРАЯ.db --state state.json --out новый.json
"""
import argparse
import json
import sqlite3
import subprocess
import sys
import time
import uuid as uuidlib

# старый вход → наш ид входа (по протоколу, транспорту и безопасности)
MAP = {
    ("vless", "tcp", "reality"): "reality",
    ("vless", "xhttp", "reality"): "vless-xhttp-reality",
    ("trojan", "tcp", "reality"): "trojan-reality",
    ("wireguard", None, None): "wireguard",
}
# без эквивалента в нашей матрице — названный пропуск
NO_EQUIV = {
    ("hysteria", "hysteria", None): "hysteria1: наша матрица знает hysteria2 — формат узла другой",
}


def old_inbounds(db):
    out = {}
    for iid, port, proto, en, strm_raw, set_raw in db.execute(
            "select id,port,protocol,enable,stream_settings,settings from inbounds"):
        try:
            strm = json.loads(strm_raw or "{}")
        except Exception:
            strm = {}
        try:
            setts = json.loads(set_raw or "{}")
        except Exception:
            setts = {}
        out[iid] = {"port": port, "proto": proto, "net": strm.get("network"),
                    "sec": strm.get("security"), "enable": bool(en),
                    "stream": strm, "settings": setts}
    return out


def ours_key(ib):
    return (ib["proto"], ib["net"] or None, ib["sec"] or None)


def ours_key_loose(ib):
    k = ours_key(ib)
    return MAP.get(k) or MAP.get((k[0], k[1], None))


def reality_carve(stream):
    """Ключи reality для переноса: приватный, публичный, shortIds, sni, dest."""
    rs = stream.get("realitySettings") or {}
    inner = rs.get("settings") or {}
    return {
        "private_key": rs.get("privateKey") or "",
        "public_key": inner.get("publicKey") or rs.get("publicKey") or "",
        "sids": [str(x) for x in (rs.get("shortIds") or []) if str(x)],
        "sni": (rs.get("serverNames") or [""])[0] or "",
        "dest": rs.get("dest") or "",
        "mldsa": bool(rs.get("mldsa65Seed") or inner.get("mldsa65Verify")),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--out", default="")
    ap.add_argument("--carry-ports", action="store_true",
                    help="перенести номера портов старых входов (иначе ссылки клиентов меняются по адресу)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if not a.dry_run and not a.out:
        print("без --out писать некуда: или --dry-run, или --out ФАЙЛ"); return 2

    db = sqlite3.connect("file:%s?mode=ro" % a.db, uri=True)
    st = json.load(open(a.state, encoding="utf-8"))
    inbs = st.get("inbounds") or {}
    obs = old_inbounds(db)

    # карта старый вход → наш вход + переносимые ключи
    plan, skipped_in, carry, old_ports, wgsrc = {}, {}, {}, {}, {}
    for iid, ib in obs.items():
        if not ib["enable"]:
            skipped_in[iid] = "выключен на старой панели"
            continue
        our = ours_key_loose(ib)
        if our is None:
            k = ours_key(ib)
            skipped_in[iid] = NO_EQUIV.get(k) or NO_EQUIV.get((k[0], k[1], None)) or \
                "нет нашей пары для (%s,%s,%s)" % k
            continue
        if our not in inbs:
            skipped_in[iid] = "наш вход «%s» не заведён — включите протокол до переезда" % our
            continue
        plan[iid] = our
        if ib["sec"] == "reality":
            c = reality_carve(ib["stream"])
            if not c["private_key"] or not c["public_key"]:
                skipped_in[iid] = "у старого входа нет ключей reality"
                del plan[iid]
                continue
            carry[our] = c
        if our == "wireguard":
            # пиры живут в settings.peers старой базы, а не в таблице clients:
            # переносим серверную пару и каждый пир дословно, иначе устройства
            # проснутся без туннеля (слово хозяина: wg переносить 1в1)
            wgsrc[our] = ib["settings"]
        if ib["port"]:
            old_ports[our] = ib["port"]

    # люди: покрытие по client_inbounds, недостающее — по типу секрета
    creds = {}
    for cid, email, sub, uu, pw, auth, wgp, enabled, tgb, exp, lip in db.execute(
            "select id,email,sub_id,uuid,password,auth,wg_private_key,enable,"
            "total_gb,expiry_time,limit_ip from clients"):
        creds[cid] = {"email": email, "sub": sub, "uuid": uu, "pw": pw,
                      "auth": auth, "wg": wgp, "on": bool(enabled),
                      "tgb": tgb, "exp": exp, "lip": lip}
    links = {}
    for cid, iid in db.execute("select client_id,inbound_id from client_inbounds"):
        links.setdefault(cid, []).append(iid)

    now = int(time.time())
    added, skipped_p = [], []
    per_proto = {}
    for cid, c in creds.items():
        if not c["on"]:
            skipped_p.append((c["email"], "выключен на старой панели"))
            continue
        my_links = [i for i in links.get(cid, []) if i in plan]
        if not links.get(cid):
            # покрытие черпается из типа секрета: uuid → vless, pw → trojan и т.п.
            guess = None
            if c["uuid"]:
                guess = "reality"
            elif c["pw"]:
                guess = "trojan-reality"
            elif c["auth"]:
                skipped_p.append((c["email"], "без покрытия: hysteria1 — эквивалента нет"))
                continue
            elif c["wg"]:
                guess = "wireguard"
            if guess is None:
                skipped_p.append((c["email"], "без покрытия: протокол не угадан"))
                continue
            target_iid = next((i for i, o in plan.items() if o == guess), None)
            if target_iid is None:
                skipped_p.append((c["email"], "без покрытия: наш вход «%s» не участвует" % guess))
                continue
            my_links = [target_iid]
            added_note = "по типу секрета"
        else:
            added_note = "по покрытию"
        if not my_links:
            skipped_p.append((c["email"], "висящий на пропущенном входе"))
            continue
        for iid in my_links:
            our = plan[iid]
            rec = {"uuid": c["uuid"] or str(uuidlib.uuid4()),
                   "name": c["email"],
                   "sub_token": c["sub"] or uuidlib.uuid4().hex[:16],
                   "created": now,
                   "limit_gb": round(float(c["tgb"] or 0) / 2**30, 2),
                   "expiry": int(c["exp"] or 0) // 1000,
                   "reset_cycle": "", "cycle": "", "up": 0, "down": 0,
                   "max_devices": int(c["lip"] or 0)}
            if our == "wireguard" and not c["wg"]:
                skipped_p.append((c["email"], "wireguard: ключей пары в базе нет"))
                continue
            if our.startswith("trojan"):
                # пароль — то, что несёт ссылку трояна; без него запись мертва
                rec["password"] = c["pw"] or uuidlib.uuid4().hex[:24]
            exist = (inbs[our].get("clients") or [])
            if any(isinstance(x, dict) and x.get("uuid") == rec["uuid"] for x in exist):
                skipped_p.append((c["email"], "уже есть в целевом входе — не дублируем"))
                continue
            exist.append(rec)
            inbs[our]["clients"] = exist
            per_proto[our] = per_proto.get(our, 0) + 1
            added.append((c["email"], our, added_note))

    # #282: таблица `clients` — не весь список. Живой состав старой панели лежит
    # в блобе `settings` самого входа (промерено на свежей копии боевой базы:
    # из 49 подписчиков в таблице только 20). Кто не в таблице и не в
    # `client_inbounds`, тем некуда крепиться, — орудие брало их по ключу секрета
    # прямо из блоба признанного входа; лимиты и срок переезжают тем же порядком.
    table_keys = set()
    for c in creds.values():
        for k in (c["uuid"], c["pw"]):
            if k:
                table_keys.add(str(k))
    n_blob = 0
    for iid, our in sorted(plan.items()):
        if our == "wireguard":
            continue
        for x in obs[iid]["settings"].get("clients") or []:
            if not isinstance(x, dict):
                continue
            key = str(x.get("id") or x.get("password") or "").strip()
            if not key:
                skipped_p.append((str(x.get("email") or "?"), "в блобе входа нет секрета"))
                continue
            if key in table_keys:
                continue
            if x.get("enable") is False:
                skipped_p.append((str(x.get("email") or "?"), "выключен в блобе входа"))
                continue
            tj = our.startswith("trojan")
            rec = {"uuid": str(uuidlib.uuid4()) if tj else key,
                   "name": str(x.get("email") or "").strip() or "переехавший",
                   "sub_token": str(x.get("subId") or "").strip() or uuidlib.uuid4().hex[:16],
                   "created": now,
                   "limit_gb": round(float(x.get("totalGB") or 0) / 2**30, 2),
                   "expiry": int(x.get("expiryTime") or 0) // 1000,
                   "reset_cycle": "", "cycle": "", "up": 0, "down": 0,
                   "max_devices": int(x.get("limitIp") or 0)}
            if tj:
                rec["password"] = key
            exist = inbs[our].get("clients") or []
            if any(isinstance(y, dict) and (y.get("uuid") == rec["uuid"] or
                                            (tj and y.get("password") == key)) for y in exist):
                skipped_p.append((rec["name"], "уже есть в целевом входе — не дублируем"))
                continue
            exist.append(rec)
            inbs[our]["clients"] = exist
            per_proto[our] = per_proto.get(our, 0) + 1
            n_blob += 1

    # перенос reality-ключей в целевые входы
    carried = []
    for our, c in carry.items():
        ib = inbs[our]
        if c.get("private_key"):
            ib["private_key"] = c["private_key"]
            ib["public_key"] = c["public_key"]
            if c["sids"]:
                ib["sids"] = c["sids"]
            if c["sni"]:
                ib["sni"] = c["sni"]
            if c["dest"]:
                ib["dest"] = c["dest"]
            carried.append((our, c["mldsa"]))
    ports_carried = []
    if a.carry_ports:
        for our, p in old_ports.items():
            if our in inbs and p:
                inbs[our]["port"] = p
                ports_carried.append((our, p))

    # wireguard: серверная пара и пиры из settings старой базы — дословно.
    # Устройства не меняют конфиг: публичный ключ сервера обязано вернуть то же
    # секретное, поэтому открытый считаем орудием `wg`, а не додумываем.
    wg_moved = None
    if wgsrc:
        our_wg = next(iter(wgsrc))
        s = wgsrc[our_wg] or {}
        secret = s.get("secretKey") or ""
        peers = s.get("peers") or []
        if not secret:
            wg_moved = ("отказ", "у старого wireguard-входа нет secretKey", 0, 0)
        else:
            try:
                r = subprocess.run(["wg", "pubkey"], input=secret.encode(),
                                   capture_output=True, timeout=10)
                pub = r.stdout.decode().strip()
            except FileNotFoundError:
                pub = ""
            if len(pub) != 44 or not pub.endswith("="):
                wg_moved = ("отказ", "нет орудия `wg` (поставьте wireguard-tools) — открытый ключ не вычислен", 0, 0)
            else:
                ib = inbs[our_wg]
                ib["private_key"] = secret
                ib["public_key"] = pub
                if s.get("mtu"):
                    ib["mtu"] = int(s["mtu"])
                addrs_inb = s.get("address") or []
                if addrs_inb:
                    # панель хранит адрес одиночной строкой (двойной список
                    # уехал бы в конфиг ядра вложенным массивом)
                    ib["address"] = str(addrs_inb[0] if isinstance(addrs_inb, list) else addrs_inb)
                exist = ib.get("clients") or []
                have_pub = {x.get("client_public_key") for x in exist if isinstance(x, dict)}
                n_max = 0
                n_new = n_nok = 0
                for p in peers:
                    if not isinstance(p, dict):
                        continue
                    pk = str(p.get("publicKey") or "").strip()
                    if not pk or pk in have_pub:
                        continue
                    v4 = [a for a in (p.get("allowedIPs") or []) if a and ":" not in a]
                    addr = (v4[0] if v4 else "") or ""
                    rec = {"uuid": str(uuidlib.uuid4()),
                           "name": "wg " + (addr.split("/")[0] if addr else pk[:8]),
                           "sub_token": uuidlib.uuid4().hex[:16],
                           "created": now, "limit_gb": 0.0, "expiry": 0,
                           "reset_cycle": "", "cycle": "", "up": 0, "down": 0,
                           "max_devices": 0,
                           "client_public_key": pk}
                    if addr:
                        rec["address"] = addr if "/" in addr else addr + "/32"
                        try:
                            n_max = max(n_max, int(addr.split("/")[0].rsplit(".", 1)[-1]))
                        except ValueError:
                            pass
                    priv = str(p.get("privateKey") or "").strip()
                    if priv:
                        rec["client_private_key"] = priv
                    else:
                        n_nok += 1
                    exist.append(rec)
                    have_pub.add(pk)
                    n_new += 1
                ib["clients"] = exist
                cur = int(ib.get("next_address") or 0)
                if n_max + 1 > cur:
                    ib["next_address"] = n_max + 1
                wg_moved = ("перенос", "", n_new, n_nok)

    print("=== отчёт переезда ===")
    print("старых входов:", len(obs), "признано:", len(plan), "пропущено:", len(skipped_in))
    for iid, why in skipped_in.items():
        print("  вход %s (%s): %s" % (iid, obs[iid]["proto"], why))
    print("перенесено записей по входам:", json.dumps(per_proto, ensure_ascii=False))
    if n_blob:
        print("из них дополучено из блобов settings входа, вне таблицы (%d)" % n_blob)
    print("пропущено людей:", len(skipped_p))
    for e, why in skipped_p:
        print("  %s: %s" % (e, why))
    for our, mldsa in carried:
        note = " — вход нёс mldsa65, ссылки таких клиентов меняются" if mldsa else ""
        print("ключи reality перенесены в «%s»%s" % (our, note))
    for our, p in ports_carried:
        print("порт %s перенесён в «%s»" % (p, our))
    if wg_moved:
        kind, why, n_new, n_nok = wg_moved
        if kind == "отказ":
            print("wireguard: ПЕРЕНОС ОТМЕНЁН — %s" % why)
        else:
            msg = "wireguard: серверная пара и пиры перенесены дословно (%d)" % n_new
            if n_nok:
                msg += (", %d пира без приватного ключа — их устройства работают, "
                        "новую ссылку панель соберёт только после поворота" % n_nok)
            print(msg)
    dupes = {}
    for our in per_proto:
        seen = set()
        n = 0
        for x in inbs[our].get("clients") or []:
            if isinstance(x, dict) and x.get("sub_token"):
                if x["sub_token"] in seen:
                    n += 1
                seen.add(x["sub_token"])
        if n:
            dupes[our] = n
    if dupes:
        print("ВНИМАНИЕ: повторяющихся sub_token внутри входа:", dupes)

    if a.dry_run:
        print("пробник: ничего не записано")
        return 0
    if a.out == a.state:
        print("--out совпадает с --state: живой файл не трогаем"); return 2
    out = json.dumps(st, ensure_ascii=False, indent=1)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(out)
    import os
    os.chmod(a.out, 0o600)
    print("записано:", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
