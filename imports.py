#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""列出 PE 的导入 DLL 与导出名，用于判断模块职责。"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8")


def _r2o(secs, r):
    for va, vs, ra, rs in secs:
        if va <= r < va + vs:
            return ra + (r - va)
    return None


def imports(path):
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    ddoff = opt + (0x60 if magic == 0x10B else 0x70)
    imp_rva = struct.unpack_from("<I", d, ddoff + 8)[0]
    so = opt + optsz
    secs = []
    for i in range(nsec):
        o = so + i * 40
        vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
        secs.append((va, vs, ra, rs))
    if not imp_rva:
        return []
    o = _r2o(secs, imp_rva)
    out = []
    while True:
        ent = d[o:o + 20]
        if len(ent) < 20 or ent == b"\x00" * 20:
            break
        _, _, _, nrva, _ = struct.unpack_from("<IIIII", ent)
        if nrva == 0:
            break
        no = _r2o(secs, nrva)
        e = d.find(b"\x00", no)
        out.append(d[no:e].decode("latin1"))
        o += 20
    return out


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print("=== %s ===" % p.split("\\")[-1])
        for n in imports(p):
            print("   ", n)
        print()