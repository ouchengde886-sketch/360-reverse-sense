#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 PE 的 .rdata/.data 读取指定 RVA 处的 GUID 表。"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8")


def secs_of(d):
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    so = pe + 24 + optsz
    out = []
    for i in range(nsec):
        o = so + i * 40
        nm = d[o:o + 8].rstrip(b"\x00").decode("latin1")
        vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
        out.append((nm, va, vs, ra, rs))
    return out


def r2o(secs, r):
    for nm, va, vs, ra, rs in secs:
        if va <= r < va + vs:
            return ra + (r - va)
    return None


def dump(path, rva, n=4):
    d = open(path, "rb").read()
    secs = secs_of(d)
    o = r2o(secs, rva)
    if o is None:
        print("  RVA 0x%X 不在任何节内" % rva)
        return
    print("RVA 0x%X -> 文件偏移 0x%X" % (rva, o))
    for i in range(n):
        g = d[o + i * 16:o + i * 16 + 16]
        if len(g) < 16:
            break
        d1, d2, d3 = struct.unpack_from("<IHH", g, 0)
        dw = struct.unpack_from("<IIII", g, 0)
        print("  #%d GUID: %08x-%04x-%04x-%s-%s" %
              (i + 1, d1, d2, d3, g[8:10].hex(), g[10:16].hex()))
        print("      DWORD: 0x%08X 0x%08X 0x%08X 0x%08X" % dw)
        print("      原始: %s" % " ".join("%02x" % x for x in g))


if __name__ == "__main__":
    p = sys.argv[1]
    for a in sys.argv[2:]:
        dump(p, int(a, 0))