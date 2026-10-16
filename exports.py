#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 PE 导出表，正确处理 forwarder 与序号导出。"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8")


def parse(path):
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    secs = []
    so = opt + optsz
    for i in range(nsec):
        o = so + i * 40
        nm = d[o:o + 8].rstrip(b"\x00").decode("latin1")
        vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
        secs.append((nm, va, vs, ra, rs))

    def r2o(r):
        for nm, va, vs, ra, rs in secs:
            if va <= r < va + vs:
                return ra + (r - va)
        return None

    ddoff = opt + (0x60 if magic == 0x10B else 0x70)
    exp_rva, exp_sz = struct.unpack_from("<II", d, ddoff)
    if not exp_rva:
        return None, []
    ed = r2o(exp_rva)
    (flags, ts, maj, mn, nameRva, base, nfunc,
     nname, addrRva, nameRva2, ordRva) = struct.unpack_from("<IIHHIIIIIII", d, ed)

    def cstr(off):
        e = d.find(b"\x00", off)
        return d[off:e].decode("latin1")

    dllname = cstr(r2o(nameRva))
    ao, no2, oo = r2o(addrRva), r2o(nameRva2), r2o(ordRva)
    out = []
    for i in range(nname):
        nr = struct.unpack_from("<I", d, no2 + i * 4)[0]
        nm = cstr(r2o(nr))
        idx = struct.unpack_from("<H", d, oo + i * 2)[0]
        fr = struct.unpack_from("<I", d, ao + idx * 4)[0]
        fwd = ""
        if exp_rva <= fr < exp_rva + exp_sz:
            fwd = " -> " + cstr(r2o(fr))
        out.append((idx + base, nm, fr, fwd))
    return dllname, out


if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else \
        r"C:\Program Files (x86)\360\360Safe\deepscan\DSFScan.dll"
    dll, ex = parse(p)
    print("DLL: %s" % dll)
    print("导出数: %d" % len(ex))
    print()
    for ordn, nm, rva, fwd in sorted(ex, key=lambda x: x[2]):
        print("  ord=%-5d RVA=0x%06X  %-24s%s" % (ordn, rva, nm, fwd))