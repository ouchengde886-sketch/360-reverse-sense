# -*- coding: utf-8 -*-
"""正确的 PE 导出表解析（处理 forwarder 与序号）。"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8")


def parse(path):
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    magic = struct.unpack_from("<H", d, pe + 24)[0]
    so = pe + 24 + optsz
    secs = []
    for i in range(nsec):
        vs, va, rs, ra = struct.unpack_from("<IIII", d, so + i * 40 + 8)
        secs.append((va, vs, ra, rs))

    def r2o(r):
        for va, vs, ra, rs in secs:
            if va <= r < va + vs:
                return ra + (r - va)
        return None

    # data directory 0 = export；32 位 PE 偏移 96，64 位偏移 112
    ddoff = pe + 24 + (96 if magic == 0x10B else 112)
    ed_rva, ed_sz = struct.unpack_from("<II", d, ddoff)
    if not ed_rva:
        return []
    o = r2o(ed_rva)
    nfun = struct.unpack_from("<I", d, o + 20)[0]
    nnam = struct.unpack_from("<I", d, o + 24)[0]
    afun = struct.unpack_from("<I", d, o + 28)[0]
    anames = struct.unpack_from("<I", d, o + 32)[0]
    aords = struct.unpack_from("<I", d, o + 36)[0]
    base = struct.unpack_from("<I", d, o + 16)[0]
    fo = r2o(afun)
    ao = r2o(anames)
    oo = r2o(aords)
    ed_end = ed_rva + ed_sz

    res = []
    for i in range(nnam):
        nr = struct.unpack_from("<I", d, ao + i * 4)[0]
        no = r2o(nr)
        e = d.index(b"\0", no)
        nm = d[no:e].decode("ascii", "replace")
        ordi = struct.unpack_from("<H", d, oo + i * 2)[0]
        fr = struct.unpack_from("<I", d, fo + ordi * 4)[0]
        # forwarder：RVA 落在导出目录范围内
        if ed_rva <= fr < ed_end:
            fno = r2o(fr)
            fe = d.index(b"\0", fno)
            tgt = d[fno:fe].decode("ascii", "replace")
            res.append((nm, None, tgt))
        else:
            res.append((nm, fr, None))
    return res


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print("=" * 70)
        print(p)
        print("=" * 70)
        try:
            ex = parse(p)
        except Exception as ex2:
            print("  parse error:", ex2)
            continue
        for nm, rva, fwd in sorted(ex):
            if fwd:
                print("  %-42s -> %s" % (nm, fwd))
            else:
                print("  %-42s RVA 0x%X" % (nm, rva))
        print("  (共 %d 个)" % len(ex))
        print()