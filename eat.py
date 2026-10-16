#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 PE 导出地址表（EAT），给出 名称 -> 真实 RVA 映射。

Ghidra 对导出名常生成 thunk（`return 0;`），真实实现在 EAT 指向的 RVA。
本脚本把 EAT 解出来，供 rea_q.py decomp 按地址反编译。
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8")


def sections(d):
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    opt_size = struct.unpack_from("<H", d, pe + 20)[0]
    sec_off = pe + 24 + opt_size
    out = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = d[o:o + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", d, o + 8)
        out.append((name, vaddr, vsize, raddr, rsize))
    return pe, opt_size, out


def r2o(secs, rva):
    for n, va, vs, ra, rs in secs:
        if rs and va <= rva < va + rs:
            return ra + (rva - va)
    return None


def eat(path):
    d = open(path, "rb").read()
    pe, opt_size, secs = sections(d)
    opt_off = pe + 24
    magic = struct.unpack_from("<H", d, opt_off)[0]
    is64 = magic == 0x20B
    dd = opt_off + (0x70 if is64 else 0x60)
    exp_rva, exp_size = struct.unpack_from("<II", d, dd)
    if not exp_rva:
        return {}
    off = r2o(secs, exp_rva)
    chars, tds, major, minor, name_rva, base, nfunc, nname, afunc, aname, aord = \
        struct.unpack_from("<IIHHIIIIIII", d, off)
    fo = r2o(secs, afunc)
    no = r2o(secs, aname)
    oo = r2o(secs, aord)
    res = {}
    for i in range(nname):
        nr = struct.unpack_from("<I", d, no + i * 4)[0]
        # AddressOfNameOrdinals is an index into AddressOfFunctions, and the
        # entries are NOT in name order -- resolve the export through its own
        # ordinal instead of assuming the i-th name owns the i-th function.
        ordi = struct.unpack_from("<H", d, oo + i * 2)[0]
        if ordi >= nfunc:
            continue
        frva = struct.unpack_from("<I", d, fo + ordi * 4)[0]
        n2 = r2o(secs, nr)
        if n2 is None:
            continue
        nm = d[n2:d.find(b"\0", n2)].decode("latin1", "replace")
        res[nm] = frva
    return res


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: eat.py <pe> [name-filter]")
        raise SystemExit
    m = eat(sys.argv[1])
    filt = sys.argv[2].lower() if len(sys.argv) > 2 else ""
    for k in sorted(m):
        if filt and filt not in k.lower():
            continue
        print("%-40s 0x%08X" % (k, m[k]))