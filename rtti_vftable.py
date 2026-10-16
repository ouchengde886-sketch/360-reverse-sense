#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通过 MSVC RTTI 定位类的 vftable。

RTTI 布局（x86）：
  TypeDescriptor: vftable_ptr, spare, name(".?AV<Class>@@")
  CompleteObjectLocator: signature, offset, cdOffset, pTypeDescriptor, pClassDescriptor
  vftable[-1] = &CompleteObjectLocator

本脚本扫描 .rdata 找 TypeDescriptor，再找引用它的 COL，最后找指向 COL 的 vftable。
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, ".")
import eat  # noqa: E402


def main():
    path = sys.argv[1]
    cls = sys.argv[2] if len(sys.argv) > 2 else "CSelfProcAPI"

    d = open(path, "rb").read()
    pe, opt_size, secs = eat.sections(d)
    opt_off = pe + 24
    ib = struct.unpack_from("<I", d, opt_off + 28)[0]

    needle = (".?AV" + cls + "@@").encode("latin1")
    i = d.find(needle)
    if i < 0:
        print("RTTI name not found:", cls)
        return
    # TypeDescriptor starts 8 bytes before the name
    td_off = i - 8
    td_rva = None
    for n, va, vs, ra, rs in secs:
        if ra <= td_off < ra + rs:
            td_rva = va + (td_off - ra)
    print("TypeDescriptor '%s' file=0x%X rva=0x%X" % (cls, td_off, td_rva))

    td_va = ib + td_rva
    pat = struct.pack("<I", td_va)
    print("searching COL referencing 0x%08X ..." % td_va)
    for m in range(len(d) - 4):
        if d[m:m + 4] != pat:
            continue
        # COL: signature(4) offset(4) cdOffset(4) pTD(4) pCD(4)
        if m < 12:
            continue
        sig = struct.unpack_from("<I", d, m - 12)[0]
        if sig != 0:
            continue
        col_off = m - 12
        col_rva = None
        for n, va, vs, ra, rs in secs:
            if ra <= col_off < ra + rs:
                col_rva = va + (col_off - ra)
        col_va = ib + col_rva
        print("  COL at file=0x%X rva=0x%X va=0x%08X" % (col_off, col_rva, col_va))
        # vftable[-1] points to COL
        cpat = struct.pack("<I", col_va)
        for k in range(len(d) - 4):
            if d[k:k + 4] == cpat:
                vt_rva = None
                for n, va, vs, ra, rs in secs:
                    if ra <= k < ra + rs:
                        vt_rva = va + (k - ra)
                print("    vftable[-1] at file=0x%X rva=0x%X -> slots start rva=0x%X"
                      % (k, vt_rva, vt_rva + 4))
                off = k + 4
                for s in range(12):
                    v = struct.unpack_from("<I", d, off + s * 4)[0]
                    print("      slot[%2d] vtable+0x%02X -> 0x%08X" % (s, s * 4, v))


if __name__ == "__main__":
    main()