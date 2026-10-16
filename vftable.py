#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 PE 中某个 vftable 的槽位（RVA 列表），用于还原 C++ 接口。

用法: vftable.py <pe> <vftable-rva-hex> [slots]
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, ".")
import eat  # noqa: E402


def main():
    path = sys.argv[1]
    vt_rva = int(sys.argv[2], 16)
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 16

    d = open(path, "rb").read()
    pe, opt_size, secs = eat.sections(d)
    opt_off = pe + 24
    ib = struct.unpack_from("<I", d, opt_off + 28)[0]

    off = eat.r2o(secs, vt_rva)
    if off is None:
        print("vftable RVA %x not mapped" % vt_rva)
        return
    print("vftable RVA 0x%X -> file 0x%X, image base 0x%X" % (vt_rva, off, ib))
    for i in range(n):
        v = struct.unpack_from("<I", d, off + i * 4)[0]
        print("  slot[%2d] vtable+0x%02X -> 0x%08X" % (i, i * 4, v))


if __name__ == "__main__":
    main()