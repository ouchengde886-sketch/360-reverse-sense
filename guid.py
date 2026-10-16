#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 PE 的 .rdata 读取指定 RVA 处的 GUID，并转成标准字符串形式。

用途：cloudcom2!CreateObject 会把入参与 DAT_10173b38 / DAT_10173ad0 两个
12 字节常量比较 —— 它们是 GUID（CLSID/IID），需要还原成可读形式。

用法: guid.py <pe> <rva-hex> [<rva-hex> ...]
"""
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, ".")
import eat  # noqa: E402


def fmt_guid(b):
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    d4 = b[8:10]
    d5 = b[10:16]
    return "{%08X-%04X-%04X-%s-%s}" % (
        d1, d2, d3, d4.hex().upper(), d5.hex().upper())


def main():
    path = sys.argv[1]
    d = open(path, "rb").read()
    pe, opt_size, secs = eat.sections(d)
    ib = struct.unpack_from("<I", d, pe + 24 + 28)[0]
    for arg in sys.argv[2:]:
        rva = int(arg, 16)
        off = eat.r2o(secs, rva)
        if off is None:
            print("0x%X not mapped" % rva)
            continue
        raw = d[off:off + 16]
        print("rva 0x%X (va 0x%X) raw=%s" % (rva, ib + rva, raw.hex()))
        print("   GUID = %s" % fmt_guid(raw))
        # 同时打印宽字符形式，便于在字符串表里定位
        try:
            print("   ascii = %r" % raw.decode("latin1"))
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    main()