#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 360SelfProtection.sys 的 IOCTL 码解析成 CTL_CODE 字段。"""
import sys

sys.stdout.reconfigure(encoding="utf-8")

CODES = [
    0x222000, 0x222004, 0x222008, 0x22200c, 0x222010, 0x222014,
    0x222020, 0x222021, 0x222024, 0x222034, 0x222038, 0x22203c,
    0x222040, 0x222044, 0x22204c, 0x22204d, 0x222050, 0x222054,
    0x222080, 0x222084, 0x22208c, 0x222090, 0x222094, 0x222095,
    0x222098, 0x22209c, 0x2220a0, 0x2220a4, 0x2220a8, 0x2220ac,
]

METHOD = {0: "METHOD_BUFFERED", 1: "METHOD_IN_DIRECT",
          2: "METHOD_OUT_DIRECT", 3: "METHOD_NEITHER"}
ACCESS = {0: "FILE_ANY_ACCESS", 1: "FILE_READ_ACCESS",
          2: "FILE_WRITE_ACCESS", 3: "FILE_READ|WRITE_ACCESS"}

print("360SelfProtection.sys  IOCTL 表（CTL_CODE 解码）")
print("=" * 78)
print("%-12s %-8s %-6s %-6s %-22s %s" % ("IOCTL", "DevType", "Func", "Meth", "Method", "Access"))
print("-" * 78)
for c in CODES:
    dev = (c >> 16) & 0xFFFF
    acc = (c >> 14) & 0x3
    fn = (c >> 2) & 0xFFF
    meth = c & 0x3
    print("0x%08X   0x%04X   %-6d %-6d %-22s %s"
          % (c, dev, fn, meth, METHOD[meth], ACCESS[acc]))

print()
print("说明：")
print("  DeviceType 0x0022 = FILE_DEVICE_UNKNOWN 的自定义区（360 自选）")
print("  函数号按功能分组：")
print("    0x000-0x015  基础查询/设置（文件、进程、规则）")
print("    0x008        0x222020 自保护总开关（0=关 1=开）★")
print("    0x013        0x22204c 查询 PID 是否受保护 ★")
print("    0x020-0x02B  扩展接口")
print()
print("★ 关键：0x222020 与 0x22204c 是自保护开关与状态查询，")
print("   与 360procmon.dll 的 IsSelfProtectOn / OffSelfProtect 对应。")