#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""汇总 static_out 的接口/自保护证据，输出可读报告。"""
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")

OUT = "static_out"

# 关注的安全相关二进制
FOCUS = [
    "360SelfProtection.sys", "360SelfProtection_win10.sys",
    "qutmdrv.sys", "qutmdrv_win10.sys", "qutmipc.sys", "qutmipc_win10.sys",
    "360FsFlt_win10.sys", "360AntiSteal.sys", "360AntiHijack.sys",
    "360AntiExploit.sys", "hookport.sys", "360disproc.sys",
    "360Box.sys", "360Box64.sys", "360Camera.sys",
    "SelfProtectAPI2.dll", "360SPTool.exe", "360Tray.exe",
    "safemon.dll", "360hipsPopWnd.dll", "360GuardBase.dll",
    "360procmon.dll", "360trayexit.dll", "ZhuDongFangYu.exe",
    "360Quarant.dll", "DSMain.exe", "deepscan.dll", "avescan.dll",
    "DSFScan.dll", "CloudEngine.dll", "cloudcom2.dll",
    "360Safe.exe", "uninst.exe", "360AppLoader.exe",
]


def load(name):
    p = os.path.join(OUT, name + ".json")
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def uniq(*lists):
    s = []
    seen = set()
    for l in lists:
        for v in l or []:
            if v not in seen:
                seen.add(v)
                s.append(v)
    return s


def main():
    print("#" * 78)
    print("# 360 安全卫士 —— 外部接口 / 自保护 静态取证汇总")
    print("#" * 78)

    for n in FOCUS:
        d = load(n)
        if d is None:
            continue
        ca = d.get("classified_ascii", {})
        cu = d.get("classified_utf16", {})

        dev = uniq(ca.get("device"), cu.get("device"))
        dos = uniq(ca.get("dosdevice"), cu.get("dosdevice"))
        short = uniq(ca.get("dosdev_short"), cu.get("dosdev_short"))
        base = uniq(ca.get("basedobj"), cu.get("basedobj"))
        reg = uniq(ca.get("regpath"), cu.get("regpath"))
        kern = uniq(ca.get("kernelobj"), cu.get("kernelobj"))
        guid = uniq(ca.get("guid"), cu.get("guid"))

        # 只保留安全相关的设备名（过滤 360 无关噪声）
        dev = [x for x in dev if len(x) < 80]
        dos = [x for x in dos if len(x) < 80]
        short = [x for x in short if len(x) < 80]

        interesting = bool(dev or dos or short or base or reg or kern)
        if not interesting and not d.get("exports") and not d.get("key_apis"):
            continue

        print("\n" + "=" * 78)
        print("## %s   [%s]  %d bytes" % (n, d.get("machine"), d["size"]))
        if d.get("dll_name"):
            print("   PE name: %s" % d["dll_name"])

        if d.get("exports"):
            print("   [导出] %s" % ", ".join(d["exports"][:40]))

        if d.get("key_apis"):
            print("   [内核自保护 API]")
            for k, v in d["key_apis"].items():
                print("      %-42s %s" % (k, v))
        if d.get("key_user_apis"):
            print("   [用户态关键 API]")
            for k, v in d["key_user_apis"].items():
                print("      %-42s %s" % (k, v))

        if dev:
            print("   [设备对象 \\Device\\*]")
            for x in dev:
                print("      %s" % x)
        if dos:
            print("   [符号链接 \\DosDevices\\*]")
            for x in dos:
                print("      %s" % x)
        if short:
            print("   [DOS 路径 \\\\.\\*]")
            for x in short:
                print("      %s" % x)
        if base:
            print("   [命名对象 \\BaseNamedObjects\\*]")
            for x in base[:20]:
                print("      %s" % x)
        if kern:
            print("   [内核对象路径]")
            for x in kern[:20]:
                print("      %s" % x)
        if reg:
            print("   [注册表路径]")
            for x in reg[:25]:
                print("      %s" % x)
        if guid:
            print("   [GUID]")
            for x in guid[:12]:
                print("      %s" % x)

        if d.get("import_dlls"):
            print("   [依赖 DLL] %s" % ", ".join(d["import_dlls"]))


if __name__ == "__main__":
    main()