#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
360 拦截状态（主动防御 / 自我保护）查询工具。

依据 REA 逆向结论（见 FINDINGS.md 第 1、3、4 节）：
  * 自我保护状态：SelfProtectAPI2.dll!APICreateObjectSelfProc(5, &obj) 后
    调 CSelfProcAPI::vtable+0x20，最终走
    ZwQuerySystemInformation(SystemInformationClass=0x36059002)。
  * 自我保护设备：\\\\.\\360SelfProtection，控制码 0x22204C 查询 PID 是否受保护。
  * 主动防御拦截开关：注册表
    HKLM\\SOFTWARE\\WOW6432Node\\360Safe\\safemon 下的一组 *Access 值
    （ExecAccess / MonAccess / FileMonAccess / AppMonAccess / DrvFWAccess /
      UDiskAccess / IEProtAccess / SiteAccess / DnsMonAccess / VulnMonAccess /
      OutwardAtkMonAccess / NetDefender / TpiDriverWorkOpen / NewExec /
      BitcoinMiner / SB_State / svcMon / LockUnknown ...）。
  * 主动防御服务：ZhuDongFangYu（服务名 ZhuDongFangYu），IPC \\\\.\\qutmipc。

本脚本汇总以上全部可观测状态，输出人类可读报告 + JSON。

用法:
  python query_intercept_state.py            # 打印报告
  python query_intercept_state.py --json     # 输出 JSON
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")

SAFEMON_KEY = r"SOFTWARE\WOW6432Node\360Safe\safemon"
SAFEMON_KEY64 = r"SOFTWARE\360Safe\safemon"

# 注册表值 -> 中文含义（据名称与 360 行为推断）
ACCESS_FLAGS = {
    "ExecAccess": "程序执行监控",
    "MonAccess": "文件监控",
    "FileMonAccess": "文件监控(细项)",
    "AppMonAccess": "程序行为监控",
    "DrvFWAccess": "驱动防火墙",
    "DrvFWAccess2": "驱动防火墙(细项)",
    "UDiskAccess": "U盘防护",
    "IEProtAccess": "IE 防护",
    "SiteAccess": "网站/网址防护",
    "DnsMonAccess": "DNS 监控",
    "VulnMonAccess": "漏洞监控",
    "OutwardAtkMonAccess": "对外攻击监控",
    "NetDefender": "网络防护",
    "TpiDriverWorkOpen": "TPI 驱动工作开关",
    "NewExec": "新程序执行监控",
    "BitcoinMiner": "挖矿木马防护",
    "flowstate": "流量状态",
    "SB_State": "沙箱状态",
    "svcMon": "服务监控",
    "LockUnknown": "锁定未知程序",
    "NoNotiNews": "不弹新闻通知",
    "NoNotiLeak": "不弹泄漏通知",
    "360RealPro12": "实时防护等级",
    "drv_ver": "驱动版本",
    "last_known_good": "上次正常时间戳",
}

# 360 主动防御相关服务
ZD_SERVICES = ["ZhuDongFangYu", "Q360AMPPL", "360SelfProtection", "HookPort",
               "qutmipc", "qutmdserv", "360Hvm", "BAPIDRV", "EfiMon", "DsArk",
               "360AntiHacker", "360AntiHijack", "360AntiSteal", "360AntiExploit",
               "360Box64", "360Camera", "360FsFlt", "360netmon", "360elam64"]

DEVICES = [r"\\.\360SelfProtection", r"\\.\360SpShadow0", r"\\.\360HookPort",
           r"\\.\qutmipc", r"\\.\qutmdrv", r"\\.\BAPI", r"\\.\360TdiFilter",
           r"\\.\360qpesv", r"\\.\DeepATS", r"\\.\360AntiHijack"]

IOCTL_IS_PID_PROTECTED = 0x22204C
SYSINFO_SELF_PROTECT = 0x36059002

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
advapi = ctypes.WinDLL("advapi32", use_last_error=True)

k32.CreateFileW.restype = wt.HANDLE
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, wt.HANDLE]
k32.DeviceIoControl.restype = wt.BOOL
k32.DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD,
                                ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD),
                                ctypes.c_void_p]
k32.CloseHandle.argtypes = [wt.HANDLE]


def reg_query(subkey):
    """读取注册表某键的全部值；返回 dict。

    注意：winreg.HKEY_LOCAL_MACHINE 是一个很大的整数（18446744071562067970），
    不能写成 0，否则 OpenKey 会静默失败并返回空 dict。
    """
    import winreg
    out = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as k:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out[name] = val
                i += 1
    except OSError:
        pass
    return out


def probe_devices():
    res = {}
    for name in DEVICES:
        h = k32.CreateFileW(name, 0xC0000000, 3, None, 3, 0, None)
        if h == ctypes.c_void_p(-1).value:
            res[name] = {"open": False, "error": ctypes.get_last_error()}
        else:
            res[name] = {"open": True, "error": 0}
            k32.CloseHandle(h)
    return res


def query_pid_protected(pid):
    h = k32.CreateFileW(r"\\.\360SelfProtection", 0xC0000000, 3, None, 3, 0, None)
    if h == ctypes.c_void_p(-1).value:
        return None, ctypes.get_last_error()
    try:
        buf = ctypes.c_uint32(pid)
        out = ctypes.create_string_buffer(4)
        ret = wt.DWORD(0)
        ok = k32.DeviceIoControl(h, IOCTL_IS_PID_PROTECTED, ctypes.byref(buf), 4,
                                 out, 4, ctypes.byref(ret), None)
        if not ok:
            return None, ctypes.get_last_error()
        return int.from_bytes(out.raw[:4], "little"), 0
    finally:
        k32.CloseHandle(h)


def query_sysinfo():
    out = wt.DWORD(0)
    retlen = wt.ULONG(0)
    st = ntdll.ZwQuerySystemInformation(wt.ULONG(SYSINFO_SELF_PROTECT),
                                        ctypes.byref(out), wt.ULONG(4),
                                        ctypes.byref(retlen))
    return st & 0xFFFFFFFF, out.value


def service_states():
    """用 sc query 获取服务状态。"""
    res = {}
    for s in ZD_SERVICES:
        try:
            p = subprocess.run(["sc", "query", s], capture_output=True,
                               text=True, timeout=10)
            txt = p.stdout
            if "1060" in txt or "指定的服务" in txt or "does not exist" in txt:
                res[s] = "NOT_INSTALLED"
            else:
                state = "UNKNOWN"
                for line in txt.splitlines():
                    if "STATE" in line and ":" in line:
                        state = line.split(":", 1)[1].strip()
                res[s] = state
        except Exception as e:  # noqa: BLE001
            res[s] = "ERR:%s" % e
    return res


def running_procs():
    try:
        p = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=20)
        out = []
        for line in p.stdout.splitlines():
            parts = [x.strip('"') for x in line.split('","')]
            if parts and any(k in parts[0].lower() for k in
                             ("360", "zhudong", "q360", "liveupdate", "softmgr")):
                out.append({"name": parts[0], "pid": parts[1] if len(parts) > 1 else "?"})
        return out
    except Exception:  # noqa: BLE001
        return []


def main():
    as_json = "--json" in sys.argv

    report = {}
    report["self_protection"] = {}
    report["active_defense"] = {}
    report["devices"] = probe_devices()
    report["services"] = service_states()
    report["processes"] = running_procs()

    # 自我保护状态
    pid_res, pid_err = query_pid_protected(os.getpid())
    st, val = query_sysinfo()
    report["self_protection"] = {
        "device_openable": report["devices"].get(r"\\.\360SelfProtection", {}).get("open", False),
        "ioctl_22204C_self_pid": pid_res,
        "ioctl_22204C_error": pid_err,
        "sysinfo_36059002_status": "0x%08X" % st,
        "sysinfo_36059002_value": val,
        "sysinfo_interpretation": (
            "STATUS_INVALID_INFO_CLASS(0xC0000003) 表示无人处理该自定义 class，"
            "通常意味 360SelfProtection.sys 未加载"
            if st == 0xC0000003 else "已由 360 内核组件应答"),
    }

    # 主动防御拦截状态
    sm = reg_query(SAFEMON_KEY)
    sm64 = reg_query(SAFEMON_KEY64)
    flags = {}
    for k, v in list(sm.items()) + list(sm64.items()):
        if k in ACCESS_FLAGS:
            flags[k] = {"value": v, "meaning": ACCESS_FLAGS[k],
                        "on": bool(v) if isinstance(v, int) else v}
    report["active_defense"] = {
        "registry_key": "HKLM\\" + SAFEMON_KEY,
        "intercept_flags": flags,
        "zd_service_states": {s: report["services"].get(s)
                              for s in ("ZhuDongFangYu", "Q360AMPPL")},
    }

    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
        return

    # 人类可读报告
    print("=" * 74)
    print("360 拦截状态报告（自我保护 / 主动防御）")
    print("=" * 74)

    print("\n【1】自我保护")
    sp = report["self_protection"]
    print("  设备 \\\\.\\360SelfProtection 可打开 : %s" % sp["device_openable"])
    if sp["ioctl_22204C_self_pid"] is not None:
        print("  IOCTL 0x22204C 查询本进程保护状态 : %s"
              % ("受保护" if sp["ioctl_22204C_self_pid"] else "不受保护"))
    else:
        print("  IOCTL 0x22204C 查询失败 : err=%s" % sp["ioctl_22204C_error"])
    print("  ZwQuerySystemInformation(0x36059002) : %s 值=%d"
          % (sp["sysinfo_36059002_status"], sp["sysinfo_36059002_value"]))
    print("  说明 : %s" % sp["sysinfo_interpretation"])

    print("\n【2】主动防御拦截开关（注册表 %s）" % report["active_defense"]["registry_key"])
    if not flags:
        print("  （未读取到，可能键不存在）")
    else:
        on = [k for k, v in flags.items() if v["on"] is True]
        off = [k for k, v in flags.items() if v["on"] is False]
        print("  已开启拦截 (%d 项):" % len(on))
        for k in on:
            print("     [开] %-22s %s = %s" % (k, flags[k]["meaning"], flags[k]["value"]))
        if off:
            print("  已关闭拦截 (%d 项):" % len(off))
            for k in off:
                print("     [关] %-22s %s = %s" % (k, flags[k]["meaning"], flags[k]["value"]))

    print("\n【3】主动防御服务")
    for s in ("ZhuDongFangYu", "Q360AMPPL"):
        print("  %-16s : %s" % (s, report["services"].get(s)))

    print("\n【4】360 相关驱动/服务状态")
    for s in ZD_SERVICES:
        stt = report["services"].get(s)
        if stt not in (None, "NOT_INSTALLED"):
            print("  %-18s : %s" % (s, stt))

    print("\n【5】运行中的 360 进程")
    if report["processes"]:
        for p in report["processes"]:
            print("  %-24s PID=%s" % (p["name"], p["pid"]))
    else:
        print("  （无）")

    print("\n【6】设备对象可达性")
    for name, info in report["devices"].items():
        if info["open"]:
            print("  %-26s 可打开" % name)
        else:
            print("  %-26s 不可达 (err=%d)" % (name, info["error"]))

    print("\n" + "=" * 74)


if __name__ == "__main__":
    main()