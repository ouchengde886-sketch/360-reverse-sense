#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
外部调用 360 自保护接口的实证脚本。

依据 REA 逆向结论：
  - 设备：\\\\.\\360SelfProtection（360SelfProtection.sys 创建，见 FINDINGS.md）
  - 控制码：DeviceType 0x22，METHOD_BUFFERED
      0x222020  自保护总开关（输入 DWORD：0=关闭，非0=开启）
      0x22204c  查询指定 PID 是否受保护（输入 DWORD pid，输出 DWORD 是否受保护）
  - 状态查询旁路：ZwQuerySystemInformation(SystemInformationClass=0x36059002)
      （SelfProtectAPI2.dll 的 IsSelfProtectOn -> APICreateObjectSelfProc(5) ->
        CSelfProcAPI::vtable+0x20 -> FUN_10011c10 -> FUN_10011ba0）

本脚本只做只读探测（默认不改变自保护状态），可用 --toggle-test 做开关回环验证。

用法:
  python selfprotect_probe.py            # 只读：打开设备 + 查询自身 PID 保护状态
  python selfprotect_probe.py --toggle-test   # 关闭再恢复自保护，验证可写
"""
import ctypes
import ctypes.wintypes as wt
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# ★ 关键：360SPTool.exe 反编译（FUN_00401ae0 / FUN_00401bd0）显示它打开设备时用的是
#     CreateFileW(L"\\\\.\\360SelfProtection", 0x100081, 3, NULL, 3, 0x40000080, NULL)
#   访问掩码 0x100081 = SYNCHRONIZE(0x100000) | FILE_READ_DATA(0x1) | FILE_WRITE_DATA(0x2)？
#   实测用 GENERIC_READ|GENERIC_WRITE (0xC0000000) 调 0x222020 会得到 ACCESS_DENIED(5)，
#   必须照抄 360 自己的掩码与打开标志才能通过驱动的调用者校验。
SP_ACCESS = 0x100081
SP_SHARE = 3
SP_FLAGS = 0x40000080

IOCTL_SELF_PROTECT_SWITCH = 0x222020
IOCTL_GET_SP_STATE = 0x222024
IOCTL_IS_PID_PROTECTED = 0x22204C
SYSTEM_INFO_CLASS_SELF_PROTECT = 0x36059002

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

k32.CreateFileW.restype = wt.HANDLE
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, wt.HANDLE]
k32.DeviceIoControl.restype = wt.BOOL
k32.DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD,
                                ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD),
                                ctypes.c_void_p]
k32.CloseHandle.argtypes = [wt.HANDLE]


def open_device(name, access=SP_ACCESS, flags=SP_FLAGS):
    """按 360SPTool.exe 的方式打开自保护设备。"""
    h = k32.CreateFileW(name, access, SP_SHARE, None,
                        OPEN_EXISTING, flags, None)
    if h == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        return None, err
    return h, 0


def ioctl(h, code, in_buf, in_len, out_len):
    out = ctypes.create_string_buffer(out_len)
    ret = wt.DWORD(0)
    ok = k32.DeviceIoControl(h, code, in_buf, in_len, out,
                             out_len, ctypes.byref(ret), None)
    if not ok:
        return None, ctypes.get_last_error()
    return out.raw[:ret.value], 0


def query_sysinfo_protect_state():
    """走 ZwQuerySystemInformation(0x36059002) 这条旁路查询自保护状态。"""
    out = wt.DWORD(0)
    retlen = wt.ULONG(0)
    status = ntdll.ZwQuerySystemInformation(
        wt.ULONG(SYSTEM_INFO_CLASS_SELF_PROTECT),
        ctypes.byref(out), wt.ULONG(4), ctypes.byref(retlen))
    return status, out.value


def main():
    print("=" * 66)
    print("360 自保护外部接口实证")
    print("=" * 66)

    # 1) 设备可达性
    h, err = open_device(r"\\.\360SelfProtection")
    print("\n[1] 打开 \\\\.\\360SelfProtection : %s"
          % ("成功" if h else "失败 err=%d" % err))
    if not h:
        print("    自保护驱动未加载（360SelfProtection.sys 未启动）")
        return

    # 2) 查询自身 PID 是否受保护
    pid = os.getpid()
    buf = ctypes.c_uint32(pid)
    res, err = ioctl(h, IOCTL_IS_PID_PROTECTED, ctypes.byref(buf), 4, 4)
    if res is None:
        print("\n[2] IOCTL 0x%08X (查询PID保护) : 失败 err=%d"
              % (IOCTL_IS_PID_PROTECTED, err))
    else:
        val = int.from_bytes(res[:4], "little")
        print("\n[2] IOCTL 0x%08X (查询PID保护) : PID=%d -> %s"
              % (IOCTL_IS_PID_PROTECTED, pid,
                 "受保护" if val else "不受保护"))

    # 2b) 查询自保护总状态 —— 这是 360SPTool.exe 自己使用的"前置门禁"
    #     FUN_00401cc0: DeviceIoControl(h, 0x222024, NULL, 0, &out, 4, &ret, NULL)
    #     该调用失败（返回 0x8CA3/0x8CA4）时，360SPTool 会直接放弃开关操作。
    res, err = ioctl(h, IOCTL_GET_SP_STATE, None, 0, 4)
    if res is None:
        print("    IOCTL 0x%08X (查询自保护总状态) : 失败 err=%d  <-- 前置门禁"
              % (IOCTL_GET_SP_STATE, err))
    else:
        val = int.from_bytes(res[:4], "little")
        print("    IOCTL 0x%08X (查询自保护总状态) : 值=%d (%s)"
              % (IOCTL_GET_SP_STATE, val, "已开启" if val else "已关闭"))

    # 3) 旁路状态查询
    status, val = query_sysinfo_protect_state()
    print("\n[3] ZwQuerySystemInformation(0x%08X) : NTSTATUS=0x%08X 值=%d"
          % (SYSTEM_INFO_CLASS_SELF_PROTECT, status & 0xFFFFFFFF, val))

    # 4) 可选的开关回环验证
    if "--toggle-test" in sys.argv:
        print("\n[4] 开关回环验证（0=关闭 -> 1=开启）")
        for target, label in ((0, "关闭"), (1, "开启")):
            b = ctypes.c_uint32(target)
            res, err = ioctl(h, IOCTL_SELF_PROTECT_SWITCH,
                             ctypes.byref(b), 4, 0)
            if res is None:
                print("    写入 %s : 失败 err=%d" % (label, err))
            else:
                print("    写入 %s : 成功" % label)
            st, v = query_sysinfo_protect_state()
            print("      复查状态 -> NTSTATUS=0x%08X 值=%d" % (st & 0xFFFFFFFF, v))

    k32.CloseHandle(h)
    print("\n完成。")


if __name__ == "__main__":
    main()