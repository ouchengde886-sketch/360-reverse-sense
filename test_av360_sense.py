#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
感知层自测 —— 证明 HIPS 弹窗与查杀通知的捕获逻辑真的有效。

做法：
  1. 弹窗检测：在本进程内注册一个类名为 Q360HIPSClass 的窗口
     （与 360 主动防御弹窗同名），并带子控件文本，验证 poll_popups()
     能识别出窗口、标题、正文、动作、判定与路径。
  2. 查杀通知检测：在临时目录写一份模拟的 360 扫描日志，
     验证 poll_scan_log() 的解析器能正确抽取路径/MD5/动作/规则ID。

注意：WNDPROC 的签名必须与 64 位 ABI 一致（LRESULT 是 64 位），
否则回调会抛 OverflowError 导致窗口过程异常。
"""
import ctypes
import ctypes.wintypes as wt
import os
import sys
import tempfile
import threading
import time

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import av360_sense as A  # noqa: E402

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# 64 位下 LRESULT/LPARAM 都是 64 位；用 c_ssize_t 才能匹配 ABI
LRESULT = ctypes.c_ssize_t
WPARAM = ctypes.c_size_t
LPARAM = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, ctypes.c_uint, WPARAM, LPARAM)

user32.DefWindowProcW.restype = LRESULT
user32.DefWindowProcW.argtypes = [wt.HWND, ctypes.c_uint, WPARAM, LPARAM]
user32.CreateWindowExW.restype = wt.HWND
user32.CreateWindowExW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
                                   ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, wt.HWND, wt.HMENU,
                                   wt.HINSTANCE, ctypes.c_void_p]


def _wndproc(hwnd, msg, wparam, lparam):
    return user32.DefWindowProcW(hwnd, msg, wparam, lparam)


_WNDPROC_REF = WNDPROC(_wndproc)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", ctypes.c_uint),
                ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wt.HINSTANCE),
                ("hIcon", wt.HICON),
                ("hCursor", wt.HANDLE),
                ("hbrBackground", wt.HBRUSH),
                ("lpszMenuName", wt.LPCWSTR),
                ("lpszClassName", wt.LPCWSTR)]


def test_popup_detection():
    """验证弹窗捕获。

    关键点：窗口必须在**有消息泵的线程**里创建，否则 EnumWindows 看不到它
    （窗口创建后需要消息泵处理 WM_CREATE 等消息才会进入桌面窗口列表）。
    这里用独立线程建窗口 + PeekMessage/DispatchMessage 泵消息。
    """
    print("=" * 72)
    print("[测试 1] HIPS 弹窗捕获")
    print("=" * 72)

    s = A.AV360Sense()
    base = s.prime_popups()
    print("  基线 HIPS 弹窗数: %d" % base)

    wc = WNDCLASSW()
    wc.lpfnWndProc = _WNDPROC_REF
    wc.lpszClassName = A.HIPS_POPUP_CLASS
    if not user32.RegisterClassW(ctypes.byref(wc)):
        err = ctypes.get_last_error()
        if err != 1410:  # ERROR_CLASS_ALREADY_EXISTS
            print("  [!] RegisterClassW 失败 err=%d" % err)
            return False
    print("  已注册窗口类: %s" % A.HIPS_POPUP_CLASS)

    user32.PeekMessageW.argtypes = [ctypes.c_void_p, wt.HWND,
                                    ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
    user32.GetMessageW.argtypes = [ctypes.c_void_p, wt.HWND,
                                   ctypes.c_uint, ctypes.c_uint]

    result = {"body": "", "hwnd": 0}

    def ui_thread():
        hwnd = user32.CreateWindowExW(
            0, A.HIPS_POPUP_CLASS, "360主动防御拦截",
            0x10000000, 100, 100, 420, 220, None, None, None, None)
        if not hwnd:
            return
        result["hwnd"] = hwnd
        user32.ShowWindow(hwnd, 5)
        user32.UpdateWindow(hwnd)

        # 立刻开始泵消息 —— 窗口只有在消息泵运行后才会进入桌面窗口列表，
        # 被 EnumWindows 看到。若先 sleep 再泵，watch() 会一直找不到窗口。
        msg = ctypes.create_string_buffer(64)
        child_added = False
        end = time.time() + 6
        while time.time() < end:
            while user32.PeekMessageW(msg, hwnd, 0, 0, 1):
                user32.TranslateMessage(msg)
                user32.DispatchMessageW(msg)
            if not child_added and time.time() > end - 5:
                # 1 秒后模拟 360 延迟填充弹窗正文
                user32.CreateWindowExW(
                    0, "STATIC",
                    "检测到木马程序，已拦截\r\nC:\\test\\sample.exe",
                    0x50000000, 10, 10, 380, 60, hwnd, None, None, None)
                child_added = True
            time.sleep(0.05)
        user32.DestroyWindow(hwnd)

    th = threading.Thread(target=ui_thread, daemon=True)
    th.start()
    # 让窗口线程先跑起来，但不要等太久 —— watch() 会在启动时建立基线，
    # 因此窗口必须在 watch() 开始之后才出现，否则会被当成"历史弹窗"而忽略。
    time.sleep(0.1)
    print("  已创建窗口 hwnd=0x%X（独立线程 + 消息泵）" % result["hwnd"])

    # 用 watch() 实时捕获
    events = []
    for ev in s.watch(seconds=6, interval=0.3):
        events.append(ev)
        print("    捕获: kind=%s action=%r verdict=%r path=%r"
              % (ev.kind, ev.action, ev.verdict, ev.path))

    th.join(timeout=6)

    ok = any(e.kind in ("popup", "popup_detail") for e in events)
    detailed = any(e.action or e.verdict or e.path for e in events)
    print("\n  捕获事件数: %d" % len(events))
    print("  含结构化字段: %s" % detailed)
    print("\n  结论: %s" % ("弹窗捕获可用" if ok else "未捕获到弹窗"))
    return ok


def test_scan_log_parsing():
    print()
    print("=" * 72)
    print("[测试 2] 查杀通知解析")
    print("=" * 72)

    # 用真实日志样本验证解析器
    sample = "\n".join([
        "发现安全威胁: 2",
        "已处理安全威胁: 2",
        "",
        "[5050968] D:\\test\\evil.exe 00000000000000000000000000000000 "
        "无效的注册表启动项 禁止自启动 处理成功 rule=-1,0,-1-1-2_0_0_1",
        "[5050968] C:\\WINDOWS\\gna.sys 587255c4c0050ba58373f169701927c5 "
        "建议禁止开机自动运行的程序 禁止自启动 处理成功 rule=30,3,30-1-2_0_0_1",
    ])

    tmpdir = tempfile.mkdtemp(prefix="av360test_")
    logpath = os.path.join(tmpdir, "360safeScanLog.txt")
    with open(logpath, "w", encoding="utf-8") as f:
        f.write(sample)

    s = A.AV360Sense()
    orig = A.SCAN_LOG
    A.SCAN_LOG = logpath
    try:
        s._seen_log_size = 0
        events = s.poll_scan_log()
        summ = s.scan_log_summary()
    finally:
        A.SCAN_LOG = orig

    print("  统计: %s" % summ)
    print("  解析出 %d 条查杀事件" % len(events))
    ok = False
    for e in events:
        print("    path    = %r" % e.path)
        print("    action  = %r" % e.action)
        print("    rule    = %r" % e.rule)
        print("    md5     = %r" % e.extra.get("md5"))
        if e.path:
            ok = True

    print("\n  结论: %s" % ("查杀通知解析可用" if ok else "解析失败"))
    return ok


def main():
    r1 = test_popup_detection()
    r2 = test_scan_log_parsing()
    print()
    print("=" * 72)
    print("总结果: 弹窗捕获=%s  查杀通知=%s" % ("通过" if r1 else "失败",
                                              "通过" if r2 else "失败"))
    print("=" * 72)
    return 0 if (r1 and r2) else 1


if __name__ == "__main__":
    sys.exit(main())