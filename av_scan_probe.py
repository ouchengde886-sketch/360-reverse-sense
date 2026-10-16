#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
外部调用 360 查杀引擎的实证脚本。

依据 REA 逆向结论（见 FINDINGS.md 第 2 节）：
  cloudcom2.dll 导出 GetFileTrustState / GetFileTrustStateEx /
  GetFileTrustStateEx2 / GetFileTrustStateWithHandle —— 文件信誉查询。
  反编译 GetFileTrustState(0x1000BB7C0) 得到转发目标
  FUN_1003d580(path, handle, out, flags, timeout)，
  其中 GetFileTrustState 的调用为
      FUN_1003d580(param_1, INVALID_HANDLE_VALUE, NULL, 0, 300000)
  即 (路径, 句柄, 输出缓冲, 标志=0, 超时=300000ms)。

本脚本用 ctypes 直接加载该 DLL 并调用导出，验证"外部可调用"。

用法:
  python av_scan_probe.py <file-or-dir> [...]
  python av_scan_probe.py --self          # 用脚本自身做样本
"""
import ctypes
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")

DLL_DIR = r"C:\Users\Administrator\Desktop\360Safe\deepscan"
DLL = os.path.join(DLL_DIR, "cloudcom2.dll")


def load():
    """加载 cloudcom2.dll；先把依赖目录加入 DLL 搜索路径。"""
    if hasattr(os, "add_dll_directory"):
        try:
            os.add_dll_directory(DLL_DIR)
        except OSError as e:
            print("[!] add_dll_directory: %s" % e)
    # cloudcom2 依赖同目录的 360 基础库，预加载可提高成功率
    for dep in ("360Base.dll", "360Common.dll", "360Util.dll"):
        p = os.path.join(r"C:\Users\Administrator\Desktop\360Safe", dep)
        if os.path.exists(p):
            try:
                ctypes.WinDLL(p)
            except OSError:
                pass
    return ctypes.WinDLL(DLL)


def main():
    targets = sys.argv[1:]
    if not targets or targets == ["--self"]:
        targets = [os.path.abspath(__file__)]

    print("=" * 70)
    print("360 查杀引擎外部调用实证 (cloudcom2.dll!GetFileTrustState)")
    print("=" * 70)
    print("DLL: %s" % DLL)

    if not os.path.exists(DLL):
        print("[!] DLL 不存在")
        return

    try:
        dll = load()
    except OSError as e:
        print("[!] 加载失败: %s" % e)
        print("    （360 引擎依赖较多，若失败可改用 DSFScan/进程内调用）")
        return

    print("[+] 加载成功\n")

    # GetFileTrustState(const wchar_t* path) -> 写入调用方提供的结构
    # 反编译显示输出缓冲为调用方栈上结构，这里给足 4KB 余量。
    fn = getattr(dll, "GetFileTrustState", None)
    if fn is None:
        print("[!] 未找到 GetFileTrustState 导出")
        return

    fn.restype = None
    fn.argtypes = [ctypes.c_void_p]

    for t in targets:
        if not os.path.exists(t):
            print("[!] 跳过（不存在）: %s" % t)
            continue
        buf = ctypes.create_string_buffer(4096)
        try:
            fn(ctypes.cast(buf, ctypes.c_void_p))
            raw = buf.raw
            # 结构首字段通常是状态码
            first = int.from_bytes(raw[:4], "little")
            print("[+] %s" % t)
            print("    首字段(状态码) = 0x%08X (%d)" % (first, first))
            print("    原始前 32 字节 = %s" % raw[:32].hex())
        except Exception as e:  # noqa: BLE001
            print("[!] %s 调用异常: %s" % (t, e))

    print("\n说明：状态码语义需结合 360 信誉分级（0=未知/1=安全/2=可疑…），")
    print("      本脚本先证明『外部可调用』这一目标。")


if __name__ == "__main__":
    main()