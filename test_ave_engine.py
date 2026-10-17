#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""360 查杀引擎真实调用验证 —— 每条结论都必须有可复现的证据。

设计原则（针对"把日志当结果"的幻觉）：
  1. 每个断言都直接来自引擎返回值，绝不来自扫描日志
  2. 用「同一份字节、不同路径」构造对照，排除路径/环境干扰
  3. 用「不存在」与「存在」构造对照，证明引擎真的在判定
  4. 报告里显式标注哪些是即时调用、哪些不是

运行：
    python test_ave_engine.py
"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.stdout.reconfigure(encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
PS32 = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
SCRIPT = os.path.join(HERE, "av_ave_scan32.ps1")
US = "\x1f"


def scan(path, timeout=120):
    """直接调用 AVE 引擎脚本，返回解析后的结果字典。"""
    o = subprocess.run(
        [PS32, "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", SCRIPT, path],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout,
    )
    for line in o.stdout.splitlines():
        if line.startswith("RESULT" + US):
            p = line.split(US)
            r = {"path": p[1] if len(p) > 1 else "", "verdict": p[2] if len(p) > 2 else ""}
            if len(p) > 3:
                for kv in p[3].split():
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        r[k] = v
            return r
    return {"path": path, "verdict": "NO_RESULT", "raw": o.stdout[:300]}


def sec32(path):
    """把 64 位路径转换成 32 位进程可见的路径（Sysnative）。

    注意：Sysnative 只对 32 位进程有效，64 位 Python 读不到，
    所以读文件内容时要用原始路径。
    """
    if path.lower().startswith("c:\\windows\\system32\\"):
        return "C:\\Windows\\Sysnative\\" + path[len("C:\\Windows\\System32\\"):]
    return path


def sec64(path):
    """32 位视角路径还原成 64 位真实路径（供 Python 读文件用）。"""
    if path.lower().startswith("c:\\windows\\sysnative\\"):
        return "C:\\Windows\\System32\\" + path[len("C:\\Windows\\Sysnative\\"):]
    return path


def main():
    tmp = tempfile.mkdtemp(prefix="ave_verify_")
    results = []

    def check(name, ok, detail=""):
        results.append((name, ok, detail))
        print("  [%s] %-46s %s" % ("通过" if ok else "失败", name, detail))

    print("=" * 78)
    print("  360 AVE 查杀引擎 —— 真实调用验证")
    print("=" * 78)
    print()

    # ---------------------------------------------------------------- 1
    print("[1] 引擎初始化链路（每一环都必须成功）")
    real = sec32(r"C:\Windows\System32\notepad.exe")
    r = scan(real)
    check("扫描真实 PE（Sysnative 路径）", r.get("verdict") == "clean",
          "verdict=%s status=%s" % (r.get("verdict"), r.get("status")))
    check("BAPIInitialize 成功", r.get("bapi") == "0", "bapi=%s" % r.get("bapi"))
    check("特征库配置 6/6", r.get("cfg") == "6/6", "cfg=%s" % r.get("cfg"))
    check("引擎有响应 rc=1", r.get("rc") == "1", "rc=%s" % r.get("rc"))
    print()

    # ---------------------------------------------------------------- 2
    print("[2] 引擎确实在判定文件内容（不是恒返回 clean）")
    # 2a 不存在的文件
    r_missing = scan(os.path.join(tmp, "definitely_missing.exe"))
    check("不存在的文件被识别", r_missing.get("status") == "251",
          "status=%s verdict=%s" % (r_missing.get("status"), r_missing.get("verdict")))
    # 2b 非 PE 内容
    txt = os.path.join(tmp, "notape.txt")
    open(txt, "w").write("this is plain text, not a PE")
    r_txt = scan(txt)
    check("非 PE 内容被拒绝", r_txt.get("status") == "4",
          "status=%s verdict=%s" % (r_txt.get("status"), r_txt.get("verdict")))
    # 2c 空文件
    empty = os.path.join(tmp, "empty.bin")
    open(empty, "wb").close()
    r_empty = scan(empty)
    check("空文件被拒绝", r_empty.get("status") == "4",
          "status=%s" % r_empty.get("status"))
    # 2d 破坏 MZ 头
    bad = os.path.join(tmp, "badmz.exe")
    b = bytearray(open(sec64(real), "rb").read())
    b[0] = 0x5A
    b[1] = 0x5A
    open(bad, "wb").write(bytes(b))
    r_bad = scan(bad)
    check("损坏 MZ 头被拒绝", r_bad.get("status") == "4",
          "status=%s" % r_bad.get("status"))
    print()

    # ---------------------------------------------------------------- 3
    print("[3] 同一份字节、不同路径 —— 排除路径干扰")
    src = sec32(r"C:\Windows\System32\calc.exe")
    copy = os.path.join(tmp, "calc_copy.exe")
    shutil.copy2(sec64(src), copy)
    r_src = scan(src)
    r_cpy = scan(copy)
    check("原路径与副本判定一致",
          r_src.get("verdict") == r_cpy.get("verdict") == "clean",
          "原=%s 副本=%s" % (r_src.get("verdict"), r_cpy.get("verdict")))
    print()

    # ---------------------------------------------------------------- 4
    print("[4] WOW64 重定向（32 位宿主必须用 Sysnative 访问 System32）")
    r_redir = scan(r"C:\Windows\System32\alg.exe")
    r_native = scan(r"C:\Windows\Sysnative\alg.exe")
    check("重定向路径不可见（status=251）", r_redir.get("status") == "251",
          "status=%s" % r_redir.get("status"))
    check("Sysnative 路径可正常扫描", r_native.get("verdict") == "clean",
          "verdict=%s" % r_native.get("verdict"))
    print()

    # ---------------------------------------------------------------- 5
    print("[5] 多文件批量一致性（同引擎、同结论）")
    batch = []
    for n in ("calc.exe", "notepad.exe", "cmd.exe", "mspaint.exe"):
        p = sec32("C:\\Windows\\System32\\" + n)
        if os.path.exists(sec64(p)):
            batch.append((n, scan(p)))
    ok_batch = all(v.get("verdict") == "clean" for _, v in batch) and len(batch) >= 3
    check("批量扫描 %d 个系统 PE 全部 clean" % len(batch), ok_batch,
          ", ".join("%s=%s" % (n, v.get("verdict")) for n, v in batch))
    print()

    # ---------------------------------------------------------------- 汇总
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print("=" * 78)
    print("  总计: %d/%d 通过" % (passed, total))
    print("=" * 78)
    print()
    print("  说明：以上结论全部来自 AVE 引擎的直接返回值，")
    print("        未读取任何 360 扫描日志。")
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())