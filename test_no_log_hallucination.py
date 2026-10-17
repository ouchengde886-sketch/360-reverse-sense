#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""证明「把日志当结果」的幻觉已被消除。

核心断言：
  A. 对 360 从未扫描过的新文件，判定必须来自即时引擎，不能来自日志
  B. 日志中存在的旧威胁，不能污染新文件的判定
  C. 判定结论必须可追溯到具体的引擎返回值

运行：
    python test_no_log_hallucination.py
"""
import os
import shutil
import sys
import tempfile

sys.stdout.reconfigure(encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from av360_sense import AV360Sense  # noqa: E402


def main():
    tmp = tempfile.mkdtemp(prefix="nolog_verify_")
    results = []

    def check(name, ok, detail=""):
        results.append((name, ok, detail))
        print("  [%s] %-52s %s" % ("通过" if ok else "失败", name, detail))

    print("=" * 80)
    print("  验证：判定结论不来自扫描日志")
    print("=" * 80)
    print()

    s = AV360Sense()

    # ---------------------------------------------------------------- A
    print("[A] 全新文件（360 从未扫描过）")
    new_ps1 = os.path.join(tmp, "brand_new_never_scanned.ps1")
    open(new_ps1, "w", encoding="utf-8").write('Write-Host "hello"\n')
    r = s.scan_all_engines(new_ps1)

    # 日志里绝对没有这个文件
    logged = [t for t in s.scan_log_threats()
              if t["path"].lower() == os.path.abspath(new_ps1).lower()]
    check("新文件不在日志威胁列表中", len(logged) == 0,
          "日志命中=%d" % len(logged))
    check("reference 明确标注不参与判定",
          "不参与判定" in (r.get("reference", {}).get("source") or ""),
          r.get("reference", {}).get("source", ""))
    check("reference 未把新文件报成 threat",
          r.get("reference", {}).get("found") is False,
          "found=%s" % r.get("reference", {}).get("found"))
    print()

    # ---------------------------------------------------------------- B
    print("[B] 日志中的旧威胁不得污染判定")
    # 找一个日志里确实存在的威胁文件。
    # ★ 注意：360safeScanLog.txt 只保留最近一次扫描，若最近一次是空扫描
    #   它就没有威胁记录。因此这里回退到历史日志聚合，避免测试
    #   因为"最近一次扫描恰好没查到东西"而假失败。
    old = s.scan_log_threats()
    if not old:
        old = s.scan_log_threats_all()
    # ★ 日志里的威胁文件可能已被 360 删除/隔离（实测 EICAR 就被删了），
    #   因此要挑一个**当前仍存在**的，否则测试会因为"文件没了"而假失败。
    old = [t for t in old if os.path.exists(t["path"])]
    if old:
        victim = old[0]["path"]
        if os.path.exists(victim):
            rv = s.scan_all_engines(victim)
            # 该文件是 .ps1，AVE 处理不了 -> 即时引擎给不出 clean
            ave_v = rv["engines"].get("ave", {}).get("verdict")
            check("AVE 对非 PE 不谎报 clean",
                  ave_v != "clean",
                  "ave=%s（应为 engine_error）" % ave_v)
            check("日志内容只出现在 reference 中",
                  "official" not in rv["engines"],
                  "engines=%s" % list(rv["engines"].keys()))
        else:
            check("日志威胁文件存在", False, victim)
    else:
        check("日志中存在威胁记录", False, "日志为空")
    print()

    # ---------------------------------------------------------------- C
    print("[C] 判定必须可追溯到即时引擎返回值")
    # ★ 用 .com 副本而非 Sysnative\notepad.exe：
    #   实测发现临时目录里的 notepad 副本启动后立即退出，
    #   导致 AVE 拿到的是"进程正在终止"而非真实扫描结果。
    #   改用系统原路径的 notepad.exe（实测稳定返回 status=0）。
    real = "C:\\Windows\\System32\\notepad.exe"
    if not os.path.exists(real):
        real = "C:\\Windows\\Sysnative\\notepad.exe"
    rc = s.scan_all_engines(real)
    check("verdict 来自 ave 引擎",
          rc.get("verdict") == "clean" and rc["engines"]["ave"].get("status") == 0,
          "verdict=%s ave.status=%s" % (rc.get("verdict"), rc["engines"]["ave"].get("status")))
    check("engines 中不含 official 通道",
          "official" not in rc["engines"],
          "engines=%s" % list(rc["engines"].keys()))
    print()

    # ---------------------------------------------------------------- D
    print("[D] 日志通道仍需可显式访问（没有被删掉，只是不参与判定）")
    latest = s.scan_log_latest()
    check("scan_log_latest 仍可用",
          isinstance(latest, dict) and "engines" in latest,
          "engines=%s" % (latest.get("engines") or [])[:3])
    print()

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print("=" * 80)
    print("  总计: %d/%d 通过" % (passed, total))
    print("=" * 80)
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())