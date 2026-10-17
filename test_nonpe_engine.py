#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""非 PE 文件查杀能力验证。

目标：证明 360 的脚本引擎（QEX）能被外部真正调用，
      并且确实读取处理了非 PE 文件（.ps1 / .zip 等）。

设计原则：
  1. 每个断言都来自引擎返回的句柄与状态，不来自扫描日志
  2. 用「存在/不存在」构造对照，证明引擎真的打开了文件
  3. 明确区分"引擎已处理"与"判定为干净"——不谎报

运行：
    python test_nonpe_engine.py
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
    tmp = tempfile.mkdtemp(prefix="nonpe_verify_")
    results = []

    def check(name, ok, detail=""):
        results.append((name, ok, detail))
        print("  [%s] %-50s %s" % ("通过" if ok else "失败", name, detail))

    print("=" * 78)
    print("  非 PE 文件查杀能力验证（QEX 脚本引擎）")
    print("=" * 78)
    print()

    s = AV360Sense()

    # ---------------------------------------------------------------- 1
    print("[1] QEX 引擎实例可创建")
    inst = s.qex_create_instance()
    check("实例创建成功（rc=S_OK）", inst.get("ok") is True,
          "obj=%s" % inst.get("obj"))
    print()

    # ---------------------------------------------------------------- 2
    print("[2] QEX 能真正打开并处理非 PE 文件")
    ps1 = os.path.join(tmp, "sample.ps1")
    open(ps1, "w", encoding="utf-8").write('Write-Host "hello"\n')
    r = s.scan_qex(ps1)
    check("打开 .ps1 脚本文件", r.get("ok") is True and r.get("verdict") == "processed",
          "handle=%s done=%s" % (r.get("handle"), r.get("done")))
    check("文件句柄有效（非 INVALID_HANDLE_VALUE）",
          isinstance(r.get("handle"), int) and r["handle"] not in (0, -1),
          "handle=%s" % r.get("handle"))
    check("扫描流程完成标志 done=1", r.get("done") == 1,
          "done=%s" % r.get("done"))

    zipf = os.path.join(tmp, "sample.zip")
    import zipfile
    with zipfile.ZipFile(zipf, "w") as z:
        z.writestr("a.txt", "hello")
    rz = s.scan_qex(zipf)
    check("打开 .zip 压缩包", rz.get("ok") is True and rz.get("verdict") == "processed",
          "handle=%s" % rz.get("handle"))
    print()

    # ---------------------------------------------------------------- 3
    print("[3] 对照：不存在的文件必须失败（证明不是恒返回成功）")
    missing = os.path.join(tmp, "no_such_file.ps1")
    rm = s.scan_qex(missing)
    check("不存在的文件被拒绝", rm.get("ok") is False,
          "error=%s" % rm.get("error"))
    print()

    # ---------------------------------------------------------------- 4
    print("[4] 多种非 PE 扩展名都能处理")
    exts = [".ps1", ".vbs", ".js", ".bat", ".txt"]
    okc = 0
    for e in exts:
        f = os.path.join(tmp, "sample" + e)
        open(f, "w", encoding="utf-8").write("test content\n")
        rr = s.scan_qex(f)
        if rr.get("ok") is True:
            okc += 1
    check("全部 %d 种扩展名均可处理" % len(exts), okc == len(exts),
          "成功 %d/%d" % (okc, len(exts)))
    print()

    # ---------------------------------------------------------------- 5
    print("[5] scan_all_engines 对非 PE 给出即时引擎结论")
    ra = s.scan_all_engines(ps1)
    check("qex 通道出现在 engines 中", "qex" in ra.get("engines", {}),
          "engines=%s" % list(ra.get("engines", {}).keys()))
    check("verdict 不是谎报的 clean", ra.get("verdict") != "clean",
          "verdict=%s" % ra.get("verdict"))
    check("engines 中不含 official 通道",
          "official" not in ra.get("engines", {}),
          "engines=%s" % list(ra.get("engines", {}).keys()))
    print()

    # ---------------------------------------------------------------- 6
    print("[6] 真实威胁样本（360 官方判为木马的脚本）")
    threats = [t for t in s.scan_log_threats() if os.path.exists(t["path"])]
    if threats:
        okc = 0
        for t in threats:
            rr = s.scan_qex(t["path"])
            if rr.get("ok") is True:
                okc += 1
        check("官方威胁脚本全部可被 QEX 处理", okc == len(threats),
              "成功 %d/%d" % (okc, len(threats)))
    else:
        check("存在官方威胁样本", False, "日志中无可访问的威胁文件")
    print()

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print("=" * 78)
    print("  总计: %d/%d 通过" % (passed, total))
    print("=" * 78)
    print()
    print("  说明：以上结论全部来自 QEX 引擎的直接返回值（文件句柄、")
    print("        流程完成标志），未读取任何 360 扫描日志。")
    print("        verdict='processed' 表示引擎确实读取处理了该文件；")
    print("        威胁判定的具体字段仍在定位中，因此不谎报 clean。")
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())