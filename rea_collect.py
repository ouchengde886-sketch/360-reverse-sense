#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REA 批量取证采集器。

对每个目标二进制调用 REA CLI（Ghidra 12.1.4 provider），采集：
  - binary_overview（节表/函数数/字符串数）
  - 字符串清单（search --kind strings）
  - 过程名清单（search --kind procedures）
  - 导入表（inspect 的 imports 视图）
并把结果落到 out/<name>.json，供后续分析脚本消费。

用法:
  python rea_collect.py <binary> [<binary> ...]
  python rea_collect.py --list targets.txt
"""
import os
import re
import sys
import json
import subprocess

WS = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
REA = os.path.join(WS, "rea.cmd")
OUT = os.path.join(WS, "rea_out")


def run_rea(args, timeout=1800):
    """调用 rea.cmd，返回解析后的 JSON（失败返回 {'error': ...}）。"""
    cmd = ["cmd", "/c", REA] + args
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "args": args}
    out = p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    # rea 在 stdout 输出 JSON；stderr 可能混有 JVM 噪声
    start = out.find("{")
    if start < 0:
        return {"error": "no-json", "stdout": out[:4000], "stderr": err[:4000], "args": args}
    try:
        return json.loads(out[start:])
    except json.JSONDecodeError as e:
        return {"error": "bad-json: %s" % e, "stdout": out[:4000], "args": args}


def collect(binary):
    name = os.path.basename(binary)
    rec = {"binary": binary, "name": name}

    print("[*] overview %s" % name, flush=True)
    ov = run_rea(["inspect", binary, "--format", "json"])
    rec["overview"] = ov

    print("[*] strings  %s" % name, flush=True)
    st = run_rea(["search", binary, "--kind", "strings", "--mode", "regex", "--pattern", ".+", "--format", "json"])
    rec["strings"] = st

    print("[*] procs    %s" % name, flush=True)
    pr = run_rea(["search", binary, "--kind", "procedures", "--mode", "regex", "--pattern", ".+", "--format", "json"])
    rec["procedures"] = pr

    return rec


def main():
    args = sys.argv[1:]
    targets = []
    if args and args[0] == "--list":
        with open(args[1], encoding="utf-8") as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        targets = args

    os.makedirs(OUT, exist_ok=True)
    for t in targets:
        if not os.path.isfile(t):
            print("[!] missing: %s" % t, flush=True)
            continue
        rec = collect(t)
        dst = os.path.join(OUT, os.path.basename(t) + ".json")
        with open(dst, "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=1)
        sizes = {k: (len(json.dumps(v)) if isinstance(v, dict) else 0) for k, v in rec.items() if k != "binary"}
        print("[+] wrote %s  %s" % (dst, sizes), flush=True)


if __name__ == "__main__":
    main()