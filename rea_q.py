#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""REA 查询助手：避免在 cmd 中内联管道/正则导致的转义问题。

用法:
  python rea_q.py strings <binary> <regex>
  python rea_q.py procs   <binary> <regex>
  python rea_q.py decomp  <binary> <procedure>
  python rea_q.py func    <binary> <procedure>
"""
import json
import os
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")

WS = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
# Invoke the Node entry point directly. Going through rea.cmd would route the
# arguments through cmd.exe, which treats | & < > ^ as metacharacters even
# inside quotes and corrupts regex alternation.
REA_NODE = r"C:\Users\Administrator\Documents\Codex\tools\rea\node_modules\rea-agents\scripts\rea.mjs"
NODE = r"C:\Users\Administrator\Documents\Codex\tools\rea\node.exe"

# Environment mirroring rea.cmd: the DSH sandbox lets the Java child process
# write only inside the workspace, so TEMP/TMP/XDG_CONFIG_HOME must point here.
REA_ENV = dict(os.environ)
REA_ENV["GHIDRA_INSTALL_DIR"] = os.path.join(WS, "tools", "ghidra_12.1.4_PUBLIC")
REA_ENV["JAVA_HOME"] = os.path.join(WS, "tools", "jdk", "jdk-21.0.12.1+1")
REA_ENV["PATH"] = REA_ENV["JAVA_HOME"] + os.pathsep + REA_ENV.get("PATH", "")
REA_ENV["TEMP"] = os.path.join(WS, "tools", "rea-tmp")
REA_ENV["TMP"] = REA_ENV["TEMP"]
REA_ENV["XDG_CONFIG_HOME"] = os.path.join(WS, "tools", "ghidra-user", "config")


def run(args, timeout=1800):
    exe = NODE if os.path.exists(NODE) else "node"
    p = subprocess.run([exe, REA_NODE] + args, capture_output=True,
                       timeout=timeout, env=REA_ENV)
    out = p.stdout.decode("utf-8", "replace")
    i = out.find("{")
    if i < 0:
        return {"error": "no-json", "stdout": out[:2000],
                "stderr": p.stderr.decode("utf-8", "replace")[:2000]}
    try:
        return json.loads(out[i:])
    except json.JSONDecodeError as e:
        return {"error": "bad-json %s" % e, "stdout": out[:2000]}


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return
    mode, binary, arg = sys.argv[1], sys.argv[2], sys.argv[3]

    if mode in ("strings", "procs"):
        kind = "strings" if mode == "strings" else "procedures"
        d = run(["search", binary, "--kind", kind, "--mode", "regex",
                 "--pattern", arg, "--format", "json"])
        if "error" in d:
            print(json.dumps(d, ensure_ascii=False, indent=1)[:3000])
            return
        for r in d.get("raw_result", []):
            print("%-14s %s" % (r.get("address"), r.get("value")))

    elif mode == "decomp":
        d = run(["decompile", binary, arg, "--format", "json"])
        if "error" in d:
            print(json.dumps(d, ensure_ascii=False, indent=1)[:3000])
            return
        nr = d.get("normalized_result")
        if isinstance(nr, str):
            print(nr)
        elif isinstance(nr, dict):
            code = nr.get("code") or nr.get("decompiled") or nr.get("pseudocode")
            print(code if isinstance(code, str) else json.dumps(nr, ensure_ascii=False, indent=1))
        else:
            print(json.dumps(d, ensure_ascii=False, indent=1)[:6000])

    elif mode == "func":
        d = run(["function", binary, arg, "--format", "json"])
        if "error" in d:
            print(json.dumps(d, ensure_ascii=False, indent=1)[:4000])
            return
        print(json.dumps(d.get("normalized_result", d), ensure_ascii=False, indent=1)[:8000])

    else:
        print(__doc__)


if __name__ == "__main__":
    main()