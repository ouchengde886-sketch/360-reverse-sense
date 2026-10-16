#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""提取 PE 里的 UTF-16 与 ASCII 字符串。"""
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")

# UTF-16LE：可打印 ASCII 或中文，后跟 00
U16 = re.compile(rb"(?:[\x20-\x7e]\x00|[\x00-\xff][\x4e-\x9f]){4,}")
A8 = re.compile(rb"[\x20-\x7e]{5,}")

if __name__ == "__main__":
    path = sys.argv[1]
    kw = sys.argv[2:] or [""]
    d = open(path, "rb").read()
    seen = set()
    res = []
    for m in U16.finditer(d):
        try:
            t = m.group().decode("utf-16-le").strip()
        except UnicodeDecodeError:
            continue
        if len(t) < 4 or t in seen:
            continue
        seen.add(t)
        if t.isascii() or any("\u4e00" <= c <= "\u9fff" for c in t):
            res.append(t)
    for m in A8.finditer(d):
        t = m.group().decode("latin1").strip()
        if t in seen:
            continue
        seen.add(t)
        res.append(t)
    for t in res:
        if any(k in t for k in kw):
            print("  %s" % t)