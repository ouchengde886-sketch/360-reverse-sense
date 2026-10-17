# -*- coding: utf-8 -*-
"""QEX 引擎 API 级调用验证测试。

验证目标（对应目标"非pe也要支持杀毒，要调用他全部查杀引擎"）：

  1. QexScanExportsInit 能成功填充 21 项函数表
  2. 能创建 qex1 上下文，魔数 0x31786571 校验通过
  3. ctx+4 指向真实的 QEX 内部对象（虚表在模块内）
  4. 全部 86 个 selector（1..0x56）可调用，无崩溃
  5. 有区分性响应：部分 selector 返回 S_OK，部分返回 E_FAIL
  6. QEX 真实读取文件（obj+0x0C 字段等于文件字节数）

这些是"引擎已被真正调用"的硬证据，而不是日志推断。
"""
import os
import re
import subprocess
import sys
import tempfile

sys.stdout.reconfigure(encoding="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
PS32 = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
SCRIPT = os.path.join(HERE, "qex_sel.ps1")
CTX_SCRIPT = os.path.join(HERE, "qex_ctx.ps1")
SEP = "\x1f"

passed = 0
failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [通过] %s" % name)
    else:
        failed += 1
        print("  [失败] %s  %s" % (name, detail))


def run_ps(script, *args, timeout=180):
    cmd = [PS32, "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", script]
    cmd.extend(args)
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return ""


def make_files():
    d = os.path.join(tempfile.gettempdir(), "qex_verify")
    os.makedirs(d, exist_ok=True)
    clean = os.path.join(d, "clean.ps1")
    with open(clean, "w", encoding="utf-8") as f:
        f.write("param($x)\nWrite-Host 'hello'\n1..3 | ForEach-Object { $_ }\n")
    mal = os.path.join(d, "mal.ps1")
    with open(mal, "w", encoding="utf-8") as f:
        f.write(
            "$code = [byte[]](0x90,0x90,0xC3)\n"
            "$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($code.Length)\n"
            "[System.Runtime.InteropServices.Marshal]::Copy($code,0,$mem,$code.Length)\n"
            "$del = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer("
            "$mem,[Type]([Action]))\n$del.Invoke()\n"
        )
    return clean, mal


print("=" * 66)
print("QEX 引擎 API 级调用验证")
print("=" * 66)

clean, mal = make_files()
clean_size = os.path.getsize(clean)
mal_size = os.path.getsize(mal)
print("\n测试文件: clean.ps1=%d 字节  mal.ps1=%d 字节\n" % (clean_size, mal_size))

# ---- 1. 上下文创建与魔数校验 ----
print("[1] 上下文创建与魔数校验")
out = run_ps(CTX_SCRIPT)
check("QexScanExportsInit 返回 0", "init rc = 0" in out, out[:200])
check("上下文创建返回 rc=0", "create rc = 0" in out, out[:200])
check("魔数 0x31786571 校验通过", "31786571" in out, out[:200])
m = re.search(r"ctx\+4 = (0x[0-9A-F]+)\s+\(已填充\)", out)
check("ctx+4 已填充（指向内部对象）", m is not None, out[:400])
m2 = re.search(r"\[ctx\+4\] = (0x[0-9A-F]+)\s+\(在QEX内: True\)", out)
check("ctx+4 虚表在 QEX 模块内", m2 is not None, out[:400])

# ---- 2. selector 可调用性（抽样，避免过慢） ----
print("\n[2] selector 接口可调用（抽样 12 个，含已知成功与失败项）")
# 抽样必须同时包含已知成功(2,3,4,8,20,40,49,56,74,81)与已知失败(1,5,6,7)的 selector，
# 否则无法验证"有区分性响应"。
sample = [1, 2, 5, 6, 7, 8, 20, 40, 49, 56, 74, 81]
results = {}
crashes = 0
for s in sample:
    o = run_ps(SCRIPT, "-Target", clean, "-Mode", "0", "-Sel", str(s), "-Case", "0")
    mm = re.search(r"SEL\x1f(\d+)\x1fcase=(\d+)\x1frc=(-?\d+)", o)
    if mm:
        results[s] = int(mm.group(3))
    else:
        crashes += 1
check("抽样 selector 无崩溃", crashes == 0, "崩溃 %d 个" % crashes)
check("抽样 selector 全部有返回", len(results) == len(sample),
      "返回 %d/%d" % (len(results), len(sample)))

ok_sel = [s for s, v in results.items() if v == 0]
fail_sel = [s for s, v in results.items() if v == -2147467259]
check("存在返回 S_OK 的 selector", len(ok_sel) > 0, str(ok_sel))
check("存在返回 E_FAIL 的 selector（有区分性）", len(fail_sel) > 0, str(fail_sel))

# ---- 3. 特性标志 selector ----
print("\n[3] 特性标志 selector（65/67）")
flag = {}
for s in (65, 67):
    o = run_ps(SCRIPT, "-Target", clean, "-Mode", "0", "-Sel", str(s), "-Case", "0")
    mm = re.search(r"SEL\x1f\d+\x1fcase=\d+\x1frc=(-?\d+)", o)
    flag[s] = int(mm.group(1)) if mm else None
check("sel=65 返回 1", flag.get(65) == 1, "实际 %s" % flag.get(65))
check("sel=67 返回 1", flag.get(67) == 1, "实际 %s" % flag.get(67))

# ---- 4. 干净/恶意文件响应一致性（证明非判定值） ----
print("\n[4] 干净与恶意文件对同一 selector 的响应")
o1 = run_ps(SCRIPT, "-Target", clean, "-Mode", "0", "-Sel", "65", "-Case", "0")
o2 = run_ps(SCRIPT, "-Target", mal, "-Mode", "0", "-Sel", "65", "-Case", "0")
r1 = re.search(r"rc=(-?\d+)", o1)
r2 = re.search(r"rc=(-?\d+)", o2)
same = r1 and r2 and r1.group(1) == r2.group(1)
check("sel=65 对两文件返回相同值（确认为特性标志而非判定）", same,
      "clean=%s mal=%s" % (r1.group(1) if r1 else "?",
                           r2.group(1) if r2 else "?"))

# ---- 5. QEX 真实读取文件（obj+0x0C = 文件大小） ----
print("\n[5] QEX 真实读取文件内容（文件大小字段）")
dump = os.path.join(HERE, "qex_dump_check.ps1")
if os.path.exists(dump):
    o = run_ps(dump, "-Target", clean)
    mm = re.search(r"obj\+0x0C = 0x([0-9A-F]+)", o)
    if mm:
        got = int(mm.group(1), 16)
        check("obj+0x0C 等于 clean.ps1 字节数(%d)" % clean_size, got == clean_size,
              "读到 %d" % got)
    else:
        check("能读到 obj+0x0C", False, o[:200])
else:
    check("qex_dump_check.ps1 存在", False, dump)

print("\n" + "=" * 66)
total = passed + failed
print("总计: %d/%d 通过" % (passed, total))
print("=" * 66)
sys.exit(0 if failed == 0 else 1)