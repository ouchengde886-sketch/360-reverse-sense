# Ghidra headless post-script: 导出 360 驱动的关键信息
# @category 360Analysis
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\ghidra_out"
import os
if not os.path.isdir(OUT):
    os.makedirs(OUT)

prog = currentProgram
fm = prog.getFunctionManager()
listing = prog.getListing()
symtab = prog.getSymbolTable()

result = {
    "program": prog.getName(),
    "language": str(prog.getLanguageID()),
    "image_base": str(prog.getImageBase()),
    "functions": [],
    "imports": [],
    "strings": [],
    "entry_points": [],
}

# 入口点
for ep in prog.getSymbolTable().getExternalEntryPointIterator():
    result["entry_points"].append(str(ep))

# 导入表
for sym in symtab.getExternalSymbols():
    result["imports"].append(sym.getName())

# 函数清单
for fn in fm.getFunctions(True):
    result["functions"].append({
        "name": fn.getName(),
        "entry": str(fn.getEntryPoint()),
        "size": fn.getBody().getNumAddresses(),
        "params": fn.getParameterCount(),
    })

# 字符串
di = DecompInterface()
di.openProgram(prog)
monitor = ConsoleTaskMonitor()

# 反编译关键函数：DriverEntry 及大函数
targets = []
for fn in fm.getFunctions(True):
    n = fn.getName()
    sz = fn.getBody().getNumAddresses()
    if n in ("DriverEntry", "GsDriverEntry") or sz > 400:
        targets.append((n, sz, fn))

targets.sort(key=lambda t: -t[1])
targets = targets[:25]

decompiled = []
for n, sz, fn in targets:
    try:
        res = di.decompileFunction(fn, 60, monitor)
        code = res.getDecompiledFunction().getC() if res and res.decompileCompleted() else None
        decompiled.append({"name": n, "size": sz, "code": code})
    except Exception as e:
        decompiled.append({"name": n, "size": sz, "code": "ERROR: %s" % e})

result["decompiled"] = decompiled
result["function_count"] = len(result["functions"])
result["import_count"] = len(result["imports"])

with open(os.path.join(OUT, "decompiled.json"), "w") as f:
    json.dump(result, f, indent=1)

# 人类可读报告
with open(os.path.join(OUT, "decompiled.txt"), "w") as f:
    f.write("PROGRAM: %s\n" % result["program"])
    f.write("LANG: %s\n" % result["language"])
    f.write("BASE: %s\n" % result["image_base"])
    f.write("FUNCTIONS: %d\n" % result["function_count"])
    f.write("IMPORTS: %d\n" % result["import_count"])
    f.write("\n=== IMPORTS ===\n")
    for i in sorted(set(result["imports"])):
        f.write("  %s\n" % i)
    f.write("\n=== TOP FUNCTIONS ===\n")
    for fn in sorted(result["functions"], key=lambda x: -x["size"])[:40]:
        f.write("  %-50s %s  size=%d\n" % (fn["name"], fn["entry"], fn["size"]))
    f.write("\n\n=== DECOMPILED ===\n")
    for d in decompiled:
        f.write("\n" + "=" * 78 + "\n")
        f.write("// %s  (size=%d)\n" % (d["name"], d["size"]))
        f.write("=" * 78 + "\n")
        f.write((d["code"] or "(failed)") + "\n")

print("EXPORTED: %s" % OUT)
print("functions=%d imports=%d decompiled=%d" % (result["function_count"], result["import_count"], len(decompiled)))