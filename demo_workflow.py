"""★ 实战演示：免杀自动化感知层的完整工作流。

这不是单元测试，而是模拟真实使用场景：
  1. 生成一个"目标文件"（payload）
  2. 用 360 自己的引擎查杀它（主动调用）
  3. 感知 360 的反应（弹窗通道 + 日志通道）
  4. 给出明确判定（不误报干净）

这正是用户最初的需求："自动化脚本生成目标，主动调用查杀，
运行时和一般情况下知道哪里被拦截"。
"""
import os, sys, time, json, shutil
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, '.')

import av360_sense as A

def hr(t=""):
    print("=" * 74)
    if t: print("  " + t); print("=" * 74)

hr("实战演示：免杀自动化感知层完整工作流")
print()

s = A.AV360Sense()

# ---- 步骤1: 生成目标 ----
print("[步骤1] 生成测试目标")
d = r"D:\evasion_demo_%d" % (int(time.time()) % 100000)
os.makedirs(d, exist_ok=True)
eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
targets = {
    "payload.com": eicar,                      # 会被查杀
    "payload.txt": eicar,                      # 会被查杀
    "clean.txt":   "hello world, benign",      # 干净
}
for n, c in targets.items():
    with open(os.path.join(d, n), "w", encoding="ascii") as f:
        f.write(c)
    print("      %s (%d 字节)" % (n, len(c)))
print()

# ---- 步骤2: 主动调用 360 引擎查杀 ----
print("[步骤2] 主动调用 360 引擎查杀（不依赖用户点右键）")
print()
for n in targets:
    p = os.path.join(d, n)
    r = s.scan_all_engines(p)
    eng = r.get("engines", {})
    print("      %s" % n)
    for k, v in eng.items():
        st = v.get("verdict") or v.get("error", "")[:40]
        print("          %-8s -> %s" % (k, st))
print()

# ---- 步骤3: 感知弹窗 ----
print("[步骤3] 感知 360 弹窗（22 个窗口类覆盖）")
s.poll_popups(include_all_360=True)   # 建基线
print("      基线已建立")
print()

# ---- 步骤4: 触发 360 自己的扫描 ----
print("[步骤4] 触发 360 自己的扫描并做双通道判定")
print()
v = s.scan_and_verdict(d, wait=90)
print("      判定来源: %s" % v["verdict_source"])
print("      结果可读: %s" % v["log_available"])
print("      ★ 可判定干净: %s" % v["clean_known"])
print("      威胁数: %d" % len(v["threats"]))
print("      触发: 已触发=%s 已执行=%s" % (
    v["trigger"]["triggered"], v["trigger"]["executed"]))
print()
print("      结论: %s" % v["note"])
if v["threats"]:
    print()
    print("      --- 威胁明细 ---")
    for t in v["threats"][:5]:
        print("        [%s] %s" % (t.get("engine"), t.get("verdict")))
        print("              %s" % t.get("path"))
print()

# ---- 步骤5: 给出决策 ----
hr("决策输出（自动化脚本应如何使用这些信息）")
print()
if v["clean_known"]:
    print("  → 确定干净，可以继续")
elif v["verdict_source"] == "cache_only":
    print("  → 扫描跑了但结果不可读，不能声称干净")
    print("  → 建议：改用主 UI 扫描，或降低置信度")
elif v["log_available"]:
    print("  → 检出威胁 %d 个，需要处理" % len(v["threats"]))
else:
    print("  → 扫描未执行（或结果尚未落盘）")
    print("  → 建议：等待后重试，或检查 360 是否在忙")
print()
hr()
