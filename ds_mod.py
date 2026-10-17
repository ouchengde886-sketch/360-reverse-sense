import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
# 方法 [6] = 0x56DC4720，模块基址 0x56DC0000（运行时）
# 需要换算成文件偏移。先看它属于哪个模块。
# 0x56DC4720 - 0x56DC0000 = 0x4720
# 但 deepscan base = 0x6C2A0000，所以 0x56DC4720 不在 deepscan 里。
# 它在另一个模块。看模块列表。
print("  方法 [6] = 0x56DC4720，虚表 = 0x56E2B124")
print("  deepscan base = 0x6C2A0000 -> 0x56DC4720 不在 deepscan")
print()
print("  0x56DC4720 属于哪个模块？")
print("  从虚表 0x56E2B124 和 0x56E2B160/0x56E2B168 看，")
print("  这些地址都在 0x56Dxxxxx - 0x56Exxxxx 区间。")
print()
print("  引擎对象 0x07E17AC8 是堆地址，虚表 0x56E2B124 是模块数据段。")
print("  所以引擎对象来自一个**独立的 DLL**，不是 deepscan.dll。")
print()
print("  之前记录的模块：AVEI.dll / AVEngine.dll / QEX.dll / Cloudsec3.dll ...")
print("  0x56DC0000 附近的模块基址 —— 需要枚举进程模块确认。")
