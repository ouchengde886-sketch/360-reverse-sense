#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""感知通道实测：主动防御弹窗 / 查杀通知 / 进程监控。

直接运行（不要经 Start-Job，其管道会破坏中文输出）。
"""
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace")

from av360_sense import AV360Sense, HIPS_POPUP_CLASS, MAIN_WINDOW_CLASS  # noqa: E402

s = AV360Sense()

print("=" * 70)
print("  360 感知通道实测")
print("=" * 70)

print("\n[1] 主动防御弹窗通道")
print("    监听窗口类: %s" % HIPS_POPUP_CLASS)
print("    主监控窗口: %s" % MAIN_WINDOW_CLASS)
wins = s._enum_windows()
mon = [w for w in wins if w[1] == MAIN_WINDOW_CLASS]
print("    主监控窗口存在: %s" % ("是" if mon else "否"))
print("    当前 360 窗口数: %d" % len([w for w in wins
      if "360" in w[1] or "Q360" in w[1]]))

print("\n[2] 查杀通知通道")
s._seen_log_size = 0
hits = s.poll_scan_log()
print("    捕获查杀命中: %d 条" % len(hits))
for e in hits:
    print("      [%s] %s" % (e.extra.get("engine", "-"), e.title))
    print("            %s" % e.path)

print("\n[3] 进程监控通道")
s.poll_processes()          # 建立基线
time.sleep(1)
evs = s.poll_processes()
print("    基线已建立，本次新增事件: %d" % len(evs))

print("\n[4] 拦截状态")
st = s.state()
print("    监控开关: 启用 %d / 关闭 %d" % (st["enabled_count"], st["disabled_count"]))
print("    主动防御: %s" % st["services"].get("ZhuDongFangYu"))
print("    自我保护设备可打开: %s" % st["self_protection"].get("device_openable"))

print("\n" + "=" * 70)