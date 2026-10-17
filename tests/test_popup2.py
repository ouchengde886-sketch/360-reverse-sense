import sys, time
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0,'.')
import av360_sense as A
s=A.AV360Sense()
print("=== 基线建立（首次调用不产出事件）===")
e1=s.poll_popups()
print("  首次: %d 个事件（应为 0）"%len(e1))
print("  已记录窗口: %d 个"%len(s._seen_hwnds))
print()
print("=== 第二次调用（应无新事件）===")
e2=s.poll_popups()
print("  第二次: %d 个事件"%len(e2))
print()
print("=== ★ 列出被识别为 360 弹窗的窗口 ===")
rows=s._enum_windows()
n=0
for hwnd,cls,title in rows:
    if A.is_popup_class(cls) or A.is_popup_title(title):
        n+=1
        if n<=25:
            print("  0x%-8X cls=%-30s '%s'"%(hwnd,cls[:30],title[:40]))
print("  合计 %d 个被识别为弹窗类窗口"%n)
print()
print("=== ★ 测试 include_all_360 ===")
s2=A.AV360Sense()
e3=s2.poll_popups(include_all_360=True)
print("  首次: %d 个事件，记录 %d 个窗口"%(len(e3),len(s2._seen_hwnds)))
