import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0,'.')
import av360_sense as A
s=A.AV360Sense()
print("HIPS_POPUP_CLASS =", A.HIPS_POPUP_CLASS)
print("MAIN_WINDOW_CLASS =", A.MAIN_WINDOW_CLASS)
print()
ev = s.poll_popups()
print("poll_popups() 返回 %d 个事件"%len(ev))
for e in ev:
    print("   ", e)
