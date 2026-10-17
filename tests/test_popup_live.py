import sys, time, threading, subprocess
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0,'.')
import av360_sense as A
s=A.AV360Sense()
print("=== ★★★ 实时弹窗感知测试：基线 + 触发 + 捕获 ===")
print()
base=s.poll_popups()
print("基线: %d 个 360 窗口已登记"%len(s._seen_hwnds))
print()
# 后台制造一个带"360"标题的窗口来验证捕获链路
import ctypes
def make_popup():
    time.sleep(3)
    subprocess.Popen(['cmd.exe','/c','title 360木马查杀提醒您测试 && timeout /t 6 >nul'],
                     creationflags=0x00000010)
t=threading.Thread(target=make_popup,daemon=True); t.start()
print("等待弹窗出现（8 秒轮询）...")
found=[]
t0=time.time()
while time.time()-t0 < 12:
    ev=s.poll_popups(include_all_360=True)
    for e in ev:
        found.append(e)
        print("  ★ [%.1fs] 捕获: kind=%s title='%s' hwnd=0x%X"%(time.time()-t0,e.kind,e.title,e.hwnd))
        if e.body: print("        正文: %s"%e.body[:120].replace('\n','|'))
    time.sleep(0.5)
print()
print("=== 共捕获 %d 个事件 ==="%len(found))
print()
print("=== 验证：普通 360 窗口不会误报（第二次轮询）===")
ev2=s.poll_popups(include_all_360=True)
print("  第二轮: %d 个新事件（应为 0）"%len(ev2))
