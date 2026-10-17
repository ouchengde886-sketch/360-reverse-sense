import ctypes, sys, subprocess, time, os, shutil
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.CloseHandle.argtypes=[wintypes.HANDLE]

print("=== ★★★ 验证：.com 副本进程是否立即退出 ===")
print()
t=r'C:\Users\Administrator\AppData\Local\Temp\cp3.com'
shutil.copy(r'C:\Windows\System32\notepad.exe',t)
print("  启动 %s"%t)
p=subprocess.Popen([t])
for d in [0.1,0.5,1.0,2.0,3.0]:
    time.sleep(d if d==0.1 else d-0.1)
    rc=p.poll()
    print("    %.1fs 后 poll()=%s %s"%(d,rc,'★ 已退出' if rc is not None else '(仍在运行)'))
print()
print("=== 对照：系统 notepad ===")
p2=subprocess.Popen([r'C:\Windows\System32\notepad.exe'])
for d in [0.1,0.5,1.0,2.0,3.0]:
    time.sleep(d if d==0.1 else d-0.1)
    rc=p2.poll()
    print("    %.1fs 后 poll()=%s %s"%(d,rc,'已退出' if rc is not None else '(仍在运行)'))
print()
print("=== 结论 ===")
print("  若 .com 副本很快退出，说明它**启动失败或立即结束**，")
print("  那么 VirtualAllocEx 失败只是'进程正在终止'的正常现象，")
print("  ★ 根本不是 360 拦截！")
try: p2.terminate()
except: pass
