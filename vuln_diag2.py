import ctypes, sys, subprocess, time, os
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]; k.VirtualAllocEx.restype=wintypes.LPVOID
k.CloseHandle.argtypes=[wintypes.HANDLE]

print("=== 对照实验：不同目标进程的 VirtualAllocEx ===")
print()
targets=[]
# 1. 系统 notepad（原版路径）
p1=subprocess.Popen([r'C:\Windows\System32\notepad.exe']); targets.append(('系统 notepad.exe',p1))
# 2. 复制成 .com 的 notepad
import shutil
t=os.path.join(os.environ['TEMP'],'cmp_tgt.com')
shutil.copy(r'C:\Windows\System32\notepad.exe',t)
p2=subprocess.Popen([t]); targets.append(('复制为 .com 的 notepad',p2))
# 3. cmd.exe
p3=subprocess.Popen(['cmd.exe','/c','pause']); targets.append(('cmd.exe',p3))
time.sleep(2.5)
for name,p in targets:
    pid=p.pid
    k.SetLastError(0)
    h=k.OpenProcess(0x1F0FFF,False,pid)
    e1=k.GetLastError()
    k.SetLastError(0)
    a=k.VirtualAllocEx(h,None,4096,0x3000,0x40) if h else 0
    e2=k.GetLastError()
    print("  %-26s PID %-7d OpenProcess=0x%-5X(err=%d)  VirtualAllocEx=0x%-12X(err=%d)"%(name,pid,h or 0,e1,a or 0,e2))
    if h: k.CloseHandle(h)
print()
print("=== 关键：第一次成功的测试用的是什么目标？===")
print("  第 25 轮 vuln_inject.py: subprocess.Popen(['notepad.exe'])  -> 成功")
print("  本轮: subprocess.Popen([<绝对路径>])  -> 失败")
print()
print("=== 再测：用裸名字 notepad.exe ===")
p4=subprocess.Popen(['notepad.exe'])
time.sleep(2.5)
pid=p4.pid
h=k.OpenProcess(0x1F0FFF,False,pid)
k.SetLastError(0)
a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
print("  notepad.exe PID %d: OpenProcess=0x%X VirtualAllocEx=0x%X err=%d"%(pid,h or 0,a or 0,k.GetLastError()))
if h: k.CloseHandle(h)
print()
print("=== 检查这些进程的父进程/完整性级别差异 ===")
for name,p in targets+[('notepad.exe(裸名)',p4)]:
    print("  %-26s PID %d"%(name,p.pid))
for p in [p1,p2,p3,p4]:
    try: p.terminate()
    except: pass
