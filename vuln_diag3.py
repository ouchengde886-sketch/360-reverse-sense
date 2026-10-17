import ctypes, sys, subprocess, time, os, shutil
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]; k.VirtualAllocEx.restype=wintypes.LPVOID
k.CloseHandle.argtypes=[wintypes.HANDLE]
k.IsWow64Process.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.BOOL)]

print("=== ★ 找出真正的判别条件 ===")
print()
tests=[]
# A. 纯系统 notepad（多次）
for i in range(2):
    tests.append(('系统notepad#%d'%i, subprocess.Popen([r'C:\Windows\System32\notepad.exe'])))
time.sleep(2)
# B. cmd.exe
tests.append(('cmd.exe', subprocess.Popen(['cmd.exe','/k','rem'])))
time.sleep(2)
# C. 复制到 D 盘 .com
t1=r'D:\cmp_tgt.com'
shutil.copy(r'C:\Windows\System32\notepad.exe',t1)
tests.append(('D盘.com副本', subprocess.Popen([t1])))
time.sleep(2)
# D. 复制到 D 盘 .exe（已存在则覆盖会失败，用新名字）
t2=r'D:\cmp_tgt_new.exe'
try:
    shutil.copy(r'C:\Windows\System32\notepad.exe',t2)
    tests.append(('D盘.exe副本', subprocess.Popen([t2])))
except Exception as e:
    print("  无法创建 .exe 副本: %s"%e)
time.sleep(2)
# E. 系统 notepad 再测一次（验证稳定性）
tests.append(('系统notepad#2', subprocess.Popen([r'C:\Windows\System32\notepad.exe'])))
time.sleep(2)

print("%-22s %-8s %-10s %-8s %-14s %s"%("目标","PID","OpenProc","err","VirtAllocEx","err"))
print("-"*80)
for name,p in tests:
    pid=p.pid
    k.SetLastError(0)
    h=k.OpenProcess(0x1F0FFF,False,pid)
    e1=k.GetLastError()
    k.SetLastError(0)
    a=k.VirtualAllocEx(h,None,4096,0x3000,0x40) if h else 0
    e2=k.GetLastError()
    w=wintypes.BOOL()
    k.IsWow64Process(h,ctypes.byref(w)) if h else None
    print("%-22s %-8d 0x%-8X %-8d 0x%-12X %d  wow64=%d"%(name,pid,h or 0,e1,a or 0,e2,w.value if h else -1))
    if h: k.CloseHandle(h)
print()
for p in [x[1] for x in tests]:
    try: p.terminate()
    except: pass
