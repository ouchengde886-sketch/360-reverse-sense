import ctypes, sys, subprocess, time
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]; k.VirtualAllocEx.restype=wintypes.LPVOID
k.CloseHandle.argtypes=[wintypes.HANDLE]

print("=== ★★★ 验证：控制台继承是判别条件 ===")
print()
print("  假设: 当子进程**共享父进程的控制台**时，OpenProcess 拿到的句柄")
print("        缺少 VM_OPERATION 权限（尽管请求了 ALL_ACCESS）。")
print()
# 用 cmd 反复验证
for i in range(3):
    p=subprocess.Popen(['cmd.exe','/k','rem'])   # 继承控制台
    time.sleep(1.5)
    h=k.OpenProcess(0x1F0FFF,False,p.pid)
    k.SetLastError(0)
    a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
    print("  继承控制台 #%d: PID %-7d VirtAlloc=0x%-12X err=%d"%(i+1,p.pid,a or 0,k.GetLastError()))
    if h: k.CloseHandle(h)
    try: p.terminate()
    except: pass
print()
for i in range(3):
    p=subprocess.Popen(['cmd.exe','/k','rem'],creationflags=0x10)  # NEW_CONSOLE
    time.sleep(1.5)
    h=k.OpenProcess(0x1F0FFF,False,p.pid)
    k.SetLastError(0)
    a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
    print("  NEW_CONSOLE   #%d: PID %-7d VirtAlloc=0x%-12X err=%d"%(i+1,p.pid,a or 0,k.GetLastError()))
    if h: k.CloseHandle(h)
    try: p.terminate()
    except: pass
print()
print("=== 补充验证：D 盘 .com 副本（GUI 程序，之前失败）===")
import shutil,os
t=r'D:\probe_gui2.com'
shutil.copy(r'C:\Windows\System32\notepad.exe',t)
for i in range(2):
    p=subprocess.Popen([t])
    time.sleep(2)
    h=k.OpenProcess(0x1F0FFF,False,p.pid)
    k.SetLastError(0)
    a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
    print("  D盘.com 继承控制台 #%d: PID %-7d VirtAlloc=0x%-12X err=%d"%(i+1,p.pid,a or 0,k.GetLastError()))
    if h: k.CloseHandle(h)
    try: p.terminate()
    except: pass
for i in range(2):
    p=subprocess.Popen([t],creationflags=0x10)
    time.sleep(2)
    h=k.OpenProcess(0x1F0FFF,False,p.pid)
    k.SetLastError(0)
    a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
    print("  D盘.com NEW_CONSOLE   #%d: PID %-7d VirtAlloc=0x%-12X err=%d"%(i+1,p.pid,a or 0,k.GetLastError()))
    if h: k.CloseHandle(h)
    try: p.terminate()
    except: pass
