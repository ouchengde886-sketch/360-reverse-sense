import ctypes, sys, subprocess, time, os
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]; k.VirtualAllocEx.restype=wintypes.LPVOID
k.CloseHandle.argtypes=[wintypes.HANDLE]

print("=== ★★ 判别：是否与进程启动后的时间有关 ===")
print()
# 同一目标 cmd.exe，在不同延迟后测试
for delay in [0.2,1.0,2.0,4.0,8.0]:
    p=subprocess.Popen(['cmd.exe','/k','rem'])
    time.sleep(delay)
    pid=p.pid
    h=k.OpenProcess(0x1F0FFF,False,pid)
    k.SetLastError(0)
    a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
    e=k.GetLastError()
    print("  cmd.exe 延迟 %.1fs 后: VirtAlloc=0x%-12X err=%d"%(delay,a or 0,e))
    if h: k.CloseHandle(h)
    try: p.terminate()
    except: pass
print()
print("=== 同一 notepad 在不同延迟 ===")
for delay in [0.2,1.0,2.0]:
    p=subprocess.Popen([r'C:\Windows\System32\notepad.exe'])
    time.sleep(delay)
    pid=p.pid
    h=k.OpenProcess(0x1F0FFF,False,pid)
    k.SetLastError(0)
    a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
    e=k.GetLastError()
    print("  notepad 延迟 %.1fs 后: VirtAlloc=0x%-12X err=%d"%(delay,a or 0,e))
    if h: k.CloseHandle(h)
    try: p.terminate()
    except: pass
print()
print("=== ★★★ 关键：反复对同一个进程尝试（是否首次失败后续成功）===")
p=subprocess.Popen(['cmd.exe','/k','rem'])
time.sleep(2)
pid=p.pid
h=k.OpenProcess(0x1F0FFF,False,pid)
for i in range(5):
    k.SetLastError(0)
    a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
    print("  第 %d 次尝试: 0x%-12X err=%d"%(i+1,a or 0,k.GetLastError()))
    if a: k.VirtualFreeEx(h,ctypes.c_void_p(a),0,0x8000)
    time.sleep(0.5)
if h: k.CloseHandle(h)
try: p.terminate()
except: pass
