import ctypes, sys, subprocess, time, os, shutil
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]; k.VirtualAllocEx.restype=wintypes.LPVOID
k.CloseHandle.argtypes=[wintypes.HANDLE]

print("=== ★★★ 决定性：用 NtAllocateVirtualMemory 绕过 kernel32 的 VirtualAllocEx ===")
print()
ntdll=ctypes.windll.ntdll
ntdll.NtAllocateVirtualMemory.argtypes=[wintypes.HANDLE,ctypes.POINTER(ctypes.c_void_p),ctypes.c_ulong,
    ctypes.POINTER(ctypes.c_size_t),ctypes.c_ulong,ctypes.c_ulong]
ntdll.NtAllocateVirtualMemory.restype=ctypes.c_long

def test(name,path):
    try:
        p=subprocess.Popen([path]); time.sleep(2)
    except Exception as e:
        print("  %-20s 启动失败"%name); return
    pid=p.pid
    h=k.OpenProcess(0x1F0FFF,False,pid)
    # kernel32 路径
    k.SetLastError(0)
    a1=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
    e1=k.GetLastError()
    # ntdll 路径
    base=ctypes.c_void_p(0)
    size=ctypes.c_size_t(4096)
    st=ntdll.NtAllocateVirtualMemory(h,ctypes.byref(base),0,ctypes.byref(size),0x3000,0x40)
    print("  %-20s PID %-7d"%(name,pid))
    print("      kernel32 VirtualAllocEx -> 0x%-12X err=%d"%(a1 or 0,e1))
    print("      ntdll NtAllocateVirtualMemory -> status=0x%08X base=0x%X size=%d"%(
        st & 0xFFFFFFFF, base.value or 0, size.value))
    if h: k.CloseHandle(h)
    try: p.terminate()
    except: pass

test('系统 notepad', r'C:\Windows\System32\notepad.exe')
t=r'C:\Users\Administrator\AppData\Local\Temp\cp2.com'
shutil.copy(r'C:\Windows\System32\notepad.exe',t)
test('TEMP .com 副本', t)
print()
print("=== 若 ntdll 路径成功 => kernel32 的 VirtualAllocEx 被 hook ===")
