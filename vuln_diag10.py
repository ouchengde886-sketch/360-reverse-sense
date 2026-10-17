import ctypes, sys, subprocess, time, os, shutil
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]; k.VirtualAllocEx.restype=wintypes.LPVOID
k.CloseHandle.argtypes=[wintypes.HANDLE]
k.VirtualQueryEx.argtypes=[wintypes.HANDLE,wintypes.LPCVOID,ctypes.c_void_p,ctypes.c_size_t]; k.VirtualQueryEx.restype=ctypes.c_size_t

print("=== ★★★ 关键：检查 OpenProcess 返回的句柄**实际权限** ===")
print()
print("  VirtualAllocEx 需要 PROCESS_VM_OPERATION(0x8)。")
print("  若请求 ALL_ACCESS 但实际句柄缺少 0x8，就会 err=5。")
print("  用 NtQueryInformationProcess 或直接试最小权限组合。")
print()
def test(name,path):
    try:
        p=subprocess.Popen([path]); time.sleep(2)
    except Exception as e:
        print("  %-22s 启动失败"%name); return
    pid=p.pid
    print("  --- %s (PID %d) ---"%(name,pid))
    for acc,desc in [(0x1F0FFF,'ALL_ACCESS'),(0x8,'VM_OPERATION'),(0x38,'VM_OP|WRITE|READ'),
                     (0x28,'VM_OP|READ'),(0x1038,'QUERY|VM_OP|WRITE|READ')]:
        h=k.OpenProcess(acc,False,pid)
        k.SetLastError(0)
        a=k.VirtualAllocEx(h,None,4096,0x3000,0x40) if h else 0
        e=k.GetLastError()
        print("      OpenProcess(0x%-6X %-24s) h=0x%-5X VirtAlloc=0x%-12X err=%d"%(acc,desc,h or 0,a or 0,e))
        if a: k.VirtualFreeEx(h,ctypes.c_void_p(a),0,0x8000)
        if h: k.CloseHandle(h)
    try: p.terminate()
    except: pass

test('系统 notepad', r'C:\Windows\System32\notepad.exe')
t=r'C:\Users\Administrator\AppData\Local\Temp\cp1.com'
shutil.copy(r'C:\Windows\System32\notepad.exe',t)
test('TEMP .com 副本', t)
