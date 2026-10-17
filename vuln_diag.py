import ctypes, sys, subprocess, time, os, shutil
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]; k.VirtualAllocEx.restype=wintypes.LPVOID
k.CloseHandle.argtypes=[wintypes.HANDLE]

print("=== 诊断 VirtualAllocEx 失败原因 ===")
tgt=os.path.join(os.environ['TEMP'],'dsh_tgt2.com')
shutil.copy(r'C:\Windows\System32\notepad.exe',tgt)
p=subprocess.Popen([tgt]); time.sleep(2.5)
pid=p.pid
print("  目标 PID %d"%pid)
print()
for name,acc in [("ALL_ACCESS",0x1F0FFF),("VM_OPERATION|VM_WRITE|VM_READ",0x38),
                 ("VM_OPERATION",0x8),("QUERY|VM_OP|VM_WRITE|VM_READ",0x1038)]:
    k.SetLastError(0)
    h=k.OpenProcess(acc,False,pid)
    err=k.GetLastError()
    print("  OpenProcess(0x%X) %-30s -> 0x%X err=%d"%(acc,name,h or 0,err))
    if h:
        k.SetLastError(0)
        a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
        e2=k.GetLastError()
        print("        VirtualAllocEx -> 0x%X err=%d"%(a or 0,e2))
        if not a:
            # 试不同参数
            for fl,prot,desc in [(0x1000,0x04,"MEM_COMMIT/PAGE_READWRITE"),(0x3000,0x40,"MEM_COMMIT|RESERVE/PAGE_EXECUTE_READWRITE")]:
                k.SetLastError(0)
                a2=k.VirtualAllocEx(h,None,4096,fl,prot)
                print("        试 %-45s -> 0x%X err=%d"%(desc,a2 or 0,k.GetLastError()))
        k.CloseHandle(h)
print()
print("  进程是否 64 位: %s"%("是" if ctypes.sizeof(ctypes.c_void_p)==8 else "否"))
print("  目标进程是否 64 位: 需检查")
# 检查目标进程位数
w=ctypes.c_int()
h2=k.OpenProcess(0x1000,False,pid)
if h2:
    k.IsWow64Process(h2,ctypes.byref(w))
    print("  IsWow64Process -> %d (%s)"%(w.value,"32位进程" if w.value else "64位进程"))
    k.CloseHandle(h2)
p.terminate()
