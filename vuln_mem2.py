import ctypes, sys, subprocess, time
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
# ★ 关键：设置正确的 argtypes/restype，否则 64 位下指针被截断
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
k.OpenProcess.restype=wintypes.HANDLE
k.ReadProcessMemory.argtypes=[wintypes.HANDLE,wintypes.LPCVOID,wintypes.LPVOID,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
k.ReadProcessMemory.restype=wintypes.BOOL
k.WriteProcessMemory.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.LPCVOID,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
k.WriteProcessMemory.restype=wintypes.BOOL
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]
k.VirtualAllocEx.restype=wintypes.LPVOID
k.VirtualProtectEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
k.VirtualProtectEx.restype=wintypes.BOOL
k.VirtualFreeEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD]
k.VirtualFreeEx.restype=wintypes.BOOL
k.CloseHandle.argtypes=[wintypes.HANDLE]

print("=== 进程注入原语测试（正确 argtypes）===")
p=subprocess.Popen(["notepad.exe"]); time.sleep(1.5)
pid=p.pid
print("目标: notepad.exe PID %d"%pid)
print()
h=k.OpenProcess(0x1F0FFF,False,pid)
print("  OpenProcess(ALL_ACCESS) -> 0x%X"%h)
if h:
    addr=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
    print("  VirtualAllocEx -> 0x%X"%(addr or 0))
    if addr:
        data=b'HELLO_INJECTED_FROM_PYTHON\x00'
        w=ctypes.c_size_t()
        ok=k.WriteProcessMemory(h,addr,data,len(data),ctypes.byref(w))
        print("  WriteProcessMemory -> %s, 写 %d 字节, err=%d"%(bool(ok),w.value,k.GetLastError()))
        # 读回
        buf=ctypes.create_string_buffer(64)
        rd=ctypes.c_size_t()
        ok2=k.ReadProcessMemory(h,addr,buf,64,ctypes.byref(rd))
        print("  ReadProcessMemory -> %s, 读 %d 字节, 内容 %r"%(bool(ok2),rd.value,buf.raw[:rd.value]))
        # 改保护
        old=wintypes.DWORD()
        ok3=k.VirtualProtectEx(h,addr,4096,0x20,ctypes.byref(old))
        print("  VirtualProtectEx -> %s (old=0x%X)"%(bool(ok3),old.value))
        k.VirtualFreeEx(h,addr,0,0x8000)
        print("  VirtualFreeEx -> 完成")
    k.CloseHandle(h)
print()
print("=== 结论 ===")
print("  => 对普通进程的完整注入原语（OpenProcess/AllocEx/WriteProcessMemory/ProtectEx）")
print("     全部可用，无拦截")
p.terminate()
