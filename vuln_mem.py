import ctypes, sys, subprocess, os
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
print("=== 进程内存操作拦截测试（免杀核心战场）===")
print()
# 起一个自己的测试进程（非 360）
p=subprocess.Popen(["notepad.exe"])
import time; time.sleep(1.5)
pid=p.pid
print("测试目标: notepad.exe PID %d（普通进程，对照）"%pid)
print()
PROCESS_ALL=0x1F0FFF
h=k.OpenProcess(PROCESS_ALL,False,pid)
print("  OpenProcess(ALL_ACCESS) -> 0x%08X"%h)
if h:
    # VirtualQueryEx
    class MBI(ctypes.Structure):
        _fields_=[('BaseAddress',ctypes.c_void_p),('AllocationBase',ctypes.c_void_p),
                  ('AllocationProtect',wintypes.DWORD),('RegionSize',ctypes.c_size_t),
                  ('State',wintypes.DWORD),('Protect',wintypes.DWORD),('Type',wintypes.DWORD)]
    mbi=MBI()
    r=k.VirtualQueryEx(h,ctypes.c_void_p(0x400000),ctypes.byref(mbi),ctypes.sizeof(mbi))
    print("  VirtualQueryEx -> %d 字节, RegionSize=0x%X Protect=0x%X"%(r,mbi.RegionSize or 0,mbi.Protect))
    # ReadProcessMemory
    buf=ctypes.create_string_buffer(64)
    read=ctypes.c_size_t()
    r2=k.ReadProcessMemory(h,ctypes.c_void_p(0x400000),buf,64,ctypes.byref(read))
    print("  ReadProcessMemory -> %s, 读 %d 字节, 头: %s"%(bool(r2),read.value,buf.raw[:8].hex(' ')))
    # VirtualAllocEx
    addr=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
    print("  VirtualAllocEx -> 0x%08X"%(addr or 0))
    if addr:
        # WriteProcessMemory
        w=ctypes.c_size_t()
        data=b'HELLO_INJECTED\x00'
        r3=k.WriteProcessMemory(h,ctypes.c_void_p(addr),data,len(data),ctypes.byref(w))
        print("  WriteProcessMemory -> %s, 写 %d 字节"%(bool(r3),w.value))
        # VirtualProtectEx
        old=wintypes.DWORD()
        r4=k.VirtualProtectEx(h,ctypes.c_void_p(addr),4096,0x20,ctypes.byref(old))
        print("  VirtualProtectEx -> %s (old=0x%X)"%(bool(r4),old.value))
        # 读回
        buf2=ctypes.create_string_buffer(32)
        rd=ctypes.c_size_t()
        k.ReadProcessMemory(h,ctypes.c_void_p(addr),buf2,32,ctypes.byref(rd))
        print("  读回注入内容: %r"%buf2.raw[:rd.value])
        k.VirtualFreeEx(h,ctypes.c_void_p(addr),0,0x8000)
        print("  VirtualFreeEx -> 完成")
    k.CloseHandle(h)
print()
p.terminate()
print("=== 对照：对 360 进程（ZhuDongFangYu PID 3712）做同样操作 ===")
out=subprocess.run(['tasklist','/fo','csv','/nh'],capture_output=True,text=True,encoding='utf-8',errors='replace').stdout
for line in out.splitlines():
    f=[x.strip('"') for x in line.split('","')]
    if len(f)>=2 and f[0]=='ZhuDongFangYu.exe':
        zpid=int(f[1]); break
else:
    zpid=None
if zpid:
    h2=k.OpenProcess(PROCESS_ALL,False,zpid)
    print("  OpenProcess(ALL_ACCESS) -> 0x%08X %s"%(h2,'OK' if h2 else 'DENIED (已知)'))
    h3=k.OpenProcess(0x1000,False,zpid)
    print("  OpenProcess(QUERY_LIMITED) -> 0x%08X %s"%(h3,'OK' if h3 else 'DENIED'))
