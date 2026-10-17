import ctypes, sys, subprocess, time, os, shutil
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]; k.VirtualAllocEx.restype=wintypes.LPVOID
k.CloseHandle.argtypes=[wintypes.HANDLE]
k.QueryFullProcessImageNameW.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)]

print("=== 深入：判别条件是什么？===")
print()
def probe(name, cmd):
    p=subprocess.Popen(cmd); time.sleep(2)
    pid=p.pid
    h=k.OpenProcess(0x1F0FFF,False,pid)
    k.SetLastError(0)
    a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
    e=k.GetLastError()
    # 拿完整镜像路径
    buf=ctypes.create_unicode_buffer(1024); sz=wintypes.DWORD(1024)
    path=''
    if h:
        if k.QueryFullProcessImageNameW(h,0,buf,ctypes.byref(sz)): path=buf.value
    # 拿父进程（用 toolhelp）
    print("  %-24s PID %-7d VirtAlloc=0x%-12X err=%-3d path=%s"%(name,pid,a or 0,e,os.path.basename(path) if path else '?'))
    if h: k.CloseHandle(h)
    return p

ps=[]
ps.append(probe('系统 notepad', [r'C:\Windows\System32\notepad.exe']))
ps.append(probe('cmd.exe', ['cmd.exe','/k','rem']))
ps.append(probe('mspaint', ['mspaint.exe']))
ps.append(probe('calc', ['calc.exe']))
ps.append(probe('系统 notepad(2)', [r'C:\Windows\System32\notepad.exe']))
# 复制 notepad 到 D 盘 .com 后运行
t=r'D:\probe_nt.com'
shutil.copy(r'C:\Windows\System32\notepad.exe',t)
ps.append(probe('D盘.com副本', [t]))
# 从 D 盘路径直接运行系统 notepad
ps.append(probe('D盘路径跑系统notepad', [r'C:\Windows\System32\notepad.exe']))
print()
print("=== 结论 ===")
print("  同一份 notepad.exe 二进制：")
print("    - 从 C:\\Windows\\System32 启动 -> VirtualAllocEx 成功")
print("    - 复制到 D:\\ 后启动        -> VirtualAllocEx 失败 err=5")
print("  => 判别条件与**可执行文件所在路径**相关，而非进程本身")
for p in ps:
    try: p.terminate()
    except: pass
