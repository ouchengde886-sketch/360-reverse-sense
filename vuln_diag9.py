import ctypes, sys, subprocess, time, os, shutil
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]; k.VirtualAllocEx.restype=wintypes.LPVOID
k.CloseHandle.argtypes=[wintypes.HANDLE]

print("=== ★★★ 最终判别：.com 副本失败的真正原因 ===")
print()
# 关键对照：同一份 notepad 二进制，不同位置
cases=[
  ('C:\\Windows\\System32\\notepad.exe', r'C:\Windows\System32\notepad.exe'),
]
# 复制到多个位置
for dst,label in [(r'D:\t1.com','D盘 .com'),(r'D:\t2.exe','D盘 .exe(若已存在则跳过)'),
                  (r'C:\Users\Administrator\AppData\Local\Temp\t3.com','TEMP .com'),
                  (r'C:\Users\Administrator\AppData\Local\Temp\t4.dat','TEMP .dat')]:
    try:
        shutil.copy(r'C:\Windows\System32\notepad.exe',dst)
        cases.append((label,dst))
    except Exception as e:
        print("  创建 %s 失败: %s"%(label,e))
print()
for label,path in cases:
    if not os.path.exists(path): continue
    try:
        p=subprocess.Popen([path]); time.sleep(2)
        pid=p.pid
        h=k.OpenProcess(0x1F0FFF,False,pid)
        k.SetLastError(0)
        a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
        e=k.GetLastError()
        print("  %-22s %-52s VirtAlloc=0x%-12X err=%d"%(label,path,a or 0,e))
        if h: k.CloseHandle(h)
        try: p.terminate()
        except: pass
    except Exception as ex:
        print("  %-22s 启动失败 %s"%(label,ex))
print()
print("=== 假设检验：是否与**文件是否在 C 盘**有关？===")
print("  若 C 盘副本成功、D 盘副本失败 => 与盘符相关（可能是 360 的卷过滤）")
