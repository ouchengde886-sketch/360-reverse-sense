import ctypes, sys, subprocess, time
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]
k.VirtualAllocEx.restype=wintypes.LPVOID
k.CloseHandle.argtypes=[wintypes.HANDLE]

print("=== ★★★ 关键对照：cmd.exe 用不同方式启动 ===")
print()
print("假设: 之前失败的 cmd.exe 是**从 PowerShell 继承控制台**启动的，")
print("      而成功的 powershell/ping 是独立启动的。")
print("      实际上失败可能与 **stdin/stdout 继承** 有关。")
print()
import os
cases = [
  ("cmd 继承控制台", ['cmd.exe','/k','rem'], None),
  ("cmd 无控制台(DETACHED)", ['cmd.exe','/k','rem'], 0x00000008),
  ("cmd 新控制台(NEW_CONSOLE)", ['cmd.exe','/k','rem'], 0x00000010),
  ("cmd 重定向输出", ['cmd.exe','/c','echo hi'], 'pipe'),
  ("notepad 继承", [r'C:\Windows\System32\notepad.exe'], None),
  ("notepad 无控制台", [r'C:\Windows\System32\notepad.exe'], 0x00000008),
]
for name,cmd,flag in cases:
    try:
        if flag=='pipe':
            p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stdin=subprocess.PIPE)
        elif flag is None:
            p=subprocess.Popen(cmd)
        else:
            p=subprocess.Popen(cmd,creationflags=flag)
        time.sleep(2)
        pid=p.pid
        h=k.OpenProcess(0x1F0FFF,False,pid)
        k.SetLastError(0)
        a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
        e=k.GetLastError()
        print("  %-28s PID %-7d Open=0x%-5X VirtAlloc=0x%-12X err=%d"%(name,pid,h or 0,a or 0,e))
        if h: k.CloseHandle(h)
        try: p.terminate()
        except: pass
    except Exception as ex:
        print("  %-28s 异常 %s"%(name,ex))
