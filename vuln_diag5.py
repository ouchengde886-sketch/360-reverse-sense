import ctypes, sys, subprocess, time, os, shutil
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]; k.OpenProcess.restype=wintypes.HANDLE
k.VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]; k.VirtualAllocEx.restype=wintypes.LPVOID
k.CloseHandle.argtypes=[wintypes.HANDLE]

print("=== ★★ 决定性判别：GUI 进程 vs 控制台进程 ===")
print()
def probe(name, cmd, gui_hint):
    try:
        p=subprocess.Popen(cmd); time.sleep(2.5)
    except Exception as e:
        print("  %-24s 启动失败 %s"%(name,e)); return None
    pid=p.pid
    h=k.OpenProcess(0x1F0FFF,False,pid)
    k.SetLastError(0)
    a=k.VirtualAllocEx(h,None,4096,0x3000,0x40)
    e=k.GetLastError()
    print("  %-24s %-10s PID %-7d VirtAlloc=0x%-12X err=%d"%(name,gui_hint,pid,a or 0,e))
    if h: k.CloseHandle(h)
    return p

ps=[]
# GUI 进程
ps.append(probe('notepad (GUI)','notepad.exe'.split(),'GUI'))
ps.append(probe('mspaint (GUI)',['mspaint.exe'],'GUI'))
ps.append(probe('write (GUI)',['write.exe'],'GUI'))
ps.append(probe('charmap (GUI)',['charmap.exe'],'GUI'))
# 控制台进程
ps.append(probe('cmd (CONSOLE)',['cmd.exe','/k','rem'],'CONSOLE'))
ps.append(probe('powershell (CONSOLE)',['powershell.exe','-NoProfile','-Command','Start-Sleep 30'],'CONSOLE'))
ps.append(probe('ping (CONSOLE)',['ping.exe','-n','30','127.0.0.1'],'CONSOLE'))
# 复制到 D 盘的 GUI 进程
t=r'D:\probe_gui.com'
shutil.copy(r'C:\Windows\System32\notepad.exe',t)
ps.append(probe('D盘 .com 副本',[t],'GUI?'))
print()
print("=== 结论 ===")
print("  若 GUI 全部成功、CONSOLE 全部失败 => 判别条件是进程类型")
for p in ps:
    if p:
        try: p.terminate()
        except: pass
