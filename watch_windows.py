import ctypes, sys, os, time
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
u=ctypes.windll.user32
u.EnumWindows.argtypes=[ctypes.WINFUNCTYPE(ctypes.c_bool,wintypes.HWND,wintypes.LPARAM),wintypes.LPARAM]
u.GetWindowTextLengthW.argtypes=[wintypes.HWND]
u.GetWindowTextW.argtypes=[wintypes.HWND,wintypes.LPWSTR,ctypes.c_int]
u.IsWindowVisible.argtypes=[wintypes.HWND]
u.GetClassNameW.argtypes=[wintypes.HWND,wintypes.LPWSTR,ctypes.c_int]
u.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)]

print("=== ★ 当前所有可见窗口（含 360 弹窗）===")
print()
CB=ctypes.WINFUNCTYPE(ctypes.c_bool,wintypes.HWND,wintypes.LPARAM)
rows=[]
def cb(h,l):
    if not u.IsWindowVisible(h): return True
    n=u.GetWindowTextLengthW(h)
    if n==0: return True
    b=ctypes.create_unicode_buffer(n+1); u.GetWindowTextW(h,b,n+1)
    cn=ctypes.create_unicode_buffer(256); u.GetClassNameW(h,cn,256)
    pid=wintypes.DWORD(); u.GetWindowThreadProcessId(h,ctypes.byref(pid))
    rows.append((h,pid.value,b.value,cn.value))
    return True
u.EnumWindows(CB(cb),0)
# 按进程名归类
import subprocess
out=subprocess.run(['tasklist','/fo','csv','/nh'],capture_output=True,text=True,encoding='utf-8',errors='replace').stdout
pid2name={}
for line in out.splitlines():
    f=[x.strip('"') for x in line.split('","')]
    if len(f)>=2:
        try: pid2name[int(f[1])]=f[0]
        except: pass
print("%-10s %-22s %-42s %s"%("HWND","进程","标题","类名"))
print("-"*130)
for h,pid,t,cn in rows:
    nm=pid2name.get(pid,'?')
    mark=''
    if '360' in nm or 'DSMain' in nm or 'ZhuDong' in nm or '木马' in t or '安全' in t:
        mark=' ★'
    print("0x%-8X %-22s %-42s %s%s"%(h,nm,t[:40],cn[:28],mark))
