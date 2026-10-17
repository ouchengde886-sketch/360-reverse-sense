import ctypes, sys, subprocess
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
u=ctypes.windll.user32
u.GetWindowTextLengthW.argtypes=[wintypes.HWND]
u.GetWindowTextW.argtypes=[wintypes.HWND,wintypes.LPWSTR,ctypes.c_int]
u.GetClassNameW.argtypes=[wintypes.HWND,wintypes.LPWSTR,ctypes.c_int]
u.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)]
u.IsWindowVisible.argtypes=[wintypes.HWND]
u.EnumWindows.argtypes=[ctypes.WINFUNCTYPE(ctypes.c_bool,wintypes.HWND,wintypes.LPARAM),wintypes.LPARAM]
u.EnumChildWindows.argtypes=[wintypes.HWND,ctypes.WINFUNCTYPE(ctypes.c_bool,wintypes.HWND,wintypes.LPARAM),wintypes.LPARAM]
CB=ctypes.WINFUNCTYPE(ctypes.c_bool,wintypes.HWND,wintypes.LPARAM)
def p2n():
    o=subprocess.run(['tasklist','/fo','csv','/nh'],capture_output=True,text=True,encoding='utf-8',errors='replace').stdout
    m={}
    for line in o.splitlines():
        f=[x.strip('"') for x in line.split('","')]
        if len(f)>=2:
            try: m[int(f[1])]=f[0]
            except: pass
    return m
nm=p2n()
print("=== 所有 360 进程的窗口（含不可见）===")
rows=[]
def cb(h,l):
    pid=wintypes.DWORD(); u.GetWindowThreadProcessId(h,ctypes.byref(pid))
    name=nm.get(pid.value,'?')
    if '360' in name or 'ZhuDong' in name or 'DSMain' in name:
        n=u.GetWindowTextLengthW(h)
        b=ctypes.create_unicode_buffer(n+2); u.GetWindowTextW(h,b,n+1)
        cn=ctypes.create_unicode_buffer(256); u.GetClassNameW(h,cn,256)
        rows.append((h,pid.value,name,b.value,cn.value,bool(u.IsWindowVisible(h))))
    return True
u.EnumWindows(CB(cb),0)
for h,pid,name,t,cn,vis in rows:
    print("  0x%-8X %-18s vis=%-5s cls=%-26s '%s'"%(h,name,vis,cn[:26],t[:40]))
print()
print("=== ★ 展开 #32770 对话框的子控件 ===")
for h,pid,name,t,cn,vis in rows:
    if cn=='#32770':
        print("  对话框 0x%X (%s) 标题='%s'"%(h,name,t))
        kids=[]
        def cb2(ch,l):
            n=u.GetWindowTextLengthW(ch)
            b=ctypes.create_unicode_buffer(n+2); u.GetWindowTextW(ch,b,n+1)
            c2=ctypes.create_unicode_buffer(256); u.GetClassNameW(ch,c2,256)
            kids.append((ch,c2.value,b.value))
            return True
        u.EnumChildWindows(h,CB(cb2),0)
        print("    子控件 %d 个:"%len(kids))
        for ch,c2,t2 in kids[:25]:
            print("      0x%-8X [%-22s] '%s'"%(ch,c2[:22],t2[:50]))
