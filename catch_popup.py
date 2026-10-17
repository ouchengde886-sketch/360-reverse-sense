import ctypes, sys, time, subprocess
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
u=ctypes.windll.user32
u.GetWindowTextLengthW.argtypes=[wintypes.HWND]
u.GetWindowTextW.argtypes=[wintypes.HWND,wintypes.LPWSTR,ctypes.c_int]
u.IsWindowVisible.argtypes=[wintypes.HWND]
u.GetClassNameW.argtypes=[wintypes.HWND,wintypes.LPWSTR,ctypes.c_int]
u.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)]
CB=ctypes.WINFUNCTYPE(ctypes.c_bool,wintypes.HWND,wintypes.LPARAM)
def snap():
    rows=[]
    def cb(h,l):
        n=u.GetWindowTextLengthW(h)
        b=ctypes.create_unicode_buffer(n+2); u.GetWindowTextW(h,b,n+1)
        cn=ctypes.create_unicode_buffer(256); u.GetClassNameW(h,cn,256)
        pid=wintypes.DWORD(); u.GetWindowThreadProcessId(h,ctypes.byref(pid))
        rows.append((int(h),pid.value,b.value,cn.value,bool(u.IsWindowVisible(h))))
        return True
    u.EnumWindows(CB(cb),0)
    return rows
def p2n():
    o=subprocess.run(['tasklist','/fo','csv','/nh'],capture_output=True,text=True,encoding='utf-8',errors='replace').stdout
    m={}
    for line in o.splitlines():
        f=[x.strip('"') for x in line.split('","')]
        if len(f)>=2:
            try: m[int(f[1])]=f[0]
            except: pass
    return m
base={r[0] for r in snap()}
print("基线 %d 个窗口"%len(base),flush=True)
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 60
t0=time.time()
seen=set(base)
while time.time()-t0<DUR:
    cur=snap(); ids={r[0] for r in cur}
    new=ids-seen
    if new:
        nm=p2n()
        for h,pid,t,cn,vis in cur:
            if h in new:
                print("NEW 0x%-8X %-20s vis=%-5s cls=%-28s title='%s'"%(h,nm.get(pid,'?'),vis,cn[:28],t[:45]),flush=True)
        seen=ids
    time.sleep(0.25)
print("DONE",flush=True)
