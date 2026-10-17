import ctypes, sys, os, time, subprocess
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
u=ctypes.windll.user32
u.GetWindowTextLengthW.argtypes=[wintypes.HWND]
u.GetWindowTextW.argtypes=[wintypes.HWND,wintypes.LPWSTR,ctypes.c_int]
u.IsVisibleWindow=u.IsWindowVisible
u.IsWindowVisible.argtypes=[wintypes.HWND]
u.GetClassNameW.argtypes=[wintypes.HWND,wintypes.LPWSTR,ctypes.c_int]
u.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)]
CB=ctypes.WINFUNCTYPE(ctypes.c_bool,wintypes.HWND,wintypes.LPARAM)

def pid2name():
    out=subprocess.run(['tasklist','/fo','csv','/nh'],capture_output=True,text=True,encoding='utf-8',errors='replace').stdout
    m={}
    for line in out.splitlines():
        f=[x.strip('"') for x in line.split('","')]
        if len(f)>=2:
            try: m[int(f[1])]=f[0]
            except: pass
    return m

def snapshot():
    rows=[]
    def cb(h,l):
        if not u.IsWindowVisible(h): return True
        n=u.GetWindowTextLengthW(h)
        if n==0: return True
        b=ctypes.create_unicode_buffer(n+1); u.GetWindowTextW(h,b,n+1)
        cn=ctypes.create_unicode_buffer(256); u.GetClassNameW(h,cn,256)
        pid=wintypes.DWORD(); u.GetWindowThreadProcessId(h,ctypes.byref(pid))
        rows.append((int(h),pid.value,b.value,cn.value))
        return True
    u.EnumWindows(CB(cb),0)
    return rows

DUR=int(sys.argv[1]) if len(sys.argv)>1 else 120
print("WATCH_START duration=%ds"%DUR, flush=True)
base={r[0] for r in snapshot()}
seen=set(base)
print("baseline=%d windows"%len(base), flush=True)
t0=time.time()
while time.time()-t0 < DUR:
    cur=snapshot()
    curids={r[0] for r in cur}
    new=curids-seen
    gone=seen-curids
    if new or gone:
        names=pid2name()
        for h,pid,t,cn in cur:
            if h in new:
                print("[%6.1fs] NEW  0x%-8X %-22s '%s' [%s]"%(time.time()-t0,h,names.get(pid,'?'),t[:50],cn[:28]), flush=True)
        for h in gone:
            print("[%6.1fs] GONE 0x%-8X"%((time.time()-t0),h), flush=True)
        seen=curids
    time.sleep(0.3)
print("WATCH_END", flush=True)
