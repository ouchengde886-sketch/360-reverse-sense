import os, sys, glob, re, time
sys.stdout.reconfigure(encoding='utf-8')
import ctypes
from ctypes import wintypes
k=ctypes.windll.kernel32
k.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
k.CreateFileW.restype=wintypes.HANDLE
k.ReadFile.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID]
k.ReadFile.restype=wintypes.BOOL
k.CloseHandle.argtypes=[wintypes.HANDLE]
GENERIC_READ=0x80000000
SHARE_ALL=0x1|0x2|0x4
OPEN_EXISTING=3
INVALID=wintypes.HANDLE(-1).value

def read_shared(path):
    h=k.CreateFileW(path,GENERIC_READ,SHARE_ALL,None,OPEN_EXISTING,0,None)
    if h==INVALID or h==0:
        return None,k.GetLastError()
    buf=ctypes.create_string_buffer(1<<20)
    rd=wintypes.DWORD()
    ok=k.ReadFile(h,buf,1<<20,ctypes.byref(rd),None)
    k.CloseHandle(h)
    if not ok: return None,k.GetLastError()
    return buf.raw[:rd.value],0

d=os.path.join(os.environ['APPDATA'],'360Safe','LogInfo')
print("=== ★★★ 360 LogInfo 内容（共享模式读取，绕过文件锁）===")
print()
fs=sorted(glob.glob(os.path.join(d,'*.log2')),key=os.path.getmtime,reverse=True)[:5]
for f in fs:
    mt=time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(os.path.getmtime(f)))
    data,err=read_shared(f)
    print("--- %s  (%d 字节, %s) ---"%(os.path.basename(f),os.path.getsize(f),mt))
    if data is None:
        print("    读取失败 err=%d"%err); continue
    best=None
    for enc in ['utf-16-le','gbk','utf-8']:
        t=data.decode(enc,errors='replace')
        pr=sum(1 for c in t if c.isprintable() or c in '\r\n\t')/max(1,len(t))
        if best is None or pr>best[1]: best=(enc,pr,t)
    enc,pr,t=best
    print("    编码 %s 可打印率 %.1f%%"%(enc,pr*100))
    frags=re.findall(r'[\u4e00-\u9fffA-Za-z0-9_\-\.\\/: ]{4,}',t)
    seen=set()
    for fr in frags:
        fr=fr.strip()
        if len(fr)>=4 and fr not in seen:
            seen.add(fr)
            print("        %s"%fr[:120])
        if len(seen)>=18: break
    print()
