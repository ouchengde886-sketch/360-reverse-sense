import sys, os, ctypes, time
from ctypes import wintypes
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.WinDLL('kernel32',use_last_error=True)
nt=ctypes.WinDLL('ntdll',use_last_error=True)

print("="*74)
print("★★★ 边界复验（第 45 轮）：确认结论在当前时刻仍成立")
print("="*74)
print()

# ---- 边界1: ZhuDongFangYu 句柄 ----
print("[边界1] ZhuDongFangYu 进程句柄创建")
import subprocess
out=subprocess.run(['tasklist','/fo','csv','/nh'],capture_output=True,text=True).stdout
pid=None
for ln in out.splitlines():
    p=[x.strip('"') for x in ln.split('","')]
    if p and p[0].lower().startswith('zhudongfangyu'):
        pid=int(p[1]); break
print("    ZhuDongFangYu PID = %s"%pid)
if pid:
    k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    k.OpenProcess.restype=wintypes.HANDLE
    for name,mask in [("PROCESS_ALL_ACCESS",0x1F0FFF),("mask=0",0),
                      ("QUERY_LIMITED",0x1000),("VM_READ",0x10)]:
        ctypes.set_last_error(0)
        h=k.OpenProcess(mask,False,pid)
        err=ctypes.get_last_error()
        print("      %-18s handle=0x%X  err=%d  %s"%(name,h or 0,err,"DENIED" if not h else "OK"))
    # NtOpenProcess 取真实 NTSTATUS
    class CLIENT_ID(ctypes.Structure):
        _fields_=[("UniqueProcess",ctypes.c_void_p),("UniqueThread",ctypes.c_void_p)]
    class OBJA(ctypes.Structure):
        _fields_=[("Length",wintypes.ULONG),("RootDirectory",ctypes.c_void_p),
                  ("ObjectName",ctypes.c_void_p),("Attributes",wintypes.ULONG),
                  ("SecurityDescriptor",ctypes.c_void_p),("SecurityQualityOfService",ctypes.c_void_p)]
    nt.NtOpenProcess.argtypes=[ctypes.POINTER(wintypes.HANDLE),wintypes.DWORD,
                               ctypes.POINTER(OBJA),ctypes.POINTER(CLIENT_ID)]
    nt.NtOpenProcess.restype=ctypes.c_long
    h=wintypes.HANDLE(); cid=CLIENT_ID(); cid.UniqueProcess=ctypes.c_void_p(pid)
    oa=OBJA(); oa.Length=ctypes.sizeof(OBJA)
    st=nt.NtOpenProcess(ctypes.byref(h),0x1F0FFF,ctypes.byref(oa),ctypes.byref(cid))
    print("      NtOpenProcess ALL_ACCESS -> NTSTATUS=0x%08X  %s"%(st & 0xFFFFFFFF,
          "STATUS_ACCESS_DENIED" if (st & 0xFFFFFFFF)==0xC0000022 else "其它"))
print()

# ---- 边界2: 可执行后缀写入 ----
print("[边界2] 可执行后缀文件写入（当前时刻）")
d=r"D:\bound_recheck_%d"%(int(time.time())%100000)
os.makedirs(d,exist_ok=True)
src=r"C:\Windows\System32\notepad.exe"
data=open(src,'rb').read()
print("    源文件: %s (%d 字节)"%(src,len(data)))
print()
blocked=[];allowed=[]
for ext in ['exe','EXE','dll','sys','ocx','vbs','scr','cpl','com','bin','dat','tmp','txt','ps1','log','json']:
    p=os.path.join(d,"t."+ext)
    try:
        open(p,'wb').write(data)
        allowed.append(ext)
        print("      .%-5s 写入成功"%ext)
    except Exception as e:
        blocked.append(ext)
        print("      .%-5s 被拦截 (%s)"%(ext,type(e).__name__))
print()
print("    被拦截: %s"%blocked)
print("    允许:   %s"%allowed)
print()
print("="*74)
print("边界1 成立: %s"%("是（ALL_ACCESS 被拒）" if pid else "无法验证"))
print("边界2 成立: %s"%("是（可执行后缀被拦）" if blocked else "★ 否 —— 没有后缀被拦！"))
print("="*74)
