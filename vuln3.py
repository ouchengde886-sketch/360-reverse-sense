import ctypes, sys, subprocess
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
adv=ctypes.windll.advapi32
# ★ 关键发现: ZhuDongFangYu 连 access mask 0 都拒绝 => 不是权限问题，是**句柄创建被 hook**
# 测试绕过手段
print("=== 绕过手段测试: ZhuDongFangYu (PID 3712) ===")
pid=3712
# 1. DuplicateHandle from a pseudo-handle? 不行，需要源句柄
# 2. 用 NtOpenProcess 直接调（绕过 kernel32 的 OpenProcess）
ntdll=ctypes.windll.ntdll
class CLIENT_ID(ctypes.Structure):
    _fields_=[('UniqueProcess',ctypes.c_void_p),('UniqueThread',ctypes.c_void_p)]
class OBJ_ATTR(ctypes.Structure):
    _fields_=[('Length',ctypes.c_ulong),('RootDirectory',ctypes.c_void_p),
              ('ObjectName',ctypes.c_void_p),('Attributes',ctypes.c_ulong),
              ('SecurityDescriptor',ctypes.c_void_p),('SecurityQualityOfService',ctypes.c_void_p)]
class UNICODE_STRING(ctypes.Structure):
    _fields_=[('Length',ctypes.c_ushort),('MaximumLength',ctypes.c_ushort),('Buffer',ctypes.c_void_p)]
oa=OBJ_ATTR(); oa.Length=ctypes.sizeof(OBJ_ATTR)
cid=CLIENT_ID(); cid.UniqueProcess=ctypes.c_void_p(pid); cid.UniqueThread=None
h=ctypes.c_void_p()
st=ntdll.NtOpenProcess(ctypes.byref(h),0x1000,ctypes.byref(oa),ctypes.byref(cid))
print("  NtOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) -> status=0x%08X handle=0x%X"%(st & 0xFFFFFFFF, h.value or 0))
h2=ctypes.c_void_p()
st2=ntdll.NtOpenProcess(ctypes.byref(h2),0x0400,ctypes.byref(oa),ctypes.byref(cid))
print("  NtOpenProcess(PROCESS_QUERY_INFORMATION)        -> status=0x%08X handle=0x%X"%(st2 & 0xFFFFFFFF, h2.value or 0))
print()
# 3. 用 OpenProcess 但通过不同的调用路径 —— 试 QueryFullProcessImageName
print("=== 其它 API 测试 ===")
buf=ctypes.create_unicode_buffer(1024); sz=ctypes.c_ulong(1024)
r=k.QueryFullProcessImageNameW(ctypes.c_void_p(pid),0,buf,ctypes.byref(sz))
print("  QueryFullProcessImageNameW -> %s, path=%r"%(bool(r),buf.value))
# GetProcessTimes
ct=[ctypes.c_ulong(0) for _ in range(4)]
r2=k.GetProcessTimes(ctypes.c_void_p(pid),*[ctypes.byref(x) for x in ct])
print("  GetProcessTimes -> %s"%bool(r2))
# IsWow64Process
w=ctypes.c_int()
r3=k.IsWow64Process(ctypes.c_void_p(pid),ctypes.byref(w))
print("  IsWow64Process -> %s wow64=%d"%(bool(r3),w.value))
print()
# 4. ★ 关键: 用 WMI 拿信息（走不同通道）
print("=== WMI 通道（可能绕过）===")
out=subprocess.run(['wmic','process','where','ProcessId=3712','get','Name,ExecutablePath,CommandLine','/format:list'],
                   capture_output=True,text=True,encoding='utf-8',errors='replace').stdout
print("  wmic: %r"%out.strip()[:200])
