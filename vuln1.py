import ctypes, sys
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
PROCESS_QUERY_INFORMATION=0x0400
PROCESS_VM_READ=0x0010
PROCESS_ALL_ACCESS=0x1F0FFF
PROCESS_QUERY_LIMITED=0x1000
SYNCHRONIZE=0x00100000
import subprocess
out=subprocess.run(['tasklist','/fo','csv','/nh'],capture_output=True,text=True).stdout
pids=[]
for line in out.splitlines():
    p=line.split('","')
    if len(p)>2 and ('360' in p[0] or 'ZhuDong' in p[0] or 'DSMain' in p[0]):
        pids.append((p[1],p[0].strip('"')))
print("  目标进程: %s"%pids)
print()
tests=[('PROCESS_QUERY_LIMITED_INFORMATION',0x1000),
       ('SYNCHRONIZE',0x00100000),
       ('PROCESS_QUERY_INFORMATION',0x0400),
       ('PROCESS_VM_READ',0x0010),
       ('PROCESS_ALL_ACCESS',0x1F0FFF),
       ('0x1000|0x00100000',0x101000)]
for name,pid in pids[:3]:
    print("  === %s (PID %s) ==="%(name,pid))
    for tn,tv in tests:
        h=k.OpenProcess(tv,False,int(pid))
        err=k.GetLastError()
        print("     %-32s -> handle=0x%08X err=%d %s"%(tn,h,err,'OK' if h else 'DENIED'))
    print()
