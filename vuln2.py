import ctypes, sys, subprocess
sys.stdout.reconfigure(encoding='utf-8')
k=ctypes.windll.kernel32
out=subprocess.run(['tasklist','/fo','csv','/nh'],capture_output=True,text=True,encoding='utf-8',errors='replace').stdout
pids=[]
for line in out.splitlines():
    p=[x.strip('"') for x in line.split('","')]
    if len(p)>=2 and ('360' in p[0] or 'ZhuDong' in p[0] or 'DSMain' in p[0]):
        pids.append((p[0],p[1]))
print("  目标进程: %s"%pids)
print()
tests=[('PROCESS_QUERY_LIMITED_INFORMATION',0x1000),
       ('SYNCHRONIZE',0x00100000),
       ('PROCESS_QUERY_INFORMATION',0x0400),
       ('PROCESS_VM_READ',0x0010),
       ('PROCESS_ALL_ACCESS',0x1F0FFF),
       ('QUERY_LIMITED|SYNCHRONIZE',0x101000),
       ('0 (no access, just handle)',0x0)]
for name,pid in pids:
    print("  === %s (PID %s) ==="%(name,pid))
    for tn,tv in tests:
        h=k.OpenProcess(tv,False,int(pid))
        err=k.GetLastError() if not h else 0
        print("     %-32s -> handle=0x%08X %s"%(tn,h,'OK' if h else 'DENIED err=%d'%err))
        if h: k.CloseHandle(h)
    print()
