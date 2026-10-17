import sys,os,re
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
for f in ['360Safe.exe','360Tray.exe','360AppLoader.exe']:
    p=os.path.join(root,f)
    if not os.path.exists(p):
        print("  [缺失] "+f); continue
    d=open(p,'rb').read()
    print("=== %s (%d 字节) ==="%(f,len(d)))
    # UTF-16LE 开关（360 多用宽字符）
    sw=set()
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){2,30}',d):
        s=m.group().decode('utf-16-le',errors='ignore')
        if s.startswith('/') or s.startswith('-'):
            sw.add(s)
    print("  宽字符开关:", sorted(sw)[:30] if sw else "(无)")
    # ASCII 开关
    sw2=set()
    for m in re.finditer(rb'(?<![A-Za-z0-9])[/-][A-Za-z][A-Za-z0-9_]{1,25}',d):
        sw2.add(m.group().decode('latin1'))
    print("  ASCII 开关:", sorted(sw2)[:40] if sw2 else "(无)")
    # 含 scan 关键字的宽字符串
    print("  含 scan/Scan 的宽字符串:")
    seen=set()
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,40}',d):
        s=m.group().decode('utf-16-le',errors='ignore')
        if 'scan' in s.lower() and s not in seen:
            seen.add(s); print("    "+repr(s))
            if len(seen)>=15: break
    print()
