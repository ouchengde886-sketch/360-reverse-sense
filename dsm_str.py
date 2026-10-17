import sys,re
sys.stdout.reconfigure(encoding='utf-8')
d=open(r'C:\Program Files (x86)\360\360Safe\deepscan\DSMain.exe','rb').read()
seen=set()
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,60}',d):
    s=m.group().decode('utf-16-le',errors='ignore')
    if any(k in s for k in ('/','scan','Scan','SCAN')) and s not in seen:
        seen.add(s)
        if len(seen)<=40: print("  "+repr(s))
print("  共 %d 个"%len(seen))
