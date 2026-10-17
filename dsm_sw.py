import sys,re
sys.stdout.reconfigure(encoding='utf-8')
d=open(r'C:\Program Files (x86)\360\360Safe\deepscan\DSMain.exe','rb').read()
seen=[]
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,60}',d):
    s=m.group().decode('utf-16-le',errors='ignore')
    if s not in seen: seen.append(s)
print("  === 所有以 / 开头的开关（共 %d）==="%len([s for s in seen if s.strip().startswith('/')]))
for s in seen:
    if s.strip().startswith('/'): print("    "+repr(s))
