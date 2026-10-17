import sys,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\DSmain.exe'
d=open(p,'rb').read()
print("  大小:",len(d))
# 找 /xxx 形式的开关
sw=set()
for m in re.finditer(rb'/[a-zA-Z][a-zA-Z0-9_]{2,20}',d):
    sw.add(m.group().decode('latin1'))
print("  斜杠开关:")
for s in sorted(sw)[:40]:
    print("    "+s)
print()
# 找 -xxx 形式
sw2=set()
for m in re.finditer(rb'(?<![a-zA-Z0-9])-[a-zA-Z][a-zA-Z0-9_]{2,20}',d):
    sw2.add(m.group().decode('latin1'))
print("  横杠开关:")
for s in sorted(sw2)[:30]:
    print("    "+s)
