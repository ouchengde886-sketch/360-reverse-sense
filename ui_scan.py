import re,sys
sys.stdout.reconfigure(encoding='utf-8')
d=open(r'C:\Program Files (x86)\360\360Safe\360Safe.exe','rb').read()
# 找形如 /xxx 的开关（ASCII 和 UTF-16）
sw=set()
for m in re.finditer(rb'/[a-zA-Z_][a-zA-Z0-9_]{1,20}',d):
    s=m.group().decode('latin1')
    sw.add(s)
print("  ASCII 开关 (%d 个):"%len(sw))
print("   ",sorted(sw)[:40])
# UTF-16 开关
sw2=set()
for m in re.finditer(rb'(?:/[a-zA-Z_][a-zA-Z0-9_]{1,20})\x00',d):
    s=m.group()[:-1].decode('latin1')
    sw2.add(s)
print("  UTF-16 开关 (%d 个):"%len(sw2))
print("   ",sorted(sw2)[:40])
# 找含 scan 的字符串
print()
print("  含 scan/Scan 的字符串:")
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,60}',d):
    s=m.group().decode('utf-16-le',errors='ignore')
    if 'scan' in s.lower() or 'Scan' in s:
        print("     @0x%X %r"%(m.start(),s))
