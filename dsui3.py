import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\DSMainUI.dll'
d=open(p,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz
secs=[]
for i in range(nsec):
    nm=d[so+i*40:so+i*40+8].rstrip(b'\x00').decode('latin1')
    vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
    secs.append((nm,va,vs,ra,rs))
def r2o(r):
    for nm,va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
# 完整读出 0x042310 处的宽字符串
o=r2o(0x042310)
print("  === RVA 0x042310 完整字符串 ===")
end=o
while end+1<len(d) and not (d[end]==0 and d[end+1]==0):
    end+=2
print("  "+repr(d[o:end+2].decode('utf-16-le',errors='ignore')))
print()
# 读 0x04116C 'DeepscanCmdLine' 附近的字符串群
o2=r2o(0x04116C)
print("  === RVA 0x04116C 附近（前后各 400 字节）的宽字符串 ===")
seg=d[max(0,o2-400):o2+400]
import re
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,80}',seg):
    print("    "+repr(m.group().decode('utf-16-le',errors='ignore')))
