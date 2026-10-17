import sys,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\DSMain.exe'
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
def o2r(o):
    for nm,va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
def r2o(r):
    for nm,va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
# 找 scanark 字符串及其附近的开关
i=d.find(b'scanark')
print("  'scanark' 文件偏移=0x%X RVA=0x%X"%(i,o2r(i)))
print("  附近字符串（前后 400 字节内）:")
for m in re.finditer(rb'[\x20-\x7e]{3,50}',d[max(0,i-400):i+400]):
    s=m.group().decode('latin1')
    print("    "+s)
