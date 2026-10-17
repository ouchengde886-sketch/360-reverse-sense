import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\deepscan.dll'
d=open(p,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz
secs=[]
for i in range(nsec):
    vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
    secs.append((va,vs,ra,rs))
def r2o(r):
    for va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
def o2r(o):
    for va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
# 0x2A682C 的绝对地址字节
for target in (0x102A682C, 0x2A682C, 0x102A6830, 0x2A6830):
    pat=struct.pack('<I',target)
    idx=0; found=[]
    while True:
        i=d.find(pat,idx)
        if i<0: break
        rva=o2r(i)
        if rva: found.append(rva)
        idx=i+1
    print("  地址 0x%X 出现 %d 次:" % (target,len(found)))
    for r in found[:12]:
        print("    RVA 0x%X" % r)
    print()
