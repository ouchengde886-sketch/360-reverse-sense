import sys,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\ave\AVEI.dll'
d=open(p,'rb').read()
print("  AVEI.dll 大小:",len(d))
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
IB=struct.unpack_from('<I',d,pe+24+28)[0]
print("  ImageBase=0x%08X"%IB)
so=pe+24+optsz
secs=[]
for i in range(nsec):
    nm=d[so+i*40:so+i*40+8].rstrip(b'\x00').decode('latin1')
    vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
    secs.append((nm,va,vs,ra,rs))
    print("    %-8s VA=0x%08X VS=0x%08X"%(nm,va,vs))
def r2o(r):
    for nm,va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
def dump(rva,n,label):
    o=r2o(rva)
    if o is None: print("  %s RVA=0x%X 不在节内"%(label,rva)); return
    print("  === %s RVA=0x%X ==="%(label,rva))
    b=d[o:o+n]
    for i in range(0,n,16):
        print("    +%03X: %s"%(i,' '.join('%02X'%c for c in b[i:i+16])))
    print()
dump(0x3900,0xA0,"ScanW (RVA 0x3900)")
# 找 ScanW 里的 call 目标
o=r2o(0x3900)
b=d[o:o+0x100]
print("  ScanW 里的 call 目标:")
i=0
while i<len(b)-5:
    if b[i]==0xE8:
        rel=struct.unpack_from('<i',b,i+1)[0]
        print("    +%03X: call 0x%X"%(i,0x3900+i+5+rel))
        i+=5
    else:
        i+=1
