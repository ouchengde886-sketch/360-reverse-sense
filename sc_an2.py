import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\ScChecker.dll'
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
ddoff=pe+24+96
edrva=struct.unpack_from('<I',d,ddoff)[0]
eo=r2o(edrva)
nfun,nnam=struct.unpack_from('<II',d,eo+20)
anam,afun=struct.unpack_from('<II',d,eo+32)
no=r2o(anam); fo=r2o(afun)
print("  导出函数与 RVA（正确解析）:")
for i in range(nnam):
    nr=struct.unpack_from('<I',d,no+i*4)[0]
    o=r2o(nr); e=d.index(b'\x00',o)
    nm=d[o:e].decode('latin1')
    ordv=struct.unpack_from('<H',d,fo+i*2)[0]
    fr=struct.unpack_from('<I',d,r2o(afun)+ordv*4)[0]
    extra=""
    if edrva<=fr<edrva+148:
        so2=r2o(fr); e2=d.index(b'\x00',so2)
        extra=" -> 转发到 "+d[so2:e2].decode('latin1')
    print("    %-20s RVA=0x%-8X%s"%(nm,fr,extra))
print()
print("  运行时基址 0x56CF0000 下的方法[6]:")
print("    0x56DC4720 - 0x56CF0000 = 0x%X"%(0x56DC4720-0x56CF0000))
print("  虚表 0x56E2B124 - 0x56CF0000 = 0x%X"%(0x56E2B124-0x56CF0000))
print()
print("  方法[6] 在文件中的位置 0xD4720:")
o=r2o(0xD4720)
print("    文件偏移 0x%X"%o)
b=d[o:o+0x120]
for i in range(0,0x120,16):
    print("    +%03X: %s"%(i,' '.join('%02X'%c for c in b[i:i+16])))
