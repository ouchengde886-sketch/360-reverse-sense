import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\Utils\360SafeChecker.dll'
d=open(p,'rb').read()
print("  360SafeChecker.dll 大小:",len(d))
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz
secs=[]
for i in range(nsec):
    nm=d[so+i*40:so+i*40+8].rstrip(b'\x00').decode('latin1')
    vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
    secs.append((nm,va,vs,ra,rs))
    print("  节 %-10s VA=0x%08X VS=0x%08X"%(nm,va,vs))
def r2o(r):
    for nm,va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
# 导出表
ed=struct.unpack_from('<II',d,pe+24+96)[0],struct.unpack_from('<I',d,pe+24+96+4)[0]
erva,esz=ed
print("  导出表 RVA=0x%X 大小=%d"%(erva,esz))
if erva:
    o=r2o(erva)
    nfun,nnam,af,an,ao=struct.unpack_from('<IIIII',d,o+20)
    print("  NumberOfFunctions=%d NumberOfNames=%d"%(nfun,nnam))
    for i in range(min(nnam,60)):
        nr=struct.unpack_from('<I',d,r2o(an)+i*4)[0]
        nm=d[r2o(nr):d.find(b'\x00',r2o(nr))].decode('latin1')
        ordv=struct.unpack_from('<H',d,r2o(ao)+i*2)[0]
        fr=struct.unpack_from('<I',d,r2o(af)+ordv*4)[0]
        print("    %-44s RVA=0x%X"%(nm,fr))
