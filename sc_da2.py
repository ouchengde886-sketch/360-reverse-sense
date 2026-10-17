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
# 重新精确解析导出表
ddoff=pe+24+96
edrva,edsz=struct.unpack_from('<II',d,ddoff)
eo=r2o(edrva)
nfun,nnam=struct.unpack_from('<II',d,eo+20)
anam,afun=struct.unpack_from('<II',d,eo+32)
print("  导出目录 RVA=0x%X, nfun=%d nnam=%d"%(edrva,nfun,nnam))
print("  AddressOfNames RVA=0x%X  AddressOfFunctions RVA=0x%X"%(anam,afun))
no=r2o(anam); fo=r2o(afun)
print("  names 文件偏移=0x%X  funcs 文件偏移=0x%X"%(no,fo))
print()
for i in range(nnam):
    nr=struct.unpack_from('<I',d,no+i*4)[0]
    o=r2o(nr); e=d.index(b'\x00',o)
    nm=d[o:e].decode('latin1')
    ordv=struct.unpack_from('<H',d,fo+i*2)[0]
    fr=struct.unpack_from('<I',d,fo+ordv*4)[0]
    print("    [%d] %-20s ord=%d funcRVA=0x%X"%(i,nm,ordv,fr))
    if fr and not (edrva<=fr<edrva+edsz):
        oo=r2o(fr)
        if oo:
            print("        字节: %s"%' '.join('%02X'%c for c in d[oo:oo+16]))
    else:
        oo=r2o(fr); e2=d.index(b'\x00',oo)
        print("        转发: %s"%d[oo:e2].decode('latin1'))
