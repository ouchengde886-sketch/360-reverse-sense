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
edrva,edsz=struct.unpack_from('<II',d,ddoff)
eo=r2o(edrva)
# 导出目录结构: +20 NumberOfFunctions, +24 NumberOfNames,
# +28 AddressOfFunctions, +32 AddressOfNames, +36 AddressOfNameOrdinals
nfun, nnam, afun, anam, aord = struct.unpack_from('<IIIII', d, eo+20)
print("  导出目录: nfun=%d nnam=%d"%(nfun,nnam))
print("  AddressOfFunctions RVA=0x%X"%afun)
print("  AddressOfNames     RVA=0x%X"%anam)
print("  AddressOfNameOrdinals RVA=0x%X"%aord)
fo=r2o(afun); no=r2o(anam); oo=r2o(aord)
print("  文件偏移: funcs=0x%X names=0x%X ords=0x%X"%(fo,no,oo))
print()
for i in range(nnam):
    nr=struct.unpack_from('<I',d,no+i*4)[0]
    o=r2o(nr); e=d.index(b'\x00',o)
    nm=d[o:e].decode('latin1')
    ordv=struct.unpack_from('<H',d,oo+i*2)[0]
    fr=struct.unpack_from('<I',d,fo+ordv*4)[0]
    print("    %-20s ord=%d RVA=0x%X"%(nm,ordv,fr))
    if edrva<=fr<edrva+edsz:
        s2=r2o(fr); e2=d.index(b'\x00',s2)
        print("        转发 -> %s"%d[s2:e2].decode('latin1'))
    else:
        off=r2o(fr)
        print("        文件偏移=0x%X 字节: %s"%(off,' '.join('%02X'%c for c in d[off:off+16])))
