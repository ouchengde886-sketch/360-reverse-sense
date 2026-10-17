import sys,struct,re,os
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\PopSoftEng.dll'
d=open(p,'rb').read()
print("  PopSoftEng.dll 大小:",len(d))
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
magic=struct.unpack_from('<H',d,pe+24)[0]
IB=struct.unpack_from('<I',d,pe+24+28)[0]
print("  PE: %s  ImageBase=0x%08X"%('PE32' if magic==0x10b else 'PE32+',IB))
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
def o2r(o):
    for nm,va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
# 导出
ddoff=pe+24+(96 if magic==0x10b else 112)
edrva,edsz=struct.unpack_from('<II',d,ddoff)
print()
if edrva:
    eo=r2o(edrva)
    nfun,nnam,afun,anam,aord=struct.unpack_from('<IIIII',d,eo+20)
    print("  导出: nfun=%d nnam=%d"%(nfun,nnam))
    if nnam:
        no=r2o(anam); fo=r2o(afun); oo=r2o(aord)
        for i in range(min(nnam,40)):
            nr=struct.unpack_from('<I',d,no+i*4)[0]
            o=r2o(nr); e=d.index(b'\x00',o)
            nm=d[o:e].decode('latin1')
            ordv=struct.unpack_from('<H',d,oo+i*2)[0]
            fr=struct.unpack_from('<I',d,fo+ordv*4)[0]
            print("    %-40s RVA=0x%X"%(nm,fr))
else:
    print("  无导出表")
# sc.con 引用位置
print()
i=d.find('sc.con'.encode('utf-16le'))
print("  'sc.con' 宽字符引用 文件偏移=0x%X RVA=0x%X"%(i,o2r(i)))
o=i-40
print("  附近字符串:")
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,60}',d[max(0,i-200):i+200]):
    s=m.group().decode('utf-16le')
    print("    "+s)
