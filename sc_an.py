import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\ScChecker.dll'
d=open(p,'rb').read()
print('  文件大小:',len(d))
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
magic=struct.unpack_from('<H',d,pe+24)[0]
print('  PE: %s'%('PE32' if magic==0x10b else 'PE32+'))
so=pe+24+optsz
secs=[]
for i in range(nsec):
    nm=d[so+i*40:so+i*40+8].rstrip(b'\x00').decode('latin1')
    vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
    secs.append((nm,va,vs,ra,rs))
    print('  sec %-8s VA=0x%08X VS=0x%08X RAW=0x%08X'%(nm,va,vs,ra))
def r2o(r):
    for nm,va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
ddoff=pe+24+(96 if magic==0x10b else 112)
edrva,edsz=struct.unpack_from('<II',d,ddoff)
print()
print('  导出目录 RVA=0x%X size=%d'%(edrva,edsz))
if edrva:
    eo=r2o(edrva)
    nfun,nnam=struct.unpack_from('<II',d,eo+20)
    anam,afun,aord=struct.unpack_from('<III',d,eo+32)
    print('  导出: 函数=%d 名字=%d'%(nfun,nnam))
    if nnam:
        no=r2o(anam); fo=r2o(afun)
        for i in range(min(nnam,300)):
            nr=struct.unpack_from('<I',d,no+i*4)[0]
            o=r2o(nr); e=d.index(b'\x00',o)
            nm=d[o:e].decode('latin1')
            ordv=struct.unpack_from('<H',d,fo+i*2)[0]
            fr=struct.unpack_from('<I',d,r2o(afun)+0)[0]
            # 正确取函数 RVA
            fr=struct.unpack_from('<I',d,fo+i*4)[0]
            print('    %-60s RVA=0x%X'%(nm,fr))
print()
print('  导入的 DLL:')
io=r2o(struct.unpack_from('<I',d,ddoff+8)[0])
if io:
    n=0
    while True:
        nr=struct.unpack_from('<I',d,io+n*20+12)[0]
        if nr==0: break
        o=r2o(nr); e=d.index(b'\x00',o)
        print('    ',d[o:e].decode('latin1'))
        n+=1
