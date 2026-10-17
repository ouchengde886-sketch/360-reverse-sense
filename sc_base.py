import sys,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\ScChecker.dll'
d=open(p,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
imgbase=struct.unpack_from('<I',d,pe+24+28)[0]
print("  ★ ScChecker.dll 镜像基址 = 0x%08X"%imgbase)
print("    之前我一直用 0x10100000，错了 0x%X"%(0x10100000-imgbase))
print()
nsec=struct.unpack_from('<H',d,pe+6)[0]
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
# 虚表 0x13B124
vt=0x13B124
o=r2o(vt)
print("  引擎对象虚表 RVA=0x%X，方法列表（正确换算）:"%vt)
for k in range(20):
    v=struct.unpack_from('<I',d,o+k*4)[0]
    rv=v-imgbase
    tag=""
    if 0x1000<=rv<0x119B5A: tag=" .text ✓"
    elif 0x11A000<=rv<0x15C4B0: tag=" .rdata"
    print("    [%2d] 0x%08X RVA=0x%-8X%s"%(k,v,rv,tag))
print()
colptr=struct.unpack_from('<I',d,o-4)[0]
colrva=colptr-imgbase
print("  COL RVA=0x%X"%colrva)
co=r2o(colrva)
if co and co>0:
    sig,off,cd,ptd,pcd=struct.unpack_from('<IIIII',d,co)
    print("    sig=%d offset=%d cdOffset=%d pTypeDescriptor=0x%08X"%(sig,off,cd,ptd))
    if ptd:
        tio=r2o(ptd-imgbase)
        if tio:
            print("    type_info 原始: %s"%' '.join('%02X'%c for c in d[tio:tio+24]))
            for off2 in range(0,20,4):
                v=struct.unpack_from('<I',d,tio+off2)[0]
                rv=v-imgbase
                if 0<=rv<0x173000:
                    no=r2o(rv)
                    if no:
                        e=d.index(b'\x00',no)
                        nm=d[no:e]
                        if all(32<=c<127 for c in nm) and len(nm)>3:
                            print("      +%d -> '%s'"%(off2,nm.decode('latin1')))
