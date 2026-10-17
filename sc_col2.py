import sys,struct,re
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
def o2r(o):
    for nm,va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
# vftable 在 0x1013B124。COL 通常紧邻 vftable 之前（-4）
vt=0x13B124
print("  引擎对象虚表 RVA=0x%X"%vt)
o=r2o(vt)
print("  虚表前 16 字节（找 COL 指针）:")
for k in range(-16,0,4):
    v=struct.unpack_from('<I',d,o+k)[0]
    print("    [%+d] 0x%08X"%(k,v))
print()
# COL 指针应该在 vftable-4
colptr=struct.unpack_from('<I',d,o-4)[0]
print("  vftable-4 = 0x%08X"%colptr)
colrva=colptr-0x10100000
print("  -> COL RVA=0x%X"%colrva)
co=r2o(colrva)
if co and co>0:
    sig,off,cd,ptd,pcd=struct.unpack_from('<IIIII',d,co)
    print("    COL: sig=%d offset=%d cdOffset=%d pTypeDescriptor=0x%08X pClassDescriptor=0x%08X"%(
        sig,off,cd,ptd,pcd))
    if ptd:
        tio=r2o(ptd-0x10100000)
        if tio:
            print("    type_info 内容: %s"%' '.join('%02X'%c for c in d[tio:tio+32]))
            # 找名字
            for off2 in range(0,24,4):
                v=struct.unpack_from('<I',d,tio+off2)[0]
                if 0x10100000<v<0x10100000+0x173000:
                    no=r2o(v-0x10100000)
                    if no:
                        e=d.index(b'\x00',no)
                        nm=d[no:e]
                        if all(32<=c<127 for c in nm) and len(nm)>3:
                            print("      +%d -> 名字 '%s'"%(off2,nm.decode('latin1')))
print()
print("  虚表全部方法（RVA）:")
for k in range(24):
    v=struct.unpack_from('<I',d,o+k*4)[0]
    rv=v-0x10100000
    tag=""
    if 0x1000<=rv<0x119B5A: tag=" .text"
    elif 0x11A000<=rv<0x15C4B0: tag=" .rdata"
    print("    [%2d] 0x%08X RVA=0x%-8X%s"%(k,v,rv,tag))
