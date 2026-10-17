import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\avescan.dll'
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
# 0x2E1B 往前看，找真正的函数入口
print("  0x2E1B 往前 0x40 字节:")
o=r2o(0x2DDB)
for k in range(0,0x40,16):
    print("    +%03X (RVA 0x%X): %s"%(k,0x2DDB+k,' '.join('%02X'%c for c in d[o+k:o+k+16])))
print()
# 导出表里 QueryFileInAVE 的真实 RVA 再确认
ddoff=pe+24+96
edrva,edsz=struct.unpack_from('<II',d,ddoff)
eo=r2o(edrva)
nfun,nnam,afun,anam,aord=struct.unpack_from('<IIIII',d,eo+20)
no=r2o(anam); fo=r2o(afun); oo=r2o(aord)
print("  导出表精确内容:")
for i in range(nnam):
    nr=struct.unpack_from('<I',d,no+i*4)[0]
    o2=r2o(nr); e=d.index(b'\x00',o2)
    nm=d[o2:e].decode('latin1')
    ordv=struct.unpack_from('<H',d,oo+i*2)[0]
    fr=struct.unpack_from('<I',d,fo+ordv*4)[0]
    print("    %-30s ord=%d RVA=0x%X"%(nm,ordv,fr))
print()
# 检查 0x3649 里的 IAT 调用
print("  0x3649 引用的 IAT 地址:")
# FF 15 xx xx xx xx
o=r2o(0x3649)
b=d[o:o+0x70]
i=0
while i<len(b)-6:
    if b[i]==0xFF and b[i+1]==0x15:
        imm=struct.unpack_from('<I',b,i+2)[0]
        rva=imm-0x10000000
        oo=r2o(rva)
        tgt=struct.unpack_from('<I',d,oo)[0] if oo else 0
        print("    +%03X: call [0x%08X] -> 0x%08X"%(i,imm,tgt))
        i+=6
    else:
        i+=1
