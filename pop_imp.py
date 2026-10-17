import sys,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\PopSoftEng.dll'
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
# 导入表
ddoff=pe+24+96
idrva,idsz=struct.unpack_from('<II',d,ddoff+8)
print("  导入表 RVA=0x%X"%idrva)
o=r2o(idrva)
print("  PopSoftEng.dll 导入的 DLL 及关键函数:")
while True:
    oft,ts,fc,nrva,ft=struct.unpack_from('<IIIII',d,o)
    if nrva==0: break
    no=r2o(nrva); e=d.index(b'\x00',no)
    dll=d[no:e].decode('latin1')
    print("    %s"%dll)
    # 列函数
    fo=r2o(oft if oft else ft)
    k=0
    while True:
        v=struct.unpack_from('<I',d,fo+k*4)[0]
        if v==0: break
        if v & 0x80000000:
            print("      ord#%d"%(v&0xFFFF))
        else:
            no2=r2o(v); e2=d.index(b'\x00',no2)
            print("      %s"%d[no2:e2].decode('latin1'))
        k+=1
    o+=20
