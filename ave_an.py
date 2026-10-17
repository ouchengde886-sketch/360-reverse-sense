import sys,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\avescan.dll'
import os
if not os.path.exists(p):
    for dp,dirs,files in os.walk(r'C:\Program Files (x86)\360\360Safe'):
        if 'avescan.dll' in files:
            p=os.path.join(dp,'avescan.dll'); break
print("  路径:",p)
d=open(p,'rb').read()
print("  大小:",len(d))
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
IB=struct.unpack_from('<I',d,pe+24+28)[0]
print("  ImageBase=0x%08X"%IB)
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
def dump(rva,n,label):
    o=r2o(rva)
    if o is None: print("  %s RVA=0x%X 不在任何节"%(label,rva)); return
    print("  === %s RVA=0x%X ==="%(label,rva))
    b=d[o:o+n]
    for i in range(0,n,16):
        print("    +%03X: %s"%(i,' '.join('%02X'%c for c in b[i:i+16])))
    print()
dump(0x2E1B,0x90,"QueryFileInAVE")
dump(0x3B83,0x70,"CreateADSAVEScanInstance")
# 字符串
print("  avescan.dll 关键字符串:")
for m in re.finditer(rb'[\x20-\x7e]{4,70}',d):
    s=m.group().decode('latin1')
    if any(k in s for k in ['AVE','ave','Scan','scan','.dll','Query','Create','virus','Virus']):
        print("    "+s)
