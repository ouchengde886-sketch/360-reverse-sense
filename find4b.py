import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\ave\AVEI.dll'
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
def dump(rva,n,label):
    o=r2o(rva)
    if o is None: print("  %s RVA=0x%X 不在节内"%(label,rva)); return
    print("  === %s RVA=0x%X ==="%(label,rva))
    b=d[o:o+n]
    for i in range(0,n,16):
        print("    +%03X (0x%X): %s"%(i,rva+i,' '.join('%02X'%c for c in b[i:i+16])))
    print()
# ScanW 调用的真实扫描函数 0x9014 附近
dump(0x9014,0x60,"ScanW 调用的扫描函数 0x9014")
# 写 4 的位置
dump(0x9300,0x40,"写 4 处 0x931F 上下文")
dump(0x9700,0x40,"写 4 处 0x971F 上下文")
# 0x4ED6 也在 ScanW 附近
dump(0x4EC0,0x30,"写 4 处 0x4ED6 上下文")
