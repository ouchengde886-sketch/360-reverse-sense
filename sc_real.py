import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\ScChecker.dll'
d=open(p,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
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
def dump(rva,n,label):
    o=r2o(rva)
    print("  === %s RVA=0x%X ==="%(label,rva))
    b=d[o:o+n]
    for i in range(0,n,16):
        print("    +%03X: %s"%(i,' '.join('%02X'%c for c in b[i:i+16])))
    print()
# 真实入口
dump(0xA7720,0x80,"初始化检查 0xA7720")
dump(0xD6BF0,0x50,"子对象A 创建 0xD6BF0")
dump(0x628F0,0x50,"子对象B/D 创建 0x628F0")
dump(0xD6AB0,0x50,"子对象C 创建 0xD6AB0")
