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
def dump(rva,n,label):
    o=r2o(rva)
    if o is None: print("  %s RVA=0x%X 不在节内"%(label,rva)); return
    print("  === %s RVA=0x%X ==="%(label,rva))
    b=d[o:o+n]
    for i in range(0,n,16):
        print("    +%03X: %s"%(i,' '.join('%02X'%c for c in b[i:i+16])))
    print()
# QueryFileInAVE 的真实起点：从 0x2E1B 开始
dump(0x2E1B,0x60,"QueryFileInAVE 起点")
# 它 call 0x2FA0，再 call 0x3649
# 0x2FA0 是"获取全局实例"
dump(0x2FA0,0x50,"内部 0x2FA0（获取实例）")
# 0x3649 是真实扫描
dump(0x3649,0x70,"内部 0x3649（扫描）")
# 关键：0x3649 里的 call [0x1011068] 是什么
print("  0x3649 里的间接调用目标:")
for addr in [0x1011058,0x1011064,0x1011068]:
    o=r2o(addr-0x10000000)
    if o:
        v=struct.unpack_from('<I',d,o)[0]
        print("    [0x%08X] = 0x%08X"%(addr,v))
