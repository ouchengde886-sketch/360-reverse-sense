import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\deepscan.dll'
d=open(p,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
so=pe+24+optsz
secs=[]
for i in range(nsec):
    vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
    secs.append((va,vs,ra,rs))
def r2o(r):
    for va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
print("  ScanAveMemoryWithCode (RVA 0x4001E) 反汇编:")
o=r2o(0x4001E)
b=d[o:o+0x70]
for i in range(0,0x50,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
print()
# 找 ret N
for i in range(0x40):
    if b[i]==0xC2:
        n=struct.unpack_from('<H',b,i+1)[0]
        print("    +%03X: C2 %04X  ret 0x%X  => %d 个栈参数" % (i,n,n,n//4))
        break
print()
print("  对比 ScanAveMemory (RVA 0x3FEC8):")
o2=r2o(0x3FEC8)
b2=d[o2:o2+0x30]
for i in range(0,0x20,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b2[i:i+16])))
