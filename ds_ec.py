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
# 内部实现 0x3FEE4
o=r2o(0x3FEE4)
b=d[o:o+0x200]
print("  内部实现 0x3FEE4 完整反汇编（找错误码）:")
for i in range(0,0x180,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
print()
print("  搜索 push imm8 后跟 pop eax 的模式（错误码返回）:")
for i in range(len(b)-2):
    if b[i]==0x6A and b[i+2]==0x58:   # push imm8; pop eax
        imm=b[i+1]
        if imm>=0x80: imm-=256
        print("    +%03X: push 0x%02X (%d) ; pop eax" % (i,b[i+1],imm))
