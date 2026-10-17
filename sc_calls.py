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
# 找真正的函数入口：搜索 call 指令的目标
# 在 SCC_Create 里 call 0x107AC1 的机器码是 E8 xx xx xx xx
o=r2o(0x65C60)
b=d[o:o+0x140]
print("  SCC_Create 里所有 call 指令的真实目标:")
i=0
while i<len(b)-5:
    if b[i]==0xE8:
        rel=struct.unpack_from('<i',b,i+1)[0]
        tgt=0x65C60+i+5+rel
        print("    +%03X: call 0x%X"%(i,tgt))
        i+=5
    else:
        i+=1
print()
# 反汇编 0x107AC1 往前找入口
print("  0x107AC1 往前 0x40 字节:")
o=r2o(0x107A81)
for k in range(0,0x40,16):
    print("    +%03X: %s"%(k,' '.join('%02X'%c for c in d[o+k:o+k+16])))
