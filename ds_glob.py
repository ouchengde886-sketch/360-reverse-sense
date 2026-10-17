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
print("  全局变量 0x2A682C / 0x2A6830 的引用点（写操作）:")
# 搜索 mov [0x2A682C], reg  = 89 05 2C 68 2A 10
pat=bytes([0x89,0x05,0x2C,0x68,0x2A,0x10])
idx=0
while True:
    i=d.find(pat,idx)
    if i<0: break
    # 转回 RVA
    rva=None
    for va,vs,ra,rs in secs:
        if ra<=i<ra+rs: rva=va+(i-ra); break
    print("    文件偏移 0x%X  RVA 0x%X : mov [0x2A682C],eax" % (i,rva))
    idx=i+1
print()
print("  搜索 0x2A6830 的写:")
pat2=bytes([0x89,0x05,0x30,0x68,0x2A,0x10])
idx=0
while True:
    i=d.find(pat2,idx)
    if i<0: break
    rva=None
    for va,vs,ra,rs in secs:
        if ra<=i<ra+rs: rva=va+(i-ra); break
    print("    文件偏移 0x%X  RVA 0x%X : mov [0x2A6830],eax" % (i,rva))
    idx=i+1
print()
print("  搜索所有引用 0x2A682C 的指令:")
for pat_b,desc in [(bytes([0x2C,0x68,0x2A,0x10]),'0x2A682C'),(bytes([0x30,0x68,0x2A,0x10]),'0x2A6830')]:
    idx=0; found=[]
    while True:
        i=d.find(pat_b,idx)
        if i<0: break
        rva=None
        for va,vs,ra,rs in secs:
            if ra<=i<ra+rs: rva=va+(i-ra); break
        if rva: found.append((rva,i))
        idx=i+1
    print("  %s 共 %d 处引用:" % (desc,len(found)))
    for rva,i in found[:20]:
        print("    RVA 0x%X (文件 0x%X)" % (rva,i))
