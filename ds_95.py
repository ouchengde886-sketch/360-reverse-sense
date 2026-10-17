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
o=r2o(0x3FEE4)
b=d[o:o+0x400]
print("  搜索 0x95 (149) 错误码:")
for i in range(len(b)-2):
    if b[i]==0x6A and b[i+1]==0x95:
        print("    +%03X: 6A 95        push 0x95  (后跟 %s)" % (i,' '.join('%02X'%c for c in b[i+2:i+6])))
    if b[i]==0x6A and b[i+2]==0x58 and b[i+1]>=0x80:
        imm=b[i+1]-256
        print("    +%03X: 6A %02X 58    push %d; pop eax" % (i,b[i+1],imm))
print()
print("  0x3FEE4 附近完整字节 (0x100-0x180):")
for i in range(0x100,0x180,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
print()
print("  查找 call 到其他函数的位置（可能返回 0x95）:")
for i in range(len(b)-5):
    if b[i]==0xE8:
        rel=struct.unpack_from('<i',b,i+1)[0]
        tgt=0x3FEE4+i+5+rel
        if 0x3F000 < tgt < 0x41000:
            print("    +%03X: call 0x%X" % (i,tgt))
