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
b=d[o:o+0x500]
print("  0x95 错误码上下文 (+0x350 - +0x3F0):")
for i in range(0x350,0x3F0,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
print()
print("  解读 +0x37D 附近:")
print("    +37D: 6A 95        push 0x95")
print("    +37F: EB 06        jmp +0x387")
print("    +381: 6A 96        push 0x96")
print("    +383: EB 02        jmp +0x387")
print("    +385: 6A 97        push 0x97")
print("    +387: 58           pop eax")
print()
print("  => 这是**多分支错误码汇聚**：0x95 / 0x96 / 0x97")
print("     0x95 = -107, 0x96 = -106, 0x97 = -105")
print()
print("  看 +0x350 之前的判断逻辑:")
for i in range(0x300,0x390,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
