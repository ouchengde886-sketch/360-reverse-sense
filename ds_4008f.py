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
print("  ScanAveMemoryWithCode 走魔数分支后调用内部实现:")
print("    +15E: FF 75 0C   push [ebp+0x0C]")
print("    +161: FF 75 08   push [ebp+0x08]")
print("    +164: E8 26 00 00 00  call 0x4008F")
print()
print("  内部实现 0x4008F 的参数:")
print("    [ebp+0x08] = param_2")
print("    [ebp+0x0C] = param_3")
print("    [ebp+0x10] = param_4")
print("    [ebp+0x14] = param_5")
print("    [ebp+0x18] = param_6  (lryy 魔数指针)")
print("    [ebp+0x1C] = param_7  (长度)")
print()
print("  0x4008F 反汇编:")
o=r2o(0x4008F)
b=d[o:o+0x60]
for i in range(0,0x50,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
