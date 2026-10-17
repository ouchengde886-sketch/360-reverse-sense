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
print("  EngLib_Init 完整反汇编（RVA 0x3996E）:")
o=r2o(0x3996E)
b=d[o:o+0x120]
for i in range(0,0x110,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
print()
print("  解读关键分支:")
print("    +010: 8B 45 08      mov eax,[ebp+0x08]    param_1")
print("    +013: 50            push eax")
print("    +014: E8 61 0C 00 00  call 0x3A5E7     ★ 关键校验函数")
print("    +019: 59            pop ecx")
print("    +01A: 85 C0         test eax,eax")
print("    +01C: 0F 84 C0 00 00 00  jz +0xE2       ★ 返回 0 就跳过全部初始化！")
print()
print("  => 0x3A5E7 返回 0 时，EngLib_Init 直接跳过初始化并返回 0。")
print("     这就是为什么 rc=0 但全局没变。")
print()
print("  看 0x3A5E7 是什么:")
o2=r2o(0x3A5E7)
b2=d[o2:o2+0x80]
for i in range(0,0x70,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b2[i:i+16])))
