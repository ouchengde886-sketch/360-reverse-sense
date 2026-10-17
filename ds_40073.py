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
# 0x40073 是魔数分支的目标
o=r2o(0x40073)
b=d[o:o+0x260]
print("  0x40073 完整反汇编（前 0x100 字节）:")
for i in range(0,0x100,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
print()
print("  手工解码 0x40073 的校验序列:")
print("    +000: 55 8B EC          push ebp; mov ebp,esp")
print("    +003: 83 EC 10          sub esp,0x10")
print("    +006: 8B 45 18          mov eax,[ebp+0x18]   param_6")
print("    +009: 85 C0             test eax,eax")
print("    +00B: 0F 84 21 02 00 00  jz +0x232  失败")
print("    +011: 83 7D 1C 00       cmp dword[ebp+0x1C],0   param_7")
print("    +015: 0F 84 17 02 00 00  jz +0x232  失败")
print("    +01B: 85 C9             test ecx,ecx")
print("    +01D: 0F 84 0B 02 00 00  jz +0x22E  失败")
print("    +023: 83 7D 14 00       cmp dword[ebp+0x14],0   param_5")
print("    +027: 0F 84 01 02 00 00  jz +0x22E  失败")
print("    +02D: 68 80 68 2A 10    push 0x102A6880")
print("    +032: 8D 8D E0 FD FF FF  lea ecx,[ebp-0x220]")
print("    +038: E8 49 82 FC FF    call 0x38286")
print("    +03D: 83 65 FC 00       and dword[ebp-4],0")
print("    +041: 33 DB             xor ebx,ebx")
print("    +043: 43                inc ebx")
print("    +044: 80 3D C0 68 2A 10 00  cmp byte[0x102A68C0],0")
print("    +04B: 0F 85 97 00 00 00  jnz +0xE8")
print("    +051: 68 08 02 00 00    push 0x208")
print()
print("  ★ 关键：+044 检查字节全局 0x102A68C0")
print("     若为 0 -> 走 +0x51 初始化（push 0x208）")
print("     若非 0 -> 跳到 +0xE8")
print()
print("  +0xE8 区域:")
for i in range(0xE0,0x100,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
