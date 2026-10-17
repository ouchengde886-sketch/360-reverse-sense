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
# ScanAveMemoryWithCode = 0x4001E
o=r2o(0x4001E)
b=d[o:o+0x80]
print("  ScanAveMemoryWithCode (0x4001E) 精确字节:")
for i in range(0,0x70,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
print()
print("  手工解码:")
print("    +000: 55 8B EC          push ebp; mov ebp,esp")
print("    +003: 51 51             push ecx; push ecx")
print("    +005: 8B 45 18          mov eax,[ebp+0x18]   param_6")
print("    +008: 8B 4D 1C          mov ecx,[ebp+0x1C]   param_7")
print("    +00B: 85 C0             test eax,eax")
print("    +00D: 74 25             jz +0x34")
print("    +00F: 83 F9 04          cmp ecx,4")
print("    +012: 76 20             jbe +0x34")
print("    +014: 81 38 6C 72 79 79  cmp dword[eax],'lryy'")
print("    +01A: 75 18             jnz +0x34")
print("    +01C: 51                push ecx")
print("    +01D: 50                push eax")
print("    +01E: FF 75 14          push [ebp+0x14]")
print("    +021: FF 75 10          push [ebp+0x10]")
print("    +024: FF 75 0C          push [ebp+0x0C]")
print("    +027: FF 75 08          push [ebp+0x08]")
print("    +02A: E8 26 00 00 00    call 0x40055")   # 0x4001E+0x2A+5+0x26
print("    +02F: 83 C4 18          add esp,0x18")
print("    +032: EB 1D             jmp +0x51")
print("    +034: 89 45 F8          mov [ebp-8],eax")
print("    +037: 8D 45 F8          lea eax,[ebp-8]")
print("    +03A: 50                push eax")
print("    +03B: 6A 00             push 0")
print("    +03D: FF 75 14          push [ebp+0x14]")
print("    +040: 89 4D FC          mov [ebp-4],ecx")
print("    +043: FF 75 10          push [ebp+0x10]")
print("    +046: FF 75 0C          push [ebp+0x0C]")
print("    +049: FF 75 08          push [ebp+0x08]")
print("    +04C: E8 77 FE FF FF    call 0x3FEC8 (ScanAveMemory)")
print()
tgt=0x4001E+0x2A+5+0x26
print("  ★ 魔数分支调用目标 = 0x%X" % tgt)
print()
o2=r2o(tgt)
b2=d[o2:o2+0x80]
print("  0x%X 反汇编:" % tgt)
for i in range(0,0x70,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b2[i:i+16])))
print()
print("  手工解码 0x%X:" % tgt)
print("    +000: 55 8B EC          push ebp; mov ebp,esp")
print("    +003: 83 EC 10          sub esp,0x10")
print("    +006: 8B 45 18          mov eax,[ebp+0x18]")
print("    +009: 85 C0             test eax,eax")
print("    +00B: 0F 84 21 02 00 00  jz +0x232")
print("    +011: 83 7D 1C 00       cmp dword[ebp+0x1C],0")
print("    +015: 0F 84 17 02 00 00  jz +0x232")
print("    +01B: 85 C9             test ecx,ecx")
print("    +01D: 0F 84 0B 02 00 00  jz +0x22E")
print("    +023: 83 7D 14 00       cmp dword[ebp+0x14],0")
print("    +027: 0F 84 01 02 00 00  jz +0x22E")
print("    +02D: 68 80 68 2A 10    push 0x102A6880")
print()
print("  => 新全局 0x102A6880 和 0x102A68C0 出现!")
