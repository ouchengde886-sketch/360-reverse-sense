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
def o2r(o):
    for va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
print("  追踪 param_7 的真实用途:")
print("    +2F9: FF 75 1C   push [ebp+0x1C]  = param_7")
print("    +306: FF 50 18   call [eax+0x18]")
print()
print("  param_7 在函数里还被用在哪？搜索 [ebp+0x1C] 的引用:")
o=r2o(0x3FEE4)
b=d[o:o+0x500]
for i in range(len(b)-3):
    if b[i]==0xFF and b[i+1]==0x75 and b[i+2]==0x1C:
        print("    +%03X: FF 75 1C   push [ebp+0x1C]" % i)
    if b[i]==0x8B and b[i+1]==0x45 and b[i+2]==0x1C:
        print("    +%03X: 8B 45 1C   mov eax,[ebp+0x1C]" % i)
    if b[i]==0x8B and b[i+1]==0x4D and b[i+2]==0x1C:
        print("    +%03X: 8B 4D 1C   mov ecx,[ebp+0x1C]" % i)
print()
print("  看 +0x20 处对 param_7 的校验:")
print("    +020: 8B 7D 1C   mov edi,[ebp+0x1C]   param_7")
print("    +023: 33 DB      xor ebx,ebx")
print("    +025: 85 FF      test edi,edi")
print("    +027: 74 0D      jz +0x36")
print("    +029: 39 1F      cmp [edi],ebx        ; [param_7] 必须非 0")
print("    +02B: 74 05      jz +0x32")
print("    +02D: 39 5F 04   cmp [edi+4],ebx      ; [param_7+4] 必须非 0")
print("    +030: 75 04      jnz +0x36")
print("    +032: 6A 99      push 0x99")
print()
print("  => param_7 结构: +0 非0, +4 非0")
print("     我传的是 'lryy'(0x7979726C) 和 size，都非 0，通过了这个校验。")
print()
print("  但 vtable+0x18 要的是**特定格式**。查 vtable+0x18 指向哪:")
print("  esi 的 vtable 从 [0x102A682C] 的工厂函数来，运行时才知道。")
print("  但填入的函数表在 EngLib_Init 的 param_1+4 起:")
print("    +034: C7 46 04 42 99 03 10  mov [esi+0x04],0x10039942")
print("    +03B: C7 46 08 73 9A 03 10  mov [esi+0x08],0x10039A73")
print("    ...")
print("  这些是 RVA 0x39942, 0x39A73, ...")
print()
print("  而 ScanAveMemoryWithCode 的 vtable+0x18 是**另一个对象**的虚表。")
print("  那个对象来自 [0x102A682C] 工厂。")
print()
print("  关键：param_7 传给 vtable+0x18，可能是**文件信息结构**。")
print("  看 +0x053: call 0x409C9 和 +0x09A: call 0x40929 —— 早期处理。")
print("  看 +0x04A - +0x0A0 区域（param_2 的处理）:")
for i in range(0x40,0xB0,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
