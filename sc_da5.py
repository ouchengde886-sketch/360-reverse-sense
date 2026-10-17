import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\ScChecker.dll'
d=open(p,'rb').read()
pe=struct.unpack_from('<I',d,0x3c)[0]
nsec=struct.unpack_from('<H',d,pe+6)[0]
optsz=struct.unpack_from('<H',d,pe+20)[0]
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
print("  SCC_Create (RVA 0x65C60) 手工解码:")
print("    +000: 55 8B EC          push ebp; mov ebp,esp")
print("    +003: 6A FF             push -1")
print("    +005: 68 96 2A 11 10    push SEH 0x10112A96")
print("    +00A: 64 A1 00 00 00 00  mov eax,fs:[0]")
print("    +010: 50                push eax")
print("    +011: 83 EC 10          sub esp,0x10")
print("    +014: 53 56 57          push ebx;push esi;push edi")
print("    +017: A1 B4 D0 15 10    mov eax,[0x1015D0B4]  cookie")
print("    +01C: 33 C5             xor eax,ebp")
print("    +01E: 50                push eax")
print("    +01F: 8D 45 F4          lea eax,[ebp-0x0C]")
print("    +022: 64 A3 00 00 00 00  mov fs:[0],eax")
print("    +028: E8 B3 8A 07 00    call 0x7E6E0     ; 初始化")
print("    +02D: 8B C8             mov ecx,eax")
print("    +02F: E8 EC 8B 07 00    call 0x7E820")
print("    +034: 68 BC FC 15 10    push 0x1015FCBC   ; 类型标识")
print("    +039: 6A 40             push 0x40         ★ 分配 0x40 字节")
print("    +03B: E8 36 57 08 00    call operator new")
print("    +040: 8B D8             mov ebx,eax")
print("    +042: 83 C4 08          add esp,8")
print("    +045: 89 5D F0          mov [ebp-0x10],ebx")
print("    +048: C7 45 FC 00 00 00 00  mov [ebp-4],0")
print("    +04F: 85 DB             test ebx,ebx")
print("    +051: 0F 84 E9 00 00 00  jz +0x140")
print("    +057: C7 03 24 B1 13 10  mov [ebx],0x1013B124  ★★ 虚表！")
print("    +05D: 8D 7B 10          lea edi,[ebx+0x10]")
print()
print("  ★ 虚表 0x1013B124 + 基址 0x56CF0000 = 0x56E2B124")
print("    这正是我运行时 dump 到的虚表！完全吻合。")
print()
print("  CreateDA (RVA 0x5BFF0) 手工解码:")
print("    +000: 68 BC FC 15 10    push 0x1015FCBC   ; 同一类型标识")
print("    +005: 6A 04             push 4            ★ 分配 4 字节")
print("    +007: E8 DA F3 08 00    call operator new")
print("    +00C: 83 C4 08          add esp,8")
print("    +00F: 85 C0             test eax,eax")
print("    +011: 74 07             jz +0x1A")
print("    +013: C7 00 10 AF 13 10  mov [eax],0x1013AF10  ★ 另一个虚表")
print("    +019: C3                ret")
print("    +01A: 33 C0             xor eax,eax")
print("    +01C: C3                ret")
print()
print("  => CreateDA 分配 4 字节对象，虚表 0x1013AF10（+基址=0x56E2AF10）")
print("     这是**独立的小对象**，不是引擎对象。")
print()
# dump 两个虚表
for vt,label in [(0x13B124,'SCC_Create 的虚表'),(0x13AF10,'CreateDA 的虚表')]:
    o=r2o(vt)
    print("  %s RVA=0x%X:"%(label,vt))
    for i in range(8):
        fn=struct.unpack_from('<I',d,o+i*4)[0]
        print("    [%d] 0x%08X"%(i,fn))
    print()
