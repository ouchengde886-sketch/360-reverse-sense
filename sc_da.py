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
print("  CreateDA (RVA 0x10000) 反汇编:")
o=r2o(0x10000)
b=d[o:o+0x100]
for i in range(0,0x100,16):
    print("    +%03X: %s"%(i,' '.join('%02X'%c for c in b[i:i+16])))
print()
print("  手工解码:")
print("    +000: 55 8B EC          push ebp; mov ebp,esp")
print("    +003: 6A FF             push -1")
print("    +005: 68 ...            push SEH")
print("    +00A: 64 A1 00 00 00 00  mov eax,fs:[0]")
print("    +010: 50                push eax")
print("    +011: 83 EC 10          sub esp,0x10")
print("    +014: A1 ...            mov eax,[cookie]")
print("    +019: 33 C5             xor eax,ebp")
print("    +01B: 89 45 F0          mov [ebp-0x10],eax")
print("    +01E: 53 56 57          push ebx;push esi;push edi")
print("    +021: 50                push eax")
print("    +022: 8D 45 F4          lea eax,[ebp-0x0C]")
print("    +025: 64 A3 00 00 00 00  mov fs:[0],eax")
print()
print("  CreateIconMatcher (RVA 0x30002) 反汇编:")
o=r2o(0x30002)
b=d[o:o+0x80]
for i in range(0,0x80,16):
    print("    +%03X: %s"%(i,' '.join('%02X'%c for c in b[i:i+16])))
