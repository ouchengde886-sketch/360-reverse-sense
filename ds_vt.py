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
print("  关键：esi 从哪来？")
print("  看 +0x2C0 - +0x340:")
for i in range(0x2C0,0x340,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
print()
print("  解读 +0x310 - +0x340:")
print("    +310: 8D 8D E4 FD FF FF   lea ecx,[ebp-0x21C]")
print("    +316: 51                  push ecx")
print("    +317: 33 FF               xor edi,edi")
print("    +319: 8D 8D DC FD FF FF   lea ecx,[ebp-0x224]")
print("    +31F: 51                  push ecx")
print("    +320: 57 57 57            push edi;push edi;push edi")
print("    +323: FF 75 08            push [ebp+0x08]     param_2")
print("    +326: 8B CE               mov ecx,esi")
print("    +328: 89 BD DC FD FF FF   mov [ebp-0x224],edi")
print("    +32E: 89 BD E4 FD FF FF   mov [ebp-0x21C],edi")
print("    +334: FF 50 1C            call [eax+0x1C]     ★ vtable+0x1C")
print("    +337: 8B 8D E4 FD FF FF   mov ecx,[ebp-0x21C]")
print("    +33D: 85 C0               test eax,eax")
print("    +33F: 75 2D               jnz +0x36E")
print()
print("  => [eax+0x1C] 是 esi 对象的虚表方法，7 个参数：")
print("       param_2, 0, 0, 0, &out1, &out2")
print("     调用后 ecx = out2 的值")
print("     若 ecx==0 且 edx!=0 -> 走错误分支")
print()
print("  esi 是什么？往上找 esi 赋值：")
for i in range(0x200,0x2C0,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
