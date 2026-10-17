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
print("  EngLib_Init (RVA 0x3996E) 反汇编:")
o=r2o(0x3996E)
b=d[o:o+0x80]
for i in range(0,0x60,16):
    print("    +%03X: %s" % (i,' '.join('%02X'%c for c in b[i:i+16])))
print()
print("  解读:")
print("    +000: 55 8B EC        push ebp; mov ebp,esp")
print("    +003: 6A FF           push -1")
print("    +005: 68 ...          push SEH")
print("    +00A: 64 A1 00 00 00 00  mov eax,fs:[0]")
print("    ...")
print()
# 找 ret
for i in range(0x70):
    if b[i]==0xC2:
        n=struct.unpack_from('<H',b,i+1)[0]
        print("    +%03X: C2 %04X  ret 0x%X => %d 参数" % (i,n,n,n//4))
        break
    if b[i]==0xC3:
        print("    +%03X: C3  ret (无参数)" % i)
        break
print()
print("  EngLib_Init 内部调用了哪些函数:")
for i in range(len(b)-5):
    if b[i]==0xE8:
        rel=struct.unpack_from('<i',b,i+1)[0]
        tgt=0x3996E+i+5+rel
        print("    +%03X: call 0x%X" % (i,tgt))
    if b[i]==0xFF and b[i+1]==0x15:
        addr=struct.unpack_from('<I',b,i+2)[0]
        print("    +%03X: call [0x%X]  (导入函数)" % (i,addr))
