import sys,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\PopSoftEng.dll'
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
def fmtguid(o):
    d1,d2,d3=struct.unpack_from('<IHH',d,o)
    d4=d[o+8:o+10]
    d5=d[o+10:o+16]
    return "{%08X-%04X-%04X-%s-%s}"%(d1,d2,d3,d4.hex().upper(),d5.hex().upper())
# 从 Create360Object 里提取所有 mov edx, imm32 的 GUID 指针
o=r2o(0xDFF0)
b=d[o:o+0x400]
print("  Create360Object 里的 GUID 指针（mov edx,imm32）:")
seen=set()
i=0
while i<len(b)-5:
    if b[i]==0xBA:  # mov edx, imm32
        imm=struct.unpack_from('<I',b,i+1)[0]
        rva=imm-0x10000000
        if 0x8000<=rva<0x96000:
            if rva not in seen:
                seen.add(rva)
                oo=r2o(rva)
                if oo:
                    print("    +%03X: edx=0x%08X RVA=0x%X -> %s"%(i,imm,rva,fmtguid(oo)))
        i+=5
    else:
        i+=1
print()
print("  该函数所有 GUID（从数据段扫描）:")
for rva in sorted(seen):
    oo=r2o(rva)
    if oo: print("    RVA=0x%X %s"%(rva,fmtguid(oo)))
