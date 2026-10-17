import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\ave\AVEI.dll'
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
def o2r(o):
    for nm,va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
# 搜索所有写 4 到字节的指令
# C6 03 04       mov byte[ebx],4
# C6 00 04       mov byte[eax],4
# C6 01 04       mov byte[ecx],4
# C6 02 04       mov byte[edx],4
# C6 06 04       mov byte[esi],4
# C6 07 04       mov byte[edi],4
# C6 45 xx 04    mov byte[ebp+xx],4
# C6 44 24 xx 04 mov byte[esp+xx],4
pats = [
 (b'\xC6\x03\x04','mov byte[ebx],4'),
 (b'\xC6\x00\x04','mov byte[eax],4'),
 (b'\xC6\x01\x04','mov byte[ecx],4'),
 (b'\xC6\x02\x04','mov byte[edx],4'),
 (b'\xC6\x06\x04','mov byte[esi],4'),
 (b'\xC6\x07\x04','mov byte[edi],4'),
]
print("  AVEI.dll 中所有 '写 4 到字节' 的指令:")
total=0
for nm,va,vs,ra,rs in secs:
    if nm!='.text': continue
    b=d[ra:ra+vs]
    for pat,desc in pats:
        st=0
        while True:
            i=b.find(pat,st)
            if i<0: break
            print("    RVA=0x%X  %s"%(va+i,desc))
            total+=1
            st=i+1
    # C6 45 xx 04
    st=0
    while True:
        i=b.find(b'\xC6\x45',st)
        if i<0: break
        if i+3<len(b) and b[i+3]==4:
            print("    RVA=0x%X  mov byte[ebp+0x%02X],4"%(va+i,b[i+2]))
            total+=1
        st=i+1
    # C6 44 24 xx 04
    st=0
    while True:
        i=b.find(b'\xC6\x44\x24',st)
        if i<0: break
        if i+4<len(b) and b[i+4]==4:
            print("    RVA=0x%X  mov byte[esp+0x%02X],4"%(va+i,b[i+3]))
            total+=1
        st=i+1
print("  共 %d 处"%total)
