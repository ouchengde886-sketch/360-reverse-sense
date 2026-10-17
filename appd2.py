import sys,os,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\ipc\appd.dll'
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
    print("  节 %-10s VA=0x%08X VS=0x%08X RA=0x%08X"% (nm,va,vs,ra))
def o2r(o):
    for nm,va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
def r2o(r):
    for nm,va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
# 字符串 RVA
for s,off in [('ScanCache',0xFC0B8),('CIndex_',0xFBFC8),('MIndex.dat',0xFBFA4),('Data_',0xFBFBC)]:
    print("  %-12s RVA=0x%X"%(s,o2r(off)))
print()
# 找引用这些 RVA 的代码（push imm32）
txt=[x for x in secs if x[0]=='.text'][0]
nm,va,vs,ra,rs=txt
b=d[ra:ra+vs]
for label,stroff in [('MIndex.dat',0xFBFA4),('Data_',0xFBFBC),('CIndex_',0xFBFC8),('ScanCache',0xFC0B8)]:
    rva=o2r(stroff)
    pat=struct.pack('<I',rva)
    found=[]
    i=0
    while True:
        j=b.find(pat,i)
        if j<0: break
        if j>0 and b[j-1]==0x68:
            found.append(va+j-1)
        i=j+1
    print("  push '%s'(RVA=0x%X) 的代码位置: %s"%(label,rva,[hex(x) for x in found[:6]]))
