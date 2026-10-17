import sys,os,struct
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
def r2o(r):
    for nm,va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
# 全文件搜索这些 RVA 的 4 字节小端出现（不限 push）
for label,rva in [('MIndex.dat',0xFD1A4),('Data_',0xFD1BC),('CIndex_',0xFD1C8),('ScanCache',0xFD2B8)]:
    pat=struct.pack('<I',rva)
    found=[]
    i=0
    while True:
        j=d.find(pat,i)
        if j<0: break
        found.append((j,r2o(j)))
        i=j+1
    print("  %-12s RVA=0x%X 被引用 %d 次:"%(label,rva,len(found)))
    for off,r in found[:5]:
        print("      文件偏移 0x%X (RVA 0x%X)"%(off,r if r else 0))
