import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\sweeper\CleanSoftEng.dll'
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
def o2r(o):
    for nm,va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
# ★★★ 决定性: 在 **整个文件** 里搜索字符串 RVA 的 4 字节（任意对齐）
for s in ['%s\\360safe\\ScanCache','%s\\MIndex.dat','Data_%04d_%02d_%02d.dat']:
    off=d.find(s.encode('utf-16-le'))
    rva=o2r(off)
    pat=struct.pack('<I',rva)
    hits=[]
    st=0
    while True:
        j=d.find(pat,st)
        if j<0: break
        hits.append((j,o2r(j)))
        st=j+1
    print("  %-28r RVA=0x%X 被引用 %d 次"%(s,rva,len(hits)))
    for j,r in hits[:6]:
        print("       文件偏移 0x%X -> RVA 0x%X"%(j,r if r else 0))
print()
# ★ 若真的零引用，检查是否是 **导出符号** 或 **资源**
# 看导出表
peoff=pe
opt=pe+24
magic=struct.unpack_from('<H',d,opt)[0]
print("  Optional header magic: 0x%04X"%magic)
exp_rva=struct.unpack_from('<I',d,opt+96)[0]
exp_sz=struct.unpack_from('<I',d,opt+100)[0]
print("  导出表 RVA=0x%X 大小=%d"%(exp_rva,exp_sz))
if exp_rva:
    eo=o2r(exp_rva)
    nfun=struct.unpack_from('<I',d,eo+20)[0]
    nnam=struct.unpack_from('<I',d,eo+24)[0]
    print("  导出函数数=%d 名称数=%d"%(nfun,nnam))
    anames=struct.unpack_from('<I',d,eo+32)[0]
    for k in range(min(nnam,20)):
        no=o2r(anames)+k*4
        sr=struct.unpack_from('<I',d,no)[0]
        so2=o2r(sr)
        e=d.find(b'\x00',so2)
        print("     %s"%d[so2:e].decode('latin1'))
