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
# ★ 关键: 字符串在 .rdata (VA 0x113000-0x142A3D)。RVA 0x120DA0 在此范围内。
# 检查 .rdata 里是否有**指向字符串的指针**（.rdata 可含只读数据表）
rd=[x for x in secs if x[0]=='.rdata'][0]
nm,va,vs,ra,rs=rd
b=d[ra:ra+vs]
print("  .rdata VA=0x%X VS=0x%X"%(va,vs))
for name,rva in [('MIndex',0x120DA0),('Data_',0x120DC0),('ScanCache',0x120D8A)]:
    pat=struct.pack('<I',rva)
    hits=[]
    for j in range(len(b)-4):
        if b[j:j+4]==pat: hits.append(va+j)
    print("  %s RVA 0x%X 在 .rdata 中被指针引用: %d 处 %s"%(name,rva,len(hits),[hex(x) for x in hits[:5]]))
print()
# ★ 检查 .data 段
dt=[x for x in secs if x[0]=='.data'][0]
nm,va,vs,ra,rs=dt
b2=d[ra:ra+vs]
for name,rva in [('MIndex',0x120DA0),('Data_',0x120DC0)]:
    pat=struct.pack('<I',rva)
    hits=[va+j for j in range(len(b2)-4) if b2[j:j+4]==pat]
    print("  %s 在 .data 中被引用: %d 处 %s"%(name,len(hits),[hex(x) for x in hits[:5]]))
print()
# ★★★ 决定性: 检查字符串是否在**导入表/导出表**被引用，或根本是死字符串
# 看字符串附近是否有其它 ScanCache 相关串
i=d.find('Data_%04d_%02d_%02d.dat'.encode('utf-16-le'))
print("=== 字符串 @0x%X 附近 400 字节的所有宽字符串 ==="%i)
import re
seg=d[i-200:i+400]
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,60}',seg):
    s=m.group().decode('utf-16-le',errors='ignore')
    print("   @0x%X %r"%(i-200+m.start(),s))
