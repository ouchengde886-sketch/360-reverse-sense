import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
tags=['a5f2a880','ea89938f','91b29cc0','aabdd3bb']
# ★ 关联分析: 类型标签 vs MIndex 字段
print("=== 类型标签与 MIndex 字段的关联 ===")
print("  记录 | 标签       | MIndex+12(len) | +24(float) | +32(hash)")
for i in range(24):
    s=offs[i]
    if s+8>len(a): break
    t=a[s+4:s+8].hex()
    mo=56+i*56
    v=struct.unpack_from('<14I',mi,mo)
    f=struct.unpack_from('<f',mi,mo+24)[0]
    print("  #%-3d | %s | %6d | %12.4f | 0x%08X"%(i,t,v[3],f,v[8]))
print()
# 按标签分组统计
from collections import defaultdict
g=defaultdict(list)
for i in range(60):
    s=offs[i]
    if s+8>len(a): break
    t=a[s+4:s+8].hex()
    mo=56+i*56
    v=struct.unpack_from('<14I',mi,mo)
    f=struct.unpack_from('<f',mi,mo+24)[0]
    g[t].append((i,v[3],f,v[8]))
print("=== 按标签分组 ===")
for t,items in g.items():
    lens=[x[1] for x in items]
    fl=[x[2] for x in items]
    print("  标签 %s: %d 条"%(t,len(items)))
    print("     长度范围 %d-%d, 均值 %.0f"%(min(lens),max(lens),sum(lens)/len(lens)))
    print("     float 范围 %.2f-%.2f"%(min(fl),max(fl)))
