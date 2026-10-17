import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
# ★★★ 新思路: 标签可能不是 4 字节常量，而是**数据的一部分**。
# 检查标签之后的字节是否有结构。
print("=== 标签之后的 24 字节（记录 #0-#5）===")
for i in range(6):
    s=offs[i]
    print("  #%d 标签后: %s"%(i,a[s+8:s+8+24].hex(' ')))
print()
# ★ 关键: 前面发现记录 #0 的 76 字节周期，[27,76) 是常量模板。
# 记录 #0 的 +4 标签是 91b29cc0。检查其他同类标签记录的模板是否相同。
tags=['a5f2a880','ea89938f','91b29cc0','aabdd3bb']
from collections import defaultdict
g=defaultdict(list)
for i in range(60):
    s=offs[i]
    if s+8>len(a): break
    t=a[s+4:s+8].hex()
    g[t].append(i)
print("=== 同类标签记录的数据区相似度 ===")
for t,ids in g.items():
    if len(ids)<2: continue
    print("  标签 %s (%d 条): %s"%(t,len(ids),ids[:6]))
    # 比较前两条的数据区前 40 字节
    s1=offs[ids[0]]+8; s2=offs[ids[1]]+8
    d1=a[s1:s1+40]; d2=a[s2:s2+40]
    same=sum(1 for k in range(40) if d1[k]==d2[k])
    print("     前40字节相同数: %d/40"%same)
    print("     #%d: %s"%(ids[0],d1.hex(' ')))
    print("     #%d: %s"%(ids[1],d2.hex(' ')))
print()
# ★★★ 决定性: 比较**不同标签**记录的相同位置，看标签是否影响后续数据
print("=== 跨标签比较（各取第一条，前 24 字节）===")
for t,ids in g.items():
    s=offs[ids[0]]+8
    print("  %s: %s"%(t,a[s:s+24].hex(' ')))
