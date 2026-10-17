import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
tags=['a5f2a880','ea89938f','91b29cc0','aabdd3bb']
from collections import defaultdict
g=defaultdict(list)
for i in range(60):
    s=offs[i]
    if s+8>len(a): break
    t=a[s+4:s+8].hex()
    if t in tags: g[t].append(i)
# ★ 对每个标签组，比较所有成员的数据区，找出**哪些位置变化**
print("=== 各组内数据区的变量位置 ===")
for t,ids in g.items():
    if len(ids)<3: continue
    segs=[]
    for i in ids:
        s,e=offs[i],offs[i+1]
        segs.append(a[s+8:e])
    m=min(len(x) for x in segs)
    var=[]
    for k in range(m):
        vals=set(x[k] for x in segs)
        if len(vals)>1: var.append(k)
    print("  标签 %s: %d 条, 最短 %d 字节, 变量位置 %d 个"%(t,len(ids),m,len(var)))
    print("     变量位置前30: %s"%var[:30])
    print("     常量比例: %.1f%%"%(100*(m-len(var))/m))
print()
# ★★★ 关键: 变量位置是否集中在**开头**（如文件名/路径）？
# 看第一组的变量位置分布
t=tags[0]
ids=g[t]
segs=[a[offs[i]+8:offs[i+1]] for i in ids]
m=min(len(x) for x in segs)
var=[k for k in range(m) if len(set(x[k] for x in segs))>1]
print("=== 标签 %s 的变量位置分布 ==="%t)
if var:
    print("  最小 %d 最大 %d"%(min(var),max(var)))
    # 分段统计
    for st in range(0,m,50):
        n=sum(1 for v in var if st<=v<st+50)
        print("     [%3d,%3d): %d 个变量"%(st,st+50,n))
