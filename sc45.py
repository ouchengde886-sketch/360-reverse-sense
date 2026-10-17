import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
b=open(os.path.join(d,'Data_2026_10_17.dat'),'rb').read()
tags=['a5f2a880','ea89938f','91b29cc0','aabdd3bb']
pos={}
for t in tags:
    tb=bytes.fromhex(t)
    p=[]; st=0
    while True:
        i=b.find(tb,st)
        if i<0: break
        p.append(i); st=i+1
    pos[t]=p
allp=sorted([(p,t) for t,ps in pos.items() for p in ps])
print("=== 前 24 个标签位置及间隔 ===")
for i in range(min(24,len(allp))):
    gap=allp[i][0]-allp[i-1][0] if i>0 else 0
    print("   @0x%06X %s 间隔 %d"%(allp[i][0],allp[i][1],gap))
print()
from collections import Counter
gaps=Counter(allp[i][0]-allp[i-1][0] for i in range(1,len(allp)))
print("=== 间隔分布 top12 ===")
for g,n in gaps.most_common(12):
    print("   间隔 %d: %d 次"%(g,n))
print()
# 观察: 同类型标签之间的间隔
for t in tags:
    ps=pos[t]
    if len(ps)>3:
        g=[ps[i+1]-ps[i] for i in range(min(len(ps)-1,10))]
        print("  %s 同类间隔: %s"%(t,g))
