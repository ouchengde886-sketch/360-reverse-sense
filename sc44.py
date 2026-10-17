import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
b=open(os.path.join(d,'Data_2026_10_17.dat'),'rb').read()
tags=[bytes.fromhex(t) for t in ['a5f2a880','ea89938f','91b29cc0','aabdd3bb']]
# ★ 4 个标签出现次数几乎相等 => 固定 4 槽结构
# 找所有标签位置，看间隔是否固定
pos={}
for t in tags:
    p=[]; st=0
    while True:
        i=b.find(t,st)
        if i<0: break
        p.append(i); st=i+1
    pos[t.hex()]=p
    print("  %s: %d 处, 前5个偏移 %s"%(t.hex(),len(p),[hex(x) for x in p[:5]]))
print()
# 合并所有位置排序，看间隔模式
allp=sorted([(p,t.hex()) for t,ps in pos.items() for p in ps])
print("=== 前 20 个标签位置及间隔 ===")
for i in range(min(20,len(allp))):
    gap=allp[i][0]-allp[i-1][0] if i>0 else 0
    print("   @0x%06X %s 间隔 %d"%(allp[i][0],allp[i][1],gap))
print()
# 统计间隔分布
from collections import Counter
gaps=Counter(allp[i][0]-allp[i-1][0] for i in range(1,len(allp)))
print("=== 间隔分布 top10 ===")
for g,n in gaps.most_common(10):
    print("   间隔 %d: %d 次"%(g,n))
