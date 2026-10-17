import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
tags=['a5f2a880','ea89938f','91b29cc0','aabdd3bb']
# ★★★ 验证: 每条记录的 [8,28) 是否是该标签组的常量（即 +8 起 20 字节是组头）
print("=== 每条记录 +8 起的 20 字节（组头）===")
from collections import defaultdict
g=defaultdict(set)
for i in range(60):
    s=offs[i]
    if s+28>len(a): break
    t=a[s+4:s+8].hex()
    hdr=a[s+8:s+28].hex()
    g[t].add(hdr)
for t,hdrs in g.items():
    print("  标签 %s: %d 种不同的 20 字节组头"%(t,len(hdrs)))
    for h in list(hdrs)[:2]:
        print("     %s"%h)
print()
# ★ 若组头唯一，则 +8..+28 是**固定的类型描述**
# 那么变量数据从 +28 开始
print("=== 验证变量起点 ===")
for t,ids in [('a5f2a880',[i for i in range(60) if a[offs[i]+4:offs[i]+8].hex()==t])]:
    segs=[a[offs[i]+8:offs[i+1]] for i in ids]
    m=min(len(x) for x in segs)
    var=[k for k in range(m) if len(set(x[k] for x in segs))>1]
    print("  标签 %s: 变量最小位置 %d"%(t,min(var) if var else -1))
    # 看 [0,min(var)) 是否全常量
    if var:
        print("    [0,%d) 全常量: %s"%(min(var),all(k not in var for k in range(min(var)))))
        print("    常量头: %s"%segs[0][:min(var)].hex(' '))
