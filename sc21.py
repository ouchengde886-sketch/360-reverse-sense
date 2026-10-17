import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
# 1. 验证 >>1 在所有记录上是否一致（可打印率）
print("=== 各记录 >>1 后的可打印率 ===")
for i in range(12):
    s,e=offs[i],offs[i+1]
    seg=a[s:e]
    if not seg: continue
    out=bytes(b>>1 for b in seg)
    pr=sum(1 for c in out if 32<=c<127)
    print("  记录 #%-2d %5d 字节  >>1 可打印 %5d (%.1f%%)"%(i,len(seg),pr,100*pr/len(seg)))
print()
# 2. 搜索已知明文 'hi.MID:'
print("=== 搜索已知明文 'hi.MID:' ===")
for i in range(60):
    s,e=offs[i],offs[i+1]
    seg=a[s:e]
    if not seg: continue
    out=bytes(b>>1 for b in seg)
    for kw in [b'hi.MID:',b'hi.AVE:',b'<ext>',b'CDATA']:
        j=out.find(kw)
        if j>=0:
            print("  记录 #%d 找到 %r @%d: %r"%(i,kw,j,out[max(0,j-20):j+60]))
