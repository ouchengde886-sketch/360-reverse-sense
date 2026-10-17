import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
seg=a[offs[0]:offs[1]]
print("=== 记录 #0 是固定头部（跨3天100%%相同）===")
print("  长度 %d"%len(seg))
# 找内部重复
print()
print("=== 记录 #0 内部重复结构 ===")
for L in [74,76,37,38]:
    for i in range(len(seg)-L):
        s=seg[i:i+L]
        j=seg.find(s,i+1)
        if j>0:
            print("  长度 %d: @%d 和 @%d (间隔 %d)"%(L,i,j,j-i))
            break
print()
# 观察: 74 字节块重复。这段明文可能是一个"记录模板"
# 用 >>1 看
out=bytes(b>>1 for b in seg)
print("=== >>1 输出 ===")
print("  %r"%out)
print()
# 找重复块的精确边界
i=27; j=103
L=0
while j+L<len(out) and out[i+L]==out[j+L]: L+=1
print("  重复块 @%d 长度 %d"%(i,L))
print("  块: %r"%out[i:i+L])
print()
# ★ 关键: 这个块本身是否还有内部重复？
blk=out[i:i+L]
print("=== 块内部重复 ===")
for LL in [8,10,12,16,20]:
    for k in range(len(blk)-LL):
        s=blk[k:k+LL]
        m=blk.find(s,k+1)
        if m>0:
            print("  长度 %d: @%d 和 @%d  %r"%(LL,k,m,s))
            break
