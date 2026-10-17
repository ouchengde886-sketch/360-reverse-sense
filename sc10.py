import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
b=open(os.path.join(d,'Data_2026_10_16.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
print("=== ★ 关键：754 是 MIndex 记录 #1 的 +16 偏移 ===")
for i in range(4):
    o=56+i*56
    v=struct.unpack_from('<14I',mi,o)
    print("  记录 #%d: +0=0x%08X +4=0x%08X +12(len)=%d +16(off)=%d"%(i,v[0],v[1],v[3],v[4]))
print()
print("=== 15 与 16 的差异区段（754 处开始）===")
print("  15[754:790]: %s"%a[754:790].hex(' '))
print("  16[754:790]: %s"%b[754:790].hex(' '))
print()
# 找 15 与 16 的所有差异区间
diffs=[]
i=0
n=min(len(a),len(b))
while i<n:
    if a[i]!=b[i]:
        st=i
        while i<n and a[i]!=b[i]: i+=1
        diffs.append((st,i))
    else: i+=1
print("  15 与 16 的差异区间数: %d"%len(diffs))
print("  前 10 个: %s"%[(hex(s),hex(e),e-s) for s,e in diffs[:10]])
print()
# 这些区间是否对应 MIndex 记录边界？
offs=[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range((len(mi)-56)//56)]
oset=set(offs)
match=sum(1 for s,e in diffs if s in oset or e in oset)
print("  差异区间端点落在 MIndex +16 偏移上的数量: %d/%d"%(match,len(diffs)))
