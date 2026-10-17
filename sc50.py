import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
tags=['a5f2a880','ea89938f','91b29cc0','aabdd3bb']
# ★★★ 决定性测试: 标签是否与 MIndex 的 +32 hash 字段相关？
# 若标签是 hash 的一部分，则应有数学关系
print("=== 标签 vs MIndex +32 hash 字段 ===")
for i in range(12):
    s=offs[i]
    t=a[s+4:s+8]
    mo=56+i*56
    h=struct.unpack_from('<I',mi,mo+32)[0]
    hb=struct.pack('<I',h)
    print("  #%-2d 标签 %s  hash 0x%08X (%s)"%(i,t.hex(),h,hb.hex(' ')))
print()
# ★ 检查: 标签是否在 MIndex 里出现（作为常量）
print("=== 标签在 MIndex 中是否出现 ===")
for t in tags:
    tb=bytes.fromhex(t)
    print("  %s 在 MIndex 中出现 %d 次"%(t,mi.count(tb)))
print()
# ★★★ 关键: 4 个标签可能是**4 个不同扫描阶段的标记**
# 检查标签与记录序号的关系
print("=== 标签序列（前 30 条记录）===")
seq=[]
for i in range(30):
    s=offs[i]
    if s+8>len(a): break
    t=a[s+4:s+8].hex()
    seq.append(tags.index(t) if t in tags else -1)
print("  %s"%seq)
print()
# 检查是否周期性
for p in [2,3,4,5,6,8]:
    ok=sum(1 for i in range(len(seq)-p) if seq[i]==seq[i+p])
    print("  周期 %d 匹配率: %d/%d"%(p,ok,len(seq)-p))
