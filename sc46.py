import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
tags=['a5f2a880','ea89938f','91b29cc0','aabdd3bb']
# ★★★ 决定性验证: 标签是否出现在每条记录的**固定偏移 +4** 处？
print("=== 每条记录的 +4 处是否为类型标签 ===")
hit=0; miss=0
for i in range(60):
    s=offs[i]
    if s+8>len(a): break
    t=a[s+4:s+8].hex()
    if t in tags: hit+=1
    else:
        miss+=1
        if miss<=5: print("   记录 #%d +4 = %s (非标签)"%(i,t))
print("  命中 %d / 未命中 %d"%(hit,miss))
print()
# 记录 #0 的标签在 +4
print("  记录 #0 +0..+8: %s"%a[offs[0]:offs[0]+8].hex(' '))
print("  记录 #1 +0..+8: %s"%a[offs[1]:offs[1]+8].hex(' '))
print()
# ★ 检查标签在记录内的**所有**出现位置
print("=== 记录 #1 内标签出现位置 ===")
s,e=offs[1],offs[2]
seg=a[s:e]
for t in tags:
    tb=bytes.fromhex(t)
    p=[]; st=0
    while True:
        j=seg.find(tb,st)
        if j<0: break
        p.append(j); st=j+1
    if p: print("   %s @ %s"%(t,p))
print()
# ★★★ 关键: 检查记录内的**子结构**。记录 #1 长度 567
# 若记录内有多个条目，每个条目以标签开头
print("=== 记录 #1 长度 %d，按标签切分 ==="%len(seg))
allp=sorted([(seg.find(bytes.fromhex(t)),t) for t in tags if seg.find(bytes.fromhex(t))>=0])
print("  标签位置: %s"%[(hex(p),t) for p,t in allp])
