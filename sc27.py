import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
# 用全部记录做统计（更大样本）
allout=bytearray()
for i in range(60):
    s,e=offs[i],offs[i+1]
    if e>len(a): break
    allout+=bytes(b>>1 for b in a[s:e])
print("  总样本: %d 字节"%len(allout))
from collections import Counter
c=Counter(allout)
print("=== 字符频次 top 20 ===")
tot=len(allout)
for k,v in c.most_common(20):
    print("   0x%02X %r  %6d  %.2f%%"%(k,chr(k),v,100*v/tot))
print()
print("  不同字符数: %d"%len(c))
print("  字符范围: 0x%02X - 0x%02X"%(min(c),max(c)))
print()
# 若是替换密码，最高频应对应空格(英文)或 '\'(路径)
print("=== 假设最高频 = 空格，映射表 ===")
top=c.most_common(1)[0][0]
print("  最高频字符 0x%02X (%r) -> 空格"%(top,chr(top)))
