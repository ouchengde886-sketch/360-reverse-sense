import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
seg=a[offs[0]:offs[1]]
# ★★★ 关键洞察: 密文字节 99.8% 高位置1 => b = 0x80 | v, v 是 7 位
# 7 位值！不是 6 位。v 范围 0-126（前面测过）。
# 若 v 就是 ASCII 但被 XOR 了某个**位置相关**的密钥...
# 
# ★ 决定性测试: 记录 #0 的 27-100 和 103-176 完全相同。
# 若密钥流是位置相关的（如 i*K），则同一明文在不同位置会得到不同密文，
# 那这两段就**不该**相同。但它们相同 => **密钥流与位置无关**！
# => 加密是**逐字节独立**的（ECB 式替换或 XOR 固定密钥）
# => 但前面测过固定 XOR 不行，替换表也不行（频次平坦）
# 
# ★★ 矛盾！除非... 明文本身在这两段就是相同的，且加密是逐字节的。
# 那频次平坦说明**明文本身频次平坦**（二进制数据，不是文本）。
#
# 结论: 记录 #0 是**二进制数据**（如哈希表/位图），不是文本。
# 
# ★ 验证: 看 v 值分布是否像二进制
v=[b&0x7F for b in seg]
print("=== v 值（7位）分布 ===")
print("  范围 %d-%d, 不同值 %d"%(min(v),max(v),len(set(v))))
from collections import Counter
c=Counter(v)
print("  top10: %s"%[(k,n) for k,n in c.most_common(10)])
print()
# 检查 v 是否像 ASCII 文本（应有大量 0x20-0x7E）
pr=sum(1 for x in v if 32<=x<127)
print("  v 中可打印 ASCII 比例: %.1f%%"%(100*pr/len(v)))
print()
# 记录 #1 的 v 分布
seg1=a[offs[1]:offs[2]]
v1=[b&0x7F for b in seg1]
pr1=sum(1 for x in v1 if 32<=x<127)
print("=== 记录 #1 ===")
print("  v 中可打印 ASCII 比例: %.1f%%"%(100*pr1/len(v1)))
print("  v 范围 %d-%d"%(min(v1),max(v1)))
print()
# ★★★ 试: v 是否可能是 **UTF-16 的低字节**（高字节被省略/压缩）
# 若明文是 UTF-16LE 文本，则每 2 字节是 (char, 0)。若只存 char，就是单字节流。
# 那 v 应该就是 ASCII！但 v 可打印率低...
# 试: v + 0x20 ?
for k in [0x20,0x40,0x60,0x80]:
    o=bytes((x+k)&0x7F for x in v[:60])
    print("  v+0x%02X: %r"%(k,o.decode('latin1')))
