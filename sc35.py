import sys,os,struct,itertools
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
seg=a[offs[0]:offs[1]]
# 记录 #0 固定不变。它极可能含**版本号/魔数/固定字符串**。
# 明文猜测: 可能含 '360' 或 'ScanCache' 或版本 '1.0.0.x'
#
# ★★ 决定性测试: 若编码是"6位索引 -> 字符表"，则同一明文字符必映射到同一密文，
# 反之亦然（双射）。检查 >>1 输出里字符与位置的关系。
# 已知: 偏移 27-100 和 103-176 是**完全相同**的 74 字节。
# 这意味着明文也重复。什么样的固定头部会有 74 字节重复？
#
# ★ 更可能: 记录 #0 不是"头部"，而是**第一条真实记录**，
# 且它的内容被写了两次（两个相同文件/同一文件的两次记录）。
#
# ★★★ 换个决定性思路: 直接暴力破解 6位->ASCII 映射
# 假设: 明文 = 密文6位值 + 偏移，或 明文 = 表[6位值]
# 用**可读性评分**搜索所有 64 字符的排列不现实（64!），
# 但若假设明文是**连续 ASCII 段**（如 0x20-0x5F），只需试 64 个起始点。
print("=== 假设 6位值 + 起始偏移 = ASCII（搜索起始点）===")
out=bytes(b>>1 for b in seg)
v6=[(b>>1)&0x3F for b in seg]
best=[]
for st in range(256):
    o=bytes((v+st)&0xFF for v in v6)
    pr=sum(1 for c in o if 32<=c<127)
    common=sum(1 for c in o if chr(c) in ' etaoinshrdluET\\/:.0123456789_-')
    best.append((common,pr,st))
best.sort(reverse=True)
for common,pr,st in best[:5]:
    o=bytes((v+st)&0xFF for v in v6[:70])
    print("  +0x%02X 常见=%d 可打印=%d  %r"%(st,common,pr,o.decode('latin1')))
print()
# 观察 6位值分布
from collections import Counter
c=Counter(v6)
print("=== 6位值频次 top12 ===")
for k,v in c.most_common(12):
    print("   %2d (0x%02X) %5d  %.2f%%"%(k,k,v,100*v/len(v6)))
print("   不同值: %d"%len(c))
