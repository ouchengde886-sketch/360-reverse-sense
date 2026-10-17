import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
seg=a[offs[0]:offs[1]]
# ★★★ 关键观察: 记录 #0 的重复段 @27 和 @103 密文完全相同。
# 但这两段在**明文里也相同**吗？不一定！
# 若加密与位置无关（逐字节替换），相同密文 => 相同明文。
# 那这段 74 字节的明文是什么？为什么会重复？
#
# ★ 新思路: 也许这段不是"明文重复"，而是**密文恰好重复**，
# 因为明文重复（如同一目录下的两个文件，路径前缀相同）。
#
# ★★★ 决定性测试: 检查 76 字节周期是否与**路径长度**相关。
# 76 字节 = 38 个 UTF-16 字符。一个路径 "D:\troyr2\tools\vendor\..." 约 38 字符！
# 
# 但更直接: 检查重复段 @27 和 @103 之间的 76 字节里，
# 是否有"相同前缀 + 不同后缀"的模式（如同一目录不同文件）。
print("=== 记录 #0 的 76 字节周期切分（原始密文）===")
for k in range(0,min(len(seg),76*3),76):
    print("  [%3d] %s"%(k,seg[k:k+76].hex(' ')))
print()
# 比较块 0 和块 1 的差异位置
b0=seg[0:76]; b1=seg[76:152]
print("=== 块 0 与块 1 的差异 ===")
diffs=[i for i in range(min(len(b0),len(b1))) if b0[i]!=b1[i]]
print("  差异位置: %s"%diffs)
print("  相同字节数: %d/76"%(76-len(diffs)))
print()
# 块 0 与块 1 在 [27,103) 相同 => 27-75 相同
# 差异在 0-26 和 103-151
print("  块0[0:27]: %s"%b0[0:27].hex(' '))
print("  块1[0:27]: %s"%b1[0:27].hex(' '))
print()
# ★ 若明文是 UTF-16LE，则每 2 字节一个字符。
# 检查密文是否成对出现（偶奇位相关性）
print("=== 偶奇位相关性 ===")
even=[seg[i] for i in range(0,len(seg),2)]
odd=[seg[i] for i in range(1,len(seg),2)]
print("  偶数位不同值: %d, 奇数位不同值: %d"%(len(set(even)),len(set(odd))))
from collections import Counter
print("  偶数位 top5: %s"%[(hex(k),n) for k,n in Counter(even).most_common(5)])
print("  奇数位 top5: %s"%[(hex(k),n) for k,n in Counter(odd).most_common(5)])
