import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
r2=a[offs[2]:offs[3]]
# XOR 0xEA 后 #2 = '@\\\x84...' 
# 观察: 若明文是 'D:\\...' 则 key 应让 0xaa->0x44(D), 0xb6->0x3a(:), 0x6e->0x5c(\)
# 0xaa^0x44=0xEE, 0xb6^0x3a=0x8C, 0x6e^0x5c=0x32  -> 三个不同 key => 不是单字节 XOR
print("=== 逐字节推导所需 key（假设明文是 'D:\\' 开头）===")
for i,ch in enumerate(b'D:\\'):
    print("  密文[%d]=0x%02X  明文=0x%02X  key=0x%02X"%(i,r2[i],ch,r2[i]^ch))
print()
# 假设明文是 'C:\\' 
print("=== 假设明文 'C:\\' ===")
for i,ch in enumerate(b'C:\\'):
    print("  密文[%d]=0x%02X  明文=0x%02X  key=0x%02X"%(i,r2[i],ch,r2[i]^ch))
print()
# 关键测试：这是**替换表**吗？统计全文件字节分布，看是否 256 个值都出现
from collections import Counter
c=Counter(a)
print("=== 全文件字节分布 ===")
print("  不同字节值数: %d / 256"%len(c))
print("  最常见 10 个: %s"%[(hex(k),v) for k,v in c.most_common(10)])
print("  最少见 10 个: %s"%[(hex(k),v) for k,v in c.most_common()[-10:]])
print()
# 若是替换密码，明文的空格(0x20)会映射到某个固定密文字节，且该字节频次最高
# 路径里 '\\'(0x5c) 和 '.'(0x2e) 也高频
print("=== 若明文含大量 '\\\\'(0x5c) 和 ' '(0x20)，最高频密文字节应对应它们 ===")
print("  最高频字节: 0x%02X (%d 次)"%(c.most_common(1)[0][0],c.most_common(1)[0][1]))
