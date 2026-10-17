import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
r=a[offs[1]:offs[2]]
# 观察密文字节范围
print("=== 密文统计 ===")
print("  最小 0x%02X 最大 0x%02X"%(min(r),max(r)))
# 高 3 位分布
from collections import Counter
hi=Counter(b>>5 for b in r)
print("  高3位分布: %s"%[(hex(k<<5),v) for k,v in sorted(hi.items())])
print()
# 观察: 密文大多在 0x80-0xFF。若明文是 ASCII(<0x80)，则密钥高位置 1
# 试: 明文 = 密文 ^ 0x80 -> 得到 0x00-0x7F 范围?
dec=bytes(b^0x80 for b in r[:64])
print("=== 密文 ^ 0x80 ===")
print("  %r"%dec.decode('latin1'))
print("  hex: %s"%dec.hex(' '))
print()
# 观察密文低 7 位
lo=bytes(b&0x7f for b in r[:64])
print("=== 密文 & 0x7F ===")
print("  %r"%lo.decode('latin1'))
print()
# 也许密钥是"位置相关"的伪随机。测试：把密文按字节减去某个递增序列
# 先看密文是否为明文+固定偏移（模 256）
# 若明文 '<'(0x3C) 且密文 0xE5, 偏移 = 0xA9
# 检查所有位置是否有相同偏移
print("=== 测试差值是否恒定（明文 '<' 出现处）===")
# 找密文中重复出现的字节（可能对应明文重复字符）
c=Counter(r)
for byte,n in c.most_common(3):
    print("  密文字节 0x%02X 出现 %d 次"%(byte,n))
