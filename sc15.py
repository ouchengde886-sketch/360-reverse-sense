import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
# 记录 #1 = [187,754) 跨天相同
r=a[offs[1]:offs[2]]
print("=== 记录 #1 (%d 字节) 头部 128 字节 ==="%len(r))
print("  "+r[:128].hex(' '))
print()
# 假设明文是 '<ext><appmon><![CDATA[hi.MID:...]]></appmon></ext>'
# 明文以 '<' (0x3C) 开头
print("=== 假设明文以 '<'(0x3C) 开头，推导密钥 ===")
for i in range(8):
    print("  密文[%d]=0x%02X -> 若明文=0x%02X 则 key=0x%02X"%(i,r[i],ord('<ext><ap'[i]),r[i]^ord('<ext><ap'[i])))
print()
# 观察: 密文里是否有重复模式（对应明文重复）
from collections import Counter
print("=== 记录 #1 内字节频次 top10 ===")
c=Counter(r)
print("  %s"%[(hex(k),v) for k,v in c.most_common(10)])
print("  不同字节数: %d"%len(c))
print()
# 关键：明文 XML 里 '<' '>' '/' '[' ']' 等会重复出现
# 若密文是简单 XOR 固定 key，则这些明文字符对应固定密文字节，频次会突出
# 检查是否有字节频次异常高
tot=len(r)
print("  最高频字节占比: %.1f%%"%(100*c.most_common(1)[0][1]/tot))
print()
# 测试：明文可能是 UTF-16LE，则偶数位是 ASCII，奇数位是 0x00
# 若 XOR 固定 key K，则奇数位密文应全等于 K
odd=[r[i] for i in range(1,len(r),2)]
even=[r[i] for i in range(0,len(r),2)]
print("=== 奇偶位分析 ===")
print("  奇数位不同值数: %d"%len(set(odd)))
print("  偶数位不同值数: %d"%len(set(even)))
print("  奇数位 top5: %s"%[(hex(k),v) for k,v in Counter(odd).most_common(5)])
print("  偶数位 top5: %s"%[(hex(k),v) for k,v in Counter(even).most_common(5)])
