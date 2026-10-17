import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
seg=a[offs[2]:offs[3]]   # 记录 #2
# ★★★ 决定性测试: 密文 99.8% 是 0x80|v。
# 若明文是 UTF-16LE 文本，则每个字符 2 字节 (lo, hi=0)。
# 若只存 lo 字节并置高位，则 v = lo。
# 那么 v 应该就是 ASCII 文本！但实测 v 可打印率仅 58-61%。
#
# ★ 换假设: 明文是 UTF-16LE，**两个字节都被处理**：
#   b[2i] = 0x80 | (lo ^ k1), b[2i+1] = 0x80 | (hi ^ k2)
# 若 hi 恒为 0，则 b[2i+1] 恒定。检查奇数位是否恒定。
odd=[seg[i] for i in range(1,len(seg),2)]
even=[seg[i] for i in range(0,len(seg),2)]
from collections import Counter
print("=== 记录 #2 奇偶位统计 ===")
print("  奇数位不同值: %d, top3: %s"%(len(set(odd)),Counter(odd).most_common(3)))
print("  偶数位不同值: %d, top3: %s"%(len(set(even)),Counter(even).most_common(3)))
print()
# 奇数位若不恒定，则不是"UTF-16 高字节为0"
# ★★★ 新假设: 明文是 **UTF-16LE 文本**，但被当作**字节流**做了 >>1 的逆
# 即: 密文 = (明文 << 1) | 1 的某种形式
# 试: 明文 = 密文 >> 1 得到的字节流，直接当 UTF-16LE 解码
out=bytes(b>>1 for b in seg)
print("=== >>1 输出当 UTF-16LE 解码 ===")
for off in [0,1]:
    try:
        s=out[off:off+80].decode('utf-16-le',errors='replace')
        print("  off=%d: %r"%(off,s))
    except Exception as e: print("  off=%d 失败"%off)
print()
# 试: 密文 & 0x7F 当 UTF-16LE
out2=bytes(b&0x7f for b in seg)
print("=== &0x7F 当 UTF-16LE 解码 ===")
for off in [0,1]:
    s=out2[off:off+80].decode('utf-16-le',errors='replace')
    print("  off=%d: %r"%(off,s))
print()
# ★★★ 关键: 若明文是 UTF-16LE 且含中文路径，则字节里会有大量 0x00
# 检查 >>1 输出里 0x00 的比例
print("  >>1 输出中 0x00 数量: %d / %d"%(out.count(0),len(out)))
print("  >>1 输出中 >=0x80 数量: %d"%sum(1 for b in out if b>=0x80))
print("  >>1 输出范围: %d-%d"%(min(out),max(out)))
