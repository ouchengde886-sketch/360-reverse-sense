import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
seg=a[offs[1]:offs[2]]
# 关键: >>1 输出无空格、无小写混排，字符集中在 0x40-0x7F
# 这是**每个字节承载 6 位**的打包数据：字节 = 0x40 | (6bit)
# 即 6bit = byte & 0x3F  (因为 >>1 后是 0x40-0x7F, 原字节是 0x80-0xFF)
# 验证: 原字节是否都在 0x80-0xFF
hi=sum(1 for b in seg if b>=0x80)
print("=== 原字节高位置1比例: %d/%d = %.1f%% ==="%(hi,len(seg),100*hi/len(seg)))
print()
# 所以: 6bit = (b - 0x80) 的低6位? 或 b & 0x3F
print("=== 提取 6bit 并尝试不同位序打包 ===")
import itertools
vals=[b&0x3F for b in seg]
# 尝试 MSB-first 和 LSB-first，以及不同起始位偏移
for name,rev in [('MSB',False),('LSB',True)]:
    for skip in range(8):
        bits=[]
        for v in vals:
            rng=range(5,-1,-1) if not rev else range(6)
            for k in rng: bits.append((v>>k)&1)
        bits=bits[skip:]
        out=bytearray()
        for i in range(0,len(bits)//8*8,8):
            byte=0
            for k in range(8): byte=(byte<<1)|bits[i+k]
            out.append(byte)
        pr=sum(1 for c in out if 32<=c<127)
        if pr/max(1,len(out))>0.85:
            print("  %s skip=%d 可打印 %.0f%% %r"%(name,skip,100*pr/max(1,len(out)),bytes(out[:70])))
