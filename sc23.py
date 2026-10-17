import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
seg=a[offs[1]:offs[2]]
# 密文 b: 高6位 = b>>2 ? 还是 b>>1?
# 观察 b 值分布: 0x80-0xFF 为主。若有效数据在**低7位**且最高位是标志:
#   b = 0x80 | (6bit << 1) | 1 ?
# 测试各种提取方式，看哪个能产生可读文本
print("=== 尝试多种 6-bit 提取 + 打包 ===")
tests={
 'b>>1 -0x40': lambda b: (b>>1)&0x3F,
 'b&0x3F': lambda b: b&0x3F,
 'b>>2': lambda b: (b>>2)&0x3F,
 '(b-0x80)>>1': lambda b: ((b-0x80)>>1)&0x3F,
 'b&0x7F>>1': lambda b: (b&0x7F)>>1,
}
for name,fn in tests.items():
    vals=[fn(b) for b in seg]
    # 打包 6bit -> 8bit (MSB first)
    bits=[]
    for v in vals:
        for k in range(5,-1,-1): bits.append((v>>k)&1)
    out=bytearray()
    for i in range(0,len(bits)//8*8,8):
        byte=0
        for k in range(8): byte=(byte<<1)|bits[i+k]
        out.append(byte)
    pr=sum(1 for c in out if 32<=c<127)
    print("  %-12s 打包 %d 字节 可打印 %d (%.0f%%)  %r"%(name,len(out),pr,100*pr/max(1,len(out)),bytes(out[:60])))
