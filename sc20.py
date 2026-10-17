import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
r=a[offs[1]:offs[2]]
# 密文 106 个不同值，范围 0x16-0xFE。绝大多数 >= 0x80。
# >>1 后落在 0x40-0x7F（64 个值）—— 这是 6-bit 数据！
# 但 base64 解码不可读 => 不是文本，是**二进制 6-bit 打包**
# 
# 更可能：这是一个 **位流**，每个字节承载 7 位有效数据（最高位是标志/校验）
# 测试：取每字节低 7 位，重新打包成 8-bit 流
print("=== 取低 7 位重新打包 ===")
bits=[]
for b in r:
    v=b&0x7F
    for k in range(6,-1,-1):
        bits.append((v>>k)&1)
# 打包成字节
out=bytearray()
for i in range(0,len(bits)-7,8):
    byte=0
    for k in range(8): byte=(byte<<1)|bits[i+k]
    out.append(byte)
print("  打包得到 %d 字节"%len(out))
print("  前 80: %r"%bytes(out[:80]).decode('latin1'))
print()
# 换一种：取低 6 位
bits=[]
for b in r:
    v=b&0x3F
    for k in range(5,-1,-1): bits.append((v>>k)&1)
out2=bytearray()
for i in range(0,len(bits)-7,8):
    byte=0
    for k in range(8): byte=(byte<<1)|bits[i+k]
    out2.append(byte)
print("=== 取低 6 位重新打包 ===")
print("  前 80: %r"%bytes(out2[:80]).decode('latin1'))
print()
# 直接看 >>1 后的 hex
print("=== >>1 后的 hex（前 96）===")
print("  %s"%bytes(b>>1 for b in r[:96]).hex(' '))
