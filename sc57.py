import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
seg=a[offs[2]:offs[3]]
# ★★★ 关键事实: >>1 输出范围 55-127，无 0x00，无 >=0x80
# 55 = 0x37。127 = 0x7F。
# 若这是 6-bit 数据 + 0x40 偏移，则范围应是 0x40-0x7F (64-127)。但最小是 55。
# 55 < 64 => 不是简单 +0x40
#
# ★ 重新审视: 密文 b, b>>1 范围 55-127 => b 范围 110-255
# 前面测过 b 最小 0x16(22)。记录 #2 的 b 范围?
print("=== 记录 #2 密文范围 ===")
print("  min 0x%02X max 0x%02X"%(min(seg),max(seg)))
print("  <0x80 的字节: %s"%[(i,hex(b)) for i,b in enumerate(seg) if b<0x80][:10])
print()
# ★★★ 决定性: 若这是 **7-bit 位流**（每字节 7 位有效），
# 则应该把每字节的低 7 位串起来，重新按 8 位切分。
# 前面试过但结果不可读。换一种：**按 7 位切分后当 ASCII**
print("=== 每字节低7位 -> 直接当 ASCII ===")
v7=bytes(b&0x7f for b in seg)
print("  %r"%v7[:80].decode('latin1'))
print()
# ★ 试: 位流按 MSB-first 串起来，再按 7 位切分当 ASCII
bits=[]
for b in seg:
    for k in range(7,-1,-1): bits.append((b>>k)&1)
# 按 7 位切分
out=bytearray()
for i in range(0,len(bits)//7*7,7):
    val=0
    for k in range(7): val=(val<<1)|bits[i+k]
    out.append(val)
print("=== 8位流按7位切分当 ASCII ===")
print("  %r"%bytes(out[:80]).decode('latin1'))
print()
# ★ 试: 去掉每字节最高位后串起来，按 8 位切分
bits2=[]
for b in seg:
    for k in range(6,-1,-1): bits2.append((b>>k)&1)
out2=bytearray()
for i in range(0,len(bits2)//8*8,8):
    val=0
    for k in range(8): val=(val<<1)|bits2[i+k]
    out2.append(val)
print("=== 低7位流按8位切分 ===")
print("  %r"%bytes(out2[:80]).decode('latin1'))
print()
# ★ 试: 低7位流按8位切分，但 LSB-first
bits3=[]
for b in seg:
    for k in range(7): bits3.append((b>>k)&1)
out3=bytearray()
for i in range(0,len(bits3)//8*8,8):
    val=0
    for k in range(8): val|=(bits3[i+k]<<k)
    out3.append(val)
print("=== 低7位流 LSB-first 按8位切分 ===")
print("  %r"%bytes(out3[:80]).decode('latin1'))
