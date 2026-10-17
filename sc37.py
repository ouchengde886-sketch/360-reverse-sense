import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
seg=a[offs[0]:offs[1]]
# ★★★ 决定性测试: 高位置1比例 99.8% => 几乎全是 0x80|v
# 但 0.2% 不是。那 0.2% 是什么？可能是**长度/标志字节**。
print("=== 高 8 位为 0 的字节（即 < 0x80）===")
for i,b in enumerate(seg):
    if b<0x80:
        print("  @%d = 0x%02X (%d)"%(i,b,b))
print()
seg1=a[offs[1]:offs[2]]
print("=== 记录 #1 中 < 0x80 的字节 ===")
for i,b in enumerate(seg1):
    if b<0x80:
        print("  @%d = 0x%02X (%d)"%(i,b,b))
print()
# 这些位置是否在记录开头/结尾？
print("  记录 #0 长度 %d, 记录 #1 长度 %d"%(len(seg),len(seg1)))
print()
# ★ 检查: 是否所有字节都是 0x80|v 形式，即 v = b & 0x7F
# 若是，则这是**7位编码**（类似 base128）
# 7 位 * N 字节 = 信息量。若是文本，7位足够表示 ASCII。
# 那为什么 v 不是可读 ASCII？=> 还有一层变换（如 XOR 位置相关密钥）
#
# ★★★ 决定性测试: 用记录 #0 的重复段验证"位置相关密钥"假设
# 若密钥 = f(位置)，则明文相同但位置不同 -> 密文不同。但实测相同 => 密钥与位置无关
# 若密钥与位置无关且是 XOR，则 v ^ K = 明文，K 是常数
# 试所有 K，看哪个使 v^K 最像文本
print("=== v ^ K 搜索（找最像文本的 K）===")
v=[b&0x7F for b in seg]
best=[]
for K in range(128):
    o=bytes(x^K for x in v)
    common=sum(1 for c in o if chr(c) in ' etaoinshrdluET\\/:.0123456789_-')
    pr=sum(1 for c in o if 32<=c<127)
    best.append((common,pr,K))
best.sort(reverse=True)
for common,pr,K in best[:5]:
    o=bytes(x^K for x in v[:70])
    print("  ^0x%02X 常见=%d 可打印=%d  %r"%(K,common,pr,o.decode('latin1')))
