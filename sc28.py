import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
seg=a[offs[1]:offs[2]]
# 密文 b = 0x80 | v, v 是 7 位
# >>1 后 = 0x40 | (v>>1)
# 若这是"位流"，则每个字节的最高有效位可能是独立的位平面
# 测试: 取每字节的 bit6 (即 v>>1 的最高位)
print("=== 位平面分析（记录 #1）===")
for bit in range(8):
    plane=[(b>>bit)&1 for b in seg]
    ones=sum(plane)
    print("  bit%d: 1 的比例 %.1f%%"%(bit,100*ones/len(plane)))
print()
# 若某位平面是常数，说明该位是标志位
# 测试: 原字节是否都 >= 0x80（bit7=1）
print("=== 原字节 bit7 比例: %.1f%% ==="%(100*sum(1 for b in seg if b&0x80)/len(seg)))
print()
# 关键测试：把 >>1 输出当"7位ASCII"（去掉最高位后）
v7=[b&0x7F for b in seg]
print("=== b & 0x7F 当 ASCII（前 100）===")
print("  %r"%bytes(v7[:100]).decode('latin1'))
print()
# 观察: 原字节 0x80|v，v 的范围
print("  v 范围: %d-%d"%(min(v7),max(v7)))
print("  v 不同值: %d"%len(set(v7)))
print()
# 也许 v 本身就是 ASCII 但被加了偏移。找偏移使结果像文本
best=[]
for k in range(128):
    o=bytes((x+k)&0x7F for x in v7[:500])
    # 统计常见英文/路径字符
    common=sum(1 for x in o if chr(x) in ' etaoinshrdluET\\/:.0123456789_-')
    best.append((common,k))
best.sort(reverse=True)
print("=== v + 偏移，找最像文本的 ===")
for common,k in best[:5]:
    o=bytes((x+k)&0x7F for x in v7[:80])
    print("  +0x%02X 常见字符=%d  %r"%(k,common,o.decode('latin1')))
