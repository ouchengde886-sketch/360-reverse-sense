import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
seg=a[offs[0]:offs[1]]
# 记录 #0 是固定头部，跨3天100%相同。
# 它极可能是**版本/魔数/配置**，明文可能包含可识别的字符串。
# 
# ★ 决定性测试: 若这是 6-bit 索引指向字母表，且字母表是**标准 ASCII 顺序的子集**，
# 那么 >>1 输出的字符应该与明文有**线性关系**。
# 我们已知明文里可能有 'hi.MID:' 或路径 'D:\' 或 '360' 等。
#
# 更好的方法: 用**记录 #0 是固定内容**这一点，
# 结合 MIndex 记录 #0 的字段 (+12=567 长度, +16=187 偏移) 推断语义。
#
# ★★ 新思路: 直接看**原始密文**（不 >>1），找可识别的结构
print("=== 记录 #0 原始密文（187 字节）===")
print("  "+seg.hex(' '))
print()
# 观察: 密文里 ad f6 ae b6 91 b2 9c c0 a4 95 9c ea 85 97 8b d2 ...
# 注意 a4 95 9c ea 85 97 8b d2 在偏移 8-15 和后面重复出现
# 找重复的 8 字节序列
print("=== 找重复的 8 字节序列 ===")
seen={}
for i in range(len(seg)-8):
    s=seg[i:i+8]
    if s in seen:
        print("  @%d 和 @%d: %s"%(seen[s],i,s.hex(' ')))
    seen[s]=i
print()
# 关键: 观察密文的**字节对**模式
print("=== 密文字节对（前 40）===")
for i in range(0,80,2):
    print("    [%3d] %02X %02X"%(i,seg[i],seg[i+1]))
