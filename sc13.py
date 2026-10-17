import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
# 记录 #2 头: aa b6 6e f4 a5 f2 a8 80 90 d5 a8 aa b1 d7 bf 92 9d df be 9d af d9 a1 83 94 d3 fe aa ac c5 a8 84 8a ea 8c 92 94 df a3 9f
# 记录 #4 头: aa b6 83 f4 a5 f2 a8 80 90 d5 a8 aa b1 d7 bf 92 9d df be 9d af d9 a1 83 94 d3 fe aa ac c5 a8 84 8a ea 8c 92 94 df a3 9f
# 两者几乎相同！只有第 3 字节不同 (6e vs 83)
# => 这是**固定模板 + 少量变化**，很像文件路径记录（同目录不同文件名）
print("=== 记录 #2 与 #4 的差异 ===")
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
r2=a[offs[2]:offs[3]]; r4=a[offs[4]:offs[5]]
n=min(len(r2),len(r4))
diffs=[i for i in range(n) if r2[i]!=r4[i]]
print("  长度: #2=%d #4=%d"%(len(r2),len(r4)))
print("  差异字节位置: %s"%diffs[:20])
print("  #2: %s"%r2[:48].hex(' '))
print("  #4: %s"%r4[:48].hex(' '))
print()
print("=== 用 XOR 0xEA 解码两者 ===")
print("  #2: %r"%bytes(c^0xEA for c in r2[:64]).decode('latin1'))
print("  #4: %r"%bytes(c^0xEA for c in r4[:64]).decode('latin1'))
print()
# 关键：若明文是路径，则 XOR 后应出现 'D' ':' '\\' 等
# 观察 #2 XOR 后第 0 字节: 0xaa^0xea=0x40='@'  #4 同
# 但路径首字符应是 'D' 或 'C'
# 试不同 key 让首字节变成 'D'(0x44) 或 'C'(0x43)
print("=== 找 key 使记录 #2 首字节变成 'D' 或 'C' ===")
print("  key = 0x%02X -> 'D'"%(r2[0]^0x44))
print("  key = 0x%02X -> 'C'"%(r2[0]^0x43))
print()
# 用 key=0xEE ('D') 解码
for k in [r2[0]^0x44, r2[0]^0x43]:
    print("  key=0x%02X: %r"%(k,bytes(c^k for c in r2[:64]).decode('latin1')))
