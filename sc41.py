import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
# ★★★ 记录前 8 字节的模式:
#   #0: ad f6 ae b6 91 b2 9c c0
#   #1: e5 cd 16 f8 ea 89 93 8f
#   #2: aa b6 6e f4 a5 f2 a8 80
#   #3: 9e f6 b2 b4 91 b2 9c c0   <- 后4字节与#0同
#   #4: aa b6 83 f4 a5 f2 a8 80   <- 后4字节与#2同
#   #5: e5 cd 32 fb ea 89 93 8f   <- 后4字节与#1同
#   #6: b3 b6 fa f6 a5 f2 a8 80   <- 后4字节与#2/#4同
#   #7: f9 cd b5 f9 ea 89 93 8f   <- 后4字节与#1/#5同
# => 后 4 字节是**类型/标志**，前 4 字节是**数据**
print("=== 记录前 8 字节分组（按后4字节）===")
from collections import defaultdict
g=defaultdict(list)
for i in range(60):
    s=offs[i]
    if s+8>len(a): break
    tail=a[s+4:s+8]
    g[tail.hex(' ')].append(i)
for k,v in sorted(g.items(),key=lambda x:-len(x[1])):
    print("  后4字节 %s -> 记录 %s"%(k,v[:12]))
print()
# 前 4 字节解码（>>1）
print("=== 前 4 字节 >>1 后的字符 ===")
for i in range(12):
    s=offs[i]
    fr=a[s:s+4]
    print("  记录 #%-2d 前4=%s  >>1=%r"%(i,fr.hex(' '),bytes(b>>1 for b in fr).decode('latin1')))
