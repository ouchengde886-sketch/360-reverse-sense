import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
print("=== MIndex 记录 #0/#1 的 +16 偏移与 +12 长度 ===")
print("  #0: off=187 len=567  -> 覆盖 [187,754)")
print("  #1: off=754 len=762  -> 覆盖 [754,1516)")
print("  #2: off=1516 len=674 -> [1516,2190)")
print("  => +16 是**累计结束偏移**，记录数据在 [prev_off, off) 区间")
print()
print("=== 验证：15 与 16 在 [187,754) 区间是否完全相同 ===")
seg_a=a[187:754]; 
b=open(os.path.join(d,'Data_2026_10_16.dat'),'rb').read()
seg_b=b[187:754]
print("  相同: %s"%(seg_a==seg_b))
print("  15[187:230]: %s"%seg_a[:43].hex(' '))
print()
print("=== 若记录 #0 是固定内容（如头部/版本），它的明文应可猜 ===")
# 187 字节的记录 #0 —— 看看里面有没有可识别的结构
print("  #0 数据 [187,754) 前 96 字节:")
print("  "+a[187:283].hex(' '))
print()
# 尝试：XOR 0xEA 后看
dec=bytes(c^0xEA for c in a[187:283])
print("  XOR 0xEA 后: %r"%dec.decode('latin1'))
print()
# 观察 0xEA 在密文中的出现（明文 0x00）
from collections import Counter
print("  [187,754) 区间内 0xEA 出现次数: %d"%a[187:754].count(0xEA))
print("  [187,754) 区间内 0x00 出现次数: %d"%a[187:754].count(0x00))
print("  全文件 0xEA 出现次数: %d"%a.count(0xEA))
print("  全文件 0x00 出现次数: %d"%a.count(0x00))
