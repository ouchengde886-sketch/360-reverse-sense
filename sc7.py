import sys,os
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
da=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
# key=0xEA 时得到 'G\x1cD\\{Xv*N\x7fv\x00o}...'
# 看起来像 UTF-16LE 但每个 16 位字被 XOR 了某个值？
# 试: 把每 2 字节当一个 WORD，XOR 一个 WORD 密钥
print("=== 尝试 WORD 级 XOR（16 位密钥）===")
import struct
for k in [0x0000,0x1CEA,0xEA1C,0x00EA,0xEA00,0x1C00,0x001C]:
    out=[]
    for i in range(0,40,2):
        w=struct.unpack_from('<H',da,i)[0]
        out.append(w^k)
    s=''.join(chr(c) if 32<=c<127 else '.' for c in out)
    print("  key=0x%04X -> %s"%(k,s))
print()
# key=0xEA 单字节 XOR 后的字节序列，看结构
dec=bytes(c^0xEA for c in da[:80])
print("=== 单字节 XOR 0xEA 后的 80 字节 ===")
print("  "+dec.hex(' '))
print("  作为 latin1: %r"%dec.decode('latin1'))
print()
# 观察: 明文可能每 2 字节是 (char, 0x1C) 或 (char, 0x00)
# 0xEA^0x00=0xEA -> 若明文奇数位是 0x00，密文奇数位应都是 0xEA
odd=[da[i] for i in range(1,80,2)]
print("  奇数位字节: %s"%[hex(x) for x in odd[:20]])
from collections import Counter
print("  奇数位频次: %s"%Counter(odd).most_common(6))
even=[da[i] for i in range(0,80,2)]
print("  偶数位频次(前6): %s"%Counter(even).most_common(6))
