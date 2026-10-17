import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
tags=['a5f2a880','ea89938f','91b29cc0','aabdd3bb']
print("=== 类型标签的各种解释 ===")
for t in tags:
    b=bytes.fromhex(t)
    le=struct.unpack('<I',b)[0]
    be=struct.unpack('>I',b)[0]
    print("  标签 %s:"%t)
    print("     LE u32 = 0x%08X = %d"%(le,le))
    print("     BE u32 = 0x%08X = %d"%(be,be))
    # >>1 后
    s=bytes(x>>1 for x in b)
    print("     >>1 bytes: %s -> LE=0x%08X BE=0x%08X"%(s.hex(' '),struct.unpack('<I',s)[0],struct.unpack('>I',s)[0]))
    # &0x7F
    m=bytes(x&0x7f for x in b)
    print("     &0x7F bytes: %s -> LE=0x%08X = %d"%(m.hex(' '),struct.unpack('<I',m)[0],struct.unpack('<I',m)[0]))
    # -0x80
    d2=bytes((x-0x80)&0xff for x in b)
    print("     -0x80 bytes: %s -> LE=0x%08X = %d"%(d2.hex(' '),struct.unpack('<I',d2)[0],struct.unpack('<I',d2)[0]))
    # XOR 0x80
    x8=bytes(x^0x80 for x in b)
    print("     ^0x80 -> LE=0x%08X = %d"%(struct.unpack('<I',x8)[0],struct.unpack('<I',x8)[0]))
    print()
print("=== 目标: 引擎ID 2000(0x7D0) / 2065(0x811) ===")
print("  2000 = 0x7D0, 2065 = 0x811")
print()
# ★ 关键: 若标签是加密的引擎ID，找变换 f 使 f(标签) 接近 2000/2065
# 试: 标签的每个字节 >>1 后拼起来
for t in tags:
    b=bytes.fromhex(t)
    for name,fn in [('>>1',lambda x:x>>1),('&0x7F',lambda x:x&0x7f),('-0x80',lambda x:(x-0x80)&0xff),('^0x80',lambda x:x^0x80)]:
        v=bytes(fn(x) for x in b)
        le=struct.unpack('<I',v)[0]
        print("  %s %-6s -> 0x%08X = %d"%(t,name,le,le))
    print()
