import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
# ★★★ 4 个类型标签:
#   a5 f2 a8 80 / ea 89 93 8f / 91 b2 9c c0 / aa bd d3 bb
# 这些是 4 字节常量。观察它们 >>1 后:
for t in ['a5f2a880','ea89938f','91b29cc0','aabdd3bb']:
    b=bytes.fromhex(t)
    print("  %s >>1 = %r   &0x7F = %s"%(t,bytes(x>>1 for x in b).decode('latin1'),bytes(x&0x7f for x in b).hex(' ')))
print()
# ★ 关键: 这些常量在**明文**里对应什么？
# 可能是 4 字节的"魔数"或"类型ID"
# 观察它们的共同点: 每个字节都 >= 0x80
# 若明文是 4 字节整数，经过 0x80|x 变换...
# 试: 若明文是 0x00000001 等小整数，则密文应是 0x80|1=0x81 等
# 但实际是 a5 f2 a8 80 => 不像小整数
#
# ★★ 换思路: 这些 4 字节可能是 **UTF-16 的 2 个字符**
# a5 f2 a8 80 -> 若按 UTF-16LE: 0xf2a5 0x80a8
# 若 >>1: 0x7952 0x4054 = 'yR' 'T@' 
print("=== 按 UTF-16LE 解释类型标签 ===")
for t in ['a5f2a880','ea89938f','91b29cc0','aabdd3bb']:
    b=bytes.fromhex(t)
    w=struct.unpack('<HH',b)
    print("  %s -> UTF16: 0x%04X 0x%04X"%(t,w[0],w[1]))
    # >>1 后
    w2=tuple(x>>1 for x in w)
    print("       >>1: 0x%04X 0x%04X = %r"%(w2[0],w2[1],chr(w2[0])+chr(w2[1])))
print()
# ★★★ 决定性: 检查这 4 个标签是否对应 360 的扫描类型
# 前面已知: 云安全引擎=2000, QEX引擎=2065
# 试: 标签是否为引擎ID的编码
print("=== 标签的数值 ===")
for t in ['a5f2a880','ea89938f','91b29cc0','aabdd3bb']:
    b=bytes.fromhex(t)
    v=struct.unpack('<I',b)[0]
    print("  %s -> LE uint32 = 0x%08X = %d"%(t,v,v))
