import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
r=a[offs[1]:offs[2]]
# 密文几乎全在 0x80-0xFF => 明文 ASCII(0x00-0x7F) 被某种方式置高了最高位
# 测试: 明文 = (密文 << 1) & 0xFF  或  (密文 >> 1)
print("=== 位运算测试（前 64 字节）===")
for name,fn in [
  ('^0x80', lambda b: b^0x80),
  ('<<1', lambda b: (b<<1)&0xFF),
  ('>>1', lambda b: b>>1),
  ('<<1|1', lambda b: ((b<<1)|1)&0xFF),
  ('~b', lambda b: (~b)&0xFF),
  ('b-0x80', lambda b: (b-0x80)&0xFF),
]:
    out=bytes(fn(b) for b in r[:64])
    pr=sum(1 for c in out if 32<=c<127)
    print("  %-8s 可打印=%2d/64  %r"%(name,pr,out.decode('latin1')))
print()
# 关键观察: 密文高3位分布 0x80:220 0xa0:151 0xc0:133 0xe0:62
# 若明文均匀分布 0x00-0x7F，则密文=明文|0x80 应集中在 0x80-0xFF 且均匀
# 但这里 0x80 段最多，递减 => 像"明文 + 偏移"且偏移分布不均
# 测试: 明文 = 密文 - 0xA0 ?
print("=== 测试 b - 常数 ===")
best=[]
for k in range(256):
    out=bytes((b-k)&0xFF for b in r[:200])
    pr=sum(1 for c in out if 32<=c<127)
    best.append((pr,k))
best.sort(reverse=True)
for pr,k in best[:5]:
    out=bytes((b-k)&0xFF for b in r[:64])
    print("  -0x%02X 可打印=%3d/200  %r"%(k,pr,out.decode('latin1')))
