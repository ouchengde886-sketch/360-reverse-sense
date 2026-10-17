import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
r=a[offs[1]:offs[2]]
# >>1 后是 64 个连续字符 '@'(0x40) 到 '~'(0x7E) 加 0x7F
chars=sorted(set(b>>1 for b in r))
print("=== >>1 后的字符码点 ===")
print("  %s"%[hex(c) for c in chars])
print("  连续: %s  范围 0x%02X-0x%02X"%(chars==list(range(chars[0],chars[0]+len(chars))),chars[0],chars[-1]))
print()
# 密文原始字节范围
print("=== 原始密文字节范围 ===")
print("  最小 0x%02X 最大 0x%02X"%(min(r),max(r)))
allb=sorted(set(r))
print("  不同值数: %d"%len(allb))
print("  是否连续: %s"%([hex(x) for x in allb[:10]]))
print()
# 若密文 = (明文6bit << 1) | 1，则密文都是奇数，范围 0x81-0xFF
odd=all(b&1 for b in r)
print("  密文是否全为奇数: %s"%odd)
print("  密文低位置1的比例: %.1f%%"%(100*sum(b&1 for b in r)/len(r)))
print()
# 所以: 6bit值 = 密文 >> 1，范围 0x40-0x7F -> 减去 0x40 得 0-63
vals=[(b>>1)-0x40 for b in r]
print("=== 6bit 值（减 0x40）前 60 个 ===")
print("  %s"%vals[:60])
print("  范围: %d-%d"%(min(vals),max(vals)))
print()
# 这像 base64 索引！标准 base64 字母表
B64='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
s=''.join(B64[v] for v in vals)
print("=== 按标准 base64 字母表映射前 80 字符 ===")
print("  %s"%s[:80])
import base64
try:
    dec=base64.b64decode(s[:400]+'='*4)
    print("  base64 解码成功 %d 字节: %r"%(len(dec),dec[:80]))
except Exception as e:
    print("  失败: %s"%e)
