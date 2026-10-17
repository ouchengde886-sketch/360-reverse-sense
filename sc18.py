import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
r=a[offs[1]:offs[2]]
out=bytes(b>>1 for b in r[:80])
print("=== >>1 结果 ===")
print("  %r"%out.decode('latin1'))
print()
# 观察: 'rf\x0b|uDIGoWIR\x7fVBNiRBIpQMFmTbRq_IEbH[NmRLHb\\BLaQBR{^C^k\\KRrQKJoQHR'
# 像 base64/hex 的变体？'DIGoWIR' 'VBNiRBIpQMFmTbRq'
# 试试把它当 base64 解码
import base64
s=bytes(b>>1 for b in r)
# 只取可打印部分
print("=== 尝试 base64 解码 ===")
try:
    dec=base64.b64decode(s[:400]+b'=='*2)
    print("  成功 %d 字节: %r"%(len(dec),dec[:100]))
except Exception as e:
    print("  失败: %s"%e)
print()
# 看 >>1 后的字符集
chars=set(chr(b>>1) for b in r)
print("=== >>1 后出现的字符集 ===")
print("  %s"%''.join(sorted(chars)))
print("  字符数: %d"%len(chars))
print()
# 观察是否像 hex（0-9a-f）
hexc=set('0123456789abcdefABCDEF')
c=set(chr(b>>1) for b in r)
print("  是否全在 hex 字符集: %s"%(c<=hexc))
print("  非 hex 字符: %s"%''.join(sorted(c-hexc)))
