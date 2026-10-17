import sys,os
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
a=open(os.path.join(d,'Data_2026_10_17.dat'),'rb').read()
b=open(os.path.join(d,'Data_2026_10_18.dat'),'rb').read()
print("  17日头:",a[:48].hex(' '))
print("  18日头:",b[:48].hex(' '))
# 两文件前 32 字节相同 -> 可能是固定头部或固定密钥流
same=sum(1 for i in range(32) if a[i]==b[i])
print("  前32字节相同数:",same)
# 尝试单字节 XOR 破解：找常见明文开头（如路径 'D:\\' = 44 3A 5C 或 UTF16 44 00 3A 00）
print()
print("  尝试单字节 XOR（找 'D:\\' 或 'C:\\'）:")
for k in range(256):
    dec=bytes(c^k for c in a[:64])
    if dec[:3] in (b'D:\\',b'C:\\') or dec[1:4] in (b':\\',):
        print("    key=0x%02X -> %r"%(k,dec[:40]))
# 尝试找 XOR 后出现的可打印路径
print()
print("  尝试所有单字节 XOR，统计可打印率最高的 key:")
best=[]
for k in range(256):
    dec=bytes(c^k for c in a[:2000])
    pr=sum(1 for c in dec if 32<=c<127 or c in (0,))
    best.append((pr,k))
best.sort(reverse=True)
for pr,k in best[:5]:
    dec=bytes(c^k for c in a[:60])
    print("    key=0x%02X 可打印=%d  %r"%(k,pr,dec))
