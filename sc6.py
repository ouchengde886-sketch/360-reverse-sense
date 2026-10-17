import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
da=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
print("=== 单字节 XOR 全扫描：找能产生高可打印率的 key ===")
best=[]
for k in range(256):
    seg=da[:4000]
    dec=bytes(c^k for c in seg)
    # 统计可打印 ASCII 或 0
    pr=sum(1 for c in dec if 32<=c<127 or c==0)
    best.append((pr,k))
best.sort(reverse=True)
for pr,k in best[:6]:
    dec=bytes(c^k for c in da[:72])
    print("  key=0x%02X 可打印=%d/4000  %r"%(k,pr,dec))
print()
print("=== 假设是 UTF-16LE 文本 + XOR：试着让奇数位变 0 ===")
# 若明文是 UTF-16LE 英文/路径，奇数位多为 0x00。找 key 使 da[1]^k==0
print("  da[1]=0x%02X -> 若明文奇位为0则 key=0x%02X"%(da[1],da[1]))
print("  da[3]=0x%02X -> key=0x%02X"%(da[3],da[3]))
print("  da[5]=0x%02X -> key=0x%02X"%(da[5],da[5]))
print()
print("=== 观察 Data 头部字节对 (偶,奇) ===")
for i in range(0,40,2):
    print("    [%02d] %02X %02X"%(i,da[i],da[i+1]))
