import sys,struct
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\deepscan.dll'
d=open(p,'rb').read()
print("  魔数分析:")
print("    字节: 6C 72 79 79 = 'l','r','y','y'")
print("    DWORD(LE) = 0x%08X" % struct.unpack_from('<I',bytes([0x6C,0x72,0x79,0x79]),0)[0])
print()
print("  在 DLL 里搜索 'lryy' 出现的位置:")
idx=0; cnt=0
while True:
    i=d.find(b'lryy',idx)
    if i<0: break
    cnt+=1
    if cnt<=10: print("    文件偏移 0x%X" % i)
    idx=i+1
print("    共 %d 处" % cnt)
print()
print("  在 DLL 里搜索其他 4 字节魔数（可打印）:")
import re
for m in re.finditer(rb'[\x20-\x7e]{4}', d):
    s=m.group()
    if s in (b'lryy',b'yyrl',b'AVEI',b'QEX1',b'qex1'):
        print("    0x%X: %s" % (m.start(), s))
