import sys,os
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\ProgramData\360Safe\ScanCache\Data_2026_10_18.dat'
b=open(p,'rb').read()
print("  大小:",len(b))
print("  头部 96 字节:",b[:96].hex(' '))
print()
# 搜索可读字符串
import re
for enc,label in [('utf-16-le','UTF16LE'),('gbk','GBK'),('latin1','LATIN1')]:
    s=b.decode(enc,errors='ignore')
    for kw in ['troyr2','.ps1','.zip','木马','Trojan']:
        i=s.find(kw)
        if i>=0:
            print("  [%s] 找到 '%s' @ %d: %r"%(label,kw,i,s[max(0,i-60):i+80]))
            break
print()
# 找连续可打印 ASCII 串
print("  ASCII 串(>=6):")
found=0
for m in re.finditer(rb'[\x20-\x7e]{6,}',b):
    print("    @0x%06X %r"%(m.start(),m.group()[:90]))
    found+=1
    if found>=25: break
print("  ...共找到",len(re.findall(rb'[\x20-\x7e]{6,}',b)),"个")
