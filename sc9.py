import sys,os
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
# 比较 15/16/17 三天的 Data 文件：头部 48 字节完全相同
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
b=open(os.path.join(d,'Data_2026_10_16.dat'),'rb').read()
c=open(os.path.join(d,'Data_2026_10_17.dat'),'rb').read()
e=open(os.path.join(d,'Data_2026_10_18.dat'),'rb').read()
print("  大小: 15=%d 16=%d 17=%d 18=%d"%(len(a),len(b),len(c),len(e)))
print()
# 找公共前缀
def lcp(x,y):
    n=min(len(x),len(y)); i=0
    while i<n and x[i]==y[i]: i+=1
    return i
print("  15 vs 16 公共前缀: %d"%lcp(a,b))
print("  15 vs 17 公共前缀: %d"%lcp(a,c))
print("  15 vs 18 公共前缀: %d"%lcp(a,e))
print("  16 vs 17 公共前缀: %d"%lcp(b,c))
print()
# 15/16/17 前缀相同 -> 说明是固定头部。找头部长度
# 逐字节比较 15 和 16，找第一个不同处
i=0
while i<min(len(a),len(b)) and a[i]==b[i]: i+=1
print("  15 与 16 第一个不同字节位置: %d (0x%X)"%(i,i))
print("    15: %s"%a[max(0,i-16):i+32].hex(' '))
print("    16: %s"%b[max(0,i-16):i+32].hex(' '))
print()
# 18 与 15 第一个不同
i=0
while i<min(len(a),len(e)) and a[i]==e[i]: i+=1
print("  15 与 18 第一个不同字节位置: %d (0x%X)"%(i,i))
print("    15: %s"%a[max(0,i-16):i+32].hex(' '))
print("    18: %s"%e[max(0,i-16):i+32].hex(' '))
