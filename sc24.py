import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
seg=a[offs[1]:offs[2]]
out=bytes(b>>1 for b in seg)
print("=== >>1 输出的字符频次 top15 ===")
from collections import Counter
c=Counter(out)
for k,v in c.most_common(15):
    print("   0x%02X %r  %d 次"%(k,chr(k),v))
print()
# 观察: 输出里 'U' 很常见。若明文里最常见是 'e' 或 ' '，则偏移 = 'U'-'e' = 0x55-0x65 = -0x10
# 试各种字符偏移
print("=== 尝试字符偏移（减去常量）===")
best=[]
for k in range(256):
    o=bytes((b-k)&0xFF for b in out)
    pr=sum(1 for x in o if 32<=x<127)
    # 也统计字母/空格比例
    letters=sum(1 for x in o if chr(x).isalpha() or x==0x20)
    best.append((letters,pr,k))
best.sort(reverse=True)
for letters,pr,k in best[:6]:
    o=bytes((b-k)&0xFF for b in out[:80])
    print("  -0x%02X 字母+空格=%d 可打印=%d  %r"%(k,letters,pr,o.decode('latin1')))
