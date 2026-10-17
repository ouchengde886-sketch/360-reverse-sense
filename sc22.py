import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
for i in [0,1,8]:
    s,e=offs[i],offs[i+1]
    out=bytes(b>>1 for b in a[s:e])
    print("=== 记录 #%d >>1 前 200 字符 ==="%i)
    print("  %r"%out[:200])
    print()
