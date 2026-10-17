import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
# ★★★ 关键测试: 4 个类型标签是否在所有文件中稳定？
# 加载 16/17 日的文件，看同样的标签是否出现
tags=['a5f2a880','ea89938f','91b29cc0','aabdd3bb']
for fn in ['Data_2026_10_15.dat','Data_2026_10_16.dat','Data_2026_10_17.dat','Data_2026_10_18.dat']:
    b=open(os.path.join(d,fn),'rb').read()
    print("=== %s (%d 字节) ==="%(fn,len(b)))
    for t in tags:
        tb=bytes.fromhex(t)
        n=b.count(tb)
        print("   %s 出现 %d 次"%(t,n))
    print()
