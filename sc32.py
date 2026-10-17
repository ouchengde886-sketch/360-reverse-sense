import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
files=['Data_2026_10_15.dat','Data_2026_10_16.dat','Data_2026_10_17.dat']
data={f:open(os.path.join(d,f),'rb').read() for f in files}
# 记录 #0 在 15/16 日相同 —— 逐字节比较多个文件，找常量/变量位置
print("=== 记录 #0 [%d,%d) 跨文件逐字节比较 ==="%(offs[0],offs[1]))
s,e=offs[0],offs[1]
segs={f:data[f][s:e] for f in files if e<=len(data[f])}
print("  可用文件: %s"%{f:len(v) for f,v in segs.items()})
if len(segs)>=2:
    ks=list(segs)
    base=segs[ks[0]]
    print("  记录 #0 长度: %d"%len(base))
    # 逐字节：在所有文件中是否相同
    const=[]
    var=[]
    for i in range(len(base)):
        vals=[segs[k][i] for k in ks]
        if len(set(vals))==1: const.append(i)
        else: var.append(i)
    print("  常量字节位置数: %d / %d"%(len(const),len(base)))
    print("  变量字节位置数: %d"%len(var))
    print("  变量位置: %s"%var[:40])
    print()
    print("=== 常量段（连续）===")
    runs=[]
    if const:
        st=const[0]; pv=const[0]
        for x in const[1:]:
            if x==pv+1: pv=x
            else: runs.append((st,pv)); st=x; pv=x
        runs.append((st,pv))
    for a1,b1 in runs[:15]:
        print("    [%3d,%3d] len=%3d  %s"%(a1,b1,b1-a1+1,base[a1:b1+1].hex(' ')))
