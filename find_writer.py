import sys,os,struct,re
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
# ★ 关键: 找哪个模块**同时**引用 MIndex.dat 和 Data_ 和 CIndex_
# 前面 appd.dll 三个都有但零代码引用。检查字符串是否相邻（同一格式串）
mods=[r'\ipc\appd.dll',r'\SoftMgr\NewKernel.dll',r'\SoftMgr\somkernl.dll',r'\sweeper\CleanSoftEng.dll']
for m in mods:
    p=root+m
    if not os.path.exists(p): continue
    d=open(p,'rb').read()
    print("=== %s ==="%m)
    for kw in ['MIndex.dat','Data_','CIndex_','.dat']:
        w=kw.encode('utf-16-le')
        st=0
        while True:
            i=d.find(w,st)
            if i<0: break
            # 提取完整宽字符串
            a=i
            while a>=2 and 32<=d[a-2]<127 and d[a-1]==0: a-=2
            b=i+len(w)
            while b+1<len(d) and 32<=d[b]<127 and d[b+1]==0: b+=2
            s=d[a:b].decode('utf-16-le',errors='ignore')
            print("   %-12s @0x%X -> %r"%(kw,i,s))
            st=i+2
            break
    print()
