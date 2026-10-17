import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
da=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
print("  Data_2026_10_15.dat 大小: %d"%len(da))
print("  MIndex 记录数: %d"%((len(mi)-56)//56))
print()
# +16 是累计偏移，+12 是长度 —— 验证是否与 Data 文件大小吻合
recs=[]
for i in range((len(mi)-56)//56):
    o=56+i*56
    v=struct.unpack_from('<14I',mi,o)
    recs.append(v)
print("=== 验证 +16 累计偏移 + +12 长度 是否覆盖 Data 文件 ===")
last=recs[-1]
print("  最后一条: +12=%d +16=%d  和=%d"%(last[3],last[4],last[3]+last[4]))
print("  Data 文件大小: %d"%len(da))
print("  ★ 吻合: %s"%(last[3]+last[4]==len(da) or last[4]==len(da)))
print()
# +16 是否单调递增
inc=sum(1 for i in range(1,len(recs)) if recs[i][4]>=recs[i-1][4])
print("  +16 单调递增的比例: %d/%d"%(inc,len(recs)-1))
print()
print("=== 用 +16/+12 从 Data 中切片，看内容 ===")
for i in [0,1,2,3,5,11]:
    r=recs[i]
    off=r[4]; ln=r[3]
    if off+ln<=len(da):
        seg=da[off:off+ln]
        # 尝试多种解码
        print("  记录 #%d off=%d len=%d"%(i,off,ln))
        print("     原始: %s"%seg[:40].hex(' '))
        for enc in ['gbk','utf-16-le','latin1']:
            try:
                s=seg.decode(enc,errors='replace')
                pr=sum(1 for c in s if c.isprintable() or c in '\x00')
                if pr/len(s)>0.85:
                    print("     [%s] %r"%(enc,s[:60]))
            except: pass
