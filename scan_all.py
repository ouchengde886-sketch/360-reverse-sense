import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
# ★ 全盘扫描: 找含 'Data_%04d' 或 'ScanCache' 的所有文件（不限 dll/exe）
print("=== 全盘搜索 'Data_%04d' 和 'ScanCache' ===")
for dp,dirs,files in os.walk(root):
    for f in files:
        p=os.path.join(dp,f)
        try:
            if os.path.getsize(p)>60*1024*1024: continue
            d=open(p,'rb').read()
        except: continue
        hits=[]
        for kw in ['Data_%04d_%02d_%02d.dat','ScanCache','MIndex.dat']:
            if kw.encode('utf-16-le') in d: hits.append(kw)
        if hits:
            print("  %-58s %s"%(p.replace(root,''),hits))
