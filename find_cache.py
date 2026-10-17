import sys,os
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
kws=['ScanCache','Data_%s','CIndex_','MIndex']
print("=== 搜索引用 ScanCache 的模块 ===")
for dp,dirs,files in os.walk(root):
    for f in files:
        if not f.lower().endswith(('.dll','.exe')): continue
        p=os.path.join(dp,f)
        try: d=open(p,'rb').read()
        except: continue
        hit=[]
        for kw in kws:
            if kw.encode('utf-16-le') in d: hit.append(kw+'(u16)')
            elif kw.encode('ascii') in d: hit.append(kw+'(a)')
        if hit:
            print("  %-56s %s"%(p.replace(root,''),','.join(hit)))
