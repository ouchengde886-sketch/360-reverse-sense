import sys,os
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
kws=['自定义扫描','快速扫描','全盘扫描','扫描类型','开始扫描']
print("  搜索扫描类型字符串所在模块:")
for dp,dirs,files in os.walk(root):
    for f in files:
        if not f.lower().endswith(('.dll','.exe')): continue
        p=os.path.join(dp,f)
        try: d=open(p,'rb').read()
        except: continue
        hit=[]
        for kw in kws:
            if kw.encode('utf-16-le') in d or kw.encode('gbk') in d:
                hit.append(kw)
        if hit:
            print("    %-58s %s"%(p.replace(root,''),','.join(hit)))
