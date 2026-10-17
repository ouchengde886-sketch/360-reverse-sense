import sys,os
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
keys=['自定义扫描'.encode('utf-16-le'),'自定义扫描'.encode('gbk'),'扫描类型'.encode('utf-16-le')]
for dp,dirs,files in os.walk(root):
    for f in files:
        if not f.lower().endswith(('.dll','.exe')): continue
        p=os.path.join(dp,f)
        try: d=open(p,'rb').read()
        except: continue
        hit=[]
        for k in keys:
            if k in d: hit.append(k.decode('utf-16-le',errors='ignore') or k.decode('gbk',errors='ignore'))
        if hit:
            print("  %-64s %s"%(p.replace(root,''),','.join(set(hit))))
