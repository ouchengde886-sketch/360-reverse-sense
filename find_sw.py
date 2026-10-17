import sys,os
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
keys=[b'scanark',b'infofastscan',b'frepscan',b'ScanInProgress',b'DsMain']
print("  搜索关键开关所在模块:")
for dp,dirs,files in os.walk(root):
    for f in files:
        if not f.lower().endswith(('.dll','.exe')): continue
        p=os.path.join(dp,f)
        try: d=open(p,'rb').read()
        except: continue
        hits=[]
        for k in keys:
            if k in d or k.lower() in d.lower():
                hits.append(k.decode())
        if hits:
            print("    %-70s %s"%(p.replace(root,''),','.join(hits)))
