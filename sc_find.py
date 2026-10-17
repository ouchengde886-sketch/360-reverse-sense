import sys,struct,re
sys.stdout.reconfigure(encoding='utf-8')
import os
root=r'C:\Program Files (x86)\360\360Safe'
# 搜索所有 DLL/EXE 里引用 "sc.con" 的
targets=[b'sc.con',b'.con',b'D063']
for dirpath,dirs,files in os.walk(root):
    for f in files:
        if not f.lower().endswith(('.dll','.exe')): continue
        p=os.path.join(dirpath,f)
        try: d=open(p,'rb').read()
        except: continue
        if b'sc.con' in d:
            print("  引用 sc.con: ",p)
        if b'D063' in d:
            print("  引用 D063:   ",p)
