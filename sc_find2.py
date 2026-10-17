import sys,os,re
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
print("  搜索引用 'sc.con' 的模块:")
hits=[]
for dirpath,dirs,files in os.walk(root):
    for f in files:
        if not f.lower().endswith(('.dll','.exe')): continue
        p=os.path.join(dirpath,f)
        try: d=open(p,'rb').read()
        except: continue
        if b'sc.con' in d:
            hits.append(p); print("    ",p)
if not hits: print("    (无)")
print()
print("  搜索引用 'sc.con' 的宽字符版本:")
hits2=[]
for dirpath,dirs,files in os.walk(root):
    for f in files:
        if not f.lower().endswith(('.dll','.exe')): continue
        p=os.path.join(dirpath,f)
        try: d=open(p,'rb').read()
        except: continue
        if 'sc.con'.encode('utf-16le') in d:
            hits2.append(p); print("    ",p)
if not hits2: print("    (无)")
print()
print("  ScChecker.dll 里所有含 'con' 的字符串:")
d=open(os.path.join(root,'deepscan','ScChecker.dll'),'rb').read()
seen=set()
for m in re.finditer(rb'[\x20-\x7e]{3,60}',d):
    s=m.group()
    if b'con' in s.lower() and s not in seen:
        seen.add(s); print("    "+s.decode('latin1'))
