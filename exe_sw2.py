import sys,os,re
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
# 找 360Safe.exe 里所有 /FUNNAME= 和模块相关宽字符串
for f in ['360Safe.exe']:
    d=open(os.path.join(root,f),'rb').read()
    print("=== %s 中含 FUNNAME/PAGENAME/MODULE 的字符串 ==="%f)
    seen=set()
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,60}',d):
        s=m.group().decode('utf-16-le',errors='ignore')
        if any(k in s for k in ('FUNNAME','PAGENAME','MODULE','/S ','scan','Scan','SCAN')):
            if s not in seen:
                seen.add(s); print("  "+repr(s))
    print()
# 找所有含"木马查杀"/"扫描"的宽字符串
print("=== 含中文'扫描'/'查杀'的宽字符串（360Safe.exe）===")
d=open(os.path.join(root,'360Safe.exe'),'rb').read()
seen=set()
for kw in ['扫描','查杀','自定义']:
    kb=kw.encode('utf-16-le')
    st=0
    while True:
        i=d.find(kb,st)
        if i<0: break
        # 向前后扩展
        a=i
        while a>=2 and 32<=d[a-2]<127 and d[a-1]==0: a-=2
        b=i+len(kb)
        while b+1<len(d) and 32<=d[b]<127 and d[b+1]==0: b+=2
        s=d[a:b].decode('utf-16-le',errors='ignore')
        if s not in seen and len(s)<70:
            seen.add(s); print("  "+repr(s))
        st=i+2
