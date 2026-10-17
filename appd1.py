import sys,os,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\ipc\appd.dll'
d=open(p,'rb').read()
print("  appd.dll 大小: %d"%len(d))
# 找 ScanCache/CIndex_/MIndex 字符串位置及其上下文
for kw in ['ScanCache','CIndex_','MIndex','Data_']:
    for enc,lab in [('utf-16-le','u16'),('ascii','a')]:
        try: kb=kw.encode(enc)
        except: continue
        st=0
        while True:
            i=d.find(kb,st)
            if i<0: break
            # 提取周围宽字符串
            a=i
            while a>=2 and 32<=d[a-2]<127 and d[a-1]==0: a-=2
            b=i+len(kb)
            while b+1<len(d) and 32<=d[b]<127 and d[b+1]==0: b+=2
            try: s=d[a:b].decode('utf-16-le')
            except: s='?'
            print("  [%s] %s @0x%X -> %r"%(lab,kw,i,s))
            st=i+2
            break
