import sys,struct,os,glob
sys.stdout.reconfigure(encoding='utf-8')
def imports_of(path):
    d=open(path,'rb').read()
    try:
        pe=struct.unpack_from('<I',d,0x3c)[0]
        if d[pe:pe+4]!=b'PE\0\0': return None
        nsec=struct.unpack_from('<H',d,pe+6)[0]
        optsz=struct.unpack_from('<H',d,pe+20)[0]
        magic=struct.unpack_from('<H',d,pe+24)[0]
        so=pe+24+optsz
        secs=[]
        for i in range(nsec):
            vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
            secs.append((va,vs,ra,rs))
        def r2o(r):
            for va,vs,ra,rs in secs:
                if va<=r<va+vs: return ra+(r-va)
            return None
        ddoff = pe+24+(96 if magic==0x10b else 112)
        imp_rva,imp_sz=struct.unpack_from('<II',d,ddoff+8)
        if imp_rva==0: return []
        o=r2o(imp_rva)
        if o is None: return []
        res=[]
        i=0
        while True:
            ent=d[o+i*20:o+i*20+20]
            if len(ent)<20: break
            oft,ts,fc,nm,ft=struct.unpack('<IIIII',ent)
            if nm==0: break
            no=r2o(nm)
            if no is None: break
            s=d[no:d.find(b'\0',no)].decode('ascii','ignore')
            res.append(s)
            i+=1
            if i>60: break
        return res
    except Exception as e:
        return None
base=r'C:\Program Files (x86)\360\360Safe'
print("  搜索导入 deepscan.dll 的模块:")
for root,dirs,files in os.walk(base):
    for f in files:
        if not f.lower().endswith(('.dll','.exe')): continue
        p=os.path.join(root,f)
        try:
            imps=imports_of(p)
            if imps and any('deepscan' in x.lower() for x in imps):
                print("    %s" % p)
        except Exception: pass
