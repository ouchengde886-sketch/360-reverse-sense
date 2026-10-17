import sys,struct,os,re
sys.stdout.reconfigure(encoding='utf-8')
def exports(p):
    try: d=open(p,'rb').read()
    except: return []
    try:
        pe=struct.unpack_from('<I',d,0x3c)[0]
        if d[pe:pe+4]!=b'PE\x00\x00': return []
        nsec=struct.unpack_from('<H',d,pe+6)[0]
        optsz=struct.unpack_from('<H',d,pe+20)[0]
        magic=struct.unpack_from('<H',d,pe+24)[0]
        so=pe+24+optsz
        secs=[]
        for i in range(nsec):
            nm=d[so+i*40:so+i*40+8].rstrip(b'\x00').decode('latin1')
            vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
            secs.append((nm,va,vs,ra,rs))
        def r2o(r):
            for nm,va,vs,ra,rs in secs:
                if va<=r<va+vs: return ra+(r-va)
            return None
        ddoff=pe+24+(96 if magic==0x10b else 112)
        edrva,edsz=struct.unpack_from('<II',d,ddoff)
        if not edrva: return []
        eo=r2o(edrva)
        nfun,nnam,afun,anam,aord=struct.unpack_from('<IIIII',d,eo+20)
        if not nnam: return []
        no=r2o(anam); fo=r2o(afun); oo=r2o(aord)
        out=[]
        for i in range(nnam):
            nr=struct.unpack_from('<I',d,no+i*4)[0]
            o=r2o(nr); en=d.index(b'\x00',o)
            nm=d[o:en].decode('latin1')
            ordv=struct.unpack_from('<H',d,oo+i*2)[0]
            fr=struct.unpack_from('<I',d,fo+ordv*4)[0]
            out.append((nm,fr))
        return out
    except: return []
root=r'C:\Program Files (x86)\360\360Safe'
KEY=re.compile(r'scan|check|verdict|detect|virus|query',re.I)
print("  含 scan/check/detect 关键字的导出:")
for dp,dirs,files in os.walk(root):
    for f in files:
        if not f.lower().endswith('.dll'): continue
        p=os.path.join(dp,f)
        ex=exports(p)
        hits=[(n,r) for n,r in ex if KEY.search(n)]
        if hits:
            print("  --- %s (%d 个导出)"%(f,len(ex)))
            for n,r in hits[:14]:
                print("      %-44s RVA=0x%X"%(n,r))
