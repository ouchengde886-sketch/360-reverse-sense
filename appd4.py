import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
targets=[r'\SoftMgr\NewKernel.dll',r'\SoftMgr\somkernl.dll',r'\sweeper\CleanSoftEng.dll',
         r'\sweeper\CleanSoft.dll',r'\sweeper\360OKCleanNew.dll',r'\ipc\yhregd.dll',
         r'\deepscan\cloudcom2.dll',r'\ipc\appd.dll']
for t in targets:
    p=root+t
    if not os.path.exists(p): continue
    d=open(p,'rb').read()
    pe=struct.unpack_from('<I',d,0x3c)[0]
    nsec=struct.unpack_from('<H',d,pe+6)[0]
    optsz=struct.unpack_from('<H',d,pe+20)[0]
    so=pe+24+optsz
    secs=[]
    for i in range(nsec):
        nm=d[so+i*40:so+i*40+8].rstrip(b'\x00').decode('latin1')
        vs,va,rs,ra=struct.unpack_from('<IIII',d,so+i*40+8)
        secs.append((nm,va,vs,ra,rs))
    def o2r(o):
        for nm,va,vs,ra,rs in secs:
            if ra<=o<ra+rs: return va+(o-ra)
        return None
    print("=== %s (%d 字节) ==="%(t,len(d)))
    for kw in ['MIndex.dat','Data_','CIndex_','ScanCache']:
        kb=kw.encode('utf-16-le')
        i=d.find(kb)
        if i<0: continue
        rva=o2r(i)
        pat=struct.pack('<I',rva)
        n=d.count(pat)
        print("    %-12s RVA=0x%X  被引用 %d 次"%(kw,rva,n))
