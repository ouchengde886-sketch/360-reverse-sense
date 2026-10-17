import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
for m,rvas in [(r'\SoftMgr\NewKernel.dll',[(0x1A77AE,'MIndex'),(0x1A7800,'Data_')]),
               (r'\SoftMgr\somkernl.dll',[(0x296516,'MIndex'),(0x296560,'Data_')])]:
    p=root+m
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
    print("=== %s ==="%m)
    print("  节: %s"%[x[0] for x in secs])
    for off,name in rvas:
        rva=o2r(off)
        pat=struct.pack('<I',rva)
        n=d.count(pat)
        print("  %s @0x%X RVA=0x%X 被引用 %d 次"%(name,off,rva,n))
        if n:
            st=0; c=0
            while c<4:
                j=d.find(pat,st)
                if j<0: break
                print("     文件偏移 0x%X (RVA 0x%X)"%(j,o2r(j) or 0))
                st=j+1; c+=1
    print()
