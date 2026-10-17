import sys,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\ScChecker.dll'
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
def r2o(r):
    for nm,va,vs,ra,rs in secs:
        if va<=r<va+vs: return ra+(r-va)
    return None
def o2r(o):
    for nm,va,vs,ra,rs in secs:
        if ra<=o<ra+rs: return va+(o-ra)
    return None
print("  ScChecker.dll 中的可疑字符串（威胁名/判定相关）:")
keys=[b'Trojan',b'Virus',b'virus',b'Malware',b'riskware',b'Heur',b'Gen',
      b'Scan',b'scan',b'Check',b'Result',b'result',b'Verdict',b'verdict',
      b'Clean',b'clean',b'Threat',b'threat',b'Detect',b'detect']
found={}
for m in re.finditer(rb'[\x20-\x7e]{5,80}',d):
    s=m.group()
    for k in keys:
        if k in s:
            r=o2r(m.start())
            if r: found.setdefault(s,[]).append(r)
            break
for s,rv in sorted(found.items(), key=lambda x:x[1][0])[:60]:
    print("    RVA=0x%-8X %s"%(rv[0],s.decode('latin1')))
print()
print("  总数:",len(found))
