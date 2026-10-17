import sys,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\deepscan\DSMainUI.dll'
d=open(p,'rb').read()
# 找所有含 scan/Scan 的宽字符串及其 RVA
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
print("  === 含 scan/Scan/SCAN 的宽字符串（带 RVA）===")
seen=set()
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,50}',d):
    s=m.group().decode('utf-16-le',errors='ignore')
    if 'scan' in s.lower() and s not in seen:
        seen.add(s)
        r=o2r(m.start())
        print("    RVA=0x%06X %r"%(r if r else 0,s))
print()
print("  === 含中文'扫描'的宽字符串（带 RVA）===")
seen=set()
for m in re.finditer(rb'(?:[\x20-\x7e\u4e00-\u9fff]\x00){2,60}',d):
    try: s=m.group().decode('utf-16-le')
    except: continue
    if '扫描' in s and s not in seen and len(s)<60:
        seen.add(s)
        r=o2r(m.start())
        print("    RVA=0x%06X %r"%(r if r else 0,s))
