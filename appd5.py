import sys,os,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\ipc\appd.dll'
d=open(p,'rb').read()
# 0xFBFA4 附近是字符串池，读出所有相邻宽字符串
o=0xFBF00
seg=d[o:o+0x600]
print("=== appd.dll 0xFBF00 附近的宽字符串池 ===")
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){2,60}',seg):
    s=m.group().decode('utf-16-le',errors='ignore')
    print("  @0x%X %r"%(o+m.start(),s))
