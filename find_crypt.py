import sys,os,struct,re
sys.stdout.reconfigure(encoding='utf-8')
p=r'C:\Program Files (x86)\360\360Safe\ipc\appd.dll'
d=open(p,'rb').read()
# 提取所有含 Crypt 的宽字符串
print("=== appd.dll 中含 Crypt 的字符串 ===")
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,80}',d):
    s=m.group().decode('utf-16-le',errors='ignore')
    if 'rypt' in s or 'ncrypt' in s or 'ecrypt' in s:
        print("  @0x%X %r"%(m.start(),s))
print()
# 提取所有含 zip/Zip 的
print("=== 含 zip/Zip 的字符串 ===")
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,80}',d):
    s=m.group().decode('utf-16-le',errors='ignore')
    if 'zip' in s.lower():
        print("  @0x%X %r"%(m.start(),s))
