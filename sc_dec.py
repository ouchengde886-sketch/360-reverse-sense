import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
# Data_2026_10_17.dat 4.2MB —— 找明文路径
p=os.path.join(d,'Data_2026_10_17.dat')
b=open(p,'rb').read()
print("  Data_2026_10_17.dat 大小:",len(b))
print("  头部 64 字节:",b[:64].hex(' '))
# 找 UTF-16LE 的 "D:\" 或 "C:\"
for enc,label in [('utf-16-le','UTF16LE'),('gbk','GBK'),('utf-8','UTF8')]:
    try:
        s=b.decode(enc,errors='ignore')
    except: continue
    idx=s.find('troyr2')
    print("  [%s] 'troyr2' 位置: %s"%(label,idx))
    if idx>0:
        print("      上下文:",repr(s[max(0,idx-120):idx+200]))
        break
