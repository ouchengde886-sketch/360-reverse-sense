import sys,os,struct,datetime
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
# +24 是 float，值递增 => 疑似时间戳
# 试: FILETIME 高32位? Unix 时间? 
print("=== +24 float 值解码尝试 ===")
for i in [11,12,13,14,19,20,21,22,23,24]:
    mo=56+i*56
    f=struct.unpack_from('<f',mi,mo+24)[0]
    v=struct.unpack_from('<I',mi,mo+24)[0]
    print("  #%-3d float=%.1f  raw=0x%08X"%(i,f,v))
    # 试各种解释
    try:
        dt=datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=v/10)
        print("       FILETIME高32位: %s"%dt)
    except: pass
    try:
        dt2=datetime.datetime(1970,1,1)+datetime.timedelta(seconds=v)
        print("       Unix秒: %s"%dt2)
    except: pass
    # 试 double
    dd=struct.unpack_from('<d',mi,mo+24)[0] if mo+32<=len(mi) else None
    if dd is not None:
        print("       as double: %.6f"%dd)
