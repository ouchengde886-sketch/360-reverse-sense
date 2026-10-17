import sys,os,struct,re
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
# ★ 策略调整: 在 ScanCache 相关模块里找**字符串常量**，看有无算法名/表名
mods=[r'\ipc\appd.dll',r'\SoftMgr\NewKernel.dll',r'\SoftMgr\somkernl.dll',
      r'\sweeper\CleanSoftEng.dll',r'\sweeper\CleanSoft.dll']
kws=[b'compress',b'Compress',b'zip',b'Zip',b'huff',b'Huff',b'lz',b'LZ',
     b'encode',b'Encode',b'decode',b'Decode',b'crypt',b'Crypt',b'xor',b'Xor']
for m in mods:
    p=root+m
    if not os.path.exists(p): continue
    d=open(p,'rb').read()
    print("=== %s ==="%m)
    for kw in kws:
        # 宽字符串
        w=kw.decode().encode('utf-16-le')
        n=d.count(w)
        if n: print("   %-10s (u16) %d 次"%(kw.decode(),n))
    print()
