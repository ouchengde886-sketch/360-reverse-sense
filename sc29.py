import sys,os,struct,zlib,lzma,bz2
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
seg=a[offs[1]:offs[2]]
print("=== 测试已知压缩算法（记录 #1, %d 字节）==="%len(seg))
cands={
 'raw':seg,
 '>>1':bytes(b>>1 for b in seg),
 '&0x7F':bytes(b&0x7F for b in seg),
 '-0x80':bytes((b-0x80)&0xFF for b in seg),
}
for cname,data in cands.items():
    print("  --- 输入 %s (%d 字节) ---"%(cname,len(data)))
    for alg,fn in [('zlib',lambda x: zlib.decompress(x)),
                   ('deflate-raw',lambda x: zlib.decompress(x,-15)),
                   ('gzip',lambda x: zlib.decompress(x,31)),
                   ('lzma',lambda x: lzma.decompress(x)),
                   ('bz2',lambda x: bz2.decompress(x))]:
        try:
            out=fn(data)
            pr=sum(1 for c in out if 32<=c<127)
            print("     [%s] OK %d 字节 可打印 %.0f%% %r"%(alg,len(out),100*pr/max(1,len(out)),out[:50]))
        except Exception: pass
print()
# LZ4 手工实现（块格式）
print("=== 手工 LZ4 块解压测试 ===")
def lz4_block(src):
    out=bytearray(); i=0
    while i<len(src):
        tok=src[i]; i+=1
        lit=tok>>4
        if lit==15:
            while True:
                b=src[i]; i+=1; lit+=b
                if b!=255: break
        out+=src[i:i+lit]; i+=lit
        if i>=len(src): break
        off=src[i]|(src[i+1]<<8); i+=2
        ml=tok&0xF
        if ml==15:
            while True:
                b=src[i]; i+=1; ml+=b
                if b!=255: break
        ml+=4
        st=len(out)-off
        if st<0: raise ValueError('bad offset')
        for k in range(ml): out.append(out[st+k])
    return bytes(out)
for cname,data in cands.items():
    try:
        out=lz4_block(data)
        pr=sum(1 for c in out if 32<=c<127)
        print("  [%s] LZ4 OK %d 字节 可打印 %.0f%% %r"%(cname,len(out),100*pr/max(1,len(out)),out[:60]))
    except Exception as e:
        print("  [%s] LZ4 失败: %s"%(cname,str(e)[:40]))
