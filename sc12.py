import sys,os,struct,zlib
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
# 记录 #0 = [187,754) 567 字节，跨天完全相同 -> 固定内容
# 测试各记录是否 zlib/lz4 压缩
print("=== 测试各记录是否为压缩数据 ===")
mi=open(os.path.join(d,'MIndex.dat'),'rb').read()
offs=[0]+[struct.unpack_from('<14I',mi,56+i*56)[4] for i in range(60)]
for i in range(6):
    s,e=offs[i],offs[i+1]
    seg=a[s:e]
    print("  记录 #%d [%d,%d) %d 字节"%(i,s,e,len(seg)))
    print("     头: %s"%seg[:16].hex(' '))
    # zlib
    for name,fn in [('zlib',zlib.decompress),('raw',lambda x: zlib.decompress(x,-15))]:
        try:
            out=fn(seg); print("     [%s] 解压成功 %d 字节: %r"%(name,len(out),out[:60])); break
        except Exception as ex: pass
    else:
        print("     非 zlib/raw")
print()
# 全文件尝试 zlib
print("=== 全文件 zlib 尝试 ===")
for off in [0,16,24,56,187]:
    try:
        out=zlib.decompress(a[off:])
        print("  @%d 解压成功 %d 字节"%(off,len(out))); break
    except Exception as ex:
        print("  @%d 失败: %s"%(off,str(ex)[:50]))
