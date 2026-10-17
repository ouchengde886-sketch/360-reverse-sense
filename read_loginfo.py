import os, sys, glob, re
sys.stdout.reconfigure(encoding='utf-8')
d=os.path.join(os.environ['APPDATA'],'360Safe','LogInfo')
print("=== ★★★ 360 LogInfo 日志内容（弹窗/通知记录）===")
print()
fs=sorted(glob.glob(os.path.join(d,'*.log2')),key=os.path.getmtime,reverse=True)[:6]
for f in fs:
    import time
    mt=time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(os.path.getmtime(f)))
    sz=os.path.getsize(f)
    print("--- %s  (%d 字节, %s) ---"%(os.path.basename(f),sz,mt))
    raw=open(f,'rb').read()
    # 尝试多种编码
    for enc in ['utf-16-le','utf-8','gbk']:
        try:
            t=raw.decode(enc,errors='replace')
            # 统计可打印比例
            printable=sum(1 for c in t if c.isprintable() or c in '\r\n\t')
            ratio=printable/max(1,len(t))
            print("    [%s] 可打印率 %.1f%%"%(enc,ratio*100))
        except Exception as e:
            print("    [%s] 解码失败 %s"%(enc,e))
    # 用 utf-16-le 显示
    t=raw.decode('utf-16-le',errors='replace')
    # 提取可读片段
    frags=re.findall(r'[\u4e00-\u9fff\uff00-\uffefA-Za-z0-9_\-\.\\/: ]{4,}',t)
    print("    可读片段 (%d 个):"%len(frags))
    for fr in frags[:25]:
        fr=fr.strip()
        if len(fr)>=4: print("        %s"%fr[:110])
    print()
