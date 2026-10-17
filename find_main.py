import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
root=r'C:\Program Files (x86)\360\360Safe'
# ★ 换策略: 在**主程序**里找格式串（不是引擎DLL）
cands=[r'\360Safe.exe',r'\360Tray.exe',r'\deepscan\DSMain.exe',r'\deepscan\deepscan.dll',
       r'\deepscan\DSMainUI.dll',r'\360SafeBox.exe',r'\safemon\safemon.dll']
for c in cands:
    p=root+c
    if not os.path.exists(p):
        print("  %-40s 不存在"%c); continue
    d=open(p,'rb').read()
    hits=[]
    for kw in ['Data_%04d_%02d_%02d.dat','MIndex.dat','ScanCache','CIndex_']:
        w=kw.encode('utf-16-le')
        if w in d: hits.append(kw)
        elif kw.encode() in d: hits.append(kw+'(a)')
    print("  %-40s %d 字节  %s"%(c,len(d),hits if hits else '无'))
