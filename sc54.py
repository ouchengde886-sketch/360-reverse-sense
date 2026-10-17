import sys,os,struct,hashlib
sys.stdout.reconfigure(encoding='utf-8')
d=r"C:\ProgramData\360Safe\ScanCache"
# ★ 已知恶意文件的 MD5（来自官方日志）
known={
 '5b718721e66f0cc49d91e79ecc1c8622':'srdi-master.zip',
 'a459ecb9bd7e9297615d18ff75db79b8':'Get-LibSymbols.ps1',
 '945a972d2072aa26f9698ae7c888aa69':'MicrosoftEdgeUpdate.ps1',
 '6a39b2b2cae59e198147ece39c4fe4fa':'Get-PEHeader.ps1',
 '90b0f2eb5accae1a1aa5112ee4dab55f':'Invoke-Shellcode.ps1',
}
# 也加入路径字符串
paths=[b'D:\\troyr2',b'troyr2',b'srdi-master',b'Get-LibSymbols',b'MicrosoftEdgeUpdate',
       b'Get-PEHeader',b'Invoke-Shellcode',b'.ps1',b'.zip',b'D:',b'C:']
# 在 15 日文件里搜索各种编码形式
a=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
print("=== 搜索已知 MD5（各种编码）===")
for md5,name in known.items():
    hits=[]
    # 原始二进制
    if bytes.fromhex(md5) in a: hits.append('raw')
    # ASCII
    if md5.encode() in a: hits.append('ascii')
    # 大写 ASCII
    if md5.upper().encode() in a: hits.append('ASCII-upper')
    # UTF-16LE
    if md5.encode('utf-16-le') in a: hits.append('utf16')
    # 每个字节 ^0x80
    x=bytes((b^0x80) for b in bytes.fromhex(md5))
    if x in a: hits.append('^0x80')
    # 每个字节 |0x80
    o=bytes((b|0x80) for b in bytes.fromhex(md5))
    if o in a: hits.append('|0x80')
    # 每个字节 +0x80
    p=bytes((b+0x80)&0xff for b in bytes.fromhex(md5))
    if p in a: hits.append('+0x80')
    print("  %s (%s): %s"%(md5[:16],name,hits if hits else '未找到'))
print()
print("=== 搜索路径字符串（各种编码）===")
for p in paths:
    hits=[]
    if p in a: hits.append('ascii')
    if p.decode().encode('utf-16-le') in a: hits.append('utf16')
    # 每字节 |0x80
    o=bytes((b|0x80) for b in p)
    if o in a: hits.append('|0x80')
    x=bytes((b^0x80) for b in p)
    if x in a: hits.append('^0x80')
    print("  %-22r: %s"%(p,hits if hits else '未找到'))
