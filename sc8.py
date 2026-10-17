import sys,os,struct
sys.stdout.reconfigure(encoding='utf-8')
d=r'C:\ProgramData\360Safe\ScanCache'
da=open(os.path.join(d,'Data_2026_10_15.dat'),'rb').read()
# XOR 0xEA 后: 47 1c 44 5c 7b 58 76 2a 4e 7f 76 00 6f 7d 61 38 ...
# 若明文是 UTF-16LE 文本，则密文^0xEA 后应呈现 (可打印, 0x00) 交替
# 但看到 47 1c / 44 5c / 7b 58 ... 说明不是简单的 UTF16
# 
# 关键观察: 0x1c 出现在位置 1，0x00 出现在位置 11,27,47,55
# 位置 11,27,47,55 差值: 16,20,8 —— 不像固定周期
#
# 换个思路：这是**变密钥流**。找已知明文来推密钥流。
# 360 的扫描缓存里必然包含文件路径。我们已知扫过 D:\troyr2 等路径。
# 用已知明文 "D:\troyr2" 搜索：若 Data 是 XOR 流密码，则 密文^明文 = 密钥流，
# 密钥流在不同位置应一致（若密钥重复）。
print("=== 用已知路径做已知明文攻击 ===")
knowns=[b'D:\\troyr2', b'C:\\ProgramData', b'.ps1', b'.zip', b'\\360Safe']
for kp in knowns:
    print("  已知明文 %r:"%kp)
    for i in range(len(da)-len(kp)):
        ks=bytes(da[i+j]^kp[j] for j in range(len(kp)))
        # 密钥流若为重复短密钥，则同一密钥流片段会多次出现
        if i<len(da)-len(kp):
            pass
    # 统计所有位置的密钥流，找重复
    from collections import Counter
    c=Counter()
    for i in range(len(da)-len(kp)):
        ks=bytes(da[i+j]^kp[j] for j in range(len(kp)))
        c[ks]+=1
    top=c.most_common(3)
    print("      最频繁密钥流: %s"%[(k.hex(),n) for k,n in top])
