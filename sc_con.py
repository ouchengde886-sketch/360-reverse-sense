import sys,struct,re
sys.stdout.reconfigure(encoding='utf-8')
for p in [r'C:\Program Files (x86)\360\360Safe\deepscan\ScChecker.dll',
          r'C:\Program Files (x86)\360\360Safe\deepscan\deepscan.dll']:
    d=open(p,'rb').read()
    print("  --- %s ---"%p.split('\\')[-1])
    for m in re.finditer(rb'[\x20-\x7e]{3,60}',d):
        s=m.group()
        if b'.con' in s or b'.dat' in s or b'sc.' in s or b'rule' in s.lower() or b'Rule' in s:
            print("    "+s.decode('latin1'))
