import sys, os, json
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0,'.')
import av360_sense as A
s = A.Av360Sense() if hasattr(A,'Av360Sense') else None
if s is None:
    # 找主类名
    names=[n for n in dir(A) if n[0].isupper()]
    print("模块中的类:", names)
else:
    ts = s.scan_log_threats()
    print("scan_log_threats() 返回 %d 条:"%len(ts))
    for t in ts[:8]:
        print("   ", json.dumps(t, ensure_ascii=False)[:200])
