import sys, json
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0,'.')
import av360_sense as A
s=A.AV360Sense()
print("=== ★★★ scan_log_history() 聚合全部历史扫描日志 ===")
h=s.scan_log_history()
print("共 %d 条扫描记录:"%len(h))
print()
for r in h[:12]:
    print("  %s" % r.get('log'))
    print("      时间=%s  类型=%s" % (r.get('time'),r.get('scan_type')))
    print("      目标=%s" % r.get('target'))
    print("      文件=%s 安全=%s 威胁=%s 已处理=%s" % (r.get('files'),r.get('safe'),r.get('threats'),r.get('handled')))
    print()
print("=== ★★★ scan_log_threats_all() 去重汇总 ===")
ts=s.scan_log_threats_all()
print("共 %d 个唯一威胁:"%len(ts))
for t in ts:
    print("  [%s] %s"%(t.get('engine'),t.get('verdict')))
    print("      %s"%t.get('path'))
    print("      md5=%s  hits=%d  first=%s  last=%s"%(t.get('md5'),t.get('hits'),t.get('first_seen'),t.get('last_seen')))
