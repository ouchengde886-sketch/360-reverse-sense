import sys, os, time, json, threading, subprocess, shutil
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0,'.')
import av360_sense as A

print("="*72)
print("★★★ 端到端验收：触发真实查杀 + 双通道感知")
print("="*72)
print()
# 1. 准备一个含已知威胁的目录
d = r"D:\e2e_verify_%d" % (int(time.time()) % 100000)
os.makedirs(d, exist_ok=True)
eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
open(os.path.join(d,'sample.com'),'w',encoding='ascii').write(eicar)
open(os.path.join(d,'clean.txt'),'w').write('this is a clean file')
print("[1] 测试目录: %s"%d)
for f in os.listdir(d):
    print("      %s (%d 字节)"%(f,os.path.getsize(os.path.join(d,f))))
print()

s = A.AV360Sense()
print("[2] 建立弹窗基线...")
s.poll_popups(include_all_360=True)
print("      已登记 %d 个窗口"%len(s._seen_hwnds))
print()

# 记录扫描前的日志集合
before_logs = set(os.listdir(os.path.dirname(A.SCAN_LOG)))
before_threats = {t['path'].lower() for t in s.scan_log_threats_all()}
print("[3] 扫描前已知威胁: %d 个"%len(before_threats))
print()

# 后台监视弹窗
popup_events=[]
stop=False
def watcher():
    while not stop:
        for e in s.poll_popups(include_all_360=True):
            popup_events.append(e)
        time.sleep(0.4)
th=threading.Thread(target=watcher,daemon=True); th.start()

print("[4] 触发真实扫描（右键动词）...")
r = s.trigger_scan(d, wait=90, poll=3)
print("      已触发: %s"%r.get('triggered'))
print("      已执行: %s"%r.get('executed'))
print("      耗时: %.1fs"%r.get('elapsed',0))
print()

stop=True; time.sleep(0.6)
print("[5] 弹窗通道捕获: %d 个事件"%len(popup_events))
for e in popup_events[:8]:
    print("      [%s] %s"%(e.kind,e.title[:50]))
print()

# 日志通道
after_logs = set(os.listdir(os.path.dirname(A.SCAN_LOG)))
new_logs = after_logs - before_logs
print("[6] 日志通道: 新增 %d 个日志文件"%len(new_logs))
for n in sorted(new_logs):
    print("      %s"%n)
print()
ths = s.scan_log_threats_all()
new_threats = [t for t in ths if t['path'].lower() not in before_threats]
print("[7] 新发现的威胁: %d 个"%len(new_threats))
for t in new_threats:
    print("      [%s] %s"%(t['engine'],t['verdict']))
    print("            %s"%t['path'])
    print("            md5=%s"%t['md5'])
print()
print("[8] 本次扫描的日志详情:")
for rec in s.scan_log_history(limit=3):
    if rec.get('target') and d.split('\\')[-1] in (rec.get('target') or ''):
        print("      日志: %s"%rec['log'])
        print("      类型: %s"%rec.get('scan_type'))
        print("      目标: %s"%rec.get('target'))
        print("      文件=%s 安全=%s 威胁=%s"%(rec.get('files'),rec.get('safe'),rec.get('threats')))
print()
print("="*72)
ok = len(new_threats)>0
print("验收结果: %s"%("★ 通过 —— 感知层完整报告了本次查杀结果" if ok else "未检出（检查扫描是否真执行）"))
print("="*72)
