import socket, sys, time, threading, subprocess
sys.stdout.reconfigure(encoding='utf-8')
print("=== 网络连接拦截测试（C2 通信场景）===")
print()
# 1. 本地监听 + 连接（最基础）
print("--- 1. 本地回环 TCP 连接 ---")
srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
try:
    srv.bind(('127.0.0.1',0)); srv.listen(1)
    port=srv.getsockname()[1]
    print("    监听 127.0.0.1:%d OK"%port)
    def acc():
        try:
            c,_=srv.accept(); c.sendall(b'PONG'); c.close()
        except: pass
    t=threading.Thread(target=acc,daemon=True); t.start()
    cl=socket.socket(); cl.settimeout(5)
    cl.connect(('127.0.0.1',port))
    d=cl.recv(64)
    print("    连接+收发: OK 收到 %r"%d)
    cl.close()
except Exception as e:
    print("    失败: %s"%e)
srv.close()
print()
# 2. 外网 DNS
print("--- 2. DNS 解析 ---")
for host in ['www.baidu.com','www.360.cn','github.com','example.com']:
    try:
        ip=socket.gethostbyname(host)
        print("    %-16s -> %s"%(host,ip))
    except Exception as e:
        print("    %-16s -> FAIL %s"%(host,e))
print()
# 3. 外网 TCP 连接
print("--- 3. 外网 TCP 连接 ---")
for host,port in [('www.baidu.com',80),('www.360.cn',80),('github.com',443),('1.1.1.1',53)]:
    try:
        s=socket.socket(); s.settimeout(6)
        t0=time.time()
        s.connect((host,port))
        print("    %-18s:%-5d 连接 OK (%.0f ms)"%(host,port,(time.time()-t0)*1000))
        s.close()
    except Exception as e:
        print("    %-18s:%-5d FAIL %s"%(host,port,e))
print()
# 4. HTTP 请求
print("--- 4. HTTP 请求 ---")
try:
    import urllib.request
    r=urllib.request.urlopen('http://www.baidu.com',timeout=8)
    b=r.read(200)
    print("    HTTP GET baidu: %d 状态, %d 字节"%(r.status,len(b)))
except Exception as e:
    print("    HTTP GET 失败: %s"%e)
print()
# 5. 监听端口（服务端能力，C2 beacon 反连需要）
print("--- 5. 绑定监听端口 ---")
for port in [0,8080,8443,31337,55555]:
    try:
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('0.0.0.0',port)); s.listen(1)
        print("    bind 0.0.0.0:%-6d OK (实际 %d)"%(port,s.getsockname()[1]))
        s.close()
    except Exception as e:
        print("    bind 0.0.0.0:%-6d FAIL %s"%(port,e))
