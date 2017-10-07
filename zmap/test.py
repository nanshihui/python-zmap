from zmap import  *
t=PortScanner()
# print t.scan(hosts='182.92.189.217 182.18.5.135',ports=80)
print t.scan(hosts='127.0.0.1',ports=80)

print t.has_port(80)
# print t.all_hosts()

