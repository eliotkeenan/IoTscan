import nmap

nm = nmap.PortScanner()

nm.scan('127.0.0.1')

for host in nm.all_hosts():
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
