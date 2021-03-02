import nmap

nm = nmap.PortScanner()

# Scan virtualised network
nm.scan("10.0.2.19", arguments="-A -T5")

for host in nm.all_hosts():
    print('Host : %s' % host)
    print('State : %s' % nm[host].state())

    for proto in nm[host].all_protocols():
        print("\nProtocol: %s" % proto)

        lport = nm[host][proto].keys()
        for port in lport:
            print("port: %s\tstate: %s" % (port, nm[host][proto][port]['state']))
