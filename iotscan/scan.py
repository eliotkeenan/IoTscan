import nmap

nm = nmap.PortScanner()

# Scan IoTGoat
# use -T5 for speed (add aggression level later as optional flag)
nm.scan("10.0.2.19", arguments="-A -O -T5")

for host in nm.all_hosts():
    print('Host : %s' % host)
    print('State : %s' % nm[host].state())

    # found something that kind of works for the operating system detection
    #for osmatch in nm[host]['osmatch']:
    #print("name: {0}".format(osmatch['name']))
    #print("type: {0}".format(osmatch['type']))

    # dictionary types within the list then more shit within the dictionaries
    for osdata in nm[host]['osmatch']:
        for k, v in osdata.items():
            print(k, v)

    for proto in nm[host].all_protocols():
        print("\nProtocol: %s" % proto)

        lport = nm[host][proto].keys()
        for port in lport:
            print("port: %s\tstate: %s" % (port, nm[host][proto][port]['state']))
