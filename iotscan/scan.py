import nmap

nm = nmap.PortScanner()

# Scan IoTGoat instance
# use -T5 for speed (add aggression level later as optional flag)
# needs to be run as root due to -O
nm.scan("10.0.2.3", arguments="-A -O -T5")

for host in nm.all_hosts():
    osdata = []
    for i in range(0, len(nm[host]['osmatch'])):
        # get top three results
        if i > 2:
            break

        osdata.append(nm[host]['osmatch'][i])


    print(osdata)

    print('Host : %s' % host)
    print('State : %s' % nm[host].state())

    os_names = []
    os_accuracy = []
    os_types = []
    for unpack_osdata in osdata:
        for k, v in unpack_osdata.items():
            if k == 'name':
                os_names.append(v)
            if k == 'accuracy':
                os_accuracy.append(v)
            if k == 'osclass':
                print(v[0])
                os_types.append(v[0]['type'])

    print(os_names)
    print(os_accuracy)
    print(os_types)

    for proto in nm[host].all_protocols():
        print("\nProtocol: %s" % proto)

        lport = nm[host][proto].keys()
        for port in lport:
            print("port: %s\tstate: %s" % (port, nm[host][proto][port]['state']))
