import nmap

# set up colourised output
from colorama import init
from colorama import Fore, Back, Style
init()

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

    print('Host: %s' % host)
    print('State: %s' % nm[host].state())

    os_names = []
    os_accuracy = []
    os_types = []
    # extract os data
    for unpack_osdata in osdata:
        for k, v in unpack_osdata.items():
            if k == 'name':
                os_names.append(v)
            if k == 'accuracy':
                os_accuracy.append(v)
            if k == 'osclass':
                # due to the ridiculous number of embedded dicts, lists etc
                # this seems the best way to do it
                os_types.append(v[0]['type'])

    print("\nDevice information:\n")
    for i in range(0, len(os_names)):
        print("Name: %s\nAccuracy: %s\nType: %s\n" % (os_names[i], os_accuracy[i],
                                                      os_types[i]))

    for proto in nm[host].all_protocols():
        print("Protocol: %s" % proto)

        lport = nm[host][proto].keys()
        for port in lport:
            print("port: %s\tstate: %s" % (port, nm[host][proto][port]['state']))

    is_iot = 0
    print("\n%s Report:" % host)
    for os_type in os_types:
        if os_type == "general purpose" or os_type == "phone":
            is_iot = 1

    if is_iot:
        print(Fore.LIGHTGREEN_EX + "Very likely an IoT device")
        print(Style.RESET_ALL, end='')
