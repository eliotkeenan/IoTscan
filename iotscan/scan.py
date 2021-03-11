import nmap

# set up colourised output
from colorama import init
from colorama import Fore, Style
init()

nm = nmap.PortScanner()

# IoT device types (nmap)
iot_types = ["phone", "game console", "media device", "PDA", "printer", "webcam",
             "VoIP phone", "security-misc", "power-device", "specialized"]

# Scan IoTGoat instance
# use -T5 for speed (add aggression level later as optional flag)
# needs to be run as root due to -O
nm.scan("10.0.2.2", arguments="-A -O -T5")

for host in nm.all_hosts():
    osdata = []
    for i in range(0, len(nm[host]['osmatch'])):
        # get top six results
        if i > 5:
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
        if os_types[i] in iot_types:
            print(f"Name: %s\nAccuracy: %s\nType: {Fore.LIGHTRED_EX}%s{Style.RESET_ALL}\n"
                  % (os_names[i], os_accuracy[i], os_types[i]))
        else:
            print("Name: %s\nAccuracy: %s\nType: %s\n" % (os_names[i], os_accuracy[i],
                                                          os_types[i]))

    for proto in nm[host].all_protocols():
        print("Protocol: %s\n" % proto)

        lport = nm[host][proto].keys()

        for port in lport:
            print("port: %s\tstate: %s\ttype: %s" %
                  (port, nm[host][proto][port]['state'], nm[host][proto][port]['name']))

    print("\n%s Report:" % host)

    iot_num = 0
    noniot_num = 0
    for os_type in os_types:
        if os_type in iot_types:
            iot_num += 1
        else:
            noniot_num += 1

    if iot_num > noniot_num:
        print(Fore.LIGHTGREEN_EX + "Very likely an IoT device")
        print(Style.RESET_ALL, end='')
    elif iot_num == noniot_num:
        print("Might be an IoT device")
    else:
        print("Probably not an IoT device")
