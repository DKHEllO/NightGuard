#!/usr/bin/env python

"""
Scan the network and capture the packet
"""

import sys

from IPy import IP as IP_ADD
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1

ipv4_segment = sys.argv[1]
ip_list = [str(i) for i in IP_ADD(ipv4_segment)]

print("IP_LIST: " + str(ip_list))

for ip in ip_list:
    p = sr1(IP(dst=ip)/ICMP(), timeout=2)
    if p:
        print("[+]host {} is alive".format(ip))
    else:
        print("[-]host {} is not alive".format(ip))


