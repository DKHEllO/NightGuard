#!/usr/bin/env python

"""
@Author: k
@Date: 2020-02-12 21:31:33
@LastEditTime : 2020-02-12 22:07:39
@LastEditors  : k
@Description: packet scanner
@FilePath: /NightGuard/scanner.py

Scan the network and capture the packet
"""

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1


def scan_subnet(ip_list):
    """
    scan network segment
    :param ip_list:list
    :return: res:dict
    """
    res = {
        'alive': [],
        'dead': []
    }

    if isinstance(ip_list, list) and ip_list is not None:
        for ip in ip_list:
            p = sr1(IP(dst=ip)/ICMP(), timeout=2)
            if p:
                res['alive'].append(ip)
            else:
                res['dead'].append(ip)
        return res
    # 傳入參數有誤
    else:
        return None
