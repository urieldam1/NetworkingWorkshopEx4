#!/usr/bin/env python

import sys
from scapy.all import sniff, get_if_list

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def handle_pkt(pkt):
    print "got a packet"
    pkt.show2()
    sys.stdout.flush()


def main():
    iface = 'h2-eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
