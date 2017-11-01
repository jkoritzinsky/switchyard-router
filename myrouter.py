#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
import csv
from collections import namedtuple
from switchyard.lib.userlib import *

ForwardingEntry = namedtuple("ForwardingEntry", ["network", "next_hop", "interface"], verbose=True)

class Router(object):
    def __init__(self, net, table):
        self.net = net
        self.arp_cache = {}
        self.forwarding_table = list(table)
        # other initialization stuff here


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                self.process_packet(dev, pkt)
    def process_packet(self, dev, pkt):
        arp = pkt.get_header(Arp)
        if arp and arp.operation == ArpOperation.Request:
            try:
                iface = self.net.interface_by_ipaddr(arp.targetprotoaddr)

                self.record_in_arp_cache(arp.senderprotoaddr, arp.senderhwaddr)

                pkt = create_ip_arp_reply(iface.ethaddr, arp.senderhwaddr, iface.ipaddr, arp.senderprotoaddr)
                self.net.send_packet(dev, pkt)
            except KeyError:
                pass
        else:
            pass

    def record_in_arp_cache(self, ipaddr, ethaddr):
        self.arp_cache[ipaddr] = ethaddr


def create_forwarding_table(filename):
    with open(filename, 'rt') as csvfile:
        reader = csv.reader(csvfile, delimiter=' ')
        for row in reader:
            row = [entry for entry in row if entry]
            if not row:
                continue
            log_debug("Entry {}/{} on interface {}".format(row[0], row[1], row[2]))
            yield ForwardingEntry(IPv4Network("{}/{}".format(row[0], row[1])), IPv4Address(row[2]), row[3])

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net, create_forwarding_table('forwarding_table.txt'))
    r.router_main()
    net.shutdown()
