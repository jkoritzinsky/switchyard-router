#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
import csv
from copy import deepcopy
from collections import namedtuple
from switchyard.lib.userlib import *

ForwardingEntry = namedtuple("ForwardingEntry", ["network", "next_hop", "interface"])

class PendingPackets():
    def __init__(self, pkt, iface):
        self.pkts = [pkt]
        self.num_req = 0
        self.iface = iface
        self.last_req_time = 0


class ArpBackedForwarder(object):
    def __init__(self, net):
        self.cache = {}
        self.net = net
        self.pending_packets = {}

    def send_packet(self, pkt, next_hop, outbound_iface):
        if next_hop in self.cache:
            src = self.net.interface_by_name(outbound_iface).ethaddr
            ethertype = pkt.get_header(Ethernet).ethertype
            eth_header = Ethernet(src= src, ethertype = ethertype)
            pkt[pkt.get_header_index(Ethernet)] = eth_header
            eth_header.dst = self.cache[next_hop]
            self.net.send_packet(outbound_iface, pkt)
        else:
            if next_hop in self.pending_packets:
                self.pending_packets[next_hop].pkts.append(pkt)
            else:
                self.pending_packets[next_hop] = PendingPackets(pkt, outbound_iface)
                self.make_arp_request(next_hop, outbound_iface)

    def make_arp_request(self, ipaddr, iface):
        self.pending_packets[ipaddr].num_req += 1
        self.pending_packets[ipaddr].last_req_time = time.time()
        outbound_iface = self.net.interface_by_name(iface)
        arp_req = create_ip_arp_request(outbound_iface.ethaddr, outbound_iface.ipaddr, ipaddr)
        self.net.send_packet(iface, arp_req)

    def check_for_timeout(self):
        for ipaddr, pending_packets in self.pending_packets.items():
            if pending_packets.last_req_time + 1 < time.time():
                if pending_packets.num_req == 5:
                    del self.pending_packets[ipaddr]
                    pass # Send ICMP failure response
                    #3 ICMP destination host unreachable
                else:
                    self.make_arp_request(ipaddr, pending_packets.iface)

    def add_to_arp_cache(self, ipaddr, ethaddr):
        self.cache[ipaddr] = ethaddr
        if ipaddr in self.pending_packets:
            for pkt in self.pending_packets[ipaddr].pkts:
                self.send_packet(pkt, ipaddr, self.pending_packets[ipaddr].iface)
            del self.pending_packets[ipaddr]

class Router(object):
    def __init__(self, net, table):
        self.net = net
        self.forwarder = ArpBackedForwarder(net)
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
                self.forwarder.check_for_timeout()
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.forwarder.check_for_timeout()
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                self.process_packet(dev, pkt)

    def process_packet(self, dev, pkt):
        if pkt.has_header(Arp):
            self.process_arp(dev, pkt.get_header(Arp))
        elif pkt.has_header(IPv4):
            self.process_ip(dev, pkt)
        elif pkt.has_header(ICMP):
            self.process_icmp()

    def process_ip(self, dev, pkt):
        new_pkt = deepcopy(pkt)
        ip = new_pkt.get_header(IPv4)
        ip.ttl -= 1
        if not ip.ttl:
            pass # TTL = 0 case
            #2 ICMP time exceeded
        entry = self.get_forwarding_entry(ip.dst)
        if entry:
            log_debug("Found forwarding entry for IP {}. {}".format(ip.dst, entry))
            self.forwarder.send_packet(new_pkt, entry.next_hop or ip.dst, entry.interface)
        else:
            pass # Destination Unreachable
            #1 ICMP destination network unreachable

    def process_arp(self, dev, arp):
        self.record_in_arp_cache(arp.senderprotoaddr, arp.senderhwaddr)
        if arp.operation == ArpOperation.Request: # we need to respond to the request
            try:
                iface = self.net.interface_by_ipaddr(arp.targetprotoaddr)
                pkt = create_ip_arp_reply(iface.ethaddr, arp.senderhwaddr, iface.ipaddr, arp.senderprotoaddr)
                self.net.send_packet(dev, pkt)
            except KeyError:
                pass

    def record_in_arp_cache(self, ipaddr, ethaddr):
        self.forwarder.add_to_arp_cache(ipaddr, ethaddr)

    def get_forwarding_entry(self, dest_ip):
        log_debug("Finding best fit next hop IP for {}".format(dest_ip))
        best_fit = None
        for entry in self.forwarding_table:
            if dest_ip == entry.next_hop:
                log_debug("Found a perfect match")
                return entry # Can't beat a perfect IP match
            if dest_ip in entry.network:
                if not best_fit:
                    best_fit = entry
                    log_debug("New best fit for {} is {}".format(dest_ip, entry))
                elif entry.network.prefixlen > best_fit.network.prefixlen:
                    best_fit = entry
                    log_debug("New best fit for {} is {}".format(dest_ip, entry))
        log_debug("Best fit is {}".format(best_fit))
        return best_fit

    def process_icmp(self, dev, pkt):
        #If ping respond to ping
        reply = ICMP()
        reply.icmptype = ICMPType.EchoReply
        reply.EchoReply = pkt.icmp.icmpdata.sequence
        #else ICMP destination port unreachable

def create_forwarding_table(net, filename):
    for iface in net.interfaces():
        network_addr = IPv4Address(int(iface.ipaddr) & int(iface.netmask))
        yield ForwardingEntry(IPv4Network("{}/{}".format(network_addr, iface.netmask)), None, iface.name)

    with open(filename, 'rt') as csvfile:
        reader = csv.reader(csvfile, delimiter=' ')
        for row in reader:
            row = [entry for entry in row if entry]
            if not row:
                continue
            log_debug("Entry {}/{}, Next hop {} on interface {}".format(row[0], row[1], row[2], row[3]))
            yield ForwardingEntry(IPv4Network("{}/{}".format(row[0], row[1])), IPv4Address(row[2]), row[3])

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net, create_forwarding_table(net, 'forwarding_table.txt'))
    r.router_main()
    net.shutdown()
