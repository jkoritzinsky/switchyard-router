from switchyard.lib.userlib import *
from copy import deepcopy

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt

scenario = TestScenario("router tests")
# add_interface(name, macaddr, ipaddr=None, netmask=None, **kwargs)
scenario.add_interface('eth0', 'ab:cd:ef:ab:cd:ef', '1.2.3.4', '255.255.0.0')
scenario.add_interface('eth1', '00:11:22:ab:cd:ef', '5.6.7.8', '255.255.0.0')
scenario.add_interface('eth2', 'ab:cd:ef:00:11:22', '9.10.11.12', '255.255.255.0')
scenario.add_interface('eth3', '11:11:00:ef:11:22', '13.14.15.16', '255.255.255.0')

# test case 3: set destination to ip not in network
# 1 ICMP destination network unreachable should be returned
p = mk_pkt("ab:dd:ef:ab:cd:ef", 'ab:cd:ef:ab:cd:ef', '1.2.3.128', '5.9.2.3')

scenario.expect(PacketInputEvent('eth0', p),"A packet destined to 5.9.2.3 arrives on port eth0")

scenario.expect(PacketOutputEvent('eth0', create_ip_arp_request('ab:cd:ef:ab:cd:ef', '1.2.3.4', '1.2.3.128')), "An ARP request for 1.2.3.128 is sent")
scenario.expect(PacketInputEvent('eth0', create_ip_arp_reply("ab:dd:ef:ab:cd:ef", 'ab:cd:ef:ab:cd:ef', '1.2.3.128', '1.2.3.4')), "An ARP response arrives for 1.2.3.128")

p = deepcopy(p)
icmp = ICMP()
icmp.icmptype = ICMPType.DestinationUnreachable
icmp.icmpcode = ICMPTypeCodeMap[icmp.icmptype].NetworkUnreachable
del p[p.get_header_index(Ethernet)]
icmp.icmpdata.data = p.to_bytes()[:28]
p = Ethernet(src="ab:cd:ef:ab:cd:ef", dst="ab:dd:ef:ab:cd:ef") + \
IPv4(src="5.9.2.3", dst="1.2.3.128", protocol=IPProtocol.ICMP, ttl=4) + \
icmp
scenario.expect(PacketOutputEvent('eth0', p),"ICMP NetworkUnreachable destined to 1.2.3.128 arives on port etho")
#goes into loop of sending packets to itself
