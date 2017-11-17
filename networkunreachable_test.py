from switchyard.lib.userlib import *

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
p = Ethernet(src="ab:cd:ef:ab:cd:ef", dst="00:11:22:ab:cd:ef") + \
IPv4(src="1.2.3.4", dst="5.9.2.3", protocol=IPProtocol.UDP, ttl=5) + \
UDP(src=1234, dst=5923) + b'some payload'
scenario.expect(PacketInputEvent('eth0', p),"A udp packet destined to 5.9.2.3 arrives on port eth0")

icmp = ICMP()
icmp.icmptype = ICMPType.DestinationUnreachable
icmp.icmpcode = ICMPTypeCodeMap[icmp.icmptype].NetworkUnreachable
del p[p.get_header_index(Ethernet)]
icmp.icmpdata.data = p.to_bytes()[:28]
p = Ethernet(src="ab:cd:ef:ab:cd:ef", dst="ab:cd:ef:ab:cd:ef") + \
IPv4(src="5.9.2.3", dst="1.2.3.4", protocol=IPProtocol.ICMP, ttl=4) + \
icmp
scenario.expect(PacketInputEvent('eth0', p),"ICMP NetowrkUnreachable destined to 1.2.3.4 arives on port etho")

icmp = ICMP()
icmp.icmptype = ICMPType.DestinationUnreachable
icmp.icmpcode = ICMPTypeCodeMap[icmp.icmptype].NetworkUnreachable
del p[p.get_header_index(Ethernet)]
icmp.icmpdata.data = p.to_bytes()[:28]
z = Ethernet(src="ab:cd:ef:ab:cd:ef", dst="ab:cd:ef:ab:cd:ef") + \
IPv4(src="5.9.2.3", dst="1.2.3.4", protocol=IPProtocol.ICMP, ttl=4) + \
icmp
scenario.expect(PacketInputEvent('eth0', z),"ICMP")

icmp = ICMP()
icmp.icmptype = ICMPType.DestinationUnreachable
icmp.icmpcode = ICMPTypeCodeMap[icmp.icmptype].NetworkUnreachable
del z[z.get_header_index(Ethernet)]
icmp.icmpdata.data = p.to_bytes()[:28]
x = Ethernet(src="ab:cd:ef:ab:cd:ef", dst="ab:cd:ef:ab:cd:ef") + \
IPv4(src="5.9.2.3", dst="1.2.3.4", protocol=IPProtocol.ICMP, ttl=4) + \
icmp
scenario.expect(PacketInputEvent('eth0', x), "ICMP 3")

icmp = ICMP()
icmp.icmptype = ICMPType.DestinationUnreachable
icmp.icmpcode = ICMPTypeCodeMap[icmp.icmptype].NetworkUnreachable
del x[x.get_header_index(Ethernet)]
icmp.icmpdata.data = p.to_bytes()[:28]
z = Ethernet(src="ab:cd:ef:ab:cd:ef", dst="ab:cd:ef:ab:cd:ef") + \
IPv4(src="5.9.2.3", dst="1.2.3.4", protocol=IPProtocol.ICMP, ttl=4) + \
icmp
scenario.expect(PacketOutputEvent('eth0', z), "ICMP 3")
#goes into loop of sending packets to itself
