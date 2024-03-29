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

p = Ethernet(src="ab:cd:ef:ab:cd:ef", dst="00:11:22:ab:cd:ef") + \
IPv4(src="1.2.3.4", dst="5.6.7.8", protocol=IPProtocol.UDP, ttl=1) + \
UDP(src=1234, dst=5678) + b'some payload'

# test case 1: ttl set to 1, packet should die at router
# 2 ICMP time exceeded should be returned
scenario.expect(PacketInputEvent('eth0', p),"A udp packet destined to 5.6.7.8 arrives on port eth0")
arp_req = create_ip_arp_request("ab:cd:ef:ab:cd:ef", '1.2.3.4', '1.2.3.4')
scenario.expect(PacketOutputEvent('eth0', arp_req),"Arp request 1")
scenario.expect(PacketInputEvent('eth0', arp_req),"Arp request 2")

icmp = ICMP()
icmp.icmptype = ICMPType.TimeExceeded
icmp.icmpcode = ICMPTypeCodeMap[icmp.icmptype]
x = IPv4(src="1.2.3.4", dst="5.6.7.8", protocol=IPProtocol.UDP, ttl=1) + \
UDP(src=1234, dst=5678) + b'some payload'
icmp.icmpdata.data = x.to_bytes()[:28]
z = Ethernet(src="ab:cd:ef:ab:cd:ef", dst="ab:cd:ef:ab:cd:ef") + \
IPv4(src="5.6.7.8", dst="1.2.3.4", protocol=IPProtocol.ICMP, ttl=4) + \
icmp

scenario.expect(PacketOutputEvent('eth0', z),"ICMP TimeExceeded")
arp_rep = create_ip_arp_reply("ab:cd:ef:ab:cd:ef", "ab:cd:ef:ab:cd:ef", '1.2.3.4', '1.2.3.4')
scenario.expect(PacketOutputEvent('eth0', arp_rep),"Arp reply 1")
