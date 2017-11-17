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

# test case 4:
# 3 ICMP destination host unreachable should be returned
