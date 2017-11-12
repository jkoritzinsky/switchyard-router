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

def router_tests():
    s = TestScenario("router tests")
    # add_interface(name, macaddr, ipaddr=None, netmask=None, **kwargs)
    s.add_interface('eth0', 'ab:cd:ef:ab:cd:ef', '1.2.3.4', '255.255.0.0')
    s.add_interface('eth1', '00:11:22:ab:cd:ef', '5.6.7.8', '255.255.0.0')
    s.add_interface('eth2', 'ab:cd:ef:00:11:22', '9.10.11.12', '255.255.255.0')

    # test case 1: An EchoReply packet is sent out,
    # 4 ICMP destination port unreachable should be sent back
    testpkt = mk_pkt("ab:cd:ef:ab:cd:ef", "ab:cd:ef:ab:cd:ef", "1.2.3.4", "1.2.3.4",reply=True)
    s.expect(PacketInputEvent("eth0", testpkt, display=ICMP), "")
    s.expect(PacketOutputEvent("eth0", testpkt, display=ICMP), "")

    # test case 2: ttl set to 1, packet should die at router
    # 2 ICMP time exceeded should be returned

    # test case 3: set destination to ip not in network
    # 1 ICMP destination network unreachable should be returned

    # test case 4:
    # 3 ICMP destination host unreachable should be returned

    return s

scenario = router_tests()
