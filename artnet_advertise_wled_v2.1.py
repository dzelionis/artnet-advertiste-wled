import time
from socket import (socket,inet_aton, AF_INET, SOL_SOCKET, SOCK_DGRAM, SO_BROADCAST, SO_REUSEADDR)
from struct import unpack, pack, pack_into
import random
import threading
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
from socket import inet_ntoa
import sys
import os
import re
import subprocess


# In case soundswitch is running on different pc you can leave "0.0.0.0",
# but in case its on the same machine, you need to have adittional interface,
# could be logical one (loopback), and then you need to define here ip of that interface.
# also it has to be started before soundswitch.

UDP_IP = "0.0.0.0" # listen on all sockets- INADDR_ANY
#UDP_IP = "10.4.20.22"
UDP_PORT = 6454 #0x1936 # Art-net is supposed to only use this port

# broadcast ip of same interface which you are using to bind
#BROADCAST_IP = "10.4.20.63"
BROADCAST_IP = "10.4.20.63"
#BROADCAST_IP = "255.255.255.255"

# Autodiscovery feature for WLED,
# hostname has to contain 'wled' keyword to be detected....
# if thats enabled - all discovered IP's will be added to a IP List.
WLED_AUTODISCOVERY=False


# list of ip's which you want soundswitch would detect as Artnet/DMX nodes
LIST_OF_IPs_FOR_ADVERTISMENT = [
#    "10.4.20.22",
#    "10.4.20.28",
#   "10.4.20.29",
   "10.4.20.7",
    "10.4.20.16",
    "10.4.20.30"
#    "10.4.20.41"
]




def get_arp_table_linux():
    """
    Parse the host's ARP table on a Linux machine

    :return: Machine readable ARP table (see the Linux Kernel documentation on /proc/net/arp for more information)
    :rtype: dict {'ip_address': 'mac_address'}
    """

    with open('/proc/net/arp') as proc_net_arp:
        arp_data_raw = proc_net_arp.read(-1).split("\n")[1:-1]

    parsed_arp_table = (dict(zip(('ip_address', 'type', 'flags', 'hw_address', 'mask', 'device'), v))
                        for v in (re.split('\s+', i) for i in arp_data_raw))

    return {d['ip_address']: d['hw_address'] for d in parsed_arp_table}


def get_arp_table_darwin():
    """
    Parse the host's ARP table on an OSX machine

    :return: Machine readable ARP table (by running the "arp -a -n" command)
    :rtype: dict {'ip_address': 'mac_address'}
    """

    arp_data_re = re.compile(
        r'^\S+ \((?P<ip_address>[^\)]+)\) at (?P<hw_address>(?:[0-9a-f]{2}:){5}(?:[0-9a-f]{2})) on (?P<device>\S+) ifscope \[(?P<type>\S+)\]$')

    arp_data_raw = subprocess.check_output(['arp', '-a', '-n']).split("\n")[:-1]
    parsed_arp_table = (arp_data_re.match(i).groupdict() for i in arp_data_raw)

    return {d['ip_address']: d['hw_address'] for d in parsed_arp_table}


def get_arp_table_win32():
    # Command is arp -a
    ret = []
    dataDict = {}
    commandOutput = os.popen('arp -a').read()

    lines = commandOutput.split('\n')
    lines = [e for e in lines if (not 'ress' in e)]

    ACTIVE_IFACE = None
    ID = 1


    # Parse output
    for line in lines:

        if line == '':
            continue

        if line[:9] == 'Interface':
            ACTIVE_IFACE = line.split(' ')[1]

        else:
            if ACTIVE_IFACE is None:
                continue

            line = re.sub(r' +', r' ', line).strip()
            IPV4, PHYSICAL, CACHE_TYPE = line.split(' ')

            # Lnaguage trick
            # French is "dynamique" and English is "dynamic"
            CACHE_TYPE = 'dynamic' if CACHE_TYPE[:4] == 'dyna' else 'static'

            # ret.append([ID, ACTIVE_IFACE, IPV4, PHYSICAL, CACHE_TYPE])
            ID += 1
            ret.append([IPV4, str(PHYSICAL).replace("-", ":")])
            dataDict[IPV4] = str(PHYSICAL).replace("-", ":")

    return dataDict


def get_arp_table():
    """
    Parse the host's ARP table

    :return: Machine readable ARP table (see the Linux Kernel documentation on /proc/net/arp for more information)
    :rtype: dict {'ip_address': 'mac_address'}
    """
    #print(sys.platform)

    if sys.platform in ('linux', 'linux2'):
        return get_arp_table_linux()
    elif sys.platform == 'darwin':
        return get_arp_table_darwin()
    elif sys.platform == "win32":
        return get_arp_table_win32()
    else:
        raise Exception("Unable to fetch ARP table on %s" % (sys.platform,))


class MyListener(ServiceListener):

    wled_ip_list=[]
    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        #print(f"Service {name} updated")
        pass
    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        #print(f"Service {name} removed")
        pass
    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:

        info = zc.get_service_info(type_, name)
        #print(f"Service {name} added, service info: {info}")
        if "wled" in str(name).lower():
          self.wled_ip_list.append(inet_ntoa(info.addresses[0]))
        #print(inet_ntoa(info.addresses[0]))
        #print(self.wled_ip_list)

if WLED_AUTODISCOVERY:
    print("Autodiscovery for WLED is enabled...")
    zeroconf = Zeroconf()
    listener = MyListener()
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
    #print(listener.wled_ip_list)
    time.sleep(5)
    for ip in listener.wled_ip_list:
        LIST_OF_IPs_FOR_ADVERTISMENT.append(ip)
    print(f"Found following IP's:{listener.wled_ip_list}")
    zeroconf.close()





class ArtnetPacket:
 
    ARTNET_HEADER = b'Art-Net\x00'
    OP_OUTPUT = 0x5000
    POLL = 0x2000
    POLLREPLY = 0x2100
    sock = object()
    macs_dict = {}

    def __init__(self):
        self.op_code = None
        self.ver = None
        self.sequence = None
        self.physical = None
        self.universe = None
        self.length = None
        self.data = None
        self.arp_table = get_arp_table()


    def init_socket(self):
        try:
            self.sock = socket(AF_INET, SOCK_DGRAM)
        except:
            print("failed to init socket")

        print(("Listening in {0}:{1}").format(UDP_IP, UDP_PORT))

        self.sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)  # Enable Broadcast
        self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.sock.bind((UDP_IP, 6454))


    def send_pollreply(self, packet):
        self.sock.sendto(packet, (BROADCAST_IP, UDP_PORT))
        if BROADCAST_IP != "255.255.255.255":
            self.sock.sendto(packet, ('255.255.255.255', 6454))

    def _gen_mac(self):
        return str(hex(random.randint(1, 255))).lstrip("0x")

    def gen_mac(self):
        mac = ""
        for i in range(0,6):
            if i == 0:
                mac = self._gen_mac()
            else:
                mac += f':{self._gen_mac()}'

        return mac

    def ip2long(self, ip):
    #"""
    #Convert an IP string to long
    #"""
        packedIP = inet_aton(ip)
        return unpack("!L", packedIP)[0]

    def pollreplay(self, adv_ip):
        ip = adv_ip

        packet = bytearray(239)
        offset = 0

        # Adding artnet header
        data = (0x41, 0x72, 0x74, 0x2d, 0x4e, 0x65, 0x74, 0x00)
        offset += len(data)
        #pack_into('!HHHHHHHH', packet, 0, *data)
        pack_into('bbbbbbbb', packet, 0, *data)
        ##packet += bytearray([0x41,0x72,0x74,0x2d,0x4e,0x65, 0x74,0x00])

        # Adding OpCode
        pack_into('H', packet, offset, self.POLLREPLY)
        offset += 2

        # adding ip

        ### IP Address[4] Int8 - Array containing the Node’s IP address. First
        ###array entry is most significant byte of
        ###address. When binding is implemented,
        ###bound nodes may share the root node’s IP
        ###Address and the BindIndex is used to
        ipInt = self.ip2long(ip)
        pack_into("!L", packet, offset, ipInt)
        offset += 4

        # adding port
        port = 6454
        pack_into("H", packet, offset, port)
        offset += 2

        # Version Info
        version_info = 0x0000 # 4bites
        net_switch = 0x00 # 2bites
        sub_switch = 0x00 # 2bites
        oem = 0xffff # 4bites
        ubea = 0x00 # 2bites
        status = 0xf0 # 2bites
        ESTA = 0xffff # 4bites

        data = (0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xf0, 0xff, 0xff)
        pack_into(  "BBBBBBBBBB", packet, offset, *data)
        offset += len(data)

        # sort name
        # 18x2 bites
        sort_name = "WLED"
        pack_into("!18s",packet,offset, sort_name.encode())
        offset += 18

        # long name
        # 3lines x 16hex  x2 bits =  48 x2 = 96
        long_name = "MyArtnet - Testing python poll"
        pack_into("!48s", packet, offset, long_name.encode())
        offset += 48

        # Node report
        # 4lines x 16hex x2 bits = 64 x 2 = 128

        offset += 64
        offset += 16

        # port info
        number_of_ports = (0x00, 0x02)
        port_types = (0x40,0x40,0x00,0x00)
        input_status = (0x00,0x00,0x00,0x00)
        output_status = (0x00, 0x00,0x00,0x00)
        input_sub_switch = (0x00, 0x01, 0x00, 0x00)
        output_sub_switch = (0x00, 0x00,0x00,0x00)
        pack_into(  "BBBBBBBBBBBBBBBBBBBBBB", packet, offset, *number_of_ports, *port_types, *input_status,
                  *output_status, *input_sub_switch, *output_sub_switch)

        offset += len(number_of_ports + port_types + input_status + output_status + input_sub_switch + output_sub_switch)

        # swvideo + swmacro + swremote + spare + style
        data = [0x00] + [0x00] + [0x00] + [0x00, 0x00, 0x00] + [0x00]
        data = tuple(data)
        pack_into(  "BBBBBBB", packet, offset, *data)
        offset += len(data)

        # mac address


        if ip not in self.macs_dict.keys() and ip not in self.arp_table:
            mac = self.gen_mac()
            self.macs_dict[ip] = mac
            print(f'NOT Found mac, genrtated"{mac}" for ip "{ip}". t...')


        else:
            if ip in self.macs_dict:
              mac = self.macs_dict[ip]
              #print(f'Found mac "{mac}" for ip "{ip}" in ,macs dict...')
            elif ip in self.arp_table:
              mac = self.arp_table[ip]
              self.macs_dict[ip] = mac
              print(f'Found mac "{mac}" for ip "{ip}" in arp table...')

        macSet = []
        tmpList = mac.split(":")

        for item in tmpList:
            macSet.append(int(f'0x{item}',16))
        pack_into(  "BBBBBB", packet, offset, *tuple(macSet))

        offset += 6

        #ipInt
        ipInt = self.ip2long(UDP_IP)
        pack_into("!L", packet, offset, ipInt)
        offset += 4

        #bind_ip_address = UDP_IP
        # adding ip
        #ipSet = []
        #octets = bind_ip_address.split(".")
        #for item in octets:
        #    ipSet.append(int(item))
        #pack_into("!HHHH", packet, offset, *tuple(ipSet))
        #offset += 4

        return packet




    def unpack_raw_artnet_packet(self,raw_data):
 
        if unpack('!8s', raw_data[:8])[0] != ArtnetPacket.ARTNET_HEADER:
            return None
 
        packet = ArtnetPacket()
 
        # We can only handle data packets
        (packet.op_code,) = unpack('H', raw_data[8:10])
        #print(packet.op_code)
        if packet.op_code == ArtnetPacket.POLL:
            print("received POLL packet, sending advertisement...")
            for adv_ip in LIST_OF_IPs_FOR_ADVERTISMENT:
                self.send_pollreply(self.pollreplay(adv_ip))
            return None

        if packet.op_code != ArtnetPacket.OP_OUTPUT:
            return None
  
  
        (packet.op_code, packet.ver, packet.sequence, packet.physical,
            packet.universe, packet.length) = unpack('!HHBBHH', raw_data[8:18])
  
        (packet.universe,) = unpack('<H', raw_data[14:16])
  
        (packet.data,) = unpack(
            '{0}s'.format(int(packet.length)),
            raw_data[18:18+int(packet.length)])
  
        return packet

a = ArtnetPacket()
a.init_socket()
sock = a.sock
#print("Sending advertisement...")
#for adv_ip in LIST_OF_IPs_FOR_ADVERTISMENT:
#  a.send_pollreply(a.pollreplay(adv_ip))


lastTime = time.time()

def artnet_receiver(UNIV=None, callBack=None):
    global lastTime
    lastSequence = 0
    packetCount = 0
    lastTime = time.time()
    startTime = time.time()

    datas = []
    adata = {}
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            packet = a.unpack_raw_artnet_packet(data)
 
            if packet != None and UNIV != None:
                #print("Sequence=%i universe=%i"%(packet.sequence,packet.universe))
                if packet.universe not in adata.keys():
                    adata[packet.universe] = []
                #print(packet.data)
                if packet.universe == UNIV:
                    if callBack is not None:
                        callBack(packet.data)

                packetCount += 1
 
                while len(datas) < packet.universe + 1:
                    print("adding new universe %i"%(packet.universe))
                    datas.append('')

                # Send an update to the tape when a new sequence is received on the last universe
                if packet.universe == (len(datas)-1) and lastSequence != packet.sequence:
                    pass
                    lastSequence = packet.sequence


            if time.time() > lastTime+1:
                print("Packets per second: %i"%(packetCount))
                packetCount = 0
                lastTime = time.time()

            time.sleep(0.5)

        except KeyboardInterrupt:
            pass
            sock.close()
            sys.exit()


def cb(data):
    pass

def arntet_worker():
  artnet_receiver(callBack=cb, UNIV=0)

#art = threading.Thread(target=arntet_worker, args=())
#art.start()
start_pool_packets=False
pool_packet_time=time.time()

while True:
    #if time.time() > lastTime + 5 and start_pool_packets == False:
    #    print("have not received pool packet for 5 seconds, will start to send anyway every 2.5 seconds..")
    #    start_pool_packets=True
    #    pool_packet_time = time.time()

    #if start_pool_packets == True and time.time() > pool_packet_time + 3:
    if time.time() > pool_packet_time + 2.5:
        pool_packet_time = time.time()
        print("sent")
        for adv_ip in LIST_OF_IPs_FOR_ADVERTISMENT:
            a.send_pollreply(a.pollreplay(adv_ip))
    time.sleep(0.5)
#if __name__ == "__main__":
#    artnet_receiver()




