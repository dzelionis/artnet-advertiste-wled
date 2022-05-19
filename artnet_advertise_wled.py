import sys
import time
from socket import (socket,inet_aton, AF_INET, SOL_SOCKET, SOCK_DGRAM, SO_BROADCAST, SO_REUSEADDR)
from struct import unpack, pack, pack_into
import random
import threading
# In case soundswitch is running on different pc you can leave "0.0.0.0",
# but in case its on the same machine, you need to have adittional interface,
# could be logical one (loopback), and then you need to define here ip of that interface.
# also it has to be started before soundswitch.

UDP_IP = "0.0.0.0" # listen on all sockets- INADDR_ANY

UDP_PORT = 6454 #0x1936 # Art-net is supposed to only use this port

# broadcast ip of same interface which you are using to bind
#BROADCAST_IP = "10.4.20.63"
BROADCAST_IP = "10.4.20.127"
#BROADCAST_IP = "255.255.255.255"



# list of ip's which you want soundswitch would detect as Artnet/DMX nodes
LIST_OF_IPs_FOR_ADVERTISMENT = [
#    "10.4.20.22",
#    "10.4.20.28",
   "10.4.20.29",
   "10.4.20.140",
#    "10.4.20.14",
#    "10.4.20.40",
#    "10.4.20.41"
]

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
        sort_name = "MyArtnet"
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


        if ip not in self.macs_dict.keys():
            mac = self.gen_mac()
            self.macs_dict[ip] = mac

        else:
            mac = self.macs_dict[ip]

        macSet = []
        tmpList = mac.split(":")

        for item in tmpList:
            macSet.append(int(f'0x{item}',16))
        pack_into(  "BBBBBB", packet, offset, *tuple(macSet))

        offset += 6

        bind_ip_address = UDP_IP
        # adding ip
        ipSet = []
        octets = bind_ip_address.split(".")
        for item in octets:
            ipSet.append(int(item))
        pack_into("!HHHH", packet, offset, *tuple(ipSet))
        offset += 4

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

            time.sleep(1)

        except KeyboardInterrupt:
            pass
            sock.close()
            sys.exit()


def cb():
    pass

def arntet_worker():
  artnet_receiver(callBack=cb, UNIV=0)

art = threading.Thread(target=arntet_worker, args=())
art.start()
start_pool_packets=False
pool_packet_time=None

while True:
    if time.time() > lastTime + 5 and start_pool_packets == False:
        print("have not received pool packet for 5 seconds, will start to send anyway every 2.5 seconds..")
        start_pool_packets=True
        pool_packet_time = time.time()

    if start_pool_packets == True and time.time() > pool_packet_time + 2.5:
        pool_packet_time = time.time()
        print("sent")
        for adv_ip in LIST_OF_IPs_FOR_ADVERTISMENT:
            a.send_pollreply(a.pollreplay(adv_ip))
    time.sleep(1)
#if __name__ == "__main__":
#    artnet_receiver()



