'''
Based on code by Peter L Dordal, http://pld.cs.luc.edu/courses/451/prev/project5/, specifically connection1.py. Accessed 23 February 2024
'''

from pylibpcap.pcap import rpcap
import socket
import struct
from packet_headers import *
from stream_dictionaries import connections
# from icecream import ic		# useful debugging tool, but optional

FILENAME=''
INPUT_PCAPS= []
PACKET_COUNT = 0

class packet:
    def __init__(self, packet_num, length, time, packet_buff: bytes):
        self.packet_num = packet_num
        self.length = length
        self.time = time
        self.packet_buff = packet_buff

        self.protocols = {}

        self.ethh = self.get_header(self.packet_buff, 0, ethheader) #self.get_eth_header(self.packet_buff, 0)
        if self.ethh != None:
            self.protocols["ethernet"] = self.ethh

        match self.ethh.ethtype:
            case 0x0806: #ARP_PROTO
                self.arph = self.get_header(self.packet_buff, ETHHDRLEN, arpheader)
                if self.arph != None:
                    match self.arph.proto_type:
                        case 0x800: ##ipv4
                            self.arph.proto_src_addrb = socket.inet_ntoa(struct.pack('!L', self.arph.proto_src_addrb))
                            self.arph.proto_dst_addrb = socket.inet_ntoa(struct.pack('!L', self.arph.proto_dst_addrb))
                        case 0x86DD: ##ipv6
                            self.arph.proto_src_addrb = socket.inet_ntop(socket.AF_INET6, (struct.pack('!L', self.arph.proto_src_addrb)))
                            self.arph.proto_dst_addrb = socket.inet_ntop(socket.AF_INET6, (struct.pack('!L', self.arph.proto_dst_addrb)))
                        case other: ##not ipv4 or ipv6
                            self.arph.proto_src_addrb = '-'
                            self.arph.proto_dst_addrb = '-'
                    self.protocols["arp"] = self.arph
            case 0x0800:
                self.ip4h = self.get_header(self.packet_buff, ETHHDRLEN, ip4header) #self.get_ip4_header(self.packet_buff, ETHHDRLEN)
                if self.ip4h != None:
                    self.protocols["ip4"] = self.ip4h
                    match self.ip4h.proto:
                        case 1:
                            self.icmp4h = self.get_header(self.packet_buff, ETHHDRLEN + self.ip4h.iphdrlen, icmp4header)
                            if self.icmp4h != None:
                                self.protocols["icmp4"] = self.icmp4h
                        case 6:
                            self.tcph = self.get_header(self.packet_buff, ETHHDRLEN + self.ip4h.iphdrlen, tcpheader)
                            if self.tcph != None:
                                self.protocols["tcp"] = self.tcph
                        case 17:
                            self.udph = self.get_header(self.packet_buff, ETHHDRLEN + self.ip4h.iphdrlen, udpheader)
                            if self.udph != None:
                                self.protocols["udp"] = self.udph           
            case 0x86DD:
                self.ip6h = self.get_header(self.packet_buff, ETHHDRLEN, ip6header)
                # srcip = socket.inet_ntop(socket.AF_INET6, ip6h.srcaddrb)
                # dstip = socket.inet_ntop(socket.AF_INET6, ip6h.dstaddrb)
                if self.ip6h != None:
                    self.protocols["ip6"] =  self.ip6h
                
                    if (self.ip6h.nextheader == hex(ICMPV6_PROTO)[2:]):
                        self.icmp6h = self.get_header(self.packet_buff, ETHHDRLEN + 40, icmp6header)
                        if self.icmp6h != None:
                            self.protocols["icmp6"] = self.icmp6h

                    if (self.ip6h.extheaders != [] and (self.ip6h.extheaders[-1][0] == hex(ICMPV6_PROTO)[2:])): ##extract value from tuple
                        self.icmp6h = self.get_header(self.packet_buff, ETHHDRLEN + (self.ip6h.extheaders[-1][1]), icmp6header)
                        if self.icmp6h != None:
                            self.protocols["icmp6"] = self.icmp6h

                    if (self.ip6h.nextheader == hex(TCP_PROTO)[2:]):
                        self.tcph = self.get_header(self.packet_buff, ETHHDRLEN + 40, tcpheader)
                        if self.tcph != None:
                            self.protocols["tcp"] = self.tcph

                    if (self.ip6h.extheaders != [] and (self.ip6h.extheaders[-1][0] == hex(TCP_PROTO)[2:])): ##extract value from tuple
                        self.tcph = self.get_header(self.packet_buff, ETHHDRLEN + (self.ip6h.extheaders[-1][1]), tcpheader)
                        if self.tcph != None:
                            self.protocols["tcp"] = self.tcph

                    if (self.ip6h.nextheader == hex(UDP_PROTO)[2:]):
                        self.udph = self.get_header(self.packet_buff, ETHHDRLEN + 40, udpheader)
                        if self.udph != None:
                            self.protocols["udp"] = self.udph
                    
                    if (self.ip6h.extheaders != [] and (self.ip6h.extheaders[-1][0] == hex(UDP_PROTO)[2:])): ##extract value from tuple
                        self.udph = self.get_header(self.packet_buff, ETHHDRLEN + (self.ip6h.extheaders[-1][1]), udpheader)
                        if self.udph != None:
                            self.protocols["udp"] = self.udph
            
    def get_protocols(self):
        return (self.packet_num, self.protocols)

    def get_header(self, packet_buff, start_pos, protocol_header):
        header = protocol_header.read(packet_buff, start_pos)
        if not header:
            return None
        return header

class pcap:
    def __init__(self, filename : str):
        PACKET_COUNT = 0
        self.fname = filename
        self.stream_dicts = connections()
        for length, time, pktbuf in rpcap(self.fname):		# here we examine each packet
            PACKET_COUNT += 1
            single_packet_num, single_packet_protocols = packet(PACKET_COUNT, length, time, pktbuf).get_protocols()
            for connection_name, connection_dict in self.stream_dicts.get_connections():
                key = None
                if connection_name.lower() in single_packet_protocols:
                    if connection_name.lower() == "ethernet":
                        key = (single_packet_protocols["ethernet"].dstaddr, single_packet_protocols["ethernet"].srcaddr, single_packet_protocols["ethernet"].ethtype)
                    if key != None:
                        self.add_to_stream(single_packet_num, pktbuf, key, connection_dict)

    def add_to_stream(self, packet_num, pktbuf, key, connectiondict):
        if key in connectiondict:
            connectiondict[key].append([packet_num, pktbuf])
        else:
            connectiondict[key] = [[packet_num, pktbuf]]

    def get_connections(self):
        return self.stream_dicts.get_connections()

def print_from_terminal():
    num_packets = len(sys.argv)-1
    for i in range(num_packets): ##don't include the python script
        INPUT_PCAPS.append(sys.argv[i+1]) ##first index is the tool itself
    input_pcaps = set(INPUT_PCAPS) #remove duplicate pcaps
    print(input_pcaps)
    if len(input_pcaps) > 0:
        print(f"You have entered {len(input_pcaps)} unique files to be parsed.\n")
        for single_pcap in input_pcaps:
            PACKET_COUNT = 0 #re-initialise the packet counter
            stream_dicts = connections() #re-initialise the connection dictionaries
            print("\n\n", single_pcap)
            pcap_name = single_pcap.split('.')
            if single_pcap.split('.')[-1].lower() != 'pcap':
                print(f"File {single_pcap} not a pcap. Aborting.\n")
            else:
                FILENAME = single_pcap
                parsed_pcap = pcap(FILENAME)
                for name, connection in parsed_pcap.get_connections():
                    print(name)
                    for key in connection:
                        print(key, [connection[key][i][0] for i in range(len(connection[key]))])
                # for length, time, pktbuf in rpcap(FILENAME):		# here we examine each packet
                #     PACKET_COUNT += 1
                #     print(packet(PACKET_COUNT, length, time, pktbuf).get_protocols())
            
#                 eth_sum = 0
#                 for key in stream_dicts.ETHERNET_CONNECTIONDICT.keys():
#                     eth_sum += len(stream_dicts.ETHERNET_CONNECTIONDICT[key])
#                 print("eth_sum: ", eth_sum)

#                 arp_sum = 0
#                 for key in stream_dicts.ARP_CONNECTIONDICT.keys():
#                     arp_sum += len(stream_dicts.ARP_CONNECTIONDICT[key])
#                 print("arp_sum: ", arp_sum)

#                 ipv4_sum = 0
#                 for key in stream_dicts.IPV4_CONNECTIONDICT.keys():
#                     ipv4_sum += len(stream_dicts.IPV4_CONNECTIONDICT[key])
#                 print("ip4 sum: ", ipv4_sum)

#                 ipv6_sum = 0
#                 for key in stream_dicts.IPV6_CONNECTIONDICT.keys():
#                     ipv6_sum += len(stream_dicts.IPV6_CONNECTIONDICT[key])
#                 print("ip6 sum: ", ipv6_sum)

#                 tcp_sum = 0
#                 for key in stream_dicts.TCP_CONNECTIONDICT.keys():
#                     tcp_sum += len(stream_dicts.TCP_CONNECTIONDICT[key])
#                 print("tcp_sum: ", tcp_sum)

#                 udp_sum = 0
#                 for key in stream_dicts.UDP_CONNECTIONDICT.keys():
#                     udp_sum += len(stream_dicts.UDP_CONNECTIONDICT[key])
#                 print("udp_sum: ", udp_sum)

#                 icmpv4_sum = 0
#                 for key in stream_dicts.ICMP_V4_CONNECTIONDICT.keys():
#                     icmpv4_sum += len(stream_dicts.ICMP_V4_CONNECTIONDICT[key])
#                 print("icmp4 sum: ", icmpv4_sum)

#                 icmpv6_sum = 0
#                 for key in stream_dicts.ICMP_V6_CONNECTIONDICT.keys():
#                     icmpv6_sum += len(stream_dicts.ICMP_V6_CONNECTIONDICT[key])
#                 print("icmp6 sum: ", icmpv6_sum)

#                 print(arp_sum + tcp_sum + udp_sum + icmpv4_sum + icmpv6_sum)

# def process_from_files():
#     num_packets = len(sys.argv)-1
#     for i in range(num_packets): ##don't include the python script
#         INPUT_PCAPS.append(sys.argv[i+1]) ##first index is the tool itself
#     input_pcaps = set(INPUT_PCAPS) #remove duplicate pcaps
#     print(input_pcaps)
#     if len(input_pcaps) > 0:
#         print(f"You have entered {len(input_pcaps)} unique files to be parsed.\n")
#         for pcap in input_pcaps:
#             # PACKET_COUNT = 0 #re-initialise the packet counter
#             stream_dicts = connections() #re-initialise the connection dictionaries
#             print("\n\n", pcap)
#             pcap_name = pcap.split('.')
#             if pcap.split('.')[-1].lower() != 'pcap':
#                 print(f"File {pcap} not a pcap. Aborting.\n")
#             else:
#                 FILENAME = pcap
#                 process_packets_api(FILENAME, stream_dicts)
                    
print_from_terminal()
