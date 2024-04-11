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
        self.eth_key = None
        self.arp_key = None
        self.ip4_key = None
        self.icmp4_key = None
        self.ip6_key = None
        self.icmp6_key = None
        self.tcp_key = None
        self.udp_key = None

        self.ethh = self.get_header(self.packet_buff, 0, ethheader) #self.get_eth_header(self.packet_buff, 0)
        if self.ethh != None:
            self.protocols["ethernet"] = self.ethh
            self.eth_key = (self.ethh.dstaddr, self.ethh.srcaddr, self.ethh.ethtype)
        
        match (self.ethh.ethtype).lower():
            case '0x806': #ARP_PROTO
                self.arph = self.get_header(self.packet_buff, ETHHDRLEN, arpheader)
                if self.arph != None:
                    match self.arph.proto_type:
                        case 0x800: ##ipv4
                            srcip = socket.inet_ntoa(struct.pack('!L', self.arph.proto_src_addrb))
                            dstip = socket.inet_ntoa(struct.pack('!L', self.arph.proto_dst_addrb))
                        case 0x86DD: ##ipv6
                            srcip = socket.inet_ntop(socket.AF_INET6, (struct.pack('!L', self.arph.proto_src_addrb)))
                            dstip = socket.inet_ntop(socket.AF_INET6, (struct.pack('!L', self.arph.proto_dst_addrb)))
                        case other: ##not ipv4 or ipv6
                            srcip = '-'
                            dstip = '-'
                    self.protocols["arp"] = self.arph
                    self.arp_key = (self.arph.srcmac, srcip, self.arph.dstmac, dstip, self.arph.opcode)
            case '0x800':
                self.ip4h = self.get_header(self.packet_buff, ETHHDRLEN, ip4header)
                if self.ip4h != None:
                    self.protocols["ip4"] = self.ip4h
                    # srcip = socket.inet_ntoa(self.ip4h.srcaddrb)
                    # dstip = socket.inet_ntoa(self.ip4h.dstaddrb)
                    self.ip4_key = (self.ip4h.srcaddrb, self.ip4h.dstaddrb, self.ip4h.datagrambytes)
                    match self.ip4h.proto:
                        case 1:
                            self.icmp4h = self.get_header(self.packet_buff, ETHHDRLEN + self.ip4h.iphdrlen, icmp4header)
                            if self.icmp4h != None:
                                self.protocols["icmp4"] = self.icmp4h
                                if self.icmp4h.ip4header != None:
                                    icmp_ipheader = self.get_header(self.icmp4h.ip4header, 0, ip4header)
                                    if icmp_ipheader != None:
                                        match icmp_ipheader.proto:
                                            case 6:
                                                icmp_tcpheader = self.get_header(self.icmp4h.datagrambytes, 0, tcpheader)
                                                if icmp_tcpheader != None:
                                                    # print("ICMP IP header: ", icmp_ipheader.srcaddrb, icmp_ipheader.dstaddrb, icmp_ipheader.proto, icmp_tcpheader.srcport, icmp_tcpheader.dstport)
                                                    self.icmp4_key = (self.icmp4h.type, self.icmp4h.code, icmp_ipheader.srcaddrb, icmp_ipheader.dstaddrb, icmp_ipheader.proto, icmp_tcpheader.srcport, icmp_tcpheader.dstport, self.icmp4h.verbose)
                                            case 17:
                                                icmp_udpheader = self.get_header(self.icmp4h.datagrambytes, 0, udpheader)
                                                if icmp_udpheader != None:
                                                    # print("ICMP IP header: ", icmp_ipheader.srcaddrb, icmp_ipheader.dstaddrb, icmp_ipheader.proto, icmp_udpheader.srcport, icmp_udpheader.dstport)
                                                    self.icmp4_key = (self.icmp4h.type, self.icmp4h.code, icmp_ipheader.srcaddrb, icmp_ipheader.dstaddrb, icmp_ipheader.proto, icmp_udpheader.srcport, icmp_udpheader.dstport, self.icmp4h.verbose)
                                            case other:
                                                self.icmp4_key = (self.icmp4h.type, self.icmp4h.code, self.icmp4h.verbose)
                                    else:
                                        self.icmp4_key = (self.icmp4h.type, self.icmp4h.code, self.icmp4h.verbose)
                                else:
                                    self.icmp4_key = (self.icmp4h.type, self.icmp4h.code, self.icmp4h.verbose)
                                
                        case 6:
                            self.tcph = self.get_header(self.packet_buff, ETHHDRLEN + self.ip4h.iphdrlen, tcpheader)
                            if self.tcph != None:
                                self.protocols["tcp"] = self.tcph
                                self.tcp_key = (self.ip4h.srcaddrb, self.tcph.srcport, self.ip4h.dstaddrb, self.tcph.dstport)
                        case 17:
                            self.udph = self.get_header(self.packet_buff, ETHHDRLEN + self.ip4h.iphdrlen, udpheader)
                            if self.udph != None:
                                self.protocols["udp"] = self.udph
                                self.udp_key = (self.udph.srcport, self.udph.dstport)     
            case '0x86dd':
                self.ip6h = self.get_header(self.packet_buff, ETHHDRLEN, ip6header)
                if self.ip6h != None:
                    self.protocols["ip6"] =  self.ip6h
                    # srcip = socket.inet_ntop(socket.AF_INET6, self.ip6h.srcaddrb)
                    # dstip = socket.inet_ntop(socket.AF_INET6, self.ip6h.dstaddrb)
                    self.ip6_key = (self.ip6h.flowlabel, self.ip6h.srcaddrb, self.ip6h.dstaddrb)
                
                    if (self.ip6h.nextheader == hex(ICMPV6_PROTO)):
                        self.icmp6h = self.get_header(self.packet_buff, ETHHDRLEN + 40, icmp6header)
                        if self.icmp6h != None:
                            self.protocols["icmp6"] = self.icmp6h
                            self.icmp6_key = (self.icmp6h.type, self.icmp6h.code, self.icmp6h.verbose)

                    if (self.ip6h.extheaders != [] and (self.ip6h.extheaders[-1][0] == hex(ICMPV6_PROTO)[2:])): ##extract value from tuple
                        self.icmp6h = self.get_header(self.packet_buff, ETHHDRLEN + (self.ip6h.extheaders[-1][1]), icmp6header)
                        if self.icmp6h != None:
                            self.protocols["icmp6"] = self.icmp6h
                            self.icmp6_key = (self.icmp6h.type, self.icmp6h.code, self.icmp6h.verbose)

                    if (self.ip6h.nextheader == hex(TCP_PROTO)):
                        self.tcph = self.get_header(self.packet_buff, ETHHDRLEN + 40, tcpheader)
                        if self.tcph != None:
                            self.protocols["tcp"] = self.tcph
                            self.tcp_key = (self.ip6h.srcaddrb, self.tcph.srcport, self.ip6h.dstaddrb, self.tcph.dstport)

                    if (self.ip6h.extheaders != [] and (self.ip6h.extheaders[-1][0] == hex(TCP_PROTO)[2:])): ##extract value from tuple
                        self.tcph = self.get_header(self.packet_buff, ETHHDRLEN + (self.ip6h.extheaders[-1][1]), tcpheader)
                        if self.tcph != None:
                            self.protocols["tcp"] = self.tcph
                            self.tcp_key = (self.ip6h.srcaddrb, self.tcph.srcport, self.ip6h.dstaddrb, self.tcph.dstport)

                    if (self.ip6h.nextheader == hex(UDP_PROTO)):
                        self.udph = self.get_header(self.packet_buff, ETHHDRLEN + 40, udpheader)
                        if self.udph != None:
                            self.protocols["udp"] = self.udph
                            self.udp_key = (self.udph.srcport, self.udph.dstport)     
                    
                    if (self.ip6h.extheaders != [] and (self.ip6h.extheaders[-1][0] == hex(UDP_PROTO)[2:])): ##extract value from tuple
                        self.udph = self.get_header(self.packet_buff, ETHHDRLEN + (self.ip6h.extheaders[-1][1]), udpheader)
                        if self.udph != None:
                            self.protocols["udp"] = self.udph
                            self.udp_key = (self.udph.srcport, self.udph.dstport)     
            
    def get_protocols(self):
        return (self.packet_num, self.protocols)

    def get_header(self, packet_buff, start_pos, protocol_header):
        header = protocol_header.read(packet_buff, start_pos)
        if not header:
            return None
        return header

    def get_eth_key(self):
        if self.eth_key != None:
            return self.eth_key
    
    def get_arp_key(self):
        if self.arp_key != None:
            return self.arp_key
    
    def get_ip4_key(self):
        if self.ip4_key != None:
            return self.ip4_key
    
    def get_ip6_key(self):
        if self.ip6_key != None:
            return self.ip6_key 

    def get_icmp4_key(self):
        if self.icmp4_key != None:
            return self.icmp4_key

    def get_icmp6_key(self):
        if self.icmp6_key != None:
            return self.icmp6_key
    
    def get_tcp_key(self):
        if self.tcp_key != None:
            return self.tcp_key
        
    def get_udp_key(self):
        if self.udp_key != None:
            return self.udp_key

class pcap:
    def __init__(self, filename : str):
        PACKET_COUNT = 0
        self.fname = filename
        self.stream_dicts = connections()
        self.icmp4_rev_dict = {}
        self.packet_headers = {}
        self.ip4_dict = {}
        for length, time, pktbuf in rpcap(self.fname):		# here we examine each packet
            PACKET_COUNT += 1
            single_packet = packet(PACKET_COUNT, length, time, pktbuf)
            single_packet_num, single_packet_protocols = single_packet.get_protocols()
            self.packet_headers[single_packet_num] = single_packet_protocols
            for connection_name, connection_dict in self.stream_dicts.get_connections():
                key = None
                if connection_name.lower() in single_packet_protocols:
                    if connection_name == "ETHERNET":
                        key = single_packet.get_eth_key()
                    if connection_name == "ARP":
                        key = single_packet.get_arp_key()
                    if connection_name == "IP4":
                        key = single_packet.get_ip4_key()[0:2]
                        self.ip4_dict[single_packet_num] = single_packet.get_ip4_key()
                    if connection_name == "IP6":
                        key = single_packet.get_ip6_key()
                    if connection_name == "ICMP4":
                        key = single_packet.get_icmp4_key()
                    if connection_name == "ICMP6":
                        key = single_packet.get_icmp6_key()
                    if connection_name == "TCP":
                        key = single_packet.get_tcp_key()
                    if connection_name == "UDP":
                        key = single_packet.get_udp_key()
                    
                if key != None:
                    self.add_to_stream(single_packet_num, pktbuf, key, connection_dict)


    def add_to_stream(self, packet_num, pktbuf, key, connectiondict):
        if key in connectiondict:
            connectiondict[key].append([packet_num, pktbuf])
        else:
            connectiondict[key] = [[packet_num, pktbuf]]

    def get_connections(self):
        return self.stream_dicts.get_connections()
    
    def get_packet_headers(self):
        return self.packet_headers

    def get_ip4_datagrambytes(self):
        return self.ip4_dict

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
                # parsed_pcap = pcap(FILENAME)
                # for name, connection in parsed_pcap.get_connections():
                #     print(name)
                #     for key in connection:
                #         print(key, [connection[key][i][0] for i in range(len(connection[key]))])
                for length, time, pktbuf in rpcap(FILENAME):		# here we examine each packet
                    PACKET_COUNT += 1
                    num_protocols = packet(PACKET_COUNT, length, time, pktbuf).get_protocols()
                    packet_num = num_protocols[0]
                    protocols = num_protocols[1]
                    protocols_attributes = {}
                    for key in protocols:
                        protocols_attributes[key] = vars(protocols[key])
                    print(packet_num, protocols_attributes)
            
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
