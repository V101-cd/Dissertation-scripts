'''
For each connection, this lists the number of UPstream packets. It also prints the total number of connections

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

# LOCALADDR='192.168.4.5'	# the client IP address
# LOCALADDRB = socket.inet_aton(LOCALADDR)
    
def process_packets(fname):
    global PACKET_COUNT
    sum = 0
    count=0
    for length, time, pktbuf in rpcap(fname):		# here is where we examine each packet
        PACKET_COUNT += 1
        process_one_pkt(PACKET_COUNT, length, time, pktbuf, ETHHDRLEN)

def process_one_pkt(packet_num, length, time, pktbuf : bytes, startpos):
    ethh= ethheader.read(pktbuf, 0)
    eth_key = (ethh.dstaddr, ethh.srcaddr, ethh.ethtype)
    add_to_stream(packet_num, pktbuf, eth_key, stream_dicts.ETHERNET_CONNECTIONDICT)
    match ethh.ethtype:
        case 0x0800:
            iph = ip4header.read(pktbuf, ETHHDRLEN)
            if not iph: return 
            ipv4_key = (iph.srcaddrb, iph.dstaddrb)
            add_to_stream(packet_num, pktbuf, ipv4_key, stream_dicts.IPV4_CONNECTIONDICT)
            if iph.proto == UDP_PROTO: 
                udph = udpheader.read(pktbuf, ETHHDRLEN + iph.iphdrlen)
                # if udph.dstport == 53: print('DNS packet')
                udp_key = (udph.srcport, udph.dstport)
                add_to_stream(packet_num, pktbuf, udp_key, stream_dicts.UDP_CONNECTIONDICT)
                return 
            if iph.proto == TCP_PROTO:
                tcph = tcpheader.read(pktbuf, ETHHDRLEN + iph.iphdrlen)	# here we *do* allow for the possibility of header options
                if not tcph: return	 # Again, tcpheader.read() returns None if it doesn't look like a TCP packet
                datalen = iph.length - iph.iphdrlen -tcph.tcphdrlen	# can't use len(pktbuf) because of tcpdump-applied trailers
                localport   = tcph.srcport
                remoteport  = tcph.dstport
                remoteaddrb = iph.dstaddrb
                tcp_key = (iph.srcaddrb, localport, remoteaddrb, remoteport)
                add_to_stream(packet_num, pktbuf, tcp_key, stream_dicts.TCP_CONNECTIONDICT)
                return
            if iph.proto == ICMPV4_PROTO:
                icmph = icmp4header.read(pktbuf, ETHHDRLEN + iph.iphdrlen)
                # icmph_key = (icmph.type, icmph.code, icmph.ip4header, icmph.datagrambytes)
                icmph_key = (icmph.type, icmph.code, icmph.verbose)
                add_to_stream(packet_num, pktbuf, icmph_key, stream_dicts.ICMP_V4_CONNECTIONDICT)
                return
        case 0x86DD:
            ip6h = ip6header.read(pktbuf, ETHHDRLEN)
            srcip = socket.inet_ntop(socket.AF_INET6, ip6h.srcaddrb)
            dstip = socket.inet_ntop(socket.AF_INET6, ip6h.dstaddrb)
            ipv6_key = (ip6h.flowlabel, srcip, dstip)
            add_to_stream(packet_num, pktbuf, ipv6_key, stream_dicts.IPV6_CONNECTIONDICT)
            if (ip6h.nextheader == hex(UDP_PROTO)[2:]):
                udph = udpheader.read(pktbuf, ETHHDRLEN + 40)
                # if udph.dstport == 53: print('DNS packet')
                udp_key = (udph.srcport, udph.dstport)
                add_to_stream(packet_num, pktbuf, udp_key, stream_dicts.UDP_CONNECTIONDICT)
                return
            if (ip6h.extheaders != [] and (ip6h.extheaders[-1][0] == hex(UDP_PROTO)[2:])): ##extract value from tuple
                # print(packet_num, ": IPv6 with UDP in extension headers")
                udph = udpheader.read(pktbuf, ETHHDRLEN + (ip6h.extheaders[-1][1]))
                # if udph.dstport == 53: print('DNS packet')
                udp_key = (udph.srcport, udph.dstport)
                add_to_stream(packet_num, pktbuf, udp_key, stream_dicts.UDP_CONNECTIONDICT)
                return
            if (ip6h.nextheader == hex(TCP_PROTO)[2:]):
                # print(packet_num, ": IPv6 with TCP")
                tcph = tcpheader.read(pktbuf, ETHHDRLEN + 40)
                localport   = tcph.srcport
                remoteport  = tcph.dstport
                remoteaddrb = ip6h.dstaddrb
                tcp_key = (ip6h.srcaddrb, localport, remoteaddrb, remoteport)
                add_to_stream(packet_num, pktbuf, tcp_key, stream_dicts.TCP_CONNECTIONDICT)

            if (ip6h.extheaders != [] and (ip6h.extheaders[-1][0] == hex(TCP_PROTO)[2:])): ##extract value from tuple
                # print(packet_num, ": IPv6 with TCP in extension headers")
                tcph = tcpheader.read(pktbuf, ETHHDRLEN + (ip6h.extheaders[-1][1]))
                localport   = tcph.srcport
                remoteport  = tcph.dstport
                remoteaddrb = ip6h.dstaddrb
                tcp_key = (ip6h.srcaddrb, localport, remoteaddrb, remoteport)
                add_to_stream(packet_num, pktbuf, tcp_key, stream_dicts.TCP_CONNECTIONDICT)
                return
                
            if (ip6h.nextheader == hex(ICMPV6_PROTO)[2:]):
                # print(packet_num, ": IPv6 with ICMPv6")
                icmp6h = icmp6header.read(pktbuf, ETHHDRLEN + 40)
                icmp6h_key = (icmp6h.type, icmp6h.code, icmp6h.verbose)
                add_to_stream(packet_num, pktbuf, icmp6h_key, stream_dicts.ICMP_V6_CONNECTIONDICT)
                return

            if (ip6h.extheaders != [] and (ip6h.extheaders[-1][0] == hex(ICMPV6_PROTO)[2:])): ##extract value from tuple
                # print(packet_num, ": IPv6 with ICMPv6 in extension headers",ip6h.extheaders[-1][0], ip6h.extheaders[-1][1])
                icmp6h = icmp6header.read(pktbuf, ETHHDRLEN + (ip6h.extheaders[-1][1]))
                icmp6h_key = (icmp6h.type, icmp6h.code, icmp6h.verbose)
                add_to_stream(packet_num, pktbuf, icmp6h_key, stream_dicts.ICMP_V6_CONNECTIONDICT)
                return

        case 0x0806: #ARP_PROTO
            arph = arpheader.read(pktbuf, ETHHDRLEN)
            match arph.proto_type:
                case 0x800: ##ipv4
                    srcip = socket.inet_ntoa(struct.pack('!L', arph.proto_src_addrb))
                    dstip = socket.inet_ntoa(struct.pack('!L', arph.proto_dst_addrb))
                case 0x86DD: ##ipv6
                    srcip = socket.inet_ntop(socket.AF_INET6, (struct.pack('!L', arph.proto_src_addrb)))
                    dstip = socket.inet_ntop(socket.AF_INET6, (struct.pack('!L', arph.proto_dst_addrb)))
                case other: ##not ipv4 or ipv6
                    srcip = '-'
                    dstip = '-'
            arp_key = (arph.srcmac, srcip, arph.dstmac, dstip, arph.opcode)
            add_to_stream(packet_num, pktbuf, arp_key, stream_dicts.ARP_CONNECTIONDICT)
        case other:
            print(packet_num, ": protocol not recognised")
            return None		# ignore other packets

def add_to_stream(packet_num, pktbuf, key, connectiondict):
    if key in connectiondict:
        connectiondict[key].append([packet_num, pktbuf])
    else:
        connectiondict[key] = [[packet_num, pktbuf]]

def dumpdict(d, dict_name):		# d[key] is a list of packets
    for key in d:
        match dict_name:
            case "TCP":
                (laddrb, lport, raddrb, rport) = key
                # print('\n({},{},{},{}): {} packets'.format(socket.inet_ntoa(laddrb), lport, socket.inet_ntoa(raddrb), rport, [d[key][i][0] for i in range(len(d[key]))]))
            case "UDP":
                (lport, rport) = key
                # print('\n({},{}): {} packets'.format(lport, rport, [d[key][i][0] for i in range(len(d[key]))]))
            case "IPv4":
                (laddrb, raddrb) = key
                # print('\n({},{}): {} packets'.format(socket.inet_ntoa(laddrb), socket.inet_ntoa(raddrb), [d[key][i][0] for i in range(len(d[key]))]))
            case "IPv6":
                (flowlabel, laddrb, raddrb) = key
                # print('\n({},{},{}): {} packets'.format(flowlabel, laddrb, raddrb, [d[key][i][0] for i in range(len(d[key]))]))
            case "Ethernet":
                (laddrb, raddrb, ptype) = key
                # print('\n({},{},{}): {} packets'.format(laddrb, raddrb, ptype, [d[key][i][0] for i in range(len(d[key]))]))
            case "ARP":
                (srcmac, srcip, dstmac, dstip, opcode) = key
                # print('\n({},{},{},{},{}): {} packets'.format(srcmac, srcip, dstmac, dstip, opcode, [d[key][i][0] for i in range(len(d[key]))]))
            case "ICMPv4":
                (ptype, pcode, pverbose) = key
                # print('\n({},{},{}): {} packets'.format(ptype, pcode, pverbose, [d[key][i][0] for i in range(len(d[key]))]))
            case "ICMPv6":
                (ptype, pcode, pverbose) = key
                # print('\n({},{},{}): {} packets'.format(ptype, pcode, pverbose, [d[key][i][0] for i in range(len(d[key]))]))
    print('There were {} unique {} connections'.format(len(d), dict_name))
    print('There were {} packets captured in {}'.format(PACKET_COUNT, FILENAME))

# try:
num_packets = len(sys.argv)-1
for i in range(num_packets): ##don't include the python script
    INPUT_PCAPS.append(sys.argv[i+1]) ##first index is the tool itself
input_pcaps = set(INPUT_PCAPS) #remove duplicate pcaps
print(input_pcaps)
if len(input_pcaps) > 0:
    print(f"You have entered {len(input_pcaps)} unique files to be parsed.\n")
    for pcap in input_pcaps:
        stream_dicts = connections() #re-initialise the connection dictionaries
        PACKET_COUNT = 0 #re-initialise the packet counter
        print("\n\n", pcap)
        pcap_name = pcap.split('.')
        if pcap.split('.')[-1].lower() != 'pcap':
            print(f"File {pcap} not a pcap. Aborting.\n")
        else:
            FILENAME = pcap
            process_packets(FILENAME)

            try:
                dumpdict(stream_dicts.TCP_CONNECTIONDICT, "TCP")
            except:
                print("TCP stream could not be analysed")
            try:
                dumpdict(stream_dicts.UDP_CONNECTIONDICT, "UDP")
            except:
                print("UDP stream could not be analysed")
            try:
                dumpdict(stream_dicts.IPV4_CONNECTIONDICT, "IPv4")
            except:
                print("IPv4 stream could not be analysed")
            try:
                dumpdict(stream_dicts.ICMP_V4_CONNECTIONDICT, "ICMPv4")
            except:
                print("ICMPv4 stream could not be analysed")
            try:
                dumpdict(stream_dicts.IPV6_CONNECTIONDICT, "IPv6")
            except:
                print("IPv6 stream could not be analysed")
            try:
                dumpdict(stream_dicts.ICMP_V6_CONNECTIONDICT, "ICMPv6")
            except:
                print("ICMPv6 stream could not be analysed")
            try:
                dumpdict(stream_dicts.ARP_CONNECTIONDICT, "ARP")
            except:
                print("ARP stream could not be analysed")
            try:
                dumpdict(stream_dicts.ETHERNET_CONNECTIONDICT, "Ethernet")
            except:
                print("Ethernet stream could not be analysed")
        
            eth_sum = 0
            for key in stream_dicts.ETHERNET_CONNECTIONDICT.keys():
                eth_sum += len(stream_dicts.ETHERNET_CONNECTIONDICT[key])
            print("eth_sum: ", eth_sum)

            arp_sum = 0
            for key in stream_dicts.ARP_CONNECTIONDICT.keys():
                arp_sum += len(stream_dicts.ARP_CONNECTIONDICT[key])
            print("arp_sum: ", arp_sum)

            ipv4_sum = 0
            for key in stream_dicts.IPV4_CONNECTIONDICT.keys():
                ipv4_sum += len(stream_dicts.IPV4_CONNECTIONDICT[key])
            print("ip4 sum: ", ipv4_sum)

            ipv6_sum = 0
            for key in stream_dicts.IPV6_CONNECTIONDICT.keys():
                ipv6_sum += len(stream_dicts.IPV6_CONNECTIONDICT[key])
            print("ip6 sum: ", ipv6_sum)

            tcp_sum = 0
            for key in stream_dicts.TCP_CONNECTIONDICT.keys():
                tcp_sum += len(stream_dicts.TCP_CONNECTIONDICT[key])
            print("tcp_sum: ", tcp_sum)

            udp_sum = 0
            for key in stream_dicts.UDP_CONNECTIONDICT.keys():
                udp_sum += len(stream_dicts.UDP_CONNECTIONDICT[key])
            print("udp_sum: ", udp_sum)

            icmpv4_sum = 0
            for key in stream_dicts.ICMP_V4_CONNECTIONDICT.keys():
                icmpv4_sum += len(stream_dicts.ICMP_V4_CONNECTIONDICT[key])
            print("icmp4 sum: ", icmpv4_sum)

            icmpv6_sum = 0
            for key in stream_dicts.ICMP_V6_CONNECTIONDICT.keys():
                icmpv6_sum += len(stream_dicts.ICMP_V6_CONNECTIONDICT[key])
            print("icmp6 sum: ", icmpv6_sum)

            print(arp_sum + tcp_sum + udp_sum + icmpv4_sum + icmpv6_sum)
