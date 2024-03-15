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
            if not iph: return					# returns None if it doesn't look like an IPv4 packet
            if iph.proto == UDP_PROTO: 
                udph = udpheader.read(pktbuf, ETHHDRLEN + iph.iphdrlen)
                # if udph.dstport == 53: print('DNS packet')
                udp_key = (udph.srcport, udph.dstport)
                add_to_stream(packet_num, pktbuf, udp_key, stream_dicts.UDP_CONNECTIONDICT)
                # return
            if iph.proto != TCP_PROTO: return # ignore if not TCP_PROTO or UDP_PROTO
            tcph = tcpheader.read(pktbuf, ETHHDRLEN + iph.iphdrlen)	# here we *do* allow for the possibility of header options
            if not tcph: return					# Again, tcpheader.read() returns None if it doesn't look like a TCP packet
            datalen = iph.length - iph.iphdrlen -tcph.tcphdrlen	# can't use len(pktbuf) because of tcpdump-applied trailers
            localport   = tcph.srcport
            remoteport  = tcph.dstport
            remoteaddrb = iph.dstaddrb
            tcp_key = (iph.srcaddrb, localport, remoteaddrb, remoteport)
            add_to_stream(packet_num, pktbuf, tcp_key, stream_dicts.TCP_CONNECTIONDICT)


            ipv4_key = (iph.srcaddrb, iph.dstaddrb)
            add_to_stream(packet_num, pktbuf, ipv4_key, stream_dicts.IPV4_CONNECTIONDICT)

        case 0x86DD:
            ip6h = ip6header.read(pktbuf, ETHHDRLEN)
            srcip = socket.inet_ntop(socket.AF_INET6, ip6h.srcaddrb)
            dstip = socket.inet_ntop(socket.AF_INET6, ip6h.dstaddrb)
            ipv6_key = (ip6h.flowlabel, srcip, dstip)
            add_to_stream(packet_num, pktbuf, ipv6_key, stream_dicts.IPV6_CONNECTIONDICT)
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
        case 0x0001: #ICMPV4_PROTO
            icmph = icmp4header.read(pktbuf, ETHHDRLEN)
            icmph_key = (icmph.type, icmph.code, icmph.ip4header, icmph.datagrambytes)
            print(icmph_key)
            add_to_stream(packet_num, pktbuf, icmph_key, stream_dicts.ICMP_V4_CONNECTIONDICT)
        case 0x003A: #ICMPV6_PROTO
            pass
        case other: return None		# ignore other packets

def add_to_stream(packet_num, pktbuf, key, connectiondict):
    if key in connectiondict:
        connectiondict[key].append([packet_num, pktbuf])
    else:
        connectiondict[key] = [[packet_num, pktbuf]]

def dumpdict(d, dict_name):		# d[key] is a list of packets
    
    for key in d:
        match dict_name:
        #     case "TCP":
        #         (laddrb, lport, raddrb, rport) = key
        #         print('\n({},{},{},{}): {} packets'.format(socket.inet_ntoa(laddrb), lport, socket.inet_ntoa(raddrb), rport, len(d[key])))
        #     case "UDP":
        #         (lport, rport) = key
        #         print('\n({},{}): {} packets'.format(lport, rport, len(d[key])))
            # case "IPv4":
            #     (laddrb, raddrb) = key
            #     print('\n({},{}): {} packets'.format(socket.inet_ntoa(laddrb), socket.inet_ntoa(raddrb), len(d[key])))
            case "IPv6":
                (flowlabel, laddrb, raddrb) = key
                print('\n({},{},{}): {} packets'.format(flowlabel, laddrb, raddrb, d[key]))
            # case "Ethernet":
        #         (laddrb, raddrb, ptype) = key
        #         print('\n({},{},{}): {} packets'.format(laddrb, raddrb, ptype, len(d[key])))
            case "ARP":
                (srcmac, srcip, dstmac, dstip, opcode) = key
                print('\n({},{},{},{},{}): {} packets'.format(srcmac, srcip, dstmac, dstip, opcode, len(d[key])))
            case "ICMP":
                pass
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
                dumpdict(stream_dicts.IPV6_CONNECTIONDICT, "ICMPv6")
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
        
    # else:
    #     print(f"Error. At least one file needed to run. Aborting.\n")
    # print("No more files to be analysed. Exiting\n")
# except:
#     print("Error. Need to pass in at least one file to be analysed. Aborting\n")

# process_packets(FILENAME)
# # dumpdict(TCP_CONNECTIONDICT, "TCP")
# # dumpdict(UDP_CONNECTIONDICT, "UDP")
# # dumpdict(IPV4_CONNECTIONDICT, "IPv4")
# dumpdict(ETHERNET_CONNECTIONDICT, "Ethernet")
# dumpdict(IPV6_CONNECTIONDICT, "IPv6")