'''
For each connection, this lists the number of UPstream packets. It also prints the total number of connections

Based on code by Peter L Dordal, http://pld.cs.luc.edu/courses/451/prev/project5/, specifically connection1.py. Accessed 23 February 2024
'''

from pylibpcap.pcap import rpcap
import socket
import struct
from packet_headers import *
from stream_dictionaries import *
# from icecream import ic		# useful debugging tool, but optional

FILENAME='3MWPi_wireless-router_1.pcap'

# LOCALADDR='192.168.4.5'	# the client IP address
# LOCALADDRB = socket.inet_aton(LOCALADDR)

PACKET_COUNT = 0
    
def process_packets(fname):
    global PACKET_COUNT
    sum = 0
    count=0
    for length, time, pktbuf in rpcap(fname):		# here is where we examine each packet
        process_one_pkt(PACKET_COUNT, length, time, pktbuf, ETHHDRLEN)
        PACKET_COUNT += 1

def process_one_pkt(packet_num, length, time, pktbuf : bytes, startpos):
    ethh= ethheader.read(pktbuf, 0)
    if ethh.ethtype != 0x0800: return None		# ignore non-ipv4 packets
    iph = ip4header.read(pktbuf, ETHHDRLEN)
    if not iph: return					# returns None if it doesn't look like an IPv4 packet
    if iph.proto == UDP_PROTO: 
        udph = udpheader.read(pktbuf, ETHHDRLEN + iph.iphdrlen)
        # if udph.dstport == 53: print('DNS packet')
        udp_key = (udph.srcport, udph.dstport)
        add_to_stream(packet_num, pktbuf, udp_key, UDP_CONNECTIONDICT)
        # return
    if iph.proto != TCP_PROTO: return			# ignore
    tcph = tcpheader.read(pktbuf, ETHHDRLEN + iph.iphdrlen)	# here we *do* allow for the possibility of header options
    if not tcph: return					# Again, tcpheader.read() returns None if it doesn't look like a TCP packet
    datalen = iph.length - iph.iphdrlen -tcph.tcphdrlen	# can't use len(pktbuf) because of tcpdump-applied trailers
    # print (socket.inet_ntoa(iph.srcaddrb), tcph.dstport, datalen)
    # if iph.srcaddrb == LOCALADDRB:			# source address is local endpoint
    localport   = tcph.srcport
    remoteport  = tcph.dstport
    remoteaddrb = iph.dstaddrb
        # upstream    = True
    # else:
    #     localport   = tcph.dstport
    #     remoteaddrb = iph.srcaddrb
    #     remoteport  = tcph.srcport
        # upstream    = False
    tcp_key = (iph.srcaddrb, localport, remoteaddrb, remoteport)
    # if tcp_key in TCP_CONNECTIONDICT:
    #     TCP_CONNECTIONDICT[tcp_key].append([packet_num, pktbuf])
    # else:
    #     TCP_CONNECTIONDICT[tcp_key] = [[packet_num, pktbuf]]
    add_to_stream(packet_num, pktbuf, tcp_key, TCP_CONNECTIONDICT)


    ipv4_key = (iph.srcaddrb, iph.dstaddrb)
    add_to_stream(packet_num, pktbuf, ipv4_key, IPV4_CONNECTIONDICT)

def add_to_stream(packet_num, pktbuf, key, connectiondict):
    if key in connectiondict:
        connectiondict[key].append([packet_num, pktbuf])
    else:
        connectiondict[key] = [[packet_num, pktbuf]]



 

def dumpdict(d, dict_name):		# d[key] is a list of packets
    
    for key in d:
        # (laddrb, lport, raddrb, rport, upstream) = key
        match dict_name:
            case "TCP":
                (laddrb, lport, raddrb, rport) = key
                print('\n({},{},{},{}): {} packets'.format(socket.inet_ntoa(laddrb), lport, socket.inet_ntoa(raddrb), rport, len(d[key])))
            case "UDP":
                (lport, rport) = key
                print('\n({},{}): {} packets'.format(lport, rport, len(d[key])))
            case "IPv4":
                (laddrb, raddrb) = key
                print('\n({},{}): {} packets'.format(socket.inet_ntoa(laddrb), socket.inet_ntoa(raddrb), len(d[key])))
            # print(CONNECTIONDICT[key[:5]])
        # packet_count += len(d[key])
    # print(CONNECTIONDICT[(socket.inet_aton('192.252.206.25'), 443, socket.inet_aton('192.168.4.5'), 62964)])
    print('There were {} unique {} connections'.format(len(d), dict_name))
    print('There were {} packets captured in {}'.format(PACKET_COUNT, FILENAME))


process_packets(FILENAME)
dumpdict(TCP_CONNECTIONDICT, "TCP")
dumpdict(UDP_CONNECTIONDICT, "UDP")
dumpdict(IPV4_CONNECTIONDICT, "IPv4")