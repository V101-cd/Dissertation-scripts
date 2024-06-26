'''
A collection of functions for parsing packet headers into structures and vice-versa
Packet data is extracted from or written to a bytes object (a bytearray works too)
objects are constructed from buffers via a read() method, and are written to buffers via a write() method.
Ethernet and IP addresses are represented as bytes strings of the appropriate length.

Credit to Peter L Dordal, http://pld.cs.luc.edu/courses/451/prev/project5/packet.py Accessed 23 February 2024
'''

VERSION='2021_04_07'

IPV4FLAG = 4 #in IP header
IPV6FLAG = 6 #in IP header
UDP_PROTO = 17 #in IP header
TCP_PROTO = 6 #in IP header
ICMPV4_PROTO = 1 #in IP header
ICMPV6_PROTO = 58 #in IP header
ARP_PROTO = 0x0806 #in Ethernet header

VERIFY_CHECKSUMS = False
ETHHDRLEN = 14
UDPHDRLEN = 8
TCPFLAGMASK = 0xFF		# 8 flag bits  
IPBASEHDRLEN  = 20
TCPBASEHDRLEN = 20

DEFAULT_TTL=20

# TCP flags
FINflag = (1 << 0)
SYNflag = (1 << 1)
RSTflag = (1 << 2)
PSHflag = (1 << 3)
ACKflag = (1 << 4)
URGflag = (1 << 5)	# not used here
ECEflag = (1 << 6)	# not used here
CWRflag = (1 << 7)	# not used here


import struct
from enum import Enum
import socket as realsocket
import sys
import queue
import threading
import subprocess		# for looking up source interface

class ethheader:
    def __init__(self):
        self.dstaddr = None
        self.srcaddr = None
        self.ethtype = None
        self.verbose = None
        
    @staticmethod
    def read(buf : bytes, bufstart):
        ehdr = ethheader()
        (ehdr.dstaddr, ehdr.srcaddr, ehdr.ethtype) = struct.unpack_from('!6s6sH', buf, bufstart)
        ehdr.srcaddr = bytearray(ehdr.srcaddr).hex()
        ehdr.srcaddr = ':'.join(ehdr.srcaddr[i:i+2] for i in range (0, len(ehdr.srcaddr), 2))
        ehdr.dstaddr = bytearray(ehdr.dstaddr).hex()
        ehdr.dstaddr = ':'.join(ehdr.dstaddr[i:i+2] for i in range (0, len(ehdr.dstaddr), 2))
        ehdr.ethtype = hex(ehdr.ethtype)
        ehdr.verbose = ehdr.get_verbose()
        return ehdr
        
    def write(self, buf : bytearray, bufstart):
        struct.pack_into('!6s6sH', buf, bufstart, self.dstaddr, self.srcaddr, self.ethtype)

    def get_verbose(self):
        match (self.ethtype).lower():
            case '0x800':
                return "Ethernet type: Internet Protocol Version 4 (IPv4)"
            case '0x806':
                return "Ethernet type: Address Resolution Protocol (ARP)"
            case '0x8035':
                return "Ethernet type: Reverse Address Resolution Protocol (RARP)"
            case '0x86dd':
                return "Ethernet type: Internet Protocol Version 6 (IPv6)"
            case other:
                return None

class arpheader:
    def __init__(self):
        self.hw_type         = None
        self.proto_type      = None
        self.hw_size         = None
        self.proto_size      = None
        self.opcode          = None
        self.srcmac          = None
        self.proto_src_addrb = None
        self.dstmac          = None
        self.proto_dst_addrb = None
        self.verbose         = None
    
    @staticmethod
    def read(buf: bytes, bufstart):
        arphdr = arpheader()
        (arphdr.hw_type, arphdr.proto_type, arphdr.hw_size, arphdr.proto_size, arphdr.opcode, arphdr.srcmac, arphdr.proto_src_addrb, arphdr.dstmac, arphdr.proto_dst_addrb) = struct.unpack_from('!HHssH6sI6sI', buf, bufstart)
        # arphdr.hw_type = int.from_bytes(arphdr.hw_type, "big")
        arphdr.proto_type = hex(arphdr.proto_type)
        arphdr.hw_size = int.from_bytes(arphdr.hw_size, "big")
        arphdr.proto_size = int.from_bytes(arphdr.proto_size, "big")
        # arphdr.opcode = int.from_bytes(arphdr.opcode, "big")
        arphdr.srcmac = bytearray(arphdr.srcmac).hex()
        arphdr.srcmac = ':'.join(arphdr.srcmac[i:i+2] for i in range (0, len(arphdr.srcmac), 2))
        arphdr.dstmac = bytearray(arphdr.dstmac).hex()
        arphdr.dstmac = ':'.join(arphdr.dstmac[i:i+2] for i in range (0, len(arphdr.dstmac), 2))
        arphdr.verbose = arphdr.get_verbose()
        if arphdr.dstmac == 'ff:ff:ff:ff:ff:ff':
            arphdr.verbose += "Gratuitous ARP"
        return arphdr
    
    def get_verbose(self):
        self.verbose = ""
        match self.hw_type:
            case 1:
                self.verbose += "Hardware type: Ethernet (10Mb)\n"
            case 2:
                self.verbose += "Hardware type: Experimental Ethernet (3Mb)\n"
            case 18:
                self.verbose += "Hardware type: Fibre Channel\n"
            case 20:
                self.verbose += "Hardware type: Serial Line\n"
            case 31:
                self.verbose += "Hardware type: IPSec tunnel\n"
        match self.proto_type:
            case '0x800':
                self.verbose += "Protocol type: Internet Protocol Version 4 (IPv4)\n"
                self.proto_src_addrb = realsocket.inet_ntoa(struct.pack('!L', self.proto_src_addrb))
                self.proto_dst_addrb = realsocket.inet_ntoa(struct.pack('!L', self.proto_dst_addrb))
            case '0x806':
                self.verbose += "Protocol type: Address Resolution Protocol (ARP)\n"
            case '0x8035':
                self.verbose += "Protocol type: Reverse Address Resolution Protocol (RARP)\n"
            case '0x86DD':
                self.verbose += "Protocol type: Internet Protocol Version 6 (IPv6)\n"
                self.proto_src_addrb = realsocket.inet_ntop(realsocket.AF_INET6, (struct.pack('!L', self.proto_src_addrb)))
                self.proto_dst_addrb = realsocket.inet_ntop(realsocket.AF_INET6, (struct.pack('!L', self.proto_dst_addrb)))
        match self.opcode:
            case 1:
                self.verbose += "Opcode: ARP Request\n"
            case 2:
                self.verbose += "Opcode: ARP Reply\n"
            case 3:
                self.verbose += "Opcode: Reverse ARP Request\n"
            case 4:
                self.verbose += "Opcode: Reverse ARP Reply\n"
        return self.verbose
            
DONTFRAG  = 0x2
MOREFRAGS = 0x1

class ip4header:
    def __init__(self):
        self.iphdrlen= None			# in bytes
        self.dsfield = None			# 
        self.length  = None			# IP and TCP/UDP headers and DATA
        self.ident   = None			# ignored for outbound packets
        # self.fragflags = None
        self.reserved  = None
        self.df      = None
        self.mf      = None
        self.fragoffset= None
        self.ttl     = None
        self.proto   = None
        self.chksum  = None
        self.srcaddrb= None
        self.dstaddrb= None
        self.datagrambytes = None    # firsst 64 bits of data
        self.verbose = None

    # the following static method returns an ip4header object
    @staticmethod
    def read(buf : bytes, bufstart):
        if (buf[bufstart] >> 4) != IPV4FLAG: 
            eprint('packet not IPv4')
            return None
        ip4h = ip4header()
        ip4h.iphdrlen = (buf[bufstart] & 0x0f) * 4
        if VERIFY_CHECKSUMS and IPchksum(buf, bufstart, ip4h.iphdrlen) != 0xffff: return None 	# drop packet
        a = struct.unpack_from('!BHHHBBH4s4s', buf, bufstart+1)
        (ip4h.dsfield, ip4h.length, ip4h.ident, fragword, ip4h.ttl, ip4h.proto, ip4h.chksum, ip4h.srcaddrb, ip4h.dstaddrb) = a
        # ip4h.fragflags = (fragword >> 13) & 0x7
        fragflags = (bin((fragword >> 13) & 0x7)[2:]).zfill(8)
        ip4h.reserved = int(fragflags[0])
        ip4h.df = int(fragflags[1])
        ip4h.mf = int(fragflags[2])
        ip4h.fragoffset = fragword & ((1<<13) - 1)
        ip4h.ttl = int(ip4h.ttl)
        ip4h.proto = int(ip4h.proto)
        ip4h.srcaddrb = realsocket.inet_ntoa(ip4h.srcaddrb)
        ip4h.dstaddrb = realsocket.inet_ntoa(ip4h.dstaddrb)
        if ip4h.iphdrlen <= len(buf[bufstart:]):
            ip4h.datagrambytes = bytearray(buf[bufstart + ip4h.iphdrlen: bufstart + ip4h.iphdrlen + 8]).hex()
        else:
            ip4h.datagrambytes = None
        ip4h.verbose = ip4h.get_verbose()
        return ip4h
        
    @staticmethod
    def iphdrlen(buf : bytes, bufstart):
        return (buf[bufstart] & 0x0f) * 4

    def get_verbose(self):
        match self.proto:
            case 1:
                return "Protocol type: Internet Control Message Protocol (ICMP)\n"
            case 2:
                return "Protocol type: Internet Group Management Protocol (IGMP)\n"
            case 6:
                return "Protocol type: Transmission Control Protocol (TCP)\n"
            case 8:
                return "Protocol type: Exterior Gateway Protocol (EGP)\n"
            case 9:
                return "Protocol type: Interior Gateway Protocol (IGP)\n"
            case 17:
                return "Protocol type: User Datagram Protocol (UDP)\n"
            case other:
                return "Protocol type: Unknown\n"

    # Linux fills in the ip-header checksum, so we just leave it 0
    def write(self, buf : bytearray, bufstart):
        if not self.iphdrlen or self.iphdrlen == 0: iphdrnybble = (IPBASEHDRLEN >> 2)
        else: iphdrnybble = (self.iphdrlen >> 2)
        firstbyte = (0x4 << 4) | iphdrnybble
        if self.dsfield: dsfield = self.dsfield
        else: dsfield = 0
        if not self.length:
            eprint('ip4header.length is unset: {}'.format(self))
            return False
        ident = next_ident()	# ignore any header-class value
        fragword = 0		# no fragmentation at this level. Should we keep the header-provided bits?
        if self.ttl: ttl = self.ttl
        else: ttl = DEFAULT_TTL
        struct.pack_into('BBHHHBBH4s4s', buf, bufstart, firstbyte, dsfield, self.length, ident, fragword, ttl, self.proto, 0, self.srcaddrb, self.dstaddrb)

    def __str__(self):
        protostr = 'UNKNOWN'
        if self.proto == UDP_PROTO: protostr = 'UDP'
        elif self.proto == TCP_PROTO: protostr = 'TCP'
        return 'srcIP={}, dstIP={}, proto={}'.format(realsocket.inet_ntoa(self.srcaddrb), realsocket.inet_ntoa(self.dstaddrb), protostr)

class ip6header:
    def __init__(self):
        self.version            = None  # should be 6
        self.trafficclassfield  = None	# like differentiated services in ipv4. 8 bits
        self.flowlabel          = None  # 20 bits, new for ipv6
        self.length             = None	# IP and TCP/UDP headers and DATA
        self.nextheader         = None
        self.hoplimit           = None
        self.srcaddrb           = None
        self.dstaddrb           = None
        self.extheaders         = [] # Extension headers
        self.verbose            = None

    # the following static method returns an ip6header object
    @staticmethod
    def read(buf: bytes, bufstart):
        hexbuf = buf[bufstart:].hex() ##because we convert the bytestream to hex, divide all offsets by 4
        ip6h = ip6header()
        counter = 0
        ip6h.version = int(hexbuf[counter: counter + (4//4)])
        counter += (4//4)
        ip6h.trafficclassfield = hex(int(hexbuf[counter: counter + (8//4)],16)) ##traffic class
        counter += (8//4)
        ip6h.flowlabel = hex(int(hexbuf[counter: counter + (20//4)],16)) ##flow label
        counter += (20//4) 
        ip6h.length = int(hexbuf[counter: counter + (16//4)],16) ##payload length
        counter += (16//4) 
        ip6h.nextheader = hex(int(hexbuf[counter: counter + (8//4)],16)) ##next header
        counter += (8//4) 
        ip6h.hoplimit = int(hexbuf[counter: counter + (8//4)],16) ##hop limit
        counter += (8//4) 
        srcaddrb = bytearray.fromhex(hexbuf[counter: counter + (128//4)]) ##source address
        ip6h.srcaddrb = realsocket.inet_ntop(realsocket.AF_INET6, srcaddrb)
        counter += (128//4) 
        dstaddrb = bytearray.fromhex(hexbuf[counter: counter + (128//4)])  ##destination address
        ip6h.dstaddrb = realsocket.inet_ntop(realsocket.AF_INET6, dstaddrb)
        counter += (128//4)
        next_headers = []
        if int(ip6h.nextheader, base=16) not in [TCP_PROTO, UDP_PROTO, ICMPV4_PROTO, ICMPV6_PROTO]:
            next_headers.append(((int(ip6h.nextheader, base=16)), counter//2)) ##tuple containing header type, and offset
        ##RECURSIVELY FIND EXTENSION HEADERS
        for header,offset in next_headers:
            if header == 0: ## Hop-by-Hop Options Header
                next_headers.append(((hexbuf[counter: counter + (8//4)]), counter//2 + 8)) ##tuple containing header type immediately following the Hop-by-hop options header (same values as for Ipv4), and the offset into the IPv6 header in bytes
                counter += (8 + (int(hexbuf[counter: counter + (8//4)], base=16) * 8))//4
        ip6h.extheaders = next_headers
        ip6h.get_verbose()
        return ip6h

    def get_verbose(self):
        match int(self.nextheader, 16):
            case 0:
                self.verbose = f"Next Header type {self.nextheader}: Hop-by-Hop Options Extension Header\n"
            case 43:
                self.verbose = f"Next Header type {self.nextheader}: Routing Extension Header\n"
            case 44:
                self.verbose = f"Next Header type {self.nextheader}: Fragment Extension Header\n"
            case 51:
                self.verbose = f"Next Header type {self.nextheader}: Authentication Header (AH) Extension Header\n"
            case 50:
                self.verbose = f"Next Header type {self.nextheader}: Encapsulating Security Payload (ESP) Extension Header\n"
            case 60:
                self.verbose = f"Next Header type {self.nextheader}: Destination Options Extension Header\n"
            case 6:
                self.verbose = f"Next Header: TCP\n"
            case 17:
                self.verbose = f"Next Header: UDP\n"
            case 1:
                self.verbose = f"Next Header: ICMPv4\n"
            case 58:
                self.verbose = f"Next Header: ICMPv6\n"
            case other:
                self.verbose = f"Next Header type {self.nextheader}: Unknown\n"
            
        for i, ext_header in enumerate(self.extheaders):
            ext_headers = int(str(ext_header[0]), 16)
            match ext_headers:
                case 0:
                    self.verbose += f"Extension Header {i+1} type {ext_headers}: Hop-by-Hop Options\n"
                case 43:
                    self.verbose += f"Extension Header {i+1} type {ext_headers}: Routing\n"
                case 44:
                    self.verbose += f"Extension Header {i+1} type {ext_headers}: Fragment\n"
                case 51:
                    self.verbose += f"Extension Header {i+1} type {ext_headers}: Authentication Header (AH)\n"
                case 50:
                    self.verbose += f"Extension Header {i+1} type {ext_headers}: Encapsulating Security Payload (ESP)\n"
                case 60:
                    self.verbose += f"Extension Header {i+1} type {ext_headers}: Destination Options\n"
                case 6:
                    self.verbose += f"Next Header: TCP\n"
                case 17:
                    self.verbose += f"Next Header: UDP\n"
                case 1:
                    self.verbose += f"Next Header: ICMPv4\n"
                case 58:
                    self.verbose += f"Next Header: ICMPv6\n"
                case other:
                    self.verbose += f"Extension Header {i+1} type {ext_headers}: Unknown\n"
        
    
class icmp4header:
    def __init__(self): ##datatracker.ietf.org/html/rfc792
        self.type               = None #Type, 8 bits
        self.code               = None #Code, 8 bits
        self.checksum           = None #Checksum, 16 bits
        # self.various          = None #various uses, 32 bits
        # self.original_datagram  = None
        self.verbose            = None
        self.ip4header          = None #IPv4 header
        self.datagrambytes      = None #first 64 bits of the datagram
    
    # We need the iphdr to verify the checksum
    @staticmethod
    def read(buf, bufstart):
        icmph = icmp4header()
        # (icmph.type, icmph.code, icmph.checksum, unused, icmph.ip4header, icmph.datagrambytes) = struct.unpack_from('!ss2s4sBHHHBBH4s4s8s', buf, bufstart)
        hexbuf = buf[bufstart:].hex()
        # print(hexbuf)
        counter = 0
        icmph.type = int(hexbuf[counter: counter + (8//4)], base=16)
        counter += (8//4)
        icmph.code = int(hexbuf[counter: counter + (8//4)], base=16)
        counter += (8//4)
        icmph.checksum = hex(int(hexbuf[counter: counter + (16//4)], base=16))
        counter += (16//4)
        match icmph.type:
            case 0:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Echo Reply\n"  ##datatracker.ietf.org/doc/html/rfc792 16 March 2024
            case 3:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Destination Unreachable\n"
                counter += (32//4) #unused/various uses
                icmph.ip4header = bytearray.fromhex(hexbuf[counter: counter + (160//4)])
                counter += (160//4)
                icmph.datagrambytes = bytearray.fromhex(hexbuf[counter: counter + (64//4)])
                match icmph.code:
                    case 0:
                        icmph.verbose += f"ICMP Code {icmph.code}: Net is unreachable\n"
                    case 1:
                        icmph.verbose += f"ICMP Code {icmph.code}: Host is unreachable\n"
                    case 2:
                        icmph.verbose += f"ICMP Code {icmph.code}: Protocol is unreachable\n"
                    case 3:
                        icmph.verbose += f"ICMP Code {icmph.code}: Port is unreachable\n"
                    case 4:
                        icmph.verbose += f"ICMP Code {icmph.code}: Fragmentation is needed and \'Don\'t Fragment\' (DF) was set\n"
                    case 5:
                        icmph.verbose += f"ICMP Code {icmph.code}: Source route failed\n"
                    case 6:
                        icmph.verbose += f"ICMP Code {icmph.code}: Destination network is unknown\n"
                    case 7:
                        icmph.verbose += f"ICMP Code {icmph.code}: Destination host is unknown\n"
                    case 8:
                        icmph.verbose += f"ICMP Code {icmph.code}: Source host is isolated\n"
                    case 9:
                        icmph.verbose += f"ICMP Code {icmph.code}: Communication with destination network is administratively prohibited\n"
                    case 10:
                        icmph.verbose += f"ICMP Code {icmph.code}: Communication with destination host is administratively prohibited\n"
                    case 11:
                        icmph.verbose += f"ICMP Code {icmph.code}: Destination network is unreachable for type of service\n"
                    case 12:
                        icmph.verbose += f"ICMP Code {icmph.code}: Destination host is unreachable for type of service\n"
                    case 13:
                        icmph.verbose += f"ICMP Code {icmph.code}: Communication is administratively prohibited\n"
                    case 14:
                        icmph.verbose += f"ICMP Code {icmph.code}: Host precedence violation\n"
                    case 15:
                        icmph.verbose += f"ICMP Code {icmph.code}: Precedence cutoff is in effect\n"
            case 4:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Source Quench\n"
                counter += (32//4) #unused/various uses
                icmph.ip4header = bytearray.fromhex(hexbuf[counter: counter + (160//4)])
                counter += (160//4)
                icmph.datagrambytes = bytearray.fromhex(hexbuf[counter: counter + (64//4)])
            case 5:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Redirect\n"
                counter += (32//4) #unused/various uses
                icmph.ip4header = bytearray.fromhex(hexbuf[counter: counter + (160//4)])
                counter += (160//4)
                icmph.datagrambytes = bytearray.fromhex(hexbuf[counter: counter + (64//4)])
                match icmph.code:
                    case 0:
                        icmph.verbose += f"ICMP Code {icmph.code}: Redirect datagram for the network (or subnet)\n"
                    case 1:
                        icmph.verbose += f"ICMP Code {icmph.code}: Redirect datagram for the host\n"
                    case 2:
                        icmph.verbose += f"ICMP Code {icmph.code}: Redirect datagram for the type of service and network\n"
                    case 3:
                        icmph.verbose += f"ICMP Code {icmph.code}: Redirect datagram for the type of service and host\n"
            case 8:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Echo\n"
            case 9:
                icmph.verbose = f"ICMP Type {icmph.type}: Router Advertisement\n"
            case 10:
                icmph.verbose = f"ICMP Type {icmph.type}: Router Selection\n"
            case 11:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Time Exceeded\n"
                counter += (32//4) #unused/various uses
                icmph.ip4header = bytearray.fromhex(hexbuf[counter: counter + (160//4)])
                counter += (160//4)
                icmph.datagrambytes = bytearray.fromhex(hexbuf[counter: counter + (64//4)])
                match icmph.code:
                    case 0:
                        icmph.verbose += f"ICMP Code {icmph.code}: Time To Live (TTL) exceeded in transit\n"
                    case 1:
                        icmph.verbose += f"ICMP Code {icmph.code}: Fragment reassembly time exceeded\n"
            case 12:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Parameter Problem\n"
                counter += (32//4) #unused/various uses
                icmph.ip4header = bytearray.fromhex(hexbuf[counter: counter + (160//4)])
                counter += (160//4)
                icmph.datagrambytes = bytearray.fromhex(hexbuf[counter: counter + (64//4)])
                match icmph.code:
                    case 0:
                        icmph.verbose += f"ICMP Code {icmph.code}: Pointer [in various uses] indicates the error\n"
                    case 1:
                        icmph.verbose += f"ICMP Code {icmph.code}: Missing a required option\n"
                    case 2:
                        icmph.verbose += f"ICMP Code {icmph.code}: Bad length\n"
            case 13:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Timestamp\n"
            case 14:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Timestamp Reply\n"
            case 15:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Information Request\n"
            case 16:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Information Reply\n"
            case 17:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Address Mask Request\n"
            case 18:
                icmph.verbose = f"ICMP Type {icmph.type}: ICMP Address Mask Reply\n"
            case 30:
                icmph.verbose = f"ICMP Type {icmph.type}: Traceroute\n"
        # if VERIFY_CHECKSUMS and udph.chksum != 0:
        #     if not iphdr: 
        #         eprint('call to udpheader.read() needs iphdr')
        #         return None
        #     calc_chksum = transportheader_getchk(buf, bufstart, iphdr.srcaddrb, iphdr.dstaddrb, UDP_PROTO, len(buf)-bufstart)
        #     if calc_chksum != 0xffff: 
        #         eprint('packet with bad UDP checksum received')
        #         return None
        return icmph

class icmp6header:
    def __init__(self): ##rfc-editor.org/rfc/rfc8335 16 March 2024
        self.type           = None #Type, 8 bits
        self.code           = None #Code, 8 bits
        self.checksum       = None #Checksum, 16 bits
        # self.identifier     = None #Identifier, 16 bits
        # self.seqnum         = None #Sequence number, 8 bits
        self.verbose        = None

    @staticmethod
    def read(buf, bufstart):
        icmp6h = icmp6header()
        hexbuf = buf[bufstart:].hex()
        counter = 0
        icmp6h.type = int(hexbuf[counter: counter + (8//4)], base=16)
        counter += (8//4)
        icmp6h.code = int(hexbuf[counter: counter + (8//4)], base=16)
        counter += (8//4)
        icmp6h.checksum = hex(int(hexbuf[counter: counter + (16//4)], base=16))
        counter += (16//4)
        if icmp6h.type in range(0,128):
            match icmp6h.type:
                case 1:
                    icmp6h.verbose = "ICMPv6 Error Message: Destination Unreachable\n" ###rfc-editor.org/rfc/rfc443.html#page-8 16 March 2024
                    match icmp6h.code:
                        case 0:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: No route to destination\n"
                        case 1:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Communication with destination administratively prohibited\n"
                        case 2:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Beyond scope of source address\n"
                        case 3:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Address unreachable\n"
                        case 4:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Port unreachable\n"
                        case 5:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Source address failed ingress/egress policy\n"
                        case 6:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Reject route to destination\n"
                        case 7:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Error in Source Routing Header\n"
                        case 8:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Headers too long\n"
                case 2:
                    icmp6h.verbose = "ICMPv6 Error Message: Packet Too Big\n"
                case 3:
                    icmp6h.verbose = "ICMPv6 Error Message: Time Exceeded\n"
                    match icmp6h.code:
                        case 0:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Hop limit exceeded in transit\n"
                        case 1:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Fragment reassembly ime exceeded\n"
                case 4:
                    icmp6h.verbose = "ICMPv6 Error Message: Parameter Problem\n"
                    match icmp6h.code:
                        case 0:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Erroneous header field encountered\n"
                        case 1:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Unrecognised \'Next Header\' type encountered\n"
                        case 2:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Unrecognised IPv6 option encountered\n"
                        case 3:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: IPv6 First Fragment has incomplete IPv6 Header Chain\n"
                        case 4:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: SR Upper-layer Header Error\n"
                        case 5:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Unrecognised \'Next Header\' type encountered by intermediate node\n"
                        case 6:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Extension header too big\n"
                        case 7:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Extension header chain too long\n"
                        case 8:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Too many extension headers\n"
                        case 9:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Too many options in extension header\n"
                        case 10:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Option too big\n"
                case other:
                    icmp6h.verbose = f"ICMPv6 Error Message: unknown or invalid error message: protocol {icmp6h.type}\n"

        else:
            match icmp6h.type:
                case 128:
                    icmp6h.verbose = "ICMPv6 Informational message: Echo Request\n"
                case 129:
                    icmp6h.verbose = "ICMPv6 Informational message: Echo Reply\n"
                case 130:
                    icmp6h.verbose = "ICMPv6 Informational message: Multicast Listener Query\n"
                case 131:
                    icmp6h.verbose = "ICMPv6 Informational message: Multicast Listener Report\n"
                case 132:
                    icmp6h.verbose = "ICMPv6 Informational message: Multicast Listener Done\n"
                case 133:
                    icmp6h.verbose = "ICMPv6 Informational message: Router Solicitation\n" ###rfc-editor.org/rfc/rfc2461#page-17 16 March 2024
                case 134:
                    icmp6h.verbose = "ICMPv6 Informational message: Router Advertisement\n"
                case 135:
                    icmp6h.verbose = "ICMPv6 Informational message: Neighbor Solicitation\n"
                case 136:
                    icmp6h.verbose = "ICMPv6 Informational message: Neighbor Advertisement\n"
                case 137:
                    icmp6h.verbose = "ICMPv6 Informational message: Redirect Message\n"
                case 138:
                    icmp6h.verbose = "ICMPv6 Informational message: Router Renumbering\n"
                    match icmp6h.code:
                        case 0:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Router Renumbering Command\n"
                        case 1:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Router Renumbering Result\n"
                        case 255:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Sequence Number Reset\n"
                case 139:
                    icmp6h.verbose = "ICMPv6 Informational message: ICMP Node Information Query\n"
                    match icmp6h.code:
                        case 0:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: The \'Data\' field contains an IPv6 address which is the Subject of this Query\n"
                        case 1:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: The \'Data\' field contains a name which is the Subject of this Query, or is empty (i.e. NOOP)\n"
                        case 2:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: The \'Data\' field contains an IPv4 address which is the Subject of this Query\n"
                case 140:
                    icmp6h.verbose = "ICMPv6 Informational message: ICMP Node Information Response\n"
                    match icmp6h.code:
                        case 0:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: A successful reply. The \'Reply\' field may or may not be empty\n"
                        case 1:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: The Responder refuses to supply the answer. The \'Reply\' field will be empty.\n"
                        case 2:
                            icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: The Qtype of the Query is unknown to the Responder. The \'Reply\' field will be empty.\n"
                case 151:
                    icmp6h.verbose = "ICMPv6 Informational message: Multicast Router Advertisement\n"
                case 152:
                    icmp6h.verbose = "ICMPv6 Informational message: Multicast Router Solicitation\n"
                case 153:
                    icmp6h.verbose = "ICMPv6 Informational message: Multicast Router Termination\n"
                case 160:
                    icmp6h.verbose = "ICMPv6 Informational message: Extended Echo Request\n"
                    if icmp6h.code == 0:
                        icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: No error\n"
                    elif icmp6h.code in range(1,256):
                        icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Unassigned\n"
                case 161:
                    icmp6h.verbose = "ICMPv6 Informational message: Extended Echo Reply\n"
                    if icmp6h.code in range(0,5):
                        match icmp6h.code:
                            case 0:
                                icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: No error\n"
                            case 1:
                                icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Malformed Query\n"
                            case 2:
                                icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: No Succh Interface\n"
                            case 3:
                                icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: No Such Table Entry\n"
                            case 4:
                                icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Multiple Interfaces Satisfy Query\n"
                    elif icmp6h.code in range(5,256):
                        icmp6h.verbose += f"ICMPv6 Code {icmp6h.code}: Unassigned\n"

                case other:
                    icmp6h.verbose = f"ICMPv6 Informational message: unknown or invalid informational message: protocol {icmp6h.type}\n"
        return icmp6h

class udpheader:
    def __init__(self):
        self.srcport = None
        self.dstport = None
        self.length  = None
        self.chksum  = None
        self.verbose = None
        
    # We need the iphdr to verify the checksum
    @staticmethod
    def read(buf, bufstart, iphdr=None):
        udph = udpheader()
        (udph.srcport, udph.dstport, udph.length, udph.chksum) = struct.unpack_from('>HHHH', buf, bufstart)
        udph.srcport = int(udph.srcport)
        udph.dstport = int(udph.dstport)
        udph.length = int(udph.length)
        udph.chksum = hex(udph.chksum)
        # if VERIFY_CHECKSUMS and udph.chksum != 0:
        #     if not iphdr: 
        #         eprint('call to udpheader.read() needs iphdr')
        #         return None
        #     calc_chksum = transportheader_getchk(buf, bufstart, iphdr.srcaddrb, iphdr.dstaddrb, UDP_PROTO, len(buf)-bufstart)
        #     if calc_chksum != 0xffff: 
        #         eprint('packet with bad UDP checksum received')
        #         return None
        udph.get_verbose()
        return udph

    def get_verbose(self):
        match self.srcport:
            case 20:
                self.verbose = f"Source Port {self.srcport} : File Transfer Protocol (FTP)\n"
            case 21:
                self.verbose = f"Source Port {self.srcport} : File Transfer Protocol (FTP)\n"
            case 22:
                self.verbose = f"Source Port {self.srcport} : Secure Shell (SSH)\n"
            case 23:
                self.verbose = f"Source Port {self.srcport} : Telnet Protocol\n"
            case 25:
                self.verbose = f"Source Port {self.srcport} : Simple Mail Transfer Protocol (SMTP)\n"
            case 53:
                self.verbose = f"Source Port {self.srcport} : Domain Name System Protocol (DNS)\n"
            case 67:
                self.verbose = f"Source Port {self.srcport} : Dynamic Host Configuration Protocol (DHCP)\n"
            case 68:
                self.verbose = f"Source Port {self.srcport} : Dynamic Host Configuration Protocol (DHCP)\n"
            case 70:
                self.verbose = f"Source Port {self.srcport} : Gopher Protocol\n"
            case 80:
                self.verbose = f"Source Port {self.srcport} : Hyper-Text Transfer Protocol (HTTP)\n"
            case 109:
                self.verbose = f"Source Port {self.srcport} : Post Office Protocol version 2 (POP2)\n"
            case 110:
                self.verbose = f"Source Port {self.srcport} : Post Office Protocol version 3 (POP3)\n"
            case 115:
                self.verbose = f"Source Port {self.srcport} : Simple File Transfer Protocol (SFTP)\n"
            case 179:
                self.verbose = f"Source Port {self.srcport} : Border Gateway Protocol (BGP)\n"
            case 264:
                self.verbose = f"Source Port {self.srcport} : Border Gateway Multicast Protocol (BGMP)\n"
            case 546:
                self.verbose = f"Source Port {self.srcport} : Dynamic Host Configuration Protocol (DHCP) version 6 client\n"
            case 547:
                self.verbose = f"Source Port {self.srcport} : Dynamic Host Configuration Protocol (DHCP) version 6 server\n"
            case 443:
                self.verbose = f"Source Port {self.srcport} : Hyper-Text Transfer Protocol Secure (HTTPS)\n"
            case other:
                self.verbose = f"Source Port {self.srcport} not well-known\n"
        
        match self.dstport:
            case 20:
                self.verbose += f"Destination Port {self.dstport} : File Transfer Protocol (FTP)\n"
            case 21:
                self.verbose += f"Destination Port {self.dstport} : File Transfer Protocol (FTP)\n"
            case 22:
                self.verbose += f"Destination Port {self.dstport} : Secure Shell (SSH)\n"
            case 23:
                self.verbose += f"Destination Port {self.dstport} : Telnet Protocol\n"
            case 25:
                self.verbose += f"Destination Port {self.dstport} : Simple Mail Transfer Protocol (SMTP)\n"
            case 53:
                self.verbose += f"Destination Port {self.dstport} : Domain Name System Protocol (DNS)\n"
            case 67:
                self.verbose += f"Destination Port {self.dstport} : Dynamic Host Configuration Protocol (DHCP)\n"
            case 68:
                self.verbose += f"Destination Port {self.dstport} : Dynamic Host Configuration Protocol (DHCP)\n"
            case 70:
                self.verbose += f"Destination Port {self.dstport} : Gopher Protocol\n"
            case 80:
                self.verbose += f"Destination Port {self.dstport} : Hyper-Text Transfer Protocol (HTTP)\n"
            case 109:
                self.verbose += f"Destination Port {self.dstport} : Post Office Protocol version 2 (POP2)\n"
            case 110:
                self.verbose += f"Destination Port {self.dstport} : Post Office Protocol version 3 (POP3)\n"
            case 115:
                self.verbose += f"Destination Port {self.dstport} : Simple File Transfer Protocol (SFTP)\n"
            case 179:
                self.verbose += f"Destination Port {self.dstport} : Border Gateway Protocol (BGP)\n"
            case 264:
                self.verbose += f"Destination Port {self.dstport} : Border Gateway Multicast Protocol (BGMP)\n"
            case 546:
                self.verbose += f"Destination Port {self.dstport} : Dynamic Host Configuration Protocol (DHCP) version 6 client\n"
            case 547:
                self.verbose += f"Destination Port {self.dstport} : Dynamic Host Configuration Protocol (DHCP) version 6 server\n"
            case 443:
                self.verbose += f"Destination Port {self.dstport} : Hyper-Text Transfer Protocol Secure (HTTPS)\n"
            case other:
                self.verbose += f"Destination Port {self.dstport} not well-known\n"
 
    # Does NOT do the checksum, because we don't really know the ip header source address
    def write_nochk(self, buf : bytearray, bufstart):
        struct.pack_into('!HHHH', buf, bufstart, self.srcport, self.dstport, self.length, 0)
    
class tcpheader:  
    def __init__(self):
        self.srcport  = None
        self.dstport  = None
        self.absseqnum= None	# absolute sequence number
        self.absacknum= None
        self.tcphdrlen= None
        self.reserved = None
        self.cwr      = None
        self.ece      = None
        self.urg      = None
        self.ack      = None
        self.psh      = None
        self.rst      = None
        self.syn      = None
        self.fin      = None
        self.winsize  = None
        self.chksum   = None
        self.urgent   = None
        self.verbose  = None
        
        
    # We need the iphdr to verify the checksum
    @staticmethod
    def read(buf : bytes, bufstart, iphdr=None):	# bufstart is start of tcp header   
        # if VERIFY_CHECKSUMS:  
        #     if not iphdr: 
        #         eprint('call to tcpheader.read() needs iphdr')
        #         return None
        #     calc_chksum = transportheader_getchk(buf, bufstart, iphdr.srcaddrb, iphdr.dstaddrb, TCP_PROTO, len(buf)-bufstart)
        #     if calc_chksum != 0xffff: 
        #         eprint('packet with bad TCP checksum received')
        #         return  None
        tcph = tcpheader()
        # absacknum in the following may be garbage
        (tcph.srcport, tcph.dstport, tcph.absseqnum, tcph.absacknum, flagword, tcph.winsize, tcph.chksum, tcph.urgent) = struct.unpack_from('!HHIIHHHH', buf, bufstart)
        tcph.srcport = int(tcph.srcport)
        tcph.dstport = int(tcph.dstport)
        tcph.absseqnum = int(tcph.absseqnum)
        tcph.absacknum = int(tcph.absacknum)
        tcph.tcphdrlen = int((flagword >> 12)*4)
        tcph.reserved = (bin(0)[2:]).zfill(4) ##set to 0; can't be used because software would likely drop segments with tcph.reserved != 0 as an error
        flags = (bin(flagword & TCPFLAGMASK)[2:]).zfill(8)
        tcph.cwr = int(flags[0])
        tcph.ece = int(flags[1])
        tcph.urg = int(flags[2])
        tcph.ack = int(flags[3])
        tcph.psh = int(flags[4])
        tcph.rst = int(flags[5])
        tcph.syn = int(flags[6])
        tcph.fin = int(flags[7])
        tcph.winsize = int(tcph.winsize)
        tcph.chksum = hex(tcph.chksum)
        tcph.urgent = int(tcph.urgent)
        tcph.get_verbose()
        return tcph
    
    def get_verbose(self):
        match self.srcport:
            case 20:
                self.verbose = f"Source Port {self.srcport} : File Transfer Protocol (FTP)\n"
            case 21:
                self.verbose = f"Source Port {self.srcport} : File Transfer Protocol (FTP)\n"
            case 22:
                self.verbose = f"Source Port {self.srcport} : Secure Shell (SSH)\n"
            case 23:
                self.verbose = f"Source Port {self.srcport} : Telnet Protocol\n"
            case 25:
                self.verbose = f"Source Port {self.srcport} : Simple Mail Transfer Protocol (SMTP)\n"
            case 53:
                self.verbose = f"Source Port {self.srcport} : Domain Name System Protocol (DNS)\n"
            case 67:
                self.verbose = f"Source Port {self.srcport} : Dynamic Host Configuration Protocol (DHCP)\n"
            case 68:
                self.verbose = f"Source Port {self.srcport} : Dynamic Host Configuration Protocol (DHCP)\n"
            case 70:
                self.verbose = f"Source Port {self.srcport} : Gopher Protocol\n"
            case 80:
                self.verbose = f"Source Port {self.srcport} : Hyper-Text Transfer Protocol (HTTP)\n"
            case 109:
                self.verbose = f"Source Port {self.srcport} : Post Office Protocol version 2 (POP2)\n"
            case 110:
                self.verbose = f"Source Port {self.srcport} : Post Office Protocol version 3 (POP3)\n"
            case 115:
                self.verbose = f"Source Port {self.srcport} : Simple File Transfer Protocol (SFTP)\n"
            case 179:
                self.verbose = f"Source Port {self.srcport} : Border Gateway Protocol (BGP)\n"
            case 264:
                self.verbose = f"Source Port {self.srcport} : Border Gateway Multicast Protocol (BGMP)\n"
            case 546:
                self.verbose = f"Source Port {self.srcport} : Dynamic Host Configuration Protocol (DHCP) version 6 client\n"
            case 547:
                self.verbose = f"Source Port {self.srcport} : Dynamic Host Configuration Protocol (DHCP) version 6 server\n"
            case 443:
                self.verbose = f"Source Port {self.srcport} : Hyper-Text Transfer Protocol Secure (HTTPS)\n"
            case other:
                self.verbose = f"Source Port {self.srcport} not well-known\n"
        
        match self.dstport:
            case 20:
                self.verbose += f"Destination Port {self.dstport} : File Transfer Protocol (FTP)\n"
            case 21:
                self.verbose += f"Destination Port {self.dstport} : File Transfer Protocol (FTP)\n"
            case 22:
                self.verbose += f"Destination Port {self.dstport} : Secure Shell (SSH)\n"
            case 23:
                self.verbose += f"Destination Port {self.dstport} : Telnet Protocol\n"
            case 25:
                self.verbose += f"Destination Port {self.dstport} : Simple Mail Transfer Protocol (SMTP)\n"
            case 53:
                self.verbose += f"Destination Port {self.dstport} : Domain Name System Protocol (DNS)\n"
            case 67:
                self.verbose += f"Destination Port {self.dstport} : Dynamic Host Configuration Protocol (DHCP)\n"
            case 68:
                self.verbose += f"Destination Port {self.dstport} : Dynamic Host Configuration Protocol (DHCP)\n"
            case 70:
                self.verbose += f"Destination Port {self.dstport} : Gopher Protocol\n"
            case 80:
                self.verbose += f"Destination Port {self.dstport} : Hyper-Text Transfer Protocol (HTTP)\n"
            case 109:
                self.verbose += f"Destination Port {self.dstport} : Post Office Protocol version 2 (POP2)\n"
            case 110:
                self.verbose += f"Destination Port {self.dstport} : Post Office Protocol version 3 (POP3)\n"
            case 115:
                self.verbose += f"Destination Port {self.dstport} : Simple File Transfer Protocol (SFTP)\n"
            case 179:
                self.verbose += f"Destination Port {self.dstport} : Border Gateway Protocol (BGP)\n"
            case 264:
                self.verbose += f"Destination Port {self.dstport} : Border Gateway Multicast Protocol (BGMP)\n"
            case 546:
                self.verbose += f"Destination Port {self.dstport} : Dynamic Host Configuration Protocol (DHCP) version 6 client\n"
            case 547:
                self.verbose += f"Destination Port {self.dstport} : Dynamic Host Configuration Protocol (DHCP) version 6 server\n"
            case 443:
                self.verbose += f"Destination Port {self.dstport} : Hyper-Text Transfer Protocol Secure (HTTPS)\n"
            case other:
                self.verbose += f"Destination Port {self.dstport} not well-known\n"
        
    # needs srport, dstport, absseqnum, absacknum, flagword, winsize
    def write(self, buf : bytearray, bufstart, iphdr: ip4header):
        flagword = (self.tcphdrlen  << 10) & self.flags  	# Note tcphsize is already multiplied by 4, so shift is 10
        struct.pack_into('!HHIIHHHH', buf, bufstart, self.srcport, self.dstport, self.absseqnum, self.absacknum,
            flagword, self.winsize, 0, self.urgent)
        checksum = transportheader_getchk(buf, bufstart, iphdr.srcaddrb, iphdr.dstaddrb, TCP_PROTO, iphdr.length)
        struct.pack_into('!H', buf, bufstart+ 6, 0xFFFF - checksum)		# checksum has offset 6
            
    def __str__(self):
        return 'srcport={}, dstport={}, seqnum={}, acknum={}, flags={}, winsize={}'.format(self.srcport, self.dstport, self.absseqnum, self.absacknum, self.flags, self.winsize)
       
# ============================================================================================================
#
#  CHECKSUMS

# updates the checksum
def transportheader_getchk(buf : bytes, bufstart, srcaddrb, dstaddrb, proto, length):
    csum = checksum_1comp(buf, bufstart, length)
    psum = length
    psum += proto
    psum += ipb2int(dstaddrb)
    psum += ipb2int(srcaddrb)
    csum += psum
    return carry_fold(csum)

# bufstart is start of udp header
def udpheader_addchk(buf, bufstart, srcaddrb, dstaddrb, length):
    struct.pack_into('>H', buf, bufstart+ 6, 0xFFFF - transportheader_getchk(buf, bufstart, srcaddrb, dstaddrb, UDP_PROTO, length))

TCPCHKOFFSET = 16	# offset of checksum word in TCP header

# bufstart is start of DA; length is data length + TCP header length
def tcpheader_addchk(buf : bytes, iphdrlen, tcphdrlen, srcaddrb, dstaddrb, datalen):
    struct.pack_into('>H', buf, iphdrlen+TCPCHKOFFSET, 0xFFFF - transportheader_getchk(buf, iphdrlen+tcphdrlen, srcaddrb, dstaddrb, TCP_PROTO, datalen))
    

def checksum_1comp(buf : bytes, start, length):
    sum = 0
    if length % 2 == 1: 
        sum = buf[start+length-1] << 8
        length -= 1
    for i in range(0,length, 2):
        #sum += ord(buf[start+i])<<8 + ord(buf[start+i+1])
        byte1 = buf[start+i]
        byte2 = buf[start+i+1]
        sum += (byte1<<8) + byte2
    # eprint ('raw sum = {}'.format(sum))
    return carry_fold(sum)

def IPchksum(buf : bytes, start, length):
    csum = checksum_1comp(buf, start, length)
    csum = carry_fold(csum)
    # if csum == 0xFFFF: csum = 0
    return csum

def carry_fold(sum):
    hi = sum >> 16
    lo = sum & 0xffff
    while hi != 0:
        sum = hi + lo
        hi = sum >> 16
        lo = sum & 0xffff
    return lo

def ipb2int(addrb):
    return struct.unpack("!I", addrb)[0]

def verify_checksums(b):
    global VERIFY_CHECKSUMS
    VERIFY_CHECKSUMS = b
    
# ============================================================================================================
#
#  UTILITIES

two32 = 1<<32	# 2**32

def less32(a,b):
    return ((a-b) % two32) >> 31

def sub32(a,b):  # returns a-b
    return (a-b) % two32	# note that if a-b < 0, this returns two32+(a-b)

def add32(a,b): # returns a+b
    return ((a+b) % two32)

def eprint(s):
    print(s, file=sys.stderr, flush=True)

next_ident_value = 1

def next_ident():
    global next_ident_value
    next_ident_value+=1
    return next_ident_value

# Used to try to figure out corresponding source address, for UDP. destaddr in text form
    # destaddr in text form
def getsrcaddr(destaddr : str) -> str:
    result = subprocess.run(['ip', 'route', 'get', destaddr], stdout=subprocess.PIPE)
    result = result.stdout
    result = result.split()
    if result[1] == b'via':
        res = result[2].decode('ascii')
    elif result[1] == b'dev':
        res = result[4].decode('ascii')
    else:
        eprint('error in getsrcaddr(): {}'.format(result))
        res = ""
    # print('res={}, type is {}'.format(res+1, type(res)))
    return res

def gethostbyname(hname):
    return realsocket.gethostbyname(hname)

def peek(q):
    return q.queue[0]

gaierror = realsocket.gaierror
herror   = realsocket.herror
timeout  = realsocket.timeout




# ============================================================================================================
#
#  DIAGNOSTICS

def udpdemo1():
    s = udpsock()
    msg = b'hello world!'
    hb = (s.sendto(msg, (ASGARD,5432)))
    msg = b'hello again my pretty little baby'
    hb = (s.sendto(msg, (ASGARD,5432)))
    eprint(hb)
    eprint('orig length = {}, length with headers = {}, difference = {}'.format(len(msg), len(hb), len(hb)-len(msg)))

def tcpdemo1():
    s = tcpsock()
    s.localaddrb = realsocket.inet_aton('10.0.2.37')
    s.remoteaddrb = realsocket.inet_aton('147.126.1.2')
    s.state = ESTABLISHED
    s.localport=1234
    s.remoteport=4321
    s.sendISN=0
    s.recvISN=0
    s.snd_nxt = 100000
    s.snd_una = 2000002

    sendFIN(s)
    sendACK(s)
    send_data_packet(s, ACKflag, bytes('here is some demo data', 'ascii'))


