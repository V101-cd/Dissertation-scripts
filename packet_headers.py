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
        dstaddr = None
        srcaddr = None
        ethtype = None
        
    @staticmethod
    def read(buf : bytes, bufstart):
        ehdr = ethheader()
        (ehdr.dstaddr, ehdr.srcaddr, ehdr.ethtype) = struct.unpack_from('!6s6sH', buf, bufstart)
        return ehdr
        
    def write(self, buf : bytearray, bufstart):
        struct.pack_into('!6s6sH', buf, bufstart, self.dstaddr, self.srcaddr, self.ethtype)

class arpheader:
    def __init__(self):
        self.proto_type = None
        self.opcode = None
        self.srcmac = None
        self.proto_src_addrb = None
        self.dstmac = None
        self.proto_dst_addrb = None
        self.isgratuituous = False
    
    @staticmethod
    def read(buf: bytes, bufstart):
        arphdr = arpheader()
        (hw_type, arphdr.proto_type, hw_size, proto_size, arphdr.opcode, arphdr.srcmac, arphdr.proto_src_addrb, arphdr.dstmac, arphdr.proto_dst_addrb) = struct.unpack_from('!HHssH6sI6sI', buf, bufstart)
        arphdr.srcmac = bytearray(arphdr.srcmac).hex()
        arphdr.srcmac = ':'.join(arphdr.srcmac[i:i+2] for i in range (0, len(arphdr.srcmac), 2))
        arphdr.dstmac = bytearray(arphdr.dstmac).hex()
        arphdr.dstmac = ':'.join(arphdr.dstmac[i:i+2] for i in range (0, len(arphdr.dstmac), 2))
        if arphdr.dstmac == 'ff:ff:ff:ff:ff:ff':
            arphdr.isgratuituous = True
        return arphdr
            
DONTFRAG  = 0x2
MOREFRAGS = 0x1

class ip4header:
    def __init__(self):
        self.iphdrlen= None			# in bytes
        self.dsfield = None			# 
        self.length  = None			# IP and TCP/UDP headers and DATA
        self.ident   = None			# ignored for outbound packets
        self.fragflags = None
        self.fragoffset= None
        self.ttl     = None
        self.proto   = None
        self.chksum  = None
        self.srcaddrb= None
        self.dstaddrb= None

    # the following static method returns an ip4header object
    @staticmethod
    def read(buf : bytes, bufstart):
        if (buf[bufstart] >> 4) != IPV4FLAG: 
            eprint('packet not IPv4')
            return None
        ip4h = ip4header()
        ip4h.iphdrlen = (buf[bufstart] & 0x0f) * 4
        if VERIFY_CHECKSUMS and IPchksum(buf, bufstart,  ip4h.iphdrlen) != 0xffff: return None 	# drop packet
        a = struct.unpack_from('!BHHHBBH4s4s', buf, bufstart+1)
        (ip4h.dsfield, ip4h.length, ip4h.ident, fragword, ip4h.ttl, ip4h.proto, ip4h.chksum, ip4h.srcaddrb, ip4h.dstaddrb) = a
        ip4h.fragflags = (fragword >> 13) & 0x7
        ip4h.fragoffset = fragword & ((1<<13) - 1)
        if ip4h.fragoffset != 0 or (ip4h.fragflags & 1) != 0: 
            eprint('fragmented packet received/dropped;  fragflags={:x} offset={} word={:x}'.format(ip4h.fragflags, ip4h.fragoffset))
            return None
        return ip4h
        
    @staticmethod
    def iphdrlen(buf : bytes, bufstart):
        return (buf[bufstart] & 0x0f) * 4

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
        return '[srcIP={}, dstIP={}, proto={}'.format(realsocket.inet_ntoa(self.srcaddrb), realsocket.inet_ntoa(self.dstaddrb), protostr)

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

    # the following static method returns an ip6header object
    @staticmethod
    def read(buf: bytes, bufstart):
        hexbuf = buf[bufstart:].hex() ##because we convert the bytestream to hex, divide all offsets by 4
        ip6h = ip6header()
        counter = 0
        ip6h.version = (hexbuf[counter: counter + (4//4)])
        counter += (4//4)
        ip6h.trafficclassfield = (hexbuf[counter: counter + (8//4)]) ##traffic class
        counter += (8//4)
        ip6h.flowlabel = (hexbuf[counter: counter + (20//4)]) ##flow label
        counter += (20//4) 
        ip6h.length = (hexbuf[counter: counter + (16//4)]) ##payload length
        counter += (16//4) 
        ip6h.nextheader = (hexbuf[counter: counter + (8//4)]) ##next header
        counter += (8//4) 
        ip6h.hoplimit = hexbuf[counter: counter + (8//4)] ##hop limit
        counter += (8//4) 
        ip6h.srcaddrb = bytearray.fromhex(hexbuf[counter: counter + (128//4)]) ##source address
        counter += (128//4) 
        ip6h.dstaddrb = bytearray.fromhex(hexbuf[counter: counter + (128//4)])  ##destination address
        counter += (128//4)
        next_headers = []
        if int(ip6h.nextheader, base=16) not in [TCP_PROTO, UDP_PROTO, ICMPV4_PROTO, ICMPV6_PROTO]:
            next_headers.append(int(ip6h.nextheader, base=16))
        ##RECURSIVELY FIND EXTENSION HEADERS
        for header in next_headers:
            if header == 0: ## Hop-by-Hop Options Header
                next_headers.append(hexbuf[counter: counter + (8//4)]) ##header type immediately following the Hop-by-hop options header (same values as for Ipv4)
                counter += (8 + (int(hexbuf[counter: counter + (8//4)], base=16) * 8))//4
        ip6h.extheaders = next_headers[1:]
        return ip6h

    
class icmp4header:
    def __init__(self): ##datatracker.ietf.org/html/rfc792
        self.type           = None #Type, 8 bits
        self.code           = None #Code, 8 bits
        self.checksum       = None #Checksum, 16 bits
        self.ip4header      = None #IPv4 header
        self.datagrambytes  = None #first 64 bits of the datagram
    
    # We need the iphdr to verify the checksum
    @staticmethod
    def read(buf, bufstart, iphdr=None):
        icmph = icmp4header()
        (icmph.type, icmph.code, icmph.checksum, unused, icmph.ip4header, icmph.datagrambytes) = struct.unpack_from('!ss2s4sBHHHBBH4s4s8s', buf, bufstart)
        # if VERIFY_CHECKSUMS and udph.chksum != 0:
        #     if not iphdr: 
        #         eprint('call to udpheader.read() needs iphdr')
        #         return None
        #     calc_chksum = transportheader_getchk(buf, bufstart, iphdr.srcaddrb, iphdr.dstaddrb, UDP_PROTO, len(buf)-bufstart)
        #     if calc_chksum != 0xffff: 
        #         eprint('packet with bad UDP checksum received')
        #         return None
        return icmph

class udpheader:
    def __init__(self):
        self.udphdrlen = None
        self.srcport = None
        self.dstport = None
        self.length  = None
        self.chksum  = None
        
    # We need the iphdr to verify the checksum
    @staticmethod
    def read(buf, bufstart, iphdr=None):
        udph = udpheader()
        (udph.srcport, udph.dstport,udph.length, udph.chksum) = struct.unpack_from('>HHHH', buf, bufstart)
        if VERIFY_CHECKSUMS and udph.chksum != 0:
            if not iphdr: 
                eprint('call to udpheader.read() needs iphdr')
                return None
            calc_chksum = transportheader_getchk(buf, bufstart, iphdr.srcaddrb, iphdr.dstaddrb, UDP_PROTO, len(buf)-bufstart)
            if calc_chksum != 0xffff: 
                eprint('packet with bad UDP checksum received')
                return None
        return udph
 
    # Does NOT do the checksum, because we don't really know the ip header source address
    def write_nochk(self, buf : bytearray, bufstart):
        struct.pack_into('!HHHH', buf, bufstart, self.srcport, self.dstport, self.length, 0)
        # checksum = transportheader_getchk(buf, bufstart, iphdr.srcaddrb, iphdr.dstaddrb, UDP_PROTO, iphdr.length)
        # struct.pack_into('!H', buf, bufstart+ 6, 0xFFFF - checksum)		# checksum has offset 6
    
class tcpheader:  
    def __init__(self):
        self.tcphdrlen= None
        self.srcport  = None
        self.dstport  = None
        self.absseqnum= None	# absolute sequence number
        self.absacknum= None
        self.flags    = None
        self.winsize  = None
        self.chksum   = None
        self.urgent   = None
        
        
    # We need the iphdr to verify the checksum
    @staticmethod
    def read(buf : bytes, bufstart, iphdr=None):	# bufstart is start of tcp header   
        if VERIFY_CHECKSUMS:  
            if not iphdr: 
                eprint('call to tcpheader.read() needs iphdr')
                return None
            calc_chksum = transportheader_getchk(buf, bufstart, iphdr.srcaddrb, iphdr.dstaddrb, TCP_PROTO, len(buf)-bufstart)
            if calc_chksum != 0xffff: 
                eprint('packet with bad TCP checksum received')
                return  None
        tcph = tcpheader()
        # absacknum in the following may be garbage
        (tcph.srcport, tcph.dstport, tcph.absseqnum, tcph.absacknum, flagword, tcph.winsize, tcph.chksum, tcph.urgent) = struct.unpack_from('!HHIIHHHH', buf, bufstart)
        tcph.tcphdrlen = (flagword >> 12)*4
        tcph.flags = flagword & TCPFLAGMASK    
        return tcph
        
    # needs srport, dstport, absseqnum, absacknum, flawgword, winsize
    def write(self, buf : bytearray, bufstart, iphdr: ip4header):
        flagword = (self.tcphdrlen  << 10) & self.flags  	# Note tcphsize is already multiplied by 4, so shift is 10
        struct.pack_into('!HHIIHHHH', buf, bufstart, self.srcport, self.dstport, self.absseqnum, self.absacknum,
            flagword, self.winsize, 0, self.urgent)
        checksum = transportheader_getchk(buf, bufstart, iphdr.srcaddrb, iphdr.dstaddrb, TCP_PROTO, iphdr.length)
        struct.pack_into('!H', buf, bufstart+ 6, 0xFFFF - checksum)		# checksum has offset 6
            
    def __str__(self):
        return '[srcport={}, dstport={}, seqnum={}, acknum={}, flags={}, winsize={}'.format(self.srcport, self.dstport, self.absseqnum, self.absacknum, self.flags, self.winsize)
       
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


