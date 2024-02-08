###pip install dpkt

import datetime
import dpkt
# from dpkt.compat import compat_ord
import socket

import sys
input_pcaps = []

#### https://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html#mac_addr , accessed 21/12/2023

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    # return ':'.join('%02x' % compat_ord(b) for b in address)
    return bytearray(address).hex()

def readable_mac_addr(address):
    return ':'.join(address[i:i+2] for i in range (0, len(address), 2))

def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def print_packets(pcap):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Print out the timestamp in UTC
        print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        src = mac_addr(eth.src)
        dst = mac_addr(eth.dst)
        # print('Ethernet Frame (binary): ', dst, src, eth.type, bytearray(eth.data).hex())
        
        print('Ethernet Frame: ', readable_mac_addr(dst), readable_mac_addr(src), hex(eth.type), eth.data)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
              (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))

def dpkt_read_pcap(pcap):
    try:
        # for ts, pkt in dpkt.pcap.Reader(open(pcap, 'rb')):
        #     # print(f"{ts}: {pkt}")
        #     print_packets(pkt)
        with open(pcap, 'rb') as f: ##handles closing it afterwards
            pcap = dpkt.pcap.Reader(f)
            print_packets(pcap)
    except:
        print(f"File {pcap} not found. Aborting.\n")
        return
        
try:
    num_packets = len(sys.argv)-1
    for i in range(num_packets): ##don't include the python script
        input_pcaps.append(sys.argv[i+1]) ##first index is the tool itself
    input_pcaps = set(input_pcaps) #remove duplicate pcaps
    print(input_pcaps)
    if len(input_pcaps) > 0:
        print(f"You have entered {len(input_pcaps)} unique files to be parsed.\n")
        for pcap in input_pcaps:
            print(pcap)
            pcap_name = pcap.split('.')
            if pcap.split('.')[-1].lower() != 'pcap':
                print(f"File {pcap} not a pcap. Aborting.\n")
            else:
                # print("Imagine success.\n")
                dpkt_read_pcap(pcap)
    else:
        print(f"Error. At least one file needed to run. Aborting.\n")
    print("No more files to be analysed. Exiting\n")
except:
    print("Error. Need to pass in at least one file to be analysed. Aborting\n")