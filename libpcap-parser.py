import datetime
import sys
# sys.path.insert(1,'python-libpcap-master/pylibpcap')
import pylibpcap

input_pcaps = []
# libpcap.config(LIBPCAP=None) ##change to LIBPCAP="tcpdump" and see if it makes a difference

# def print_packets(pcap):
    # """Print out information about each packet in a pcap

    #    Args:
    #        pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    # """
    # # For each packet in the pcap process the contents
    # for timestamp, buf in pcap:

    #     # Print out the timestamp in UTC
    #     print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

    #     # Unpack the Ethernet frame (mac src/dst, ethertype)
    #     eth = libpcap.ethernet.Ethernet(buf)
    #     src = libpcap(eth.src)
    #     dst = libpcap(eth.dst)
    #     # print('Ethernet Frame (binary): ', dst, src, eth.type, bytearray(eth.data).hex())
    #     data_link_data = eth.__bytes__
    #     network_data = eth.data.__bytes__
    #     transport_data = eth.data.data.__bytes__
        
    #     print('Ethernet Frame: ', dst, src, hex(eth.type), eth.data.__bytes__)

    #     # Make sure the Ethernet data contains an IP packet
    #     if not isinstance(eth.data, dpkt.ip.IP):
    #         print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
    #         continue

    #     # Now unpack the data within the Ethernet frame (the IP packet)
    #     # Pulling out src, dst, length, fragment info, TTL, and Protocol
    #     ip = eth.data

    #     # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
    #     do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
    #     more_fragments = bool(ip.off & dpkt.ip.IP_MF)
    #     fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

    #     # Print out the info
    #     print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
    #           (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))

def print_packets(pcap_name, pcap):
    print("Packet ", pcap_name, " : ", pcap)
def libpcap_read_pcap(pcap):
    try:
        # for ts, pkt in dpkt.pcap.Reader(open(pcap, 'rb')):
        #     # print(f"{ts}: {pkt}")
        #     print_packets(pkt)
        packet_num = 0
        with open(pcap, 'rb') as f: ##handles closing it afterwards
            pcap = "hello"
            print_packets(packet_num, pcap)
            packet_num += 1
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
                libpcap_read_pcap(pcap)
    else:
        print(f"Error. At least one file needed to run. Aborting.\n")
    print("No more files to be analysed. Exiting\n")
except:
    print("Error. Need to pass in at least one file to be analysed. Aborting\n")