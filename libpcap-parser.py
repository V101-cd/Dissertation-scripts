import datetime
import sys
# import pylibpcap
from pylibpcap.pcap import rpcap
import socket
import struct
from packet import *

input_pcaps = []
FILENAME = ""

def process_single_packet(pcap_name, length, time, packet_buffer:bytes, start_position):
    global CONNECTIONDICT
    eth_header = ethheader.read(packet_buffer, 0)
    if eth_header != 0x0800: ## ignore non-IPv4 packets
        return None
    ip4_header = ip4header.read(packet_buffer, )

def libpcap_read_pcap(pcap_to_read):
    # try:
        # print("I'm reading!!!!")
        # for ts, pkt in dpkt.pcap.Reader(open(pcap, 'rb')):
        #     # print(f"{ts}: {pkt}")
        #     print_packets(pkt)
    packet_num = 0
        # with open(pcap, 'rb') as f: ##handles closing it afterwards
        #     pcap = "hello"
        #     print_packets(packet_num, pcap)
        #     packet_num += 1
    for length, time, packet_buffer in pylibpcap.rpcap(pcap_to_read):
        if packet_num <= 100: #restrict to 100 packets to avoid flooding the terminal

            print("\nPacket: ",packet_num)
            print("Buf length: ", length)
            print("Time: ", time)
            print("Buf: ", packet_buffer)
            packet_num += 1
    # except:
    #     print(f"File {pcap_to_read} not found. Aborting.\n")
    #     return
        
try:
    num_packets = len(sys.argv)-1
    for i in range(num_packets): ##don't include the python script
        input_pcaps.append(sys.argv[i+1]) ##first index is the tool itself
    input_pcaps = set(input_pcaps) #remove duplicate pcaps
    print(input_pcaps)
    if len(input_pcaps) > 0:
        print(f"You have entered {len(input_pcaps)} unique files to be parsed.\n")
        for pcap_to_parse in input_pcaps:
            print(pcap_to_parse)
            # pcap_name = pcap_to_parse.split('.')
            if pcap_to_parse.split('.')[-1].lower() != 'pcap':
                print(f"File {pcap_to_parse} not a pcap. Aborting.\n")
            else:
                # print("Imagine success.\n")
                libpcap_read_pcap(pcap_to_parse)
    else:
        print(f"Error. At least one file needed to run. Aborting.\n")
    print("No more files to be analysed. Exiting\n")
except:
    print("Error. Need to pass in at least one file to be analysed. Aborting\n")