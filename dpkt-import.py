###pip install dpkt

import dpkt

import sys
input_pcaps = []

def dpkt_read_pcap(pcap):
    try:
        for ts, pkt in dpkt.pcap.Reader(open(pcap, 'rb')):
            print(f"{ts}: {pkt}")
    except:
        print(f"File {pcap} not found. Aborting.\n")
        return
        
# pcaps = list(input("Enter list of files to be parsed:\n"))
# print(type(pcaps))
# if len(pcaps) != 0:
#     print(f"You have entered {len(pcaps)} files to be parsed.\n")
#     # pcaps = set(pcaps) ##remove duplicate pcaps
#     # print(pcaps)
#     for pcap in pcaps:
#         # pcap_name = pcap.split('.')
#         print(pcap)
#         # if pcap.split('.')[-1].lower() != 'pcap':
            
#             # print(f"File {pcap} not a pcap. Aborting.\n")
#         # else:
#             # dpkt_read_pcap(pcap)
# else:
#     print(f"Error: at least one file needed to run. Aborting.\n")

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
                print("Imagine success.\n")
                # dpkt_read_pcap(pcap)
    else:
        print(f"Error: at least one file needed to run. Aborting.\n")
    # while len(input_pcaps) > 0:
    #     dpkt_read_pcap(input_pcaps.pop())
    print("No more files to be analysed. Exiting\n")
except:
    print("Error. Need to pass in at least one file to be analysed. Aborting\n")