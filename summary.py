# summary.py 
# by Thomas Clark 06/29/2026

import sys

#first order of business: count the packets in a packet capture file
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ARP

if len(sys.argv) > 1:
    pcfile = sys.argv[1]
else:
    pcfile = 'lab.pcap'

pc = rdpcap(pcfile)

print(f"Total packets: {len(pc)}")

# get and count all source protocols
protocol_counts = Counter()
src_ip_counts = Counter()
dst_ip_counts = Counter()

def countSrcIps(packets):
    for packet in packets:
        if packet.haslayer(IP):
            src_ip_counts[packet[IP].src] += 1
    return src_ip_counts

def countDstIps(packets):
    for packet in packets:
        if packet.haslayer(IP):
            dst_ip_counts[packet[IP].dst] += 1
    return dst_ip_counts

def countProtocols(packets):
    for packet in packets:
        if packet.haslayer(ARP):
            protocol_counts["ARP"] += 1
        elif packet.haslayer(TCP):
            protocol_counts["TCP"] += 1
        elif packet.haslayer(UDP):
            protocol_counts["UDP"] += 1
        elif packet.haslayer(IP):
            protocol_counts["IP"] += 1
    return protocol_counts

print(f"Most common source ips:")
countSrcIps(pc)
for src_ip, count in src_ip_counts.most_common(5):
    print(f"{src_ip}: {count}")

print(f"Most common source dst ips:")
countDstIps(pc)
for dst_ip, count in dst_ip_counts.most_common(5):
    print(f"{dst_ip}: {count}")

print(f"Most common source protocols:")
countProtocols(pc)
for protocol, count in protocol_counts.most_common(5):
    print(f"{protocol}: {count}")
