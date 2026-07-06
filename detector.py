# detector.py
# This file is part of the pcktscrub project
# by cannondev 07/01/2026

import sys

from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, ARP

if len(sys.argv) > 1:
    pcfile = sys.argv[1]
else:
    pcfile = 'lab.pcap'

pc = rdpcap(pcfile)

#we now have a packet capture, with tons of packets
#lets detect port scanning
#so what we will do is walk through pc
#get source ip and add to dictionary if not already there
#take the the destination port and add it to the set of that source ip
# OR just keep a count of the number of unique destination ports for each source ip

#new dictionary
port_scan_dict = defaultdict(set)

for packet in pc:
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        port_scan_dict[src_ip].add(dst_port)

#gonna count now
# loop over each source ip and check how many dst ports it has, add that number to the value

port_freq_dict = defaultdict(int)
for src_ip, dst_ports in port_scan_dict.items():
    port_freq_dict[src_ip] = len(dst_ports)

for src_ip, freq in port_freq_dict.items():
    if freq > 10:  # arbitrary threshold for port scanning
        print(f"Potential port scan detected from {src_ip} to {freq} unique destination Ports.")


# Basic cleartext credentials detection for HTTP requests

#raw payload
for packet in pc:
    if packet.haslayer(TCP) and packet.haslayer(IP):
        payload = bytes(packet[TCP].payload)
        if b'Authorization: Basic' in payload:
            print(f"Potential cleartext credentials detected in HTTP from {packet[IP].src} to {packet[IP].dst}")


# ARP spoofing detection proof of concept
# looking for one IP associated with 2 or more MAC addresses
arp_dict = defaultdict(set)
for packet in pc:
    if packet.haslayer(ARP):
        arp_dict[packet[ARP].psrc].add(packet[ARP].hwsrc) #psrc refers to IP, hwsrc refers to MAC address

# Check for ARP spoofing
for ip, macs in arp_dict.items():
    if len(macs) > 1:
        print(f"Potential ARP spoofing detected for IP {ip} with MAC addresses: {macs}")