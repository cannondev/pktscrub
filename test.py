from scapy.all import rdpcap, ARP

pkts = rdpcap("arp_test.pcap")
for p in pkts:
    if p.haslayer(ARP):
        p[ARP].show()
        break