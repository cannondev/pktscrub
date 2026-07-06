# sanitizer.py
# This file is part of the pcktscrub project
# by cannondev 07/01/2026

# 4 Main Objectives:
# For each packet in a pcap file:
# Anonymize IPs - using Crypto-PAn algorithm
# Anonymize MACs - simple hasing, looking for a better practice
# Clean Payloads - remove sentitive data, replace with same byte length of data, looking for a better practice

# First we need to get the pcap file, and read it

import sys
from scapy.all import rdpcap, IP, TCP, UDP, ARP

from pathlib import Path

from yacryptopan import CryptoPAn

KEY_FILE = Path.home() / ".pktscrub" / "crypto_pan.key"
PCAP_FILE = Path("/home/cannondev/pktscrub/sample_pcaps/creds.pcap")

if not KEY_FILE.exists():
    print(f"ERROR: key file not found: {KEY_FILE}")
    sys.exit(1)

with open(KEY_FILE, "rb") as f:
    key = f.read()

if len(key) != 32:
    print(f"ERROR: invalid key length {len(key)}, expected 32 bytes")
    sys.exit(1)

try:
    cp = CryptoPAn(key)
except Exception as exc:
    print(f"ERROR: failed to initialize CryptoPAn: {exc}")
    sys.exit(1)

# key is the 32-byte binary key

if not PCAP_FILE.exists():
    print(f"ERROR: pcap file not found: {PCAP_FILE}")
    sys.exit(1)

try:
    pcapture = rdpcap(str(PCAP_FILE))
except Exception as exc:
    print(f"ERROR: failed to read pcap file: {exc}")
    sys.exit(1)

if len(pcapture) == 0:
    print("No packets found in the pcap file.")
    exit()
else: 
    print(f"Total packets in the pcap file: {len(pcapture)}")

# IP Anonymization via Crypto-PAn
# for now im just gonna add all ips to a set
ips = set()
for packet in pcapture:
    if packet.haslayer(IP):
        ips.add(packet[IP].src)

for ip in ips:
    print(f"Unique IP: {ip}")

# now they are all in a set, i want to make a dictionary of key value pairs. key is IP, value is anonymized IP using Crypto-PAn
# Then i will go back through each packet and replace the IP with the anonymized IP in the new packet construction
anon_ips = {}
for ip in ips:
    anon_ip = cp.anonymize(ip)
    anon_ips[ip] = anon_ip

print(f"Anonymized IPs: {anon_ips}")

