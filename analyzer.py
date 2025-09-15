from scapy.all import rdpcap, IP, ICMP

pcap_file = 'traceroute_capture.pcap'

try:
    packets = rdpcap(pcap_file)
except FileNotFoundError:
    print(f"Error: Capture file '{pcap_file}' not found.")
    exit()

print(f"--- Analyzing '{pcap_file}' ---")

my_ip = None
# Find the IP of your machine from the first outgoing ICMP Echo Request
for packet in packets:
    if packet.haslayer(IP) and packet.haslayer(ICMP) and packet[ICMP].type == 8: # Echo Request
        my_ip = packet[IP].src
        break

if not my_ip:
    print("Could not determine local IP from the capture file. No ICMP Echo Requests found.")
    exit()

print(f"Your IP was determined to be: {my_ip}")
print("-" * 30)


for i, packet in enumerate(packets):
    if not packet.haslayer(IP):
        continue

    # Outgoing packets sent by your machine
    if packet[IP].src == my_ip and packet.haslayer(ICMP):
        ttl = packet[IP].ttl
        dst_ip = packet[IP].dst
        icmp_type = packet[ICMP].type
        print(f"Packet #{i+1}: YOU -> {dst_ip} | TTL: {ttl: <2} | ICMP Type: {icmp_type} (Echo Request)")

    # Incoming packets received by your machine
    elif packet[IP].dst == my_ip and packet.haslayer(ICMP):
        src_ip = packet[IP].src
        icmp_type = packet[ICMP].type
        
        if icmp_type == 11:
            print(f"Packet #{i+1}: {src_ip} -> YOU | ICMP Type: 11 (TTL Exceeded)")
        elif icmp_type == 0:
            print(f"Packet #{i+1}: {src_ip} -> YOU | ICMP Type: 0 (Echo Reply) <-- FINAL DESTINATION")
        else:
            print(f"Packet #{i+1}: {src_ip} -> YOU | ICMP Type: {icmp_type}")
