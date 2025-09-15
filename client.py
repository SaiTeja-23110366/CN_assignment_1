from scapy.all import PcapReader, DNS, DNSQR, UDP
import datetime
import socket
import time

pcap_file = '6.pcap'
dns_queries = []
try:
    for packet in PcapReader(pcap_file):
        if packet.haslayer(UDP) and packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(DNSQR):
            dns_queries.append(packet)
except FileNotFoundError:
    print(f"Error: The file '{pcap_file}' was not found.")
    exit()

payloads_to_send = []
for i, packet in enumerate(dns_queries):
    now = datetime.datetime.now()
    timestamp = now.strftime("%H%M%S")
    sequence_id = f"{i:02d}"
    custom_header = (timestamp + sequence_id).encode('utf-8')
    original_dns_payload = bytes(packet[DNS])
    final_payload = custom_header + original_dns_payload
    payloads_to_send.append((final_payload, packet[DNSQR].qname.decode('utf-8')))

SERVER_IP = '127.0.0.1'
SERVER_PORT = 5300
client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print(f"\nSending {len(payloads_to_send)} DNS queries to server at {SERVER_IP}:{SERVER_PORT}...")

for payload, qname in payloads_to_send:
    client_sock.sendto(payload, (SERVER_IP, SERVER_PORT))
    print(f"Sent query for {qname}")
    time.sleep(0.1)

print("\nAll payloads sent.")
client_sock.close()
