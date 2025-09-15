import socket
from scapy.all import DNS, DNSQR
import datetime

SERVER_IP = '127.0.0.1'
SERVER_PORT = 5300
BUFFER_SIZE = 1024
LOG_FILE = 'dns_resolver.log'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, SERVER_PORT))

print(f"Resolver server is listening on {SERVER_IP}:{SERVER_PORT}")
print(f"Results will be saved to '{LOG_FILE}'")

with open(LOG_FILE, 'w') as f:
    f.write("Timestamp, Query, Custom_Header, Resolved_IP\n")

while True:
    # This is the line that was corrected
    data, addr = sock.recvfrom(BUFFER_SIZE) 
    
    try:
        custom_header = data[:8].decode('utf-8')
        dns_payload = data[8:]
        
        dns_packet = DNS(dns_payload)
        qname = dns_packet[DNSQR].qname.decode('utf-8')
        
        resolved_ip = "Not Found"
        try:
            # We use the qname without the trailing dot for resolution
            resolved_ip = socket.gethostbyname(qname.rstrip('.'))
        except socket.gaierror:
            print(f"Could not resolve: {qname}")
            
        log_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"{log_time},{qname},{custom_header},{resolved_ip}\n"
        
        print(f"Resolved: {qname} -> {resolved_ip}")
        
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
            
    except Exception as e:
        print(f"Error processing packet: {e}")
