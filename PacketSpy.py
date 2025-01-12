from scapy.all import *

# Function to analyze the packets
def packet_callback(packet):
    if packet.haslayer(IP):
        # Extracting the source and destination IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Extracting the protocol
        protocol = packet.proto
        
        # Extracting the payload data (if any)
        payload = packet.payload
        
        # Displaying packet details
        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        print(f"Payload Data: {payload}\n")

# Start sniffing packets on the network interface
def start_sniffing():
    print("Starting packet sniffer... Press CTRL+C to stop.")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()
