# NetSniffer

**NetSniffer** is a Python-based network packet analyzer that captures and analyzes network packets in real-time. Using the `scapy` library, it extracts key information such as source and destination IP addresses, protocols, and payload data. This tool is designed for educational purposes, and ethical considerations should be followed when using it.

## Features
- Captures network packets in real-time.
- Displays source and destination IP addresses.
- Analyzes network protocols (TCP, UDP, ICMP, etc.).
- Extracts and displays payload data from the packets.

## Requirements
- Python 3.x
- `scapy` library

### Installation:
1. Install the required library:
   ```bash
   pip install scapy
   
###Run the Python script with administrative privileges:

```bash

sudo python packet_sniffer.py
```
###The tool will start capturing network packets and display key information.

Example Output:
```bash
Source IP: 192.168.1.5 --> Destination IP: 192.168.1.10
Protocol: 6
Payload Data: TCP
```
###Ethical Considerations

Authorization:
Ensure you have explicit permission to use the packet sniffer on any network. Unauthorized sniffing of network traffic can be illegal.
Privacy: Do not capture personal or sensitive data without consent. This tool should only be used for educational or troubleshooting purposes on authorized networks.
##License
This project is open-source and available under the MIT License.

arduino
Copy code
