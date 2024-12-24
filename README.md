# Packet Sniffer

## Overview
The Packet Sniffer is a Python-based tool that captures and analyzes network packets. It is particularly useful for monitoring HTTP traffic, identifying sensitive data (like usernames and passwords), and troubleshooting network issues.

---

## Features
- Captures and inspects HTTP requests.
- Extracts URLs and sensitive data (e.g., usernames and passwords) from raw packets.
- Easy to use with command-line arguments for specifying the network interface.

---

## Prerequisites
Ensure the following are installed on your system:
- Python 3.x
- [Scapy](https://scapy.net/) library

Install Scapy using pip:
```bash
pip install scapy
```

---

## Usage
### 1. Clone the Repository
```bash
git clone https://github.com/rahullswami/packet-sniffer.git
cd packet-sniffer
```

### 2. Run the Script
```bash
python packet_sniffer.py -i <network_interface>
```
Replace `<network_interface>` with the interface to sniff on (e.g., `wlan0` or `eth0`).

### Example:
```bash
python packet_sniffer.py -i wlan0
```

---

## Output
- Captures and displays HTTP requests with URLs.
- Detects potential sensitive data like usernames and passwords.

### Sample Output:
```
[+] HTTP Request >> example.com/login
[+] Possible sensitive data >> username=admin&password=12345
```

---

## Notes
- **Root Permission**: This tool requires root privileges to sniff packets. Run it with `sudo` if needed.
- **Legal Warning**: Use this tool only on networks you own or have explicit permission to analyze. Unauthorized usage is illegal.

---


