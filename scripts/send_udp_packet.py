#!/usr/bin/env python3
"""
UDP Packet Sender for proto-spy testing
"""

import argparse
import os
from scapy.all import IP, UDP, Raw, send

# Configuration defaults
DEFAULTS = {
    'src_ip': '127.0.0.1',
    'dst_ip': '192.168.0.104',
    'sport': 45258,
    'dport': 47873,
    'payload': 'hello from scapy',
    'checksum': None
}


def build_ip_layer(src, dst):
    """Construct IP layer with specified source/destination"""
    return IP(src=src, dst=dst)


def build_udp_layer(params):
    """Create UDP layer with configurable parameters"""
    return UDP(
        sport=params['sport'],  # Fixed key name
        dport=params['dport'],  # Fixed key name
        chksum=params['checksum']  # Fixed key name
    )


def build_payload(data):
    """Create payload from string data"""
    return Raw(load=data)


def send_packet(packet):
    """Send constructed packet with error handling"""
    try:
        send(packet, verbose=0)
        print(f"[+] Successfully sent {len(packet)} byte UDP packet")
        print(f"    Destination: {packet[IP].dst}:{packet[UDP].dport}")
    except Exception as e:
        print(f"[!] Error sending packet: {e}")
        exit(1)


def parse_arguments():
    """Handle command-line arguments for UDP packet customization"""
    parser = argparse.ArgumentParser(
        description='UDP Packet Sender for proto-spy testing')
    parser.add_argument('--src-ip',
                        default=DEFAULTS['src_ip'],
                        help='Source IP address')
    parser.add_argument('--dst-ip',
                        default=DEFAULTS['dst_ip'],
                        help='Destination IP address')
    parser.add_argument('--sport',
                        type=int,
                        default=DEFAULTS['sport'],
                        help='Source port')
    parser.add_argument('--dport',
                        type=int,
                        default=DEFAULTS['dport'],
                        help='Destination port')
    parser.add_argument('--payload',
                        default=DEFAULTS['payload'],
                        help='Payload content')
    parser.add_argument('--checksum',
                        type=int,
                        default=DEFAULTS['checksum'],
                        help='Force specific UDP checksum (0 for none)')
    return vars(parser.parse_args())


def main():
    # Privilege check
    if os.geteuid() != 0:
        print("[!] Error: Packet sending requires root privileges (use sudo)")
        exit(1)

    # Get configuration
    params = parse_arguments()

    # Build packet layers
    ip = build_ip_layer(params['src_ip'], params['dst_ip'])
    udp = build_udp_layer(params)
    payload = build_payload(params['payload'])

    # Assemble and send packet
    packet = ip / udp / payload
    send_packet(packet)


if __name__ == "__main__":
    main()
