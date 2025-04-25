#!/usr/bin/env python3
"""
TCP Packet Sender for proto-spy testing
"""

import argparse
import os
from scapy.all import IP, TCP, Raw, send

DEFAULTS = {
    'src_ip': '127.0.0.1',
    'dst_ip': '192.168.0.104',
    'sport': 45258,
    'dport': 47873,
    'seq': 25000,
    'ack': 12500,
    'window': 0x4e02,
    'flags': 'A',
    'payload': 'hello from scapy'
}


def build_ip_layer(src, dst):
    """Construct IP layer with specified source/destination"""
    return IP(src=src, dst=dst)


def build_tcp_layer(params):
    """Create TCP layer with configured parameters"""
    return TCP(sport=params['sport'],
               dport=params['dport'],
               seq=params['seq'],
               ack=params['ack'],
               dataofs=8,
               flags=params['flags'],
               window=params['window'],
               urgptr=3,
               options=[('NOP', None), ('NOP', None),
                        ('Timestamp', (0x19a2fc43, 0xf379fb67))])


def build_payload(data):
    """Create payload from string data"""
    return Raw(load=data)


def send_packet(packet):
    """Send constructed packet with error handling"""
    try:
        send(packet, verbose=0)
        print(f"[+] Successfully sent {len(packet)} byte packet")
        print(f"    Destination: {packet[IP].dst}:{packet[TCP].dport}")
    except Exception as e:
        print(f"[!] Error sending packet: {e}")
        exit(1)


def parse_arguments():
    """Handle command-line arguments"""
    parser = argparse.ArgumentParser(description='TCP Packet Sender')
    parser.add_argument('--src-ip',
                        default=DEFAULTS['src_ip'],
                        help='Source IP')
    parser.add_argument('--dst-ip',
                        default=DEFAULTS['dst_ip'],
                        help='Destination IP')
    parser.add_argument('--sport',
                        type=int,
                        default=DEFAULTS['sport'],
                        help='Source port')
    parser.add_argument('--dport',
                        type=int,
                        default=DEFAULTS['dport'],
                        help='Destination port')
    parser.add_argument('--seq',
                        type=int,
                        default=DEFAULTS['seq'],
                        help='Sequence number')
    parser.add_argument('--ack',
                        type=int,
                        default=DEFAULTS['ack'],
                        help='Acknowledgment number')
    parser.add_argument('--window',
                        type=int,
                        default=DEFAULTS['window'],
                        help='Window size')
    parser.add_argument('--flags', default=DEFAULTS['flags'], help='TCP flags')
    parser.add_argument('--payload',
                        default=DEFAULTS['payload'],
                        help='Payload content')
    return vars(parser.parse_args())


def main():
    if os.geteuid() != 0:
        print("[!] Error: Requires root privileges (use sudo)")
        exit(1)

    params = parse_arguments()

    ip = build_ip_layer(params['src_ip'], params['dst_ip'])
    tcp = build_tcp_layer(params)
    payload = build_payload(params['payload'])

    packet = ip / tcp / payload
    send_packet(packet)


if __name__ == "__main__":
    main()
