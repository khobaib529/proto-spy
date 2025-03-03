#define _BSD_SOURCE
#define _DEFAULT_SOURCE

#include "tcp_listener.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "tcp_packet.h"

void listen_tcp() {
  int sock_raw;
  uint8_t buffer[65536];
  socklen_t saddr_len;
  struct sockaddr_in saddr;

  // Create raw socket
  if ((sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  std::cout << "Listening for TCP packets... (run as root)\n";

  while (true) {
    saddr_len = sizeof(saddr);
    int packet_size = recvfrom(sock_raw, buffer, sizeof(buffer), 0,
                               (struct sockaddr*)&saddr, &saddr_len);
    if (packet_size < 0) {
      perror("recvfrom");
      close(sock_raw);
      exit(EXIT_FAILURE);
    }

    // Parse IP header
    struct iphdr* iph = reinterpret_cast<struct iphdr*>(buffer);
    if (iph->protocol != IPPROTO_TCP) continue;

    // Calculate header lengths
    uint16_t ip_hlen = iph->ihl * 4;
    if (ip_hlen < 20 || packet_size < ip_hlen) {
      std::cerr << "Invalid IP header\n";
      continue;
    }

    // Extract TCP segment
    uint8_t* tcp_segment = buffer + ip_hlen;
    size_t tcp_segment_len = packet_size - ip_hlen;

    // Decode TCP packet
    TCPPacket packet;
    if (!packet.DecodeFrom(tcp_segment, tcp_segment_len)) {
      std::cerr << "Failed to decode TCP packet\n";
      continue;
    }

    // Format source/dest addresses
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);

    // Print results
    std::cout << "\n=========================\n"
              << "Source: " << src_ip << ":" << packet.source_port << "\n"
              << "Destination: " << dst_ip << ":" << packet.dest_port << "\n"
              << packet.DebugString() << "=========================\n";
  }
  close(sock_raw);
}