#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>

#include <array>
#include <iostream>

#include "udp_packet.h"

class RawSocket {
 public:
  explicit RawSocket(int protocol)
      : fd_(socket(AF_PACKET, SOCK_RAW, protocol)) {
    if (fd_ < 0) {
      perror("socket");
      std::exit(EXIT_FAILURE);
    }
  }

  ~RawSocket() {
    if (fd_ >= 0) close(fd_);
  }

  ssize_t receive(uint8_t* buf, size_t len) const {
    return ::recvfrom(fd_, buf, len, 0, nullptr, nullptr);
  }

 private:
  int fd_;
};

void listen_udp() {
  RawSocket sock(ETH_P_ALL);
  std::cout << "Listening for UDP packets...\n";
  std::cout << "Fields starting with * are not part of the UDP packet\n";

  constexpr size_t kMaxPacketSize = 65536;
  std::array<uint8_t, kMaxPacketSize> buffer;
  UDPPacket packet;

  while (true) {
    ssize_t packet_size = sock.receive(buffer.data(), buffer.size());
    if (packet_size < 0) {
      perror("recvfrom");
      std::exit(EXIT_FAILURE);
    }

    if (packet_size <
        static_cast<ssize_t>(sizeof(ethhdr) + sizeof(iphdr) + sizeof(udphdr))) {
      continue;
    }

    const ethhdr* eth = reinterpret_cast<const ethhdr*>(buffer.data());
    if (eth->h_proto != htons(ETH_P_IP)) continue;

    const iphdr* ip =
        reinterpret_cast<const iphdr*>(buffer.data() + sizeof(ethhdr));
    if (ip->version != 4 || ip->protocol != IPPROTO_UDP) continue;

    size_t ip_header_len = ip->ihl * 4;
    size_t udp_offset = sizeof(ethhdr) + ip_header_len;
    if (packet_size < static_cast<ssize_t>(udp_offset + sizeof(udphdr)))
      continue;

    const uint8_t* udp_seg = buffer.data() + udp_offset;
    size_t udp_len = packet_size - udp_offset;

    if (!packet.DecodeFrom(udp_seg, udp_len)) continue;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

    std::cout << "\n===== UDP Packet =====\n"
              << "* From        : " << src_ip << "\n"
              << "* To          : " << dst_ip << "\n"
              << packet.DebugString() << "\n"
              << "======================\n";
  }
}
