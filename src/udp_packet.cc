#include "udp_packet.h"

#include <arpa/inet.h>

#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>

bool UDPPacket::DecodeFrom(const uint8_t* buf, size_t len) {
  if (len < sizeof(header_)) return false;
  std::memcpy(&header_, buf, sizeof(header_));
  uint16_t udp_len = ntohs(header_.uh_ulen);
  if (udp_len < sizeof(header_) || udp_len != len) return false;

  size_t payload_len = udp_len - sizeof(header_);
  payload_.assign(buf + sizeof(header_), buf + sizeof(header_) + payload_len);
  return true;
}

std::string UDPPacket::DebugString() const {
  std::ostringstream oss;
  oss << "Source Port: " << ntohs(header_.uh_sport) << "\n"
      << "Dest Port: " << ntohs(header_.uh_dport) << "\n"
      << "Length: " << ntohs(header_.uh_ulen) << "\n"
      << "Checksum: 0x" << std::hex << std::setw(4) << std::setfill('0')
      << ntohs(header_.uh_sum) << std::dec << "\n"
      << "Payload (" << payload_.size() << " bytes): " << FormatPayload();
  return oss.str();
}

std::string UDPPacket::FormatPayload() const {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0') << std::setw(2);

  for (const uint8_t& byte : payload_) {
    if (std::isprint(byte)) {
      oss << static_cast<char>(byte);
    } else {
      oss << "0x" << static_cast<uint32_t>(byte);
    }
    oss << ' ';
  }

  return oss.str();
}
