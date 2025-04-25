#ifndef UDP_PACKET_H_
#define UDP_PACKET_H_

#include <netinet/udp.h>

#include <cstdint>
#include <string>
#include <vector>

class UDPPacket {
 public:
  // Decode raw UDP packet into header_ and payload_
  bool DecodeFrom(const uint8_t* buf, size_t len);
  // Return a string with all parsed fields for debugging
  std::string DebugString() const;

 private:
  struct udphdr header_;
  std::vector<uint8_t> payload_;
  // Helper to format payload bytes (printable or hex)
  std::string FormatPayload() const;
};

#endif  // UDP_PACKET_H_
