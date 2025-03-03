#ifndef TCP_PACKET_H_
#define TCP_PACKET_H_

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

class TCPPacket {
 public:
  // TCP header fields
  uint16_t source_port;
  uint16_t dest_port;
  uint32_t sequence_number;
  uint32_t ack_number;
  uint16_t offset_reserved_flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_pointer;
  std::vector<uint8_t> options;
  std::vector<uint8_t> payload;

  enum class TCPFlag : uint8_t {
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20,
    ECE = 0x40,
    CWR = 0x80
  };

  TCPPacket();
  bool DecodeFrom(const uint8_t* buffer, size_t len);
  std::string DebugString() const;

  // Inline accessors for header fields
  uint8_t GetDataOffset() const { return (offset_reserved_flags >> 12) & 0x0F; }
  bool GetNSFlag() const { return (offset_reserved_flags >> 9) & 0x01; }
  uint8_t GetReserved() const { return (offset_reserved_flags >> 8) & 0x07; }
  uint8_t GetFlags() const { return offset_reserved_flags & 0x00FF; }

 private:
  std::string FormatBytes(const std::vector<uint8_t>& bytes) const;
};

#endif  // TCP_PACKET_H_