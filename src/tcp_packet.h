#ifndef TCP_PACKET_H_
#define TCP_PACKET_H_

#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <string>
#include <vector>

class TCPPacket {
 public:
  bool DecodeFrom(const uint8_t* buf, size_t len);
  std::string DebugString() const;

 private:
  std::string FormatPayload() const;
  std::string FormatOptions() const;
  std::string FormatFlags() const;
  uint8_t GetDataOffset() const;
  uint8_t GetReserved() const;

  tcphdr header_;
  std::vector<uint8_t> payload_;
  std::vector<uint8_t> options_;
};

#endif  // TCP_PACKET_H_
