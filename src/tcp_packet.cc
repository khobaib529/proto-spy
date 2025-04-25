#include "tcp_packet.h"

#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>

bool TCPPacket::DecodeFrom(const uint8_t* buf, size_t len) {
  if (len < sizeof(header_)) return false;

  std::memcpy(&header_, buf, sizeof(header_));

  const uint8_t data_offset = GetDataOffset();
  const size_t hdr_len = data_offset * 4;
  if (data_offset < 5 || hdr_len > len) return false;

  // Extract options
  const size_t options_len = hdr_len - sizeof(header_);
  if (options_len > 0) {
    options_.assign(buf + sizeof(header_), buf + sizeof(header_) + options_len);
  } else {
    options_.clear();
  }

  // Extract payload
  payload_.assign(buf + hdr_len, buf + len);
  return true;
}

std::string TCPPacket::DebugString() const {
  std::ostringstream oss;
  const uint8_t data_offset = GetDataOffset();

  oss << "Source Port: " << ntohs(header_.th_sport) << "\n"
      << "Dest Port: " << ntohs(header_.th_dport) << "\n"
      << "Seq: " << ntohl(header_.th_seq) << "\n"
      << "Ack: " << ntohl(header_.th_ack) << "\n"
      << "Data Offset: 0x" << std::hex << static_cast<int>(data_offset) << "\n"
      << "Reserved: 0" << std::oct << "\n"
      << "Flags: " << FormatFlags() << "\n"
      << "Window: 0x" << std::hex << std::setw(4) << ntohs(header_.th_win)
      << "\n"
      << "Checksum: 0x" << std::hex << std::setw(4) << ntohs(header_.th_sum)
      << "\n"
      << "Urgent Pointer: 0x" << std::hex << std::setw(4)
      << ntohs(header_.th_urp) << "\n";

  if (data_offset > 5) {
    oss << "TCP Options: " << FormatOptions() << "\n";
  }

  oss << "Payload (" << payload_.size() << " bytes): " << FormatPayload();
  return oss.str();
}

// Helper methods
uint8_t TCPPacket::GetDataOffset() const { return header_.th_off; }

std::string TCPPacket::FormatFlags() const {
  std::vector<std::string> flags;
  std::string result;

  if (header_.th_flags & TH_URG) flags.push_back("URG");
  if (header_.th_flags & TH_ACK) flags.push_back("ACK");
  if (header_.th_flags & TH_PUSH) flags.push_back("PSH");
  if (header_.th_flags & TH_RST) flags.push_back("RST");
  if (header_.th_flags & TH_SYN) flags.push_back("SYN");
  if (header_.th_flags & TH_FIN) flags.push_back("FIN");

// ECN flags if supported
#ifdef TH_ECE
  if (header_.th_flags & TH_ECE) flags.push_back("ECE");
#endif
#ifdef TH_CWR
  if (header_.th_flags & TH_CWR) flags.push_back("CWR");
#endif

  std::ostringstream oss;
  for (size_t i = 0; i < flags.size(); ++i) {
    if (i > 0) oss << ", ";
    oss << flags[i];
  }
  result = oss.str();
  result.insert(0, 1, '[');
  result.push_back(']');
  return result;
}
std::string TCPPacket::FormatOptions() const {
  std::vector<std::string> hex_bytes;

  for (uint8_t byte : options_) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(byte);
    hex_bytes.push_back(oss.str());
  }

  std::ostringstream oss;
  oss << "[";
  for (size_t i = 0; i < hex_bytes.size(); ++i) {
    if (i > 0) oss << ", ";
    oss << hex_bytes[i];
  }
  oss << "]";

  return oss.str();
}

std::string TCPPacket::FormatPayload() const {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');

  for (const auto& byte : payload_) {
    unsigned char ub = static_cast<unsigned char>(byte);
    if (std::isprint(ub)) {
      oss << static_cast<char>(ub);
    } else {
      oss << "0x" << std::setw(2) << static_cast<int>(ub);
    }
    oss << ' ';
  }

  return oss.str();
}
