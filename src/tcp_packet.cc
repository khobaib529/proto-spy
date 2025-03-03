#include "tcp_packet.h"

#include <arpa/inet.h>

#include <iomanip>
#include <iostream>

TCPPacket::TCPPacket() = default;

bool TCPPacket::DecodeFrom(const uint8_t* buffer, size_t len) {
  if (len < 20) return false;  // Minimum header size

  const uint8_t* ptr = buffer;

  // Read fixed header parts
  source_port = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
  ptr += 2;
  dest_port = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
  ptr += 2;
  sequence_number = ntohl(*reinterpret_cast<const uint32_t*>(ptr));
  ptr += 4;
  ack_number = ntohl(*reinterpret_cast<const uint32_t*>(ptr));
  ptr += 4;

  // Read combined offset/reserved/flags field
  offset_reserved_flags = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
  ptr += 2;

  // Validate header structure
  const uint8_t data_offset = GetDataOffset();
  if (data_offset < 5) return false;  // Invalid header length

  const size_t header_length = data_offset * 4;
  if (len < header_length) return false;  // Truncated header

  if (GetReserved() != 0) return false;  // Reserved bits must be zero

  // Continue reading fixed header
  window = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
  ptr += 2;
  checksum = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
  ptr += 2;
  urgent_pointer = ntohs(*reinterpret_cast<const uint16_t*>(ptr));
  ptr += 2;

  // Read options (if any)
  const size_t options_length = header_length - 20;
  if (options_length > 0) {
    options.assign(ptr, ptr + options_length);
    ptr += options_length;
  }

  // Read payload
  const size_t payload_length = len - (ptr - buffer);
  if (payload_length > 0) {
    payload.assign(ptr, ptr + payload_length);
  }

  return true;
}

std::string TCPPacket::DebugString() const {
  std::ostringstream oss;
  oss << "Source Port: " << source_port << "\n"
      << "Dest Port: " << dest_port << "\n"
      << "Sequence Number: " << sequence_number << "\n"
      << "Ack Number: " << ack_number << "\n"
      << "Header Length: " << (GetDataOffset() * 4) << " bytes\n"
      << "NS Flag: " << (GetNSFlag() ? "Set" : "Not set") << "\n"
      << "Reserved Bits: 0x" << std::hex << static_cast<int>(GetReserved())
      << std::dec << "\n"
      << "Window Size: " << window << "\n"
      << "Checksum: 0x" << std::hex << checksum << std::dec << "\n"
      << "Urgent Pointer: " << urgent_pointer << "\n";

  // Format flags
  std::vector<std::string> flags;
  if (GetNSFlag()) flags.push_back("NS");
  const uint8_t flag_byte = GetFlags();
  if (flag_byte & static_cast<uint8_t>(TCPFlag::CWR)) flags.push_back("CWR");
  if (flag_byte & static_cast<uint8_t>(TCPFlag::ECE)) flags.push_back("ECE");
  if (flag_byte & static_cast<uint8_t>(TCPFlag::URG)) flags.push_back("URG");
  if (flag_byte & static_cast<uint8_t>(TCPFlag::ACK)) flags.push_back("ACK");
  if (flag_byte & static_cast<uint8_t>(TCPFlag::PSH)) flags.push_back("PSH");
  if (flag_byte & static_cast<uint8_t>(TCPFlag::RST)) flags.push_back("RST");
  if (flag_byte & static_cast<uint8_t>(TCPFlag::SYN)) flags.push_back("SYN");
  if (flag_byte & static_cast<uint8_t>(TCPFlag::FIN)) flags.push_back("FIN");

  oss << "Flags: ";
  if (!flags.empty()) {
    oss << "[";
    for (size_t i = 0; i < flags.size(); ++i) {
      if (i > 0) oss << ", ";
      oss << flags[i];
    }
    oss << "]";
  } else {
    oss << "[None]";
  }
  oss << "\n";

  // Format options and payload
  oss << "Options (" << options.size() << " bytes): " << FormatBytes(options)
      << "\n"
      << "Payload (" << payload.size() << " bytes): " << FormatBytes(payload);

  return oss.str();
}
std::string TCPPacket::FormatBytes(const std::vector<uint8_t>& bytes) const {
  std::ostringstream oss;
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (std::isprint(static_cast<unsigned char>(bytes[i]))) {
      oss << static_cast<char>(bytes[i]) << " ";
    } else {
      oss << "0x"
          << std::hex << std::setw(2) << std::setfill('0')
          << static_cast<int>(bytes[i]) << " ";
    }
  }
  return oss.str();
}
