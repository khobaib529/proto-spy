#include <cstring>
#include <iostream>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include "proto_spy.h"

// REQUIRES: The underlying storage remains valid as long as the original
// strings exist.
struct KeyValuePair {
  std::string_view key;
  std::string_view value;
};

KeyValuePair ExtractKeyValuePair(const char* arg, std::regex& pattern) {
  std::cmatch matches;
  if (std::regex_match(arg, matches, pattern)) {
    // Create a KeyValuePair by constructing string_views over the substrings
    return {std::string_view(matches[1].first, matches[1].length()),
            std::string_view(matches[2].first, matches[2].length())};
  } else {
    std::cerr << "Invalid argument format: " << arg << std::endl;
    // Handle the invalid format as needed, e.g., by returning a
    // default-constructed KeyValuePair
    return {"", ""};
  }
}

void Usage(const std::string& program_name) {
  std::cerr << "Usage: " << program_name << " --protocol=<tcp|udp>\n";
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    Usage(argv[0]);
    return EXIT_FAILURE;
  }
  // Define the regular expression pattern for --key=value
  std::regex pattern(R"(--([a-zA-Z0-9_-]+)=([a-zA-Z0-9_-]+))");

  std::vector<KeyValuePair> arguments;
  arguments.reserve(argc - 1);  // Preallocate memory

  // Convert arguments to string_views without copying
  for (int i = 1; i < argc; ++i) {
    arguments.push_back(ExtractKeyValuePair(argv[i], pattern));
  }

  bool protocol_specified = false;
  for (const auto& [key, value] : arguments) {
    if (key == "protocol") {
      protocol_specified = true;

      if (value == "tcp") {
        std::cout << "Starting TCP packet inspection...\n";
        listen_tcp();
      } else if (value == "udp") {
        std::cout << "Starting UDP packet inspection...\n";
        listen_udp();
      } else {
        std::cerr << "Unsupported protocol: " << value << "\n";
        return 1;
      }
      break;
    }
  }

  if (!protocol_specified) {
    std::cerr << "Missing required --protocol argument\n";
    Usage(argv[0]);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
