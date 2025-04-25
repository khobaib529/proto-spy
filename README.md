# proto-spy

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A network protocol inspection tool for deep diving into TCP/UDP packet structures. Created to strengthen low-level networking understanding through practical implementation.

## Features

- **Packet Sniffing**
  - Real-time TCP/UDP packet capture
  - Detailed header field analysis
  - Payload inspection (hex/ASCII)
- **Testing Suite**
  - Configurable packet generators
  - Protocol feature validation
- **Educational Focus**
  - Clear protocol field visualization

## Building from Source

**Prerequisites**
- Linux-based OS (Tested on Ubuntu 24.04.2 LTS)
- C++17 compiler (G++ recommended)
- GNU Make

**Build Instructions**

- Clone repository

``` bash
git clone https://github.com/khobaib529/proto-spy.git
cd proto-spy
```

Compile using provided Makefile
```bash
make
```

Run with root privileges (required for packet capture)
``` bash
sudo ./proto-spy --protocol=tcp
```
