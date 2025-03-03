# Compiler settings
CXX        = g++
CXXFLAGS   = -Wall -Wextra -std=c++17

# Directories and target
SRCDIR     = src
SOURCES    = $(wildcard $(SRCDIR)/*.cc)
TARGET     = proto-spy

# Default rule
all: $(TARGET)

# Linking step: build the executable from all source files.
$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(TARGET)

# Clean up build artifacts
clean:
	rm -f $(TARGET)

.PHONY: all clean
