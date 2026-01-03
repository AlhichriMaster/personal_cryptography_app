# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++17 -Wall -Wextra -Wno-deprecated-declarations -Iinclude

# Linker flags
LDFLAGS = -lssl -lcrypto

# Source files (library sources)
SOURCES = src/Encryption.cpp src/Hasher.cpp src/RSA.cpp src/Signature.cpp src/CLI.cpp

# Object files
OBJS = $(SOURCES:.cpp=.o)

# Targets
CLI_TARGET = crypto
TEST_TARGET = test_suite

# Phony targets
.PHONY: all clean run run-test

# Default rule
all: $(CLI_TARGET) $(TEST_TARGET)

# Rule to compile .cpp files into .o files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# CLI executable
$(CLI_TARGET): src/main.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Test suite executable
$(TEST_TARGET): tests/test_suite.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Run the CLI
run: $(CLI_TARGET)
	./$(CLI_TARGET)

# Run the test suite
run-test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Clean rule
clean:
	rm -f $(CLI_TARGET) $(TEST_TARGET) $(OBJS) src/*.o *.pem *.enc *.sig
