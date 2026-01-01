# Compiler
CXX = g++
# Compiler flags
CXXFLAGS = -Wno-deprecated-declarations
# Linker flags
LDFLAGS = -lssl -lcrypto
# Target Executable
TARGET = main
# Source files
SRCS = main.cpp Encryption.cpp Hasher.cpp RSA.cpp test_suite.cpp
# Object files
OBJS = $(SRCS:.cpp=.o)

# Phony targets
.PHONY: all run clean

# Default rule to build and run the exe
all: $(TARGET) run

# Rule to link object files into the target exe
$(TARGET): $(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Rule to compile .cpp files into .o files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Rule to run the exe
run: $(TARGET)
	./$(TARGET)

# Clean rule to remove generated files
clean:
	rm -f $(TARGET) $(OBJS)
