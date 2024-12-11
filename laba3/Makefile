CXX = g++
CXXFLAGS = -std=c++11 -Wall -I/usr/include

# Directories
SRC_DIR = .
OBJ_DIR = ./obj
BIN_DIR = ./bin

# Source files
SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SOURCES))

# Output executable
TARGET = $(BIN_DIR)/testApp

# Libraries
LIBS = -lUnitTest++

# Rules
all: $(TARGET)

$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CXX) $(OBJECTS) -o $@ $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
