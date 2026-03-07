CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -Isrc -MMD -MP \
         -DSERVER_PATH='"$(abspath .)"' \
         -DLOG_FILE_PATH='"$(abspath ..)/logs/server.log"'
LDFLAGS = -pthread -lssl -lcrypto -latomic

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Source files (just the names)
SOURCES = main.c auth.c logger.c request.c resolve.c \
          response.c utils.c thread_pool.c dnssec.c

# Full paths
SRC_FILES = $(addprefix $(SRC_DIR)/, $(SOURCES))
OBJECTS = $(addprefix $(OBJ_DIR)/, $(SOURCES:.c=.o))

TARGET = $(BIN_DIR)/dns

# Default target
all: directories $(TARGET)

# Create necessary directories
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)

# Link object files into executable
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile source files to object files (| directories = order-only: create dirs first)
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | directories
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Clean complete"

# Rebuild from scratch
rebuild: clean all

# Run the server
run: $(TARGET)
	sudo ./$(TARGET)

# Install to /usr/local/sbin/auth_dns
INSTALL_BIN = /usr/local/sbin
install: $(TARGET)
	install -d $(INSTALL_BIN)
	install -m 755 $(TARGET) $(INSTALL_BIN)/auth_dns
	@echo "Installed: $(INSTALL_BIN)/auth_dns"

uninstall:
	rm -f $(INSTALL_BIN)/auth_dns
	@echo "Removed: $(INSTALL_BIN)/auth_dns"

# Debugging info
debug:
	@echo "Sources: $(SRC_FILES)"
	@echo "Objects: $(OBJECTS)"
	@echo "Target: $(TARGET)"

# Auto-generated header dependency files (from -MMD -MP)
-include $(OBJECTS:.o=.d)

.PHONY: all clean rebuild run debug directories install uninstall
