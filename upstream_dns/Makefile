CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -Isrc -MMD -MP
LDFLAGS = -pthread -lssl -lcrypto

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Source files (just the names)
SOURCES = main.c config.c thread_pool.c utils.c      \
          request.c resolve.c cache.c                \
		  dns_wire.c dns_packet.c response_handler.c \
		  cname_handler.c ns_resolver.c udp_client.c \
		  ns_resolution_context.c dnssec.c

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

# Compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
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

# Install to /usr/local/sbin/upstream_dns
INSTALL_BIN = /usr/local/sbin
install: $(TARGET)
	install -d $(INSTALL_BIN)
	install -m 755 $(TARGET) $(INSTALL_BIN)/upstream_dns
	@echo "Installed: $(INSTALL_BIN)/upstream_dns"

uninstall:
	rm -f $(INSTALL_BIN)/upstream_dns
	@echo "Removed: $(INSTALL_BIN)/upstream_dns"

# Debugging info
debug:
	@echo "Sources: $(SRC_FILES)"
	@echo "Objects: $(OBJECTS)"
	@echo "Target: $(TARGET)"

# Auto-generated header dependency files (from -MMD -MP)
-include $(OBJECTS:.o=.d)

.PHONY: all clean rebuild run debug directories install uninstall
