CC = gcc

# ----------------------------------------------------------------------------
# Paths (set here; passed to the compiler as -D defines so no path is
# hardcoded in source files).
#
#   SERVER_PATH    — absolute path to this server's root directory.
#                    Used to locate misc/ and config/ subdirectories at runtime.
#   LOG_FILE_PATH  — where query logs are written.
# ----------------------------------------------------------------------------
SERVER_PATH   := $(abspath .)
LOG_DIR       := $(abspath ..)/logs
LOG_FILE_PATH := $(LOG_DIR)/server.log

CFLAGS = -Wall -Wextra -O2 -g -Isrc -MMD -MP \
         -DSERVER_PATH='"$(SERVER_PATH)"' \
         -DLOG_FILE_PATH='"$(LOG_FILE_PATH)"' \
         -DPID_FILE_PATH='"$(PID_FILE_PATH)"'
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

TARGET = $(BIN_DIR)/auth_dns
PID_FILE_PATH = /run/auth_dns.pid

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

# Install binary, systemd service, and logrotate config
INSTALL_BIN  = /usr/local/sbin
SYSTEMD_DIR  = /etc/systemd/system
LOGROTATE_DIR = /etc/logrotate.d

install: $(TARGET)
	install -d $(INSTALL_BIN)
	install -d $(LOG_DIR)
	install -m 755 $(TARGET) $(INSTALL_BIN)/auth_dns
	sed -e 's|@INSTALL_BIN@|$(INSTALL_BIN)|g' \
	    -e 's|@LOG_DIR@|$(LOG_DIR)|g' \
	    -e 's|@SERVER_PATH@|$(SERVER_PATH)|g' \
	    auth_dns.service > $(SYSTEMD_DIR)/auth_dns.service
	sed 's|@LOG_FILE_PATH@|$(LOG_FILE_PATH)|g' misc/logrotate-auth \
	    > $(LOGROTATE_DIR)/auth_dns
	systemctl daemon-reload
	@echo "Installed auth_dns. Enable with: systemctl enable --now auth_dns"

uninstall:
	systemctl stop auth_dns 2>/dev/null || true
	systemctl disable auth_dns 2>/dev/null || true
	rm -f $(INSTALL_BIN)/auth_dns
	rm -f $(SYSTEMD_DIR)/auth_dns.service
	rm -f $(LOGROTATE_DIR)/auth_dns
	systemctl daemon-reload
	@echo "Removed auth_dns"

# Debugging info
debug:
	@echo "Sources: $(SRC_FILES)"
	@echo "Objects: $(OBJECTS)"
	@echo "Target: $(TARGET)"

# Auto-generated header dependency files (from -MMD -MP)
-include $(OBJECTS:.o=.d)

.PHONY: all clean rebuild run debug directories install uninstall install-service uninstall-service
