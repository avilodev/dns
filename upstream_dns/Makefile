CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -Isrc -MMD -MP \
         -DSERVER_PATH='"$(abspath .)"' \
         -DLOG_FILE_PATH='"$(abspath ..)/logs/upstream.log"'
LDFLAGS = -pthread -lssl -lcrypto -latomic

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Source files (just the names)
SOURCES = main.c config.c thread_pool.c utils.c      \
          request.c resolve.c cache.c                \
		  dns_wire.c dns_packet.c response_handler.c \
		  cname_handler.c ns_resolver.c udp_client.c \
		  ns_resolution_context.c dnssec.c dnssec_chain.c

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

# Install cron script to /etc/cron.daily/ (requires root)
install: install-cron

uninstall: uninstall-cron

# Install the root-hints refresh cron script to /etc/cron.daily/,
# substituting @HINTS_DEST@ with the current absolute path to root_hints.txt.
CRON_DAILY   = /etc/cron.daily
CRON_SCRIPT  = $(CRON_DAILY)/refresh-root-hints
HINTS_DEST   = $(abspath .)/misc/root_hints.txt

install-cron:
	sed 's|@HINTS_DEST@|$(HINTS_DEST)|g' misc/refresh-root-hints \
	    > $(CRON_SCRIPT)
	chmod 755 $(CRON_SCRIPT)
	@echo "Installed: $(CRON_SCRIPT) (DEST=$(HINTS_DEST))"

uninstall-cron:
	rm -f $(CRON_SCRIPT)
	@echo "Removed: $(CRON_SCRIPT)"

# Debugging info
debug:
	@echo "Sources: $(SRC_FILES)"
	@echo "Objects: $(OBJECTS)"
	@echo "Target: $(TARGET)"

# Auto-generated header dependency files (from -MMD -MP)
-include $(OBJECTS:.o=.d)

.PHONY: all clean rebuild run debug directories install uninstall install-cron uninstall-cron
