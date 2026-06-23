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
LOG_FILE_PATH := $(LOG_DIR)/upstream.log

# Hardening (known_issues 4.9):
#   -fno-strict-aliasing   make the wire-parsing type-punning well-defined
#   -fstack-protector-strong / _FORTIFY_SOURCE=2 / PIE / -Wformat-security
#                          standard exploit-mitigation hardening
# The `asan` target overrides HARDEN_* to build with the sanitizers instead.
HARDEN_CFLAGS  = -fno-strict-aliasing -fstack-protector-strong \
                 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 \
                 -fPIE -Wformat -Wformat-security
HARDEN_LDFLAGS = -pie

CFLAGS = -Wall -Wextra -O2 -g -Isrc -MMD -MP $(HARDEN_CFLAGS) \
         -DSERVER_PATH='"$(SERVER_PATH)"' \
         -DLOG_FILE_PATH='"$(LOG_FILE_PATH)"' \
         -DPID_FILE_PATH='"$(PID_FILE_PATH)"'
LDFLAGS = -pthread -lssl -lcrypto -latomic $(HARDEN_LDFLAGS)

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Source files (just the names)
SOURCES = main.c config.c thread_pool.c utils.c      \
          request.c resolve.c cache.c                \
		  dns_wire.c dns_packet.c response_handler.c \
		  cname_handler.c ns_resolver.c udp_client.c \
		  ns_resolution_context.c dnssec.c dnssec_chain.c dnssec_wire.c \
		  access_control.c query_log.c udp_helpers.c workers.c

# Full paths
SRC_FILES = $(addprefix $(SRC_DIR)/, $(SOURCES))
OBJECTS = $(addprefix $(OBJ_DIR)/, $(SOURCES:.c=.o))

TARGET = $(BIN_DIR)/upstream_dns
PID_FILE_PATH = /run/upstream_dns.pid

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

# Sanitizer build (ASan + UBSan) — run the pytest suite against this to surface
# memory/UB bugs in the hand-rolled wire parsing (known_issues 4.9).
# Drops the PIE/FORTIFY hardening (incompatible with ASan) for the sanitizers.
asan: HARDEN_CFLAGS  = -fno-strict-aliasing -fno-omit-frame-pointer \
                       -fsanitize=address,undefined -fno-sanitize-recover=all
asan: HARDEN_LDFLAGS = -fsanitize=address,undefined
asan: clean all
	@echo "ASan/UBSan build complete: $(TARGET)"

# Fuzz target — libFuzzer over the untrusted wire-format query parser, built
# with ASan+UBSan (clang). Feeds arbitrary network bytes to parse_request_headers
# to surface memory/alignment/UB bugs. Standalone — no daemon or network.
#   make fuzz && obj/fuzz_request -max_total_time=30
FUZZ_DIR  = fuzz
FUZZ_SRCS = $(SRC_DIR)/request.c $(SRC_DIR)/utils.c $(SRC_DIR)/dns_packet.c $(SRC_DIR)/dns_wire.c
fuzz: | directories
	clang -g -O1 -Isrc -fno-strict-aliasing -fsanitize=fuzzer,address,undefined \
	    $(FUZZ_DIR)/fuzz_request.c $(FUZZ_SRCS) -o $(OBJ_DIR)/fuzz_request
	@echo "Fuzzer built: $(OBJ_DIR)/fuzz_request"

# Run the server
run: $(TARGET)
	sudo ./$(TARGET)

# Debugging info
debug:
	@echo "Sources: $(SRC_FILES)"
	@echo "Objects: $(OBJECTS)"
	@echo "Target: $(TARGET)"

# Auto-generated header dependency files (from -MMD -MP)
-include $(OBJECTS:.o=.d)

.PHONY: all clean rebuild asan fuzz run debug directories
