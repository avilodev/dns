# syntax=docker/dockerfile:1
#
# Multi-stage build: the binary is COMPILED inside the image, so the image is
# self-contained and portable across architectures (build with `buildx
# --platform linux/arm64,linux/amd64`). Runtime paths are baked to FIXED
# container locations here — NOT the host checkout path — which is what removes
# the old .env / DNS_ROOT mounting dance.

# --- build stage: compile from source --------------------------------------
FROM debian:bookworm-slim AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Override the path -D defines (auth_dns/Makefile:11-13) to fixed container
# paths. PID_FILE_PATH is already a fixed /run/auth_dns.pid. Strip the binary
# afterwards so debug symbols don't ship in the runtime image.
RUN make SERVER_PATH=/opt/auth_dns LOG_FILE_PATH=/var/log/dns/server.log \
    && strip bin/auth_dns

# --- runtime stage: minimal image ------------------------------------------
FROM debian:bookworm-slim AS runtime

# libssl3 provides libcrypto.so.3 (the only non-libc NEEDED lib).
# knot-dnsutils provides `kdig` for the compose healthcheck (liveness probe).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 knot-dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /build/bin/auth_dns /usr/local/bin/auth_dns

# Flags come from `command:` in docker-compose.yml, which the Makefile builds
# from dns.conf (cron_scripts/dns-args.sh). The binary starts as root (to bind
# :53) then drops to the unprivileged user itself.
ENTRYPOINT ["/usr/local/bin/auth_dns"]
