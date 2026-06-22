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

# Override the path -D defines (upstream_dns/Makefile:11-13) to fixed container
# paths. PID_FILE_PATH is already a fixed /run/upstream_dns.pid. Strip the
# binary afterwards so debug symbols don't ship in the runtime image.
RUN make SERVER_PATH=/opt/upstream_dns LOG_FILE_PATH=/var/log/dns/upstream.log \
    && strip bin/upstream_dns

# --- runtime stage: minimal image ------------------------------------------
FROM debian:bookworm-slim AS runtime

# libssl3 provides libcrypto.so.3 (the only non-libc NEEDED lib).
# knot-dnsutils provides `kdig` for the compose healthcheck (liveness probe).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 knot-dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /build/bin/upstream_dns /usr/local/bin/upstream_dns

# Flags come from `command:` in docker-compose.yml, which the Makefile builds
# from dns.conf (cron_scripts/dns-args.sh). It binds an unprivileged port
# (:5335) but still starts as root to drop to a non-root user itself.
ENTRYPOINT ["/usr/local/bin/upstream_dns"]
