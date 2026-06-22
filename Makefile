# Top-level Makefile — builds both DNS servers and installs their cron jobs.
#
# Usage:
#   make                 # build both servers
#   sudo make install    # build + install all cron jobs (daily + @reboot startup)
#   sudo make uninstall  # remove the installed cron jobs
#   make clean           # remove build artifacts
#   make rebuild         # clean + build
#   sudo make docker     # build + run both servers in containers + daily cron
#   sudo make docker-down # stop containers, remove images + daily cron
#   make release VERSION=x GHCR_OWNER=you  # build+push multi-arch images to GHCR

.PHONY: all clean rebuild install uninstall daily-cron stop-native stop-docker docker docker-down release deploy

# --- Cron jobs --------------------------------------------------------------
# Three cron jobs are installed, all derived from GENERIC files in cron_scripts/
# (no absolute path or username baked in), so cloning the repo to any path / user
# just works:
#
#   dns_log            — daily: archives + truncates the auth server.log
#                        (rendered into /etc/cron.daily)
#   refresh-root-hints — daily: refreshes the upstream resolver's root hints
#                        (rendered into /etc/cron.daily)
#   dns-startup        — @reboot: starts the servers at boot. Installed as a
#                        one-line /etc/cron.d entry that points back at the
#                        in-repo launcher, which is the file you edit (comment a
#                        line) to choose auth-only / recursive-only / both.
#
# Paths/owner are derived from this Makefile's own location:
#   LOG_DIR / HINTS_DEST  from $(abspath .)
#   RUN_USER / RUN_GROUP  from the owner of the checkout (not a hardcoded user)
DNS_ROOT   := $(abspath .)
LOG_DIR    := $(DNS_ROOT)/logs
HINTS_DEST := $(DNS_ROOT)/upstream_dns/misc/root_hints.txt
RUN_USER   := $(shell stat -c '%U' $(DNS_ROOT))
RUN_GROUP  := $(shell stat -c '%G' $(DNS_ROOT))
CRON_DAILY := /etc/cron.daily
CRON_D     := /etc/cron.d
STARTUP_SRC  := $(DNS_ROOT)/cron_scripts/dns-startup
STARTUP_CRON := $(CRON_D)/dns-startup

all:
	$(MAKE) -C auth_dns
	$(MAKE) -C upstream_dns

clean:
	$(MAKE) -C auth_dns clean
	$(MAKE) -C upstream_dns clean

rebuild:
	$(MAKE) -C auth_dns rebuild
	$(MAKE) -C upstream_dns rebuild

# Install the two DAILY maintenance cron jobs (log rotation + root-hints
# refresh). Shared by `install` (native) and `docker` — both deployments want
# these, so the recipe lives in one place. refresh-root-hints reloads whichever
# upstream_dns is running (native pid/pgrep, or `docker kill -s HUP`).
daily-cron:
	@mkdir -p $(LOG_DIR)
	@chown -R $(RUN_USER):$(RUN_GROUP) $(LOG_DIR)
	@chmod 755 $(LOG_DIR)
	sed -e 's|@LOG_DIR@|$(LOG_DIR)|g' \
	    -e 's|@RUN_USER@|$(RUN_USER)|g' \
	    -e 's|@RUN_GROUP@|$(RUN_GROUP)|g' \
	    cron_scripts/dns_log > $(CRON_DAILY)/dns_log
	chmod 755 $(CRON_DAILY)/dns_log
	sed -e 's|@HINTS_DEST@|$(HINTS_DEST)|g' \
	    cron_scripts/refresh-root-hints > $(CRON_DAILY)/refresh-root-hints
	chmod 755 $(CRON_DAILY)/refresh-root-hints

# --- Deployment switching helpers -------------------------------------------
# Each top-level target clears the OTHER deployment first, so you can flip
# between native and docker with one command (they share host ports :53/:5335
# and cannot both run).

# Stop a NATIVE deployment: kill its host processes (matched by the in-repo
# binary path, so the docker containers' /usr/local/bin copies are untouched)
# and drop its @reboot launcher.
#
# The path's leading '/' is wrapped in a regex class ([/]) so the pattern does
# NOT match pkill's OWN recipe shell — whose argv literally contains the pattern
# string. Without it, pkill SIGTERMs the shell running it and the recipe dies.
stop-native:
	@pkill -f '$(patsubst /%,[/]%,$(DNS_ROOT))/auth_dns/bin/auth_dns'         2>/dev/null || true
	@pkill -f '$(patsubst /%,[/]%,$(DNS_ROOT))/upstream_dns/bin/upstream_dns' 2>/dev/null || true
	@rm -f $(STARTUP_CRON)

# Stop a DOCKER deployment: remove the containers (frees the ports). Images and
# .env are left in place so a later `make docker` is fast.
stop-docker:
	@command -v docker >/dev/null 2>&1 && docker rm -f auth_dns upstream_dns >/dev/null 2>&1 || true

# Build, install the daily cron jobs + the @reboot boot launcher, and START the
# servers right now (needs root for /etc and for binding :53). Native deployment:
# the servers run as host processes and drop to `nobody` — the same defaults as
# the docker setup. Those defaults (DROP_USER / THREADS / QUEUE / UPSTREAM) live
# in the self-locating launcher, so nothing is hardcoded here.
install: all stop-docker stop-native daily-cron
	@chmod 755 $(STARTUP_SRC)
	@printf '%s\n%s\n%s\n' \
	    '# Run the DNS servers at boot. Edit the launcher to choose which:' \
	    '#   $(STARTUP_SRC)' \
	    '@reboot root $(STARTUP_SRC)' \
	    > $(STARTUP_CRON)
	@chmod 644 $(STARTUP_CRON)
	$(STARTUP_SRC)
	@echo ""
	@echo "Installed cron jobs:"
	@echo "  $(CRON_DAILY)/dns_log              daily log archive"
	@echo "  $(CRON_DAILY)/refresh-root-hints   daily root-hints refresh"
	@echo "  $(STARTUP_CRON)            @reboot -> $(STARTUP_SRC)"
	@echo ""
	@echo "Servers started now (dropping to 'nobody') and on every @reboot."
	@echo "Edit $(STARTUP_SRC) to pick auth-only / recursive-only / both."

# Stop the native servers and remove all their cron jobs (stop-native also kills
# the host processes and removes the @reboot launcher).
uninstall: stop-native
	rm -f $(CRON_DAILY)/dns_log $(CRON_DAILY)/refresh-root-hints
	@echo "Stopped native servers; removed cron jobs (dns_log, refresh-root-hints, dns-startup)."

# --- Docker -----------------------------------------------------------------
# `sudo make docker` reads dns.conf, installs the daily cron jobs, builds the
# self-contained images, and starts ONLY the servers whose *_ENABLED=true
# (via Compose profiles). The image compiles the binary itself with fixed
# container paths baked in, so no host `make all` and no .env/DNS_ROOT.
# Boot persistence comes from restart:unless-stopped + the host docker daemon
# being enabled at boot. Needs root for the /etc cron files.
docker: stop-native daily-cron
	@set -a; . ./dns.conf; set +a; \
	 if [ "$$AUTH_ENABLED" = true ] && [ "$$UPSTREAM_ENABLED" != true ] && [ -z "$$AUTH_UPSTREAM_IP" ]; then \
	     echo "ERROR: auth is enabled without upstream and AUTH_UPSTREAM_IP is blank."; \
	     echo "       Set AUTH_UPSTREAM_IP in dns.conf to an external resolver (e.g. 1.1.1.1)."; exit 1; \
	 fi; \
	 . ./cron_scripts/dns-args.sh; \
	 export AUTH_ARGS="$$(build_auth_args 172.28.0.2)"; \
	 export UPSTREAM_ARGS="$$(build_upstream_args)"; \
	 profiles=""; \
	 [ "$$AUTH_ENABLED" = true ]     && profiles="$$profiles --profile auth"; \
	 [ "$$UPSTREAM_ENABLED" = true ] && profiles="$$profiles --profile upstream"; \
	 [ -n "$$profiles" ] || { echo "ERROR: no servers enabled in dns.conf (set AUTH_ENABLED and/or UPSTREAM_ENABLED = true)"; exit 1; }; \
	 docker compose --profile auth --profile upstream build; \
	 docker compose --profile auth --profile upstream down --remove-orphans 2>/dev/null || true; \
	 docker compose $$profiles up -d; \
	 echo ""; \
	 echo "Started per dns.conf ($$profiles ). Follow logs: docker compose logs -f"

# Build BOTH images for arm64 (Pis) + amd64 (servers) and push to GHCR.
# Prereqs: `docker login ghcr.io`, a buildx builder, and — when building a
# foreign arch — QEMU: `docker run --privileged tonistiigi/binfmt`.
#   make release VERSION=1.0 GHCR_OWNER=<your-gh-user>
PLATFORMS ?= linux/arm64,linux/amd64
release:
	@test -n "$(VERSION)"    || { echo "set VERSION=x (e.g. make release VERSION=1.0 GHCR_OWNER=you)"; exit 1; }
	@test -n "$(GHCR_OWNER)" || { echo "set GHCR_OWNER=<your-gh-user>"; exit 1; }
	docker buildx build --platform $(PLATFORMS) \
	    -t ghcr.io/$(GHCR_OWNER)/auth_dns:$(VERSION) --push ./auth_dns
	docker buildx build --platform $(PLATFORMS) \
	    -t ghcr.io/$(GHCR_OWNER)/upstream_dns:$(VERSION) --push ./upstream_dns
	@echo ""
	@echo "Pushed ghcr.io/$(GHCR_OWNER)/{auth_dns,upstream_dns}:$(VERSION) for $(PLATFORMS)"
	@echo "On a deploy host: export GHCR_OWNER=$(GHCR_OWNER) DNS_TAG=$(VERSION); make deploy"

# Pull pre-built images from GHCR and (re)start per dns.conf — for hosts that do
# NOT build locally. Needs GHCR_OWNER + DNS_TAG set in the environment so the
# image names resolve to the registry (not the local fallback tag).
deploy:
	@set -a; . ./dns.conf; set +a; \
	 . ./cron_scripts/dns-args.sh; \
	 export AUTH_ARGS="$$(build_auth_args 172.28.0.2)"; \
	 export UPSTREAM_ARGS="$$(build_upstream_args)"; \
	 profiles=""; \
	 [ "$$AUTH_ENABLED" = true ]     && profiles="$$profiles --profile auth"; \
	 [ "$$UPSTREAM_ENABLED" = true ] && profiles="$$profiles --profile upstream"; \
	 [ -n "$$profiles" ] || { echo "ERROR: no servers enabled in dns.conf"; exit 1; }; \
	 docker compose $$profiles pull; \
	 docker compose --profile auth --profile upstream down --remove-orphans 2>/dev/null || true; \
	 docker compose $$profiles up -d; \
	 echo "Deployed per dns.conf ($$profiles )"

# Stop and remove the containers, the images this repo built, and the daily
# cron jobs.
docker-down:
	docker compose --profile auth --profile upstream down --rmi local --remove-orphans
	rm -f $(CRON_DAILY)/dns_log $(CRON_DAILY)/refresh-root-hints
	@echo "Stopped containers, removed images, and daily cron jobs"
