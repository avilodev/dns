# Top-level Makefile — builds both DNS servers and installs their cron jobs.
#
# Usage:
#   make                 # build both servers
#   sudo make install    # build + install all cron jobs (daily + @reboot startup)
#   sudo make uninstall  # remove the installed cron jobs
#   make clean           # remove build artifacts
#   make rebuild         # clean + build

.PHONY: all clean rebuild install uninstall

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

# Build, then install all three cron jobs (needs root for /etc).
install: all
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
	@chmod 755 $(STARTUP_SRC)
	@printf '%s\n%s\n%s\n' \
	    '# Run the DNS servers at boot. Edit the launcher to choose which:' \
	    '#   $(STARTUP_SRC)' \
	    '@reboot root $(STARTUP_SRC)' \
	    > $(STARTUP_CRON)
	@chmod 644 $(STARTUP_CRON)
	@echo ""
	@echo "Installed cron jobs:"
	@echo "  $(CRON_DAILY)/dns_log              daily log archive"
	@echo "  $(CRON_DAILY)/refresh-root-hints   daily root-hints refresh"
	@echo "  $(STARTUP_CRON)            @reboot -> $(STARTUP_SRC)"
	@echo ""
	@echo "Reboot to start the servers automatically, or launch them now with:"
	@echo "  sudo $(STARTUP_SRC)"
	@echo "Edit the launcher to pick auth-only / recursive-only / both."

# Remove the installed cron jobs.
uninstall:
	rm -f $(CRON_DAILY)/dns_log $(CRON_DAILY)/refresh-root-hints $(STARTUP_CRON)
	@echo "Removed cron jobs: dns_log, refresh-root-hints, dns-startup"
