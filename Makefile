# Top-level Makefile — builds and installs both DNS servers.
#
# Usage:
#   make              # build both servers
#   sudo make install # build + install binaries, systemd units, logrotate, cron
#   make clean        # remove build artifacts from both servers
#   make rebuild      # clean + build
#   sudo make uninstall

.PHONY: all clean rebuild install uninstall

all:
	$(MAKE) -C auth_dns
	$(MAKE) -C upstream_dns

clean:
	$(MAKE) -C auth_dns clean
	$(MAKE) -C upstream_dns clean

rebuild:
	$(MAKE) -C auth_dns rebuild
	$(MAKE) -C upstream_dns rebuild

install: all
	$(MAKE) -C upstream_dns install
	$(MAKE) -C auth_dns install

uninstall:
	$(MAKE) -C auth_dns uninstall
	$(MAKE) -C upstream_dns uninstall
