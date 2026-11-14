PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/volt

.PHONY: all build release install uninstall test clean

all: release

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

install: release
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 target/release/volt $(DESTDIR)$(BINDIR)/volt
	install -d $(DESTDIR)$(SHAREDIR)/profiles
	@if [ -d profiles ]; then \
		cp -r profiles/*.json $(DESTDIR)$(SHAREDIR)/profiles/ 2>/dev/null || true; \
		chmod -R 644 $(DESTDIR)$(SHAREDIR)/profiles/*.json 2>/dev/null || true; \
		chmod 755 $(DESTDIR)$(SHAREDIR)/profiles; \
	fi
	@echo "✓ Successfully installed volt binary to $(DESTDIR)$(BINDIR)/volt"
	@echo "✓ Successfully installed hardware profiles to $(DESTDIR)$(SHAREDIR)/profiles"
	@if command -v setcap >/dev/null 2>&1; then \
		setcap cap_net_raw,cap_net_admin+eip $(DESTDIR)$(BINDIR)/volt 2>/dev/null && \
		echo "✓ Granted CAP_NET_RAW capabilities for raw network scanning (nmap -sS)" || \
		echo "ℹ (Optional) Run 'sudo setcap cap_net_raw,cap_net_admin+eip $(DESTDIR)$(BINDIR)/volt' for rootless raw scans"; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/volt
	rm -rf $(DESTDIR)$(SHAREDIR)
	@echo "✓ Removed $(DESTDIR)$(BINDIR)/volt and $(DESTDIR)$(SHAREDIR)"

clean:
	cargo clean
