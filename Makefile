PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/volt

# Auto-detect whether sudo is needed for destination directories
SUDO ?= $(shell \
	dir="$(DESTDIR)$(BINDIR)"; \
	while [ ! -d "$$dir" ] && [ "$$dir" != "/" ] && [ "$$dir" != "." ]; do \
		dir=$$(dirname "$$dir"); \
	done; \
	if [ -w "$$dir" ] || [ "$$(id -u)" = "0" ]; then \
		echo ""; \
	else \
		if command -v sudo >/dev/null 2>&1; then echo "sudo"; fi; \
	fi \
)

.PHONY: all build release install uninstall test clean

all: release

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

install:
	@if [ ! -f volt ]; then \
		if [ -n "$$SUDO_USER" ] && [ "$$SUDO_USER" != "root" ]; then \
			echo "⚡ Compiling release binary as user '$$SUDO_USER'..."; \
			sudo -u "$$SUDO_USER" env "PATH=$$PATH" cargo build --release; \
		elif [ "$$(id -u)" != "0" ]; then \
			echo "⚡ Compiling release binary as current user..."; \
			cargo build --release; \
		elif [ ! -f target/release/volt ]; then \
			echo "⚡ Compiling release binary..."; \
			cargo build --release; \
		fi; \
	fi
	@BIN_SRC=$$(if [ -f volt ]; then echo "volt"; else echo "target/release/volt"; fi); \
	if [ ! -f "$$BIN_SRC" ]; then \
		echo "❌ Error: Could not locate compiled 'volt' binary at '$$BIN_SRC'"; \
		exit 1; \
	fi; \
	echo "⚡ Installing $$BIN_SRC to $(DESTDIR)$(BINDIR)/volt..."; \
	$(SUDO) install -d $(DESTDIR)$(BINDIR); \
	$(SUDO) install -m 755 "$$BIN_SRC" $(DESTDIR)$(BINDIR)/volt; \
	$(SUDO) install -d $(DESTDIR)$(SHAREDIR)/profiles; \
	if [ -d profiles ]; then \
		$(SUDO) cp -r profiles/*.json $(DESTDIR)$(SHAREDIR)/profiles/ 2>/dev/null || true; \
		$(SUDO) chmod -R 644 $(DESTDIR)$(SHAREDIR)/profiles/*.json 2>/dev/null || true; \
		$(SUDO) chmod 755 $(DESTDIR)$(SHAREDIR)/profiles; \
	fi; \
	echo "✓ Successfully installed volt binary to $(DESTDIR)$(BINDIR)/volt"; \
	echo "✓ Successfully installed hardware profiles to $(DESTDIR)$(SHAREDIR)/profiles"; \
	if command -v setcap >/dev/null 2>&1; then \
		$(SUDO) setcap cap_net_raw,cap_net_admin+eip $(DESTDIR)$(BINDIR)/volt 2>/dev/null && \
		echo "✓ Granted CAP_NET_RAW capabilities for raw network scanning (nmap -sS)" || \
		echo "ℹ (Optional) Run 'sudo setcap cap_net_raw,cap_net_admin+eip $(DESTDIR)$(BINDIR)/volt' for rootless raw scans"; \
	fi

uninstall:
	@echo "🗑️ Uninstalling VOLT..."
	@if [ -f $(DESTDIR)$(BINDIR)/volt ]; then \
		$(SUDO) rm -f $(DESTDIR)$(BINDIR)/volt && echo "✓ Removed $(DESTDIR)$(BINDIR)/volt"; \
	fi
	@if [ -d $(DESTDIR)$(SHAREDIR) ]; then \
		$(SUDO) rm -rf $(DESTDIR)$(SHAREDIR) && echo "✓ Removed $(DESTDIR)$(SHAREDIR)"; \
	fi
	@echo "✅ VOLT uninstalled successfully."

clean:
	cargo clean
