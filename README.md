# ⚡ VOLT — Volatile Observation & Logging Terminal
### *User Manual & Architectural Specification*

> **A forensic-grade sandboxed execution environment for Cybersecurity Investigations, Red Teaming, Incident Response, and Malware Analysis.**  
> *Features 5-layer kernel isolation, deceptive hardware spoofing, multi-terminal workflows, wire-speed packet capture, always-on session recording, and court-admissible cryptographic hash chains.*

---

## 📑 Table of Contents
1. [Overview & Core Philosophy](#-overview--core-philosophy)
2. [Quick Start (3-Minute Guide)](#-quick-start-3-minute-guide)
3. [Installation & Build](#-installation--build)
4. [Operation Profiles (Forensics, Red Team, Blue Team, Malware)](#-operation-profiles)
5. [Complete CLI Command Reference](#-complete-cli-command-reference)
   - [`volt init`](#1-volt-init)
   - [`volt start`](#2-volt-start)
   - [`volt join` / `exec` / `attach`](#3-volt-join--exec--attach)
   - [`volt screenshot`](#4-volt-screenshot)
   - [`volt status`](#5-volt-status)
   - [`volt report`](#6-volt-report)
   - [`volt seal`](#7-volt-seal)
   - [`volt verify`](#8-volt-verify)
   - [`volt export`](#9-volt-export)
   - [`volt stop`](#10-volt-stop)
6. [Multi-Terminal Workflow Guide](#-multi-terminal-workflow-guide)
7. [Case Storage & Directory Structure](#-case-storage--directory-structure)
8. [Hardware Identity Spoofing & Anti-Analysis](#-hardware-identity-spoofing--anti-analysis)
9. [Raw Packet Scanning & Sudo (`CAP_NET_RAW`)](#-raw-packet-scanning--sudo-cap_net_raw)
10. [Forensic Chain of Custody & Court Admissibility](#-forensic-chain-of-custody--court-admissibility)
11. [Configuration Reference (`volt.toml`)](#-configuration-reference-volttoml)

---

## 🎯 Overview & Core Philosophy

Security operators frequently face a critical dilemma:
- **Red Teamers / Pen-Testers** risk leaking host machine identity, MAC addresses, or personal host artifacts during engagements.
- **Incident Responders / Blue Teamers** risk contaminating host evidence or altering timestamps when running analysis tools.
- **Malware Analysts** face evasive samples that detect virtualization (`cpuid`, hypervisor DMI strings) and refuse to execute.
- **Forensic Investigators** must meet strict legal admissibility standards (e.g., ISO/IEC 27037) where every single action, keystroke, and packet must be proved untampered.

**VOLT solves this by creating a hardened, volatile "bubble wrap" environment:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              VOLT SESSION                                   │
│                                                                             │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌─────────────────┐  │
│  │ Fake Hardware Identity│  │ Multi-Terminal PTY    │  │ Always-On PCAP  │  │
│  │ (Dell / HP / VBox)    │  │ (term_1, term_2, ...) │  │ (tcpdump wire)  │  │
│  │ • DMI & BIOS strings  │  │ • Keystrokes & output │  │ • All interfaces│  │
│  │ • /proc/cpuinfo       │  │ • Window size synced  │  │ • Auto-rotating │  │
│  │ • Fake MAC & UUID     │  │ • Color & readline    │  │ • Wire speed    │  │
│  └───────────────────────┘  └───────────────────────┘  └─────────────────┘  │
│                                                                             │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌─────────────────┐  │
│  │ Host Tools (Read-Only)│  │ Screenshot Engine     │  │ OverlayFS CoW   │  │
│  │ • /usr/bin, /usr/sbin │  │ • Interval (every 30s)│  │ • Upper scratch │  │
│  │ • Zero host configs   │  │ • Page-load triggers  │  │ • Host files    │  │
│  │ • $HOME is BLOCKED    │  │ • On-demand hotkeys   │  │   UNTOUCHED     │  │
│  └───────────────────────┘  └───────────────────────┘  └─────────────────┘  │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              Sequential SHA-256 Cryptographic Hash Chain              │  │
│  │   Block[0] -> Block[1] -> Block[2] ... -> Final Root Seal Tip Hash    │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The 3 Core Rules of VOLT:
1. **Record EVERYTHING by Default**: There are no opt-in flags for logging. Terminal streams, raw network packets, screenshots, and file diffs are continuously captured the millisecond a session begins.
2. **Zero Host Contamination**: All writes occur inside a volatile copy-on-write overlay layer. The host filesystem is never modified by a single byte.
3. **Untamperable Chain of Custody**: Every log entry, PCAP chunk, and screenshot is linked into a sequential SHA-256 blockchain-style hash chain. Any post-operation tampering invalidates the evidence certificate.

---

## ⚡ Quick Start (3-Minute Guide)

```bash
# 1. Initialize a new case with Dell laptop spoofing and forensic mode
./target/release/volt init \
    --case "IR-2026-001" \
    --investigator "AgentSmith" \
    --mode "forensics" \
    --profile "laptop-dell"

# 2. Start the primary session (recording begins automatically)
./target/release/volt start --case "IR-2026-001"

# 3. Inside the session, you are root with access to all host tools:
[VOLT:laptop-dell ~]# whoami
root
[VOLT:laptop-dell ~]# nmap -sS -p 22,80,443 192.168.1.1
[VOLT:laptop-dell ~]# exit

# 4. Seal the evidence vault (locks against any future modification)
./target/release/volt seal --case "IR-2026-001"

# 5. Generate a court-admissible audit report (HTML or Markdown)
./target/release/volt report --case "IR-2026-001" --format html

# 6. Verify evidence integrity
./target/release/volt verify ./cases/IR-2026-001
# Output: ✅ VERIFICATION PASSED — Evidence integrity is 100% intact and untampered.
```

---

## 🔨 Installation & Build

VOLT is written in **Rust (2021 edition)** for line-rate throughput and zero runtime dependencies.

### System Requirements
- Linux kernel 5.4+ with `user_namespaces` enabled (standard on modern Linux distros)
- `bubblewrap` (`bwrap`)
- `tcpdump`
- Rust 1.75+ (for compilation)

### Building & Installing to `/usr/local/bin`

#### Option A: Automated `install.sh` Script (Recommended for Releases & Source)
Both the release archives and repository include an automated installer:
```bash
sudo ./install.sh
```
This script automatically:
1. Installs the binary to `/usr/local/bin/volt`.
2. Installs default hardware profile templates (`laptop-dell`, `vm-virtualbox`, `desktop-hp`) to standard Linux application storage: `/usr/local/share/volt/profiles/`.
3. Grants `CAP_NET_RAW` capability via `setcap` for raw stealth scans (`nmap -sS`).
4. Verifies installation.

To completely uninstall at any time:
```bash
sudo ./uninstall.sh
```

#### Option B: Using `make install`
From the project directory:
```bash
sudo make install
```

#### Option C: Manual Installation from Release Archive (No Compiler Needed)
```bash
# 1. Download release archive (replace with latest version)
curl -LO https://github.com/your-org/volt/releases/latest/download/volt-v0.1.0-linux-x86_64.tar.gz

# 2. Extract archive
tar -xzf volt-v0.1.0-linux-x86_64.tar.gz
cd volt-v0.1.0-linux-x86_64

# 3. Run included installer
sudo ./install.sh
```
```bash
# 1. Compile the release binary
cargo build --release

# 2. Copy binary to /usr/local/bin
sudo install -m 755 target/release/volt /usr/local/bin/volt

# 3. (Optional) Grant raw socket capabilities for stealth SYN scans
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/volt

# 4. Verify installation
volt --version
```

### Automated GitHub Releases (CI/CD)
To publish a new official version release with pre-compiled binaries and SHA-256 checksums, simply tag and push:
```bash
git tag v0.1.0
git push origin v0.1.0
```
The automated [release pipeline](.github/workflows/release.yml) will:
1. Build optimized binaries for both `x86_64` and `aarch64` (ARM64) Linux.
2. Package binaries with default hardware profiles and the manual into `.tar.gz` bundles.
3. Compute cryptographic SHA-256 checksums (`.sha256`).
4. Publish a formal GitHub Release with automated changelog notes.

---

## 🎯 Operation Profiles

VOLT adapts its behavior based on the chosen operation mode (`--mode`):

```bash
volt init --case <name> --mode <forensics | red-team | blue-team | malware>
```

| Profile | Target Objective | Automatic Configuration & Guarantees |
|---|---|---|
| **`forensics`** | **Digital Forensics & Law Enforcement** | Prompts for search warrant reference, physical evidence ID, and agency name. Generates ISO/IEC 27037 compliant audit reports with sworn attestation statements. |
| **`red-team`** | **Adversary Simulation & Covert Pentesting** | Disguises machine as genuine bare-metal hardware. `CAP_NET_RAW` enabled for SYN scans (`nmap -sS`), `masscan`, and `hping3`. Transparent `sudo` pass-through with no password prompt. |
| **`blue-team`** | **Incident Response & Threat Hunting** | Strict read-only base layers. Prepares volatile artifact collection workspace. Captures continuous baseline network PCAPs and connection timelines. |
| **`malware`** | **Malware Detonation & Dynamic Triage** | High-fidelity bare-metal DMI/BIOS spoofing to bypass sophisticated anti-VM/anti-analysis evasion checks (`cpuid`, hypervisor strings, MAC vendor). Rapid file system diffing. |

---

## 📖 Complete CLI Command Reference

### 1. `volt init`
Initializes a new evidence case directory and generates Genesis Block 0 of the hash chain.

```bash
volt init [OPTIONS] --case <CASE_ID>
```

**Options:**
- `-c, --case <NAME>`: Unique identifier for the case (e.g. `IR-2026-0042`). *(Required)*
- `-i, --investigator <NAME>`: Name or badge ID of the operator (default: `Investigator`).
- `-p, --profile <PROFILE>`: Hardware spoofing template (`vm-virtualbox` | `laptop-dell` | `desktop-hp`).
- `-m, --mode <MODE>`: Operation profile (`forensics` | `red-team` | `blue-team` | `malware`).
- `--agency <NAME>`: Law enforcement agency or organization name.
- `--warrant <REF>`: Search warrant number or legal authorization reference.
- `--evidence-id <TAG>`: Physical or digital evidence tracking tag ID.

**Example:**
```bash
volt init \
    --case "CASE-IR-8821" \
    --investigator "DetectiveMiller" \
    --mode forensics \
    --profile laptop-dell \
    --agency "Cyber Crime Division" \
    --warrant "SW-2026-901B" \
    --evidence-id "EVID-DISK-01"
```

---

### 2. `volt start`
Launches the primary sandboxed session with all always-on capture engines active.

```bash
volt start --case <CASE_ID> [--profile <OVERRIDE>]
```

**What occurs when you run `volt start`:**
1. **Pre-flight Assertion Check**: Confirms mount isolation is active, host `$HOME` is blocked, and case storage is writable.
2. **Identity Injection**: Bind-mounts spoofed `/proc/cpuinfo`, `/proc/version`, `/etc/hostname`, and `/sys/class/dmi/id/*`.
3. **Always-On Background tcpdump**: Starts capturing all network packets on all interfaces to auto-rotating `.pcap` files.
4. **Always-On Screenshot Engine**: Starts the 30-second interval snapshot worker.
5. **PTY Shell Launch**: Opens a dedicated pseudo-terminal (`openpty`), switches to raw terminal mode, and drops you into a colorized `/bin/bash` root prompt.

---

### 3. `volt join` / `exec` / `attach`
Connects a **full, proper interactive shell terminal** into an active VOLT container from another terminal window or tab.

```bash
volt join <CASE_ID>
# or
volt exec <CASE_ID>
# or
volt attach <CASE_ID>
```

**Features:**
- Drops you directly into an interactive root prompt (`[VOLT:profile \W]# `).
- Automatically synchronizes terminal window dimensions (`winsize`) so `vim`, `nano`, `htop`, and `nmap` display without glitches.
- Every command and keystroke in the joined terminal is recorded to its own log (`terminal_stream_<id>.jsonl`) and chained into the master hash chain.
- If you wish to run a single command non-interactively, pass `-c, --cmd <COMMAND>`:
  ```bash
  volt join CASE-IR-8821 --cmd "nmap -sS -p 80,443 10.0.0.1"
  ```

---

### 4. `volt screenshot`
Takes an immediate on-demand screenshot inside the active case and hashes it directly into the evidence chain.

```bash
volt screenshot --case <CASE_ID> [--label <TAG>]
```

**Example:**
```bash
volt screenshot --case "CASE-IR-8821" --label "sql_injection_proof"
# Output:
# 📸 Screenshot Captured & Hashed
#   File: 20261114_175230_744_sql_injection_proof.png
#   SHA:  2005229677195c558c84e7fb7ab981f2cd785b573ac15959f96edfd31f3b0bb1
```

---

### 5. `volt status`
Displays the real-time status of all cases, active sessions, and storage paths.

```bash
volt status [--case <CASE_ID>]
```

**Example Output:**
```
⚡ VOLT Status & Storage Overview
  Cases directory: ./cases
  • Case: CASE-IR-8821         | Status: ACTIVE (Recording - Multi-Terminal Enabled)
  • Case: INCIDENT-004         | Status: SEALED (Court-Ready)
```

---

### 6. `volt report`
Compiles an executive-level, court-admissible audit report in **HTML** or **Markdown**.

```bash
volt report --case <CASE_ID> [--format html|markdown] [--output <FILE>]
```

**Report Sections:**
- Certificate of Forensic Integrity & Legal Metadata
- Chain of Custody & Cryptographic Root Seal
- Environmental & Hardware Identity Layer Declaration
- Master Chronological Audit Timeline of Events
- Cryptographic Artifact Catalog (all files with sizes and SHA-256 hashes)
- Sworn Forensic Attestation Statement with Signature Blocks

---

### 7. `volt seal`
Finalizes the evidence vault, flushes all write buffers (`fsync`), computes the final root tip hash, produces `evidence_manifest.json`, and updates case status to `SEALED`.

```bash
volt seal --case <CASE_ID> [--sign] [--gpg-key <KEY_ID>]
```

> [!CAUTION]
> Once a case is sealed, it cannot be modified or re-opened for editing. It becomes a read-only historical evidence vault.

---

### 8. `volt verify`
Validates the cryptographic integrity of a case directory or exported bundle, scanning every block in the hash chain and recalculating SHA-256 hashes of every file against the manifest.

```bash
volt verify <PATH_TO_CASE_OR_BUNDLE>
```

**Example Verification Output:**
```
🔍 Verifying VOLT Evidence Integrity for "./cases/CASE-IR-8821"
  ✓ Cryptographic hash chain: VERIFIED (42 sequential blocks intact)
  ✓ Manifest artifacts:       VERIFIED (all 18 files match SHA-256)

✅ VERIFICATION PASSED — Evidence integrity is 100% intact and untampered.
```

**Tamper Detection in Action:**
If even 1 single byte of a captured screenshot, PCAP, or command log is modified:
```
Error: Artifact TAMPERED: "screenshots/login.png" (expected 200522... vs found 0c99c1...)
```

---

### 9. `volt export`
Packages a sealed case into a standalone compressed `.volt` (or `.tar.gz`) bundle with its manifest for legal or forensic handover.

```bash
volt export --case <CASE_ID> [--format volt|targz] [--output <DEST>]
```

---

### 10. `volt stop`
Gracefully terminates background capture daemons (tcpdump, screenshot worker) and closes an active session.

```bash
volt stop --case <CASE_ID>
```

---

## 🖥️ Multi-Terminal Workflow Guide

During an operation, you almost always need multiple terminals open concurrently:

```
┌─────────────────────────────────┐   ┌─────────────────────────────────┐
│ WINDOW 1: Primary Controller    │   │ WINDOW 2: Interactive Terminal  │
│ $ volt start --case "ENG-2026"  │   │ $ volt join "ENG-2026"          │
│ [VOLT:laptop-dell ~]#           │   │ [VOLT:laptop-dell ~]#           │
│ # Running web proxy / listeners │   │ # Running nmap -sS scan         │
└─────────────────────────────────┘   └─────────────────────────────────┘
┌─────────────────────────────────┐   ┌─────────────────────────────────┐
│ WINDOW 3: Interactive Terminal  │   │ WINDOW 4: Interactive Terminal  │
│ $ volt join "ENG-2026"          │   │ $ volt join "ENG-2026"          │
│ [VOLT:laptop-dell ~]#           │   │ [VOLT:laptop-dell ~]#           │
│ # Exploitation & remote SSH     │   │ # Log inspection & triage       │
└─────────────────────────────────┘   └─────────────────────────────────┘
```

Both approaches are supported:
1. **Multiple OS Windows**: Open new tabs/windows and run `volt join <case>`.
2. **Single Window with `tmux`**: Run `tmux` inside your VOLT terminal and press `Ctrl+B %` or `Ctrl+B "` to split panes.

---

## 📂 Case Storage & Directory Structure

Cases are stored by default in `./cases/<case_name>/`. The internal directory structure is organized into strict forensic zones:

```
cases/IR-2026-0042/
├── case.json                      # Case metadata, investigator, warrant, mode, status
├── hardware_profile.json          # Fake hardware identity attributes
├── evidence_manifest.json         # Cryptographic catalog of all artifacts with SHA-256
│
├── evidence/                      # Cryptographic Evidence Zone
│   ├── chain.jsonl                # SHA-256 sequential blockchain log
│   ├── terminal_stream_primary.jsonl  # PTY stream of Terminal 1
│   ├── terminal_stream_sub_*.jsonl    # PTY streams of joined terminals
│   └── file_changes.jsonl         # All file creations/modifications inside sandbox
│
├── pcaps/                         # Wire-Speed Network Capture Zone
│   ├── capture_20261114_230000.pcap   # Full raw packet captures (auto-rotated)
│   └── capture_20261114_233000.pcap
│
├── screenshots/                   # Visual Capture Zone
│   ├── 20261114_230030_interval.png   # 30-second interval screenshots
│   ├── 20261114_230115_login_page.png # On-demand manual captures
│   └── screenshots_manifest.jsonl     # Manifest of all screenshot hashes
│
├── overlay/upper/                 # Volatile Sandbox Filesystem Zone
│   └── root/                      # Any file created or modified in the sandbox
│
└── reports/                       # Formal Reporting Zone
    ├── IR-2026-0042_audit_report.html # Court-ready HTML report
    └── IR-2026-0042_audit_report.md   # Court-ready Markdown report
```

---

## 🎭 Hardware Identity Spoofing & Anti-Analysis

Evasive malware and defensive network scanners probe the local system to detect virtualization or investigate the operator. VOLT mounts fake synthetic structures over `/proc`, `/sys`, and `/etc` to disguise the system as genuine bare-metal hardware:

| Probed Artifact | Real Host Value | What VOLT Shows Inside the Sandbox |
|---|---|---|
| `/sys/class/dmi/id/product_name` | Host motherboard / VM | `Latitude 5520` (Dell) or `EliteDesk 800 G6` (HP) |
| `/sys/class/dmi/id/board_vendor` | Real vendor / VMware / QEMU | `Dell Inc.` or `HP` |
| `/sys/class/dmi/id/bios_version` | Real BIOS | `1.28.0` |
| `/etc/hostname` | Hostname | `DESKTOP-7X9821A` (Generated random corporate name) |
| `/etc/machine-id` | Real machine-id | Random UUID |
| `/proc/cpuinfo` | Host CPU | Profile CPU (e.g. `11th Gen Intel(R) Core(TM) i7-1185G7`) |
| `/etc/passwd` | Real users | `root` and `investigator` only |
| `/etc/shadow` | Host shadow file | Clean synthetic shadow file |
| `~/.ssh`, `~/.gnupg` | Host keys & credentials | **COMPLETELY BLOCKED (Invisible)** |

### Available Presets
- `laptop-dell`: Dell Latitude 5520 notebook profile
- `desktop-hp`: HP EliteDesk 800 G6 desktop profile
- `vm-virtualbox`: Innotek VirtualBox VM profile

---

## ⚡ Raw Packet Scanning & Sudo (`CAP_NET_RAW`)

Offensive security tools (`nmap -sS` SYN scans, `nmap -O` OS detection, `masscan`, `hping3`) require sending raw Ethernet/IP packets using `SOCK_RAW`.

### How VOLT Handles This:
1. **You are UID 0 inside VOLT**: Inside the sandbox, `whoami` returns `root`.
2. **Transparent `sudo` Shim**: If you or an automated script runs `sudo nmap -sS ...`, VOLT's transparent shim passes the command directly to the sandbox root process with **zero password prompts**.
3. **`CAP_NET_RAW` Support**: When launching VOLT with `sudo volt start` or `setcap cap_net_raw+ep volt`, VOLT delegates raw socket capability to the sandbox while maintaining complete filesystem and process containment.
4. **Host Safety**: Even while crafting raw network packets, the tool is strictly confined by OverlayFS and cannot touch host files or host SSH keys.

---

## 🏛️ Forensic Chain of Custody & Court Admissibility

VOLT's evidence vault satisfies the stringent requirements of legal proceedings, digital forensics standards (**ISO/IEC 27037**), and regulatory audits.

### Cryptographic Hash Chain Structure
Every discrete event $E_n$ is chained to the previous block:
$$\text{Block}_n = \text{SHA256}(\text{Index}_n + \text{Timestamp}_n + \text{Type}_n + \text{PayloadHash}_n + \text{PrevHash}_{n-1})$$

```
[Genesis Block 0]
  Hash: f8602cd41f...
        │
        ▼
[Block 1: SCREENSHOT_MANUAL]
  Payload: 2005229677...
  PrevHash: f8602cd41f...
  Hash: 0e615a70a7...
        │
        ▼
[Block 2: PCAP_CHUNK]
  Payload: 8b31a942cd...
  PrevHash: 0e615a70a7...
  Hash: 3f882a10be...
```

- If an adversary, suspect, or third-party modifies a single byte in any PCAP file or terminal log, recomputing the hash chain detects the modification immediately.
- The `volt verify` command re-checks the entire chain and validates every file against `evidence_manifest.json`.

---

## ⚙️ Configuration Reference (`volt.toml`)

Create a `volt.toml` in your working directory or pass `--config <PATH>`:

```toml
# Path where all cases and evidence vaults are stored
cases_dir = "./cases"

# Default hardware deception profile (laptop-dell | desktop-hp | vm-virtualbox)
default_hardware_profile = "laptop-dell"

# Frequency of automatic desktop screenshots in seconds
screenshot_interval_secs = 30

# Maximum size per PCAP file before auto-rotating (in Megabytes)
pcap_rotate_mb = 100

# Disk space warning threshold percentage
disk_warning_pct = 80

# Emergency auto-seal threshold percentage (stops session safely before disk fills)
disk_emergency_seal_pct = 95
```

### Environment Variable Overrides
- `VOLT_CASES_DIR`: Override base directory for cases (e.g. `export VOLT_CASES_DIR="/mnt/secure_vault"`).
- `VOLT_HOME`: Override default config directory.

---

## 📜 License
*Proprietary & Open Forensic Standard — Maintained by the VOLT Security Core Team.*
