# ⚡ Real-Time Cross-Terminal Environment Sharing Engine

VOLT provides a high-performance, real-time environment variable synchronization engine across all active terminal sessions and background subshells attached to a case.

---

## 🎯 Architecture & Guarantees

In multi-window penetration testing and digital forensics workflows, operators frequently maintain 3–8 concurrent terminal windows (e.g., controller, listeners, scanners, triage, exploitation shells). Manually copying and pasting environment variables (`$TARGET`, `$RHOSTS`, `$TOKEN`, `$LHOST`, `$LPORT`) across every terminal causes operational friction and human error.

VOLT eliminates this friction through a **zero-configuration, transparent shared environment engine**:

```
┌─────────────────────────────────┐   ┌─────────────────────────────────┐
│ WINDOW 1: Primary Controller    │   │ WINDOW 2: Interactive Scanner   │
│ $ export TARGET=10.10.10.5      │   │ $ echo $TARGET                  │
│                                 │   │ 10.10.10.5  (Instant Sync!)     │
│ $ export LPORT=4444             │   │                                 │
└───────────────┬─────────────────┘   └───────────────▲─────────────────┘
                │                                     │
                ▼                                     │
       ┌─────────────────────────────────────────────────────┐
       │ Atomic Shared Store: /root/.volt_env                │
       │ (Persisted in case overlay/upper/.volt_env)         │
       │ - flock -x non-blocking locking                     │
       │ - Microsecond mtime dirty checking                  │
       └─────────────────────────────────────────────────────┘
                ▲                                     ▲
                │                                     │
┌───────────────┴─────────────────┐   ┌───────────────┴─────────────────┐
│ WINDOW 3: Exploit Shell         │   │ WINDOW 4: Host Management CLI   │
│ $ volt-env                      │   │ $ volt env --case <CASE> --set  │
│ [Shared Variables Table]        │   │   NEW_PARAM=prod-db-1           │
└─────────────────────────────────┘   └─────────────────────────────────┘
```

### Key Guarantees:
1. **Zero Configuration**: Any standard `export KEY=VALUE` or `unset KEY` run in any sandbox shell automatically broadcasts to all other sessions.
2. **Instant Pre-Command Synchronization**: Terminal 2 receives changes before executing its very next command or returning to the prompt.
3. **Session Persistence**: Stored within the case's OverlayFS upper layer (`overlay/upper/.volt_env`). Variables survive container shutdown (`volt stop`) and re-appear upon session restart (`volt start`).
4. **Host & In-Sandbox CLI Management**: Full programmatic control via host `volt env` and in-sandbox `/volt-shims/volt-env`.

---

## 🔧 Under the Hood: How It Works

### 1. Synchronized Storage File
The engine maintains the file `/root/.volt_env` inside the sandbox root directory. Because `/root` is mapped to the case's writable OverlayFS upper layer, all writes are persisted to disk at `<case_dir>/scratch/upper/root/.volt_env` (or `<case_dir>/overlay/upper/.volt_env`).

### 2. Transparent `export` & `unset` Shell Hooks
When an interactive Bash shell starts inside VOLT, `/root/.bashrc` defines custom functions for `export` and `unset`:

```bash
export() {
    builtin export "$@"
    # Atomic file-locked append/update to /root/.volt_env
    # Updates tracking timestamp /tmp/.volt_env_sync
}

unset() {
    builtin unset "$@"
    # Atomic removal from /root/.volt_env
    # Updates tracking timestamp /tmp/.volt_env_sync
}
```

### 3. Concurrency Protection with `flock`
Concurrent shells could attempt to write variables simultaneously. VOLT wraps all mutations in `flock -x -w 1` (exclusive lock with a 1-second timeout), ensuring atomic read-modify-write cycles and eliminating race conditions or file corruption.

### 4. Zero-Latency Pre-Command Dirty Checking
Polling loops waste CPU cycles and introduce latency. Instead, VOLT hooks into Bash's:
1. `DEBUG` trap: Fires immediately *before* any command is executed.
2. `PROMPT_COMMAND`: Fires immediately *before* displaying the interactive shell prompt.

Both hooks run an ultra-fast internal timestamp comparison:
```bash
if [ -f /root/.volt_env ] && [ /root/.volt_env -nt /tmp/.volt_env_sync ]; then
    _volt_load_env
fi
```
Using the Bash built-in `[ -nt ]` (newer than) operator avoids spawning subshells or executing external binaries (`stat`, `date`), maintaining execution times under 1 millisecond.

---

## 💻 In-Sandbox Usage

Inside any VOLT shell, you have two ways to interact with shared variables:

### Method 1: Standard Bash Commands (Transparent)
```bash
# Set a shared variable (propagated instantly)
export TARGET=192.168.1.100
export API_KEY="Bearer eyJhbGciOi..."
export RHOSTS="10.0.0.0/24"

# Remove a variable (removed from all terminals)
unset TARGET
```

### Method 2: The In-Sandbox `volt-env` CLI
VOLT injects `/volt-shims/volt-env` (also aliased to `env-share`):

```bash
# 1. List all shared variables in a clean table
volt-env
# or:
env-share

# 2. Set a variable
volt-env set DB_HOST 10.10.10.50

# 3. Read a specific variable
volt-env get DB_HOST

# 4. Unset a variable
volt-env unset DB_HOST

# 5. Clear all shared variables
volt-env clear
```

---

## 🖥️ Host CLI Management: `volt env`

Operators and external automation scripts can inspect and manage shared environment variables directly from the host without attaching to an interactive shell.

### Command Reference:

```bash
# Display all shared variables for a case
volt env --case <CASE_NAME>

# Set a shared variable from the host
volt env --case <CASE_NAME> --set RHOSTS=192.168.1.0/24

# Set multiple variables
volt env --case <CASE_NAME> --set LHOST=10.10.14.2 --set LPORT=4444

# Get a specific variable value
volt env --case <CASE_NAME> --get RHOSTS

# Output as JSON (ideal for CI/CD and automation)
volt env --case <CASE_NAME> --json

# Output as shell export statements
volt env --case <CASE_NAME> --export

# Unset a variable
volt env --case <CASE_NAME> --unset RHOSTS

# Clear all shared variables
volt env --case <CASE_NAME> --clear
```

### Example: Automated Target Injection
```bash
# Inject target information into an active engagement from a host script
TARGET_IP=$(terraform output -raw instance_ip)
volt env --case "ENG-2026-ALPHA" --set TARGET="$TARGET_IP"

# Inside every active VOLT terminal, $TARGET is immediately available:
# [VOLT:laptop-dell ~]# nmap -sT $TARGET
```
