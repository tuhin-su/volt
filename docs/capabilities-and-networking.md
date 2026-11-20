# ⚡ Linux Capabilities, User Namespaces, and Network Scanning in VOLT

This document explains the security architecture of VOLT's networking layer, how Linux capabilities interact with user namespaces, and how to configure permissions for raw packet tools (`nmap -sS`, `nmap -sU`, `masscan`, `hping3`).

---

## 🔍 The Root Cause: Why Raw Sockets Fail in Unprivileged Namespaces

When running offensive scanning tools such as `nmap` or `masscan`, the tool attempts to craft raw IP or Ethernet packets:
- **`nmap -sS` (TCP SYN Stealth Scan)**: Crafts raw TCP packets without completing the OS 3-way handshake (`SOCK_RAW` / `IPPROTO_RAW`).
- **`nmap -sU` (UDP Scan)**: Crafts UDP probes and listens for ICMP Port Unreachable packets using raw packet sockets (`AF_PACKET`).
- **`nmap -O` (OS Fingerprinting)**: Sends invalid or malformed TCP/UDP/ICMP probes and analyzes raw response headers.

On Linux, opening `SOCK_RAW` or `AF_PACKET` sockets requires the `CAP_NET_RAW` capability.

### The Linux Kernel Capability Check:
Inside the Linux kernel (`net/core/sock.c` and `net/packet/af_packet.c`), socket creation verifies privileges using:

```c
if (!ns_capable(net->user_ns, CAP_NET_RAW))
    return -EPERM;
```

Here:
- `net` is the network namespace of the process.
- `net->user_ns` is the **user namespace that owns the network namespace**.

VOLT shares the host's network namespace (`--share-net`) so that:
1. All host routing tables, VPN tunnels (OpenVPN, WireGuard), and interfaces (`eth0`, `tun0`) are immediately usable.
2. Background packet captures (`tcpdump`) capture real host network traffic.

Because the network namespace is created by the host operating system, it is owned by the **initial (root) user namespace** of the host.

### The Bubblewrap (`bwrap`) Paradox:
1. **Unprivileged Rootless Execution (`volt start`)**:
   - To make you `root` (UID 0) inside the sandbox without needing `sudo` on the host, `bwrap` creates a new **child user namespace** (`CLONE_NEWUSER`) and maps your host UID to UID 0 inside.
   - Inside this child user namespace, your process has all capabilities (`CAP_NET_RAW`, `CAP_SYS_ADMIN`, etc.) — **but only within that child user namespace**!
   - Because the host network namespace is owned by the *initial* user namespace, the kernel checks `ns_capable(host_net->user_ns, CAP_NET_RAW)`.
   - Your process only has `CAP_NET_RAW` in the child user namespace, not the initial user namespace.
   - Result: `Operation not permitted (EPERM)` when opening raw sockets.

2. **Elevated Execution (`sudo volt start`)**:
   - When running as root, VOLT skips `--unshare-user`.
   - The sandbox runs directly in the host's initial user namespace while still applying:
     - Mount namespace (`CLONE_NEWNS`) with OverlayFS isolation.
     - Process namespace (`CLONE_NEWPID`).
     - Hostname/UTS namespace (`CLONE_NEWUTS`).
     - IPC namespace (`CLONE_NEWIPC`).
   - Because the initial user namespace is preserved, **`CAP_NET_RAW` and `CAP_NET_ADMIN` remain fully valid over the host network stack**!
   - Tools like `nmap -sS`, `nmap -sU`, and `masscan` succeed completely.

---

## 🛠️ How to Enable Raw Packet Scanning for Your Current User

There are two primary ways to run scans in VOLT:

### Option 1 (Recommended): Sudoers NOPASSWD Rule for VOLT

This is the standard approach used by professional security workstations (Kali, BlackArch). It allows your normal user account to launch VOLT with elevated capabilities without entering a password, while keeping all activities sandboxed and recorded.

1. Add a dedicated sudoers entry for `volt`:
   ```bash
   echo "$USER ALL=(ALL) NOPASSWD: /usr/local/bin/volt" | sudo tee /etc/sudoers.d/volt-user
   sudo chmod 0440 /etc/sudoers.d/volt-user
   ```

2. Start your session with `sudo`:
   ```bash
   sudo volt start --case ENG-2026-ALPHA
   ```

3. Inside the session, run any raw scan:
   ```bash
   # SYN stealth scan
   nmap -sS -p 22,80,443,8080 10.10.10.5

   # UDP scan
   nmap -sU -p 53,161,500 10.10.10.5

   # OS fingerprinting
   nmap -O 10.10.10.5
   ```

### Option 2: Unprivileged TCP Connect Scanning (`nmap -sT`)

If you are operating in an environment where `sudo` is unavailable or prohibited, you can perform full port scanning using standard TCP connect scans (`-sT`):

```bash
# Start rootless VOLT session
volt start --case ENG-2026-ALPHA

# Inside the session, use -sT:
nmap -sT -Pn -p- 10.10.10.5
```

#### Why `-sT` Works Without Capabilities:
- TCP Connect scans use the standard Berkeley sockets `socket(AF_INET, SOCK_STREAM, 0)` and `connect()`.
- The host Linux kernel handles the TCP 3-way handshake on behalf of the unprivileged process.
- No raw packet crafting or special capabilities (`CAP_NET_RAW`) are required.

---

## 🔒 Transparent In-Sandbox `sudo`

Inside the VOLT sandbox, your shell identity is `root`:

```bash
[VOLT:laptop-dell ~]# whoami
root
[VOLT:laptop-dell ~]# id
uid=0(root) gid=0(root) groups=0(root)
```

Many automated scripts and tools (e.g., Metasploit, exploit scripts, install scripts) hardcode `sudo <command>`.

VOLT installs a transparent `/usr/bin/sudo` shim inside `/volt-shims`:
1. If a script executes `sudo nmap ...`, the shim intercepts the call.
2. It executes the target command directly with **zero password prompts**.
3. If executed inside an unprivileged session and `nmap -sU` or `nmap -sS` is requested, the shim provides a helpful advisory explaining why `sudo volt start` is needed on the host.

---

## 📊 Summary of Scanning Modes in VOLT

| Scan Type | Nmap Flag | Requires `CAP_NET_RAW`? | Allowed in Rootless `volt start`? | Allowed in `sudo volt start`? |
|---|---|---|---|---|
| **TCP Connect** | `nmap -sT` | ❌ No | ✅ Yes | ✅ Yes |
| **TCP SYN Stealth** | `nmap -sS` | ✅ Yes | ❌ Blocked by Kernel | ✅ Yes |
| **UDP Scan** | `nmap -sU` | ✅ Yes | ❌ Blocked by Kernel | ✅ Yes |
| **OS Detection** | `nmap -O` | ✅ Yes | ❌ Blocked by Kernel | ✅ Yes |
| **ICMP Ping Sweep** | `nmap -sn` | ✅ Yes (raw ICMP) | ❌ Blocked by Kernel | ✅ Yes |
| **TCP ACK / Window** | `nmap -sA / -sW` | ✅ Yes | ❌ Blocked by Kernel | ✅ Yes |
| **Service Version** | `nmap -sV -sT` | ❌ No | ✅ Yes | ✅ Yes |
| **Nmap Scripting (NSE)** | `nmap -sC -sT` | ❌ No | ✅ Yes | ✅ Yes |
