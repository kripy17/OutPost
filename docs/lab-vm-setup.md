# OutPost Lab VM Setup & Kernel Configuration Guide

**Document Status:** Standard Operating Procedure (Pre-Implementation Dependency)  
**Target Systems:** QEMU/KVM, VMware Workstation/ESXi, VirtualBox (Hyper-V/Xen/bhyve compatible)  
**Author:** OutPost Security & Isolation Architecture  
**Revision:** 1.1.0  

---

## 1. Purpose & Isolation Boundary

Dynamic malware detonation must **never** execute on bare-metal workstations or shared-kernel container environments (`docker`, `podman`, `lxc`, `wsl`). OutPost enforces this boundary via `verify_lab_vm_safety()`, which demands:
1. Detection of a verified hardware hypervisor via `systemd-detect-virt --vm`.
2. Explicit operator confirmation via the environment variable `OUTPOST_LAB_VM=1`.

This document details the configuration of the analysis guest virtual machine and the exact procedure for capturing raw baseline strace telemetry under bubblewrap.

---

## 2. Base Virtual Machine Specification

| Parameter | Recommended Specification | Minimum Requirement |
| :--- | :--- | :--- |
| **Hypervisor** | QEMU/KVM (virt-manager / libvirt) or VMware / VirtualBox | Hardware Virtualization (VT-x/AMD-V) |
| **Guest OS** | Ubuntu 24.04 LTS (recommended) / Debian 12 / Arch Linux | Linux Kernel >= 5.15 |
| **Virtual CPUs** | 4 vCPUs | 2 vCPUs |
| **RAM** | 4 GB to 8 GB | 4 GB |
| **Disk** | 40 GB (qcow2 / thin provisioned) | 20 GB |
| **Networking** | Isolated Host-Only or Internal Network (no bridge to LAN/Internet) | Strictly Air-Gapped |
| **Sharing** | Disable shared clipboard, drag-and-drop, and shared folders | Mandatory |
| **Snapshots** | Clean Base Golden Snapshot (`clean-baseline`) | Mandatory post-install |

---

## 3. Required Packages & Installation

Install the necessary runtime and inspection utilities:

```bash
# Ubuntu 24.04 / Debian 12
sudo apt-get update && sudo apt-get install -y \
    bubblewrap \
    strace \
    tcpdump \
    nftables \
    iproute2 \
    libpcap-dev \
    python3 \
    python3-venv \
    python3-pip \
    sqlite3 \
    git \
    curl

# Arch Linux
sudo pacman -Syu --noconfirm \
    bubblewrap \
    strace \
    tcpdump \
    nftables \
    iproute2 \
    libpcap \
    python \
    sqlite \
    git
```

---

## 4. Mandatory Kernel & Sysctl Configuration

### 4.1 Ubuntu 24.04 AppArmor User Namespace Restriction
Ubuntu 24.04 restricts unprivileged user namespaces via AppArmor (`kernel.apparmor_restrict_unprivileged_userns=1`), which causes `bwrap` to fail for unprivileged users with `bwrap: No permissions to creating a new user namespace`.

> [!WARNING]
> Setting `kernel.apparmor_restrict_unprivileged_userns = 0` weakens unprivileged namespace isolation across the OS. This setting is strictly for **dedicated, disposable lab analysis VMs** and must **never** be applied to a daily workstation or production endpoint.

To permit unprivileged container micro-sandboxing inside the lab VM:
```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```
*(On Debian systems where this sysctl does not exist, use `sudo sysctl -w kernel.unprivileged_userns_clone=1` instead).*

### 4.2 Ptrace Scope Configuration
Linux kernels with the Yama security module enforce restrictions on `ptrace`.
- The default value `kernel.yama.ptrace_scope = 1` permits a parent process to trace any child process it launches directly (`strace bwrap ...`). This is sufficient for OutPost's supervisor model.
- Setting `kernel.yama.ptrace_scope = 0` permits classic ptrace where any process under the same UID can attach to any other running process. This can be used if debugging requires ad-hoc `strace -p <pid>` attachment.

```bash
# Check current scope (1 is sufficient; 0 allows ad-hoc attachment)
sysctl kernel.yama.ptrace_scope
```

### 4.3 Persistent Sysctl Settings
Persist across reboots by writing `/etc/sysctl.d/99-outpost-lab.conf`:
```ini
# /etc/sysctl.d/99-outpost-lab.conf
kernel.yama.ptrace_scope = 1
kernel.apparmor_restrict_unprivileged_userns = 0
user.max_user_namespaces = 15000
```
Apply via:
```bash
sudo sysctl --system
```

---

## 5. Lab Environment & Directory Setup

Configure the shell profile for the analysis user (`~/.bashrc` or system-wide `/etc/environment`):

```bash
# Confirms execution is inside a sanctioned lab VM
export OUTPOST_LAB_VM=1

# Maximum events captured per detonation before truncation
export OUTPOST_MAX_RUN_EVENTS=10000

# Dedicated user-owned supervisor workdir (mode 0700, outside guest jail)
export OUTPOST_SUPERVISOR_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/outpost/supervisor"
```

Create the user-owned supervisor directory (does not require root):
```bash
mkdir -p "$OUTPOST_SUPERVISOR_DIR"
chmod 0700 "$OUTPOST_SUPERVISOR_DIR"
```

---

## 6. Verification Checklist & Baseline Experiment

### Step 6.0: Bubblewrap & Namespace Sanity Check
Before executing the strace probe, confirm unprivileged bubblewrap execution works cleanly:
```bash
bwrap --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
      --proc /proc --dev /dev --unshare-all --die-with-parent /bin/true; echo "Sanity exit code: $?"
```
*Expected output: exit code `0`. If this fails with `bwrap: No permissions to creating a new user namespace`, verify `kernel.apparmor_restrict_unprivileged_userns = 0` (Section 4.1).*

### Step 6.1: Run Verification Checklist
Run in the VM to record baseline system telemetry into `reports/lab-baseline.txt`:
```bash
mkdir -p reports tests/fixtures

virt_out=$(systemd-detect-virt 2>&1)
virt_rc=$?

cat <<EOF > reports/lab-baseline.txt
=== OutPost Lab VM Baseline Audit ===
Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Hypervisor: ${virt_out} (exit code: ${virt_rc})
Kernel: $(uname -a)
Strace: $(strace --version | head -n 1)
Bwrap: $(bwrap --version)
SQLite (CLI): $(sqlite3 --version)
SQLite (Python): $(python3 -c "import sqlite3; print(sqlite3.sqlite_version)")
Ptrace Scope: $(sysctl -n kernel.yama.ptrace_scope 2>/dev/null || echo 'unset')
AppArmor Userns: $(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo 'unset')
EOF

cat reports/lab-baseline.txt
```

### Step 6.2: Run Baseline Experiment 1 (Combined Trace with PIDNS)
Execute the reference probe from the supervisor boundary:
```bash
# If strace rejects --decode-pids=pidns, remove that flag and note it in reports/lab-baseline.txt
strace -f -ttt -yy --decode-pids=pidns -s 256 -o tests/fixtures/baseline_strace_probe.log \
    bwrap \
        --ro-bind /usr /usr \
        --ro-bind-try /lib /lib \
        --ro-bind-try /lib64 /lib64 \
        --ro-bind-try /bin /bin \
        --ro-bind-try /sbin /sbin \
        --clearenv \
        --setenv PATH "/usr/local/bin:/usr/bin:/bin" \
        --tmpfs /tmp \
        --dir /tmp/sandbox \
        --chdir /tmp/sandbox \
        --unshare-pid \
        --unshare-ipc \
        --unshare-uts \
        --unshare-cgroup \
        --cap-drop ALL \
        --unshare-net \
        --die-with-parent \
        /bin/bash -c "echo '=== OutPost Probe Executing ==='; uname -a; id; ls -d /tmp"
```

### Step 6.3: Run Baseline Experiment 2 (Per-PID Split Tracing Comparison)
Run with `-ff -o` to compare parseability of per-PID individual files vs a single stream:
```bash
mkdir -p tests/fixtures/split_probe
strace -ff -ttt -yy -s 256 -o tests/fixtures/split_probe/trace \
    bwrap \
        --ro-bind /usr /usr \
        --ro-bind-try /lib /lib \
        --ro-bind-try /lib64 /lib64 \
        --ro-bind-try /bin /bin \
        --ro-bind-try /sbin /sbin \
        --clearenv \
        --setenv PATH "/usr/local/bin:/usr/bin:/bin" \
        --tmpfs /tmp \
        --dir /tmp/sandbox \
        --chdir /tmp/sandbox \
        --unshare-pid \
        --unshare-ipc \
        --unshare-uts \
        --unshare-cgroup \
        --cap-drop ALL \
        --unshare-net \
        --die-with-parent \
        /bin/bash -c "echo '=== OutPost Split Probe ==='; uname -a; id"
```

Commit `tests/fixtures/baseline_strace_probe.log` and `reports/lab-baseline.txt` to the repository once completed.
