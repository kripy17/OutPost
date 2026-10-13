# ADR 0005: Sandbox Design via Bubblewrap (bwrap) and Wine Isolation

## Status
Accepted

## Context
OutPost provides dynamic detonation and behavioral tracing of untrusted ELF, Linux shell scripts, and Windows PE binaries (`.exe`, `.dll`) on Linux hosts. Executing untrusted malware directly risks host compromise, network beaconing, and sandbox escape. Dedicated VM sandboxes (e.g. Cuckoo, CAPE) require gigabytes of disk images, QEMU/KVM setup, nested virtualization support, and take 30-60 seconds to spin up per sample.

## Decision
OutPost implements a lightweight, near-instantaneous containerless sandbox using Linux unprivileged user namespaces via `bwrap` (Bubblewrap) combined with a hardened Wine environment:
1. **Filesystem Isolation:**
   - Read-only root mount (`--ro-bind / /`).
   - Ephemeral in-memory tmpfs for sample execution (`--tmpfs /tmp`, `--tmpfs /wineprefix`).
   - Host sensitive paths (`/home`, `/root`, `/etc/shadow`, `/etc/ssh`) are explicitly masked or unmounted.
2. **Network Isolation:**
   - Detonations run with `--unshare-net` (no network access) by default, or with a dedicated local virtual tap for PCAP capture.
3. **Execution Sandboxing:**
   - Linux binaries execute under `bwrap` with seccomp filters and `RLIMIT_CPU` / `RLIMIT_AS` memory quotas.
   - Windows binaries execute inside a fresh Wine prefix within the `bwrap` container, instrumented with API hooking and forensic event capture.

## Alternatives Rejected
1. **Full QEMU/KVM Virtual Machine Snapshots:**
   - *Reason for Rejection:* Too heavy for portable single-node deployments; requires hardware virtualization (VT-x/AMD-V) which is often unavailable in cloud containers or nested VMs; multi-minute spinup times.
2. **Standard Docker Containers:**
   - *Reason for Rejection:* Requires running the Docker daemon as root or managing rootless Docker permissions; standard Docker defaults share substantial kernel attack surface without fine-grained bwrap bind mount overrides.

## Consequences & Known Costs
- **Pros:**
  - Sub-second execution spinup: detonations begin in under 500 milliseconds.
  - Zero VM image dependencies (runs directly on host system libraries).
  - Strong namespace and filesystem boundary protection.
- **Cons / Limitations:**
  - Kernel vulnerability exposure: relies on host Linux kernel isolation rather than hypervisor hardware-assisted virtualization.
  - Wine compatibility: advanced Windows kernel drivers (`.sys`) and rootkits cannot execute in Wine userland emulation.
