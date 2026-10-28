# OutPost Ground-Truth Behavioral Probe: Shell Script

## 1. Provenance & Execution Specifications
- **Source File:** `probe.sh`
- **Interpreter:** `/bin/bash`
- **Fixed SHA-256 Digest:**
  `d68f3dd20583315f4c893504c2876b6cf21edf0a1c2cd53517f0c6afccb7852f`

---

## 2. Expected Action Specification (Derived from Source)
Derived directly from `probe.sh` source statements:

| Action Index | Category | Operation | Target / Arguments | Expected Return / Status |
| :--- | :--- | :--- | :--- | :--- |
| **S1** | `process` | Script Launch | `execve("/bin/bash", ["bash", ".../probe.sh"], ...)` | Starts main shell interpreter |
| **S2** | `file` | File Write | Redirection `> probe_shell.tmp` (`"OutPost shell probe payload data\n"`) | File created and written: exactly 33 bytes (`len("OutPost shell probe payload data\n") == 33`). In bash, redirection redirects standard output (`fd 1`) to the target file (`probe_shell.tmp`), so the kernel write occurs on descriptor `fd 1` (annotated via strace `-yy` as `1<.../probe_shell.tmp>`), contrasting with C and Python where `open()` returns a dedicated descriptor (`fd 10`). |
| **S3** | `file` | Permission Change | `chmod 0600 probe_shell.tmp` | Mode updated to `0600` |
| **S4** | `file` | File Rename | `mv probe_shell.tmp probe_shell_renamed.tmp` (`rename` syscall) | Returns `0` |
| **S5** | `file` | File Deletion | `rm -f probe_shell_renamed.tmp` (`unlink` syscall) | Returns `0` |
| **S6** | `process` | Child Spawn | `/bin/sh -c 'echo "--- Shell Probe Child Process Executing ---"; exit 0'` | `clone`/`fork`, child prints banner and exits 0 |
| **S7** | `dns` | DNS Query Attempt | `getent ahosts probe-sh.test.invalid` | Resolver issues DNS lookup using `AF_UNSPEC` (querying both A [IPv4, Type 1] and AAAA [IPv6, Type 28] records). Under glibc, parallel resolution issues an A query via `sendmmsg` and an AAAA query via `sendto`. In the isolated namespace, both fail with `POLLERR` (ICMP port unreachable). With glibc default of 2 attempts, the cycle retries on a fresh socket, producing exactly 4 query attempts (2 A, 2 AAAA) and 4 paired poll failures (8 DNS events total). |
| **S8** | `network` | TCP Socket Connect | `/dev/tcp/192.0.2.1/80` via subshell | Connection fails (`ENETUNREACH` in isolated namespace) |
| **S9** | `process` | Script Exit | `exit 0` | Exit code `0` |

---

## 3. Telemetry Expectations & Noise Suppression
- **Process Count:** 8 processes (root bash script, utilities `/usr/sbin/chmod`, `/usr/sbin/mv`, `/usr/sbin/rm`, child `/bin/sh`, resolver `/usr/sbin/getent`, `/usr/sbin/timeout`, and timeout subshell `/usr/sbin/bash`).
- **Process Events:** 23 lifecycle events (fork, exec, exit across the process hierarchy).
- **File Mutations:** Exactly 5 file mutation events (`probe_shell.tmp` create, write, chmod 0600, rename `probe_shell_renamed.tmp`, unlink). Standard descriptor redirection (`dup`/`dup2`) is tracked to associate writes with the target file; operations on `/dev/null` are suppressed.
- **Suppressed System Reads:** 145 reads suppressed under standard Linux runtime noise filter (dynamic loader libraries `/etc/ld.so.cache`, `libc.so.6`, locale databases, terminfo, `/etc/nsswitch.conf`, `/etc/host.conf`, and binary executables).
- **DNS Events:** 8 paired events (4 query attempts to `probe-sh.test.invalid` [2 Type A, 2 Type AAAA across 2 resolver retry attempts] + 4 paired poll failure events under `AF_UNSPEC`).
- **Network Connects:** 1 failed TCP connect attempt to `192.0.2.1:80` (`ENETUNREACH`).
- **Total Timeline Events:** Exactly 37 events (23 process + 5 file + 8 DNS + 1 network).
