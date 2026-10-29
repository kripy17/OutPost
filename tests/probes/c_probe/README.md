# OutPost Ground-Truth Behavioral Probe: C / ELF

## 1. Provenance & Build Specifications
- **Source File:** `main.c`
- **Compiler:** `gcc (GCC) 16.2.1 20260810` (x86_64)
- **Compiler Command:**
  ```bash
  gcc -O2 -fno-ident -Wl,--build-id=none -o probe_elf main.c
  ```
- **Target Output Binary:** `probe_elf` (ELF 64-bit LSB pie executable, x86-64)
- **Fixed SHA-256 Digest:**
  `13fa7a774b13d4eb118eb8f0555676603e8deae1e130123dc23f842dd53825f6`
- **Portability & Determinism:**
  To ensure hash validity across different machines, hypervisors, and compiler toolchains without toolchain drift, the compiled `probe_elf` binary is committed directly to git alongside this source code and `build.sh`. `test_dev_probe_allowed_hashes_integrity` verifies on every run that the file on disk matches the hardcoded constant in `dynamic_sandbox.py`.

---

## 2. Expected Action Specification (Derived from Source)
This document is authored strictly from the `main.c` source code, defining the ground truth actions that any valid syscall or event tracer must observe.

| Action Index | Category | Operation | Target / Arguments | Expected Return / Status |
| :--- | :--- | :--- | :--- | :--- |
| **A1** | `process` | Process Launch | `execve("./probe_elf", ...)` | Starts main probe process |
| **A2** | `file` | File Create & Write | Open `probe_c.tmp` with `O_WRONLY\|O_CREAT\|O_TRUNC`, mode `0644`. Write payload: `"OutPost C probe test payload data\n"`. | File created and written: exactly 34 bytes (`len("OutPost C probe test payload data\n") == 34`). Explicit `open()` allocates descriptor `fd 10` (contrasting with shell stdout redirection which writes on `fd 1`); close `fd`. |
| **A3** | `file` | Permission Change | `chmod("probe_c.tmp", 0600)` | Returns `0` |
| **A4** | `file` | File Rename | `rename("probe_c.tmp", "probe_c_renamed.tmp")` | Returns `0` |
| **A5** | `file` | File Deletion | `unlink("probe_c_renamed.tmp")` | Returns `0` |
| **A6** | `process` | Child Spawn | `fork()` | Parent receives child PID; Child receives `0`, prints banner, and exits with `_exit(0)`. |
| **A7** | `process` | Child Harvest | `waitpid(child_pid, &status, 0)` | Harvests child exit status `0`. |
| **A8** | `dns` | DNS Query Attempt | `getaddrinfo("probe-c.test.invalid", "80", ...)` | Resolver issues UDP query to `127.0.0.1:53`. Local kernel returns ICMP Port Unreachable (`POLLERR`). Per glibc resolver default (`attempts: 2`), up to 2 query attempts are observed before returning `EAI_NONAME`. |
| **A9** | `network` | TCP Socket Connect | `socket(AF_INET, SOCK_STREAM, 0)` -> `connect(sock, "192.0.2.1:80", ...)` | Connection fails (`ENETUNREACH` in `--unshare-net` without routing); socket is closed. |
| **A10** | `process` | Process Exit | Clean exit from `main()` | Return code `0` |

---

## 3. Telemetry Expectations & Noise Suppression
- **Process Count:** 2 processes (parent `probe_elf` and child process from `fork`).
- **File Mutations:** Exactly 5 file mutation events (`probe_c.tmp` create, write 34 bytes, chmod 0600, rename `probe_c_renamed.tmp`, unlink).
- **Suppressed System Reads:** 1 read suppressed (`libc.so.6` dynamic library load). Note: Earlier failed loader search attempts return `-1 ENOENT` (not open descriptors); only the single successful descriptor read is counted as a suppressed system read.
- **DNS Events:** 4 events (2 UDP sendto query attempts to `127.0.0.1:53` + 2 poll failure events under `AF_INET`).
- **Network Connects:** 1 failed TCP connect attempt to `192.0.2.1:80` (`ENETUNREACH`).
