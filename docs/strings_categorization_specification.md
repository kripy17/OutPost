# OutPost Static Analysis: Strings Categorization & Extraction Specification

**Document Version**: 1.0  
**Status**: Implemented & Approved  
**Scope**: Stage 2 Static Analysis Engine (`backend/app/services/static/strings.py`)

---

## 1. Core Principles & Philosophy

1. **Analyst Context, Not Detection Evidence**:
   - Extracted strings provide human analyst triage context, fast filtering, and exploratory visibility.
   - **Strings and categorized string buckets must NEVER feed the static risk score, static severity, or `assessment_factors`.**
   - Detection signals and verdict elevations are exclusively driven by parsed binary structures (unreferenced overlays, non-standard RWX memory permissions, malicious macro payloads, verified IOC threat feeds).

2. **Strict Disambiguation Between Commands, Indicators, and Symbols**:
   - Single isolated tokens (e.g. `chmod`, `socket`, `connect`, `whoami`, `netstat`) frequently appear in benign software as libc symbol names, format string descriptors, terminal color sequences, or documentation text.
   - Bare words are **never** classified as `commands` or `network`.
   - `commands` strictly requires a verifiable command-line execution shape (interpreter + arguments or tool + administrative flags).
   - `network` strictly requires URI/URL protocol syntax, valid routable IPv4 addresses, or full FQDN dynamic DNS/C2 host shapes.
   - Function names and API imports belong to the dedicated `api_names` bucket (or the parsed import table), preventing pollution of network/command buckets.

3. **Concordance with Standard Tooling**:
   - ASCII and UTF-16LE extraction is mathematically and empirically validated against GNU Binutils `strings` (`strings -a -n 4` and `strings -a -e l -n 4`).
   - Every string preserves its physical byte offset (`offset`, `offset_hex`), length, and encoding.

---

## 2. Intelligence Category Definitions & Formal Regex Rules

### Category A: `urls`
**Purpose**: Explicit web, documentation, and resource locators.

- **URL Protocol Shapes**:
  - `https?://(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[0-9]{1,3}(?:\.[0-9]{1,3}){3})(?::\d+)?(?:/[^\s"'<>()]*)?`
  - `(?:ftp|tcp|udp|wss?)://[^\s"'<>()]+`
- **Exclusions**:
  - Excludes bare domain names without protocol schemes. Plain documentation URLs (e.g. `https://www.gnu.org/...`) are classified as `urls`, distinct from malicious C2 indicators.

---

### Category B: `network`
**Purpose**: High-confidence network indicators, C2 beacons, staging infrastructure, and HTTP request headers.

- **Routable IPv4 Addresses**:
  - Valid 4-octet IPv4 addresses (`0-255` per octet), bounded by non-period lookaround `(?<![\.\d])...(?![\.\d])`. Excludes loopback (`127.x.x.x`), broadcast/multicast (`>= 224`), zero address (`0.0.0.0`), ASN.1 OIDs (e.g. `1.3.6.1.5.5...`), and version strings ending in `.0.0` (e.g. `6.0.0.0`).
- **Dynamic DNS, C2 Staging & Webhook Domains**:
  - `\b(?:[a-zA-Z0-9.-]+\.)?(?:duckdns\.org|no-ip\.|ddns\.net|ngrok\.io|pastebin\.com|hastebin\.com|discord\.com/api|telegram\.org|raw\.githubusercontent\.com)\b`
- **HTTP Request Headers & Methods**:
  - `\b(?:POST\s+/[^\s]*\s+HTTP/1\.[01]|GET\s+/[^\s]*\s+HTTP/1\.[01]|User-Agent:\s+[^\s]+|Host:\s+[^\s]+)\b`
- **Explicitly Excluded**:
  - Bare words: `socket`, `connect`, `send`, `recv`, `listen`, `WSAStartup`, `InternetOpen` (diverted to `api_names`).

---

### Category C: `commands`
**Purpose**: Actionable shell execution lines, evasion commands, and administrative process invocation.

- **Shell Interpreters with Execution Switches**:
  - `\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\s+-[a-zA-Z]+`
  - `\bcmd(?:\.exe)?\s+/[a-zA-Z]+`
  - `/(?:usr/)?bin/(?:bash|sh|zsh)\s+-[a-zA-Z]+`
- **Execution & In-Memory Download Primitives**:
  - `\b(?:-encodedcommand|-enc)\s+[a-zA-Z0-9+/=]+`
  - `\b-windowstyle\s+hidden\b`
  - `\b-executionpolicy\s+bypass\b`
  - `\b(?:downloadstring|downloaddata)\s*\(`
  - `\b(?:invoke-expression|iex)\s+`
- **Administrative Utilities with Actionable Arguments**:
  - `\bchmod\s+(?:[+-][rwxXst]+|[0-7]{3,4})\b` (e.g. `chmod +x`, `chmod 777`)
  - `\bchown\s+[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+\b`
  - `\bnet\s+(?:user|localgroup|group)\s+[a-zA-Z0-9_-]+`
  - `\bvssadmin\s+delete\s+shadows\b`
  - `\bwbadmin\s+delete\s+catalog\b`
  - `\bbcdedit(?:\.exe)?\s+/set\b`
  - `\bschtasks(?:\.exe)?\s+/(?:create|run|delete)\b`
  - `\bsc(?:\.exe)?\s+(?:create|config|start)\s+[a-zA-Z0-9_-]+`
  - `\bsystemctl\s+(?:start|stop|restart|enable|disable)\s+[a-zA-Z0-9_-]+`
- **Explicitly Excluded**:
  - Bare binary or command names without parameters (`chmod`, `whoami`, `netstat`, `curl`, `wget`, `crontab`).

---

### Category C: `file_paths`
**Purpose**: Explicit filesystem references and sensitive configuration paths.

- **Windows Absolute & Drive Paths**:
  - `\b[a-zA-Z]:\\(?:[a-zA-Z0-9_.\- ]+\\)+[a-zA-Z0-9_.\- ]+`
  - `\\\\\.\\(?:pipe\\[a-zA-Z0-9_-]+|[a-zA-Z0-9_-]+)`
  - `\\\\\\?\\(?:[a-zA-Z]:\\|[a-zA-Z0-9_-]+)`
- **Windows Environment Variable Paths**:
  - `%(?:TEMP|APPDATA|LOCALAPPDATA|SYSTEMROOT|WINDIR|PROGRAMFILES)%\\[a-zA-Z0-9_.\-\\ ]+`
- **Unix Absolute System Directories**:
  - `/(?:etc|tmp|var|proc|sys|dev|usr|opt|root|home)/[a-zA-Z0-9_.\-/]+`
- **Sensitive Identity & Credential Files**:
  - `/(?:etc/)?(?:passwd|shadow|sudoers)`
  - `/\.ssh/(?:authorized_keys|id_rsa|id_ed25519)`
  - `\\System32\\config\\(?:SAM|SYSTEM)`
  - `\\NTDS\\ntds\.dit`
- **Explicitly Excluded**:
  - Bare filenames without path separators (`passwd`, `shadow`, `id_rsa`).

---

### Category D: `registry`
**Purpose**: Windows Registry keys, hive roots, and persistence locations.

- **Hive Abbreviations with Subkeys**:
  - `\b(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[a-zA-Z0-9_.\\]+`
- **Full Hive Names**:
  - `\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[a-zA-Z0-9_.\\]+`
- **Standard Software & Persistence Keys**:
  - `\bSoftware\\Microsoft\\[a-zA-Z0-9_.\\]+`
  - `\bSystem\\CurrentControlSet\\[a-zA-Z0-9_.\\]+`
  - `\bSoftware\\Classes\\[a-zA-Z0-9_.\\]+`

---

### Category E: `api_names`
**Purpose**: System, networking, and library function identifiers extracted from parsed symbol tables or raw strings.

- **Network & Socket Functions**:
  - `WSAStartup`, `getaddrinfo`, `socket`, `connect`, `send`, `recv`, `bind`, `listen`, `accept`, `InternetOpenA`, `InternetOpenW`, `HttpOpenRequestA`, `HttpOpenRequestW`, `URLDownloadToFileA`, `URLDownloadToFileW`.
- **Process & Execution Functions**:
  - `CreateProcessA`, `CreateProcessW`, `ShellExecuteA`, `ShellExecuteW`, `WinExec`, `execve`, `execvp`, `fork`, `popen`.
- **System & Library APIs**:
  - `chmod`, `chown`, `ptrace`, `memfd_create`, `VirtualAlloc`, `VirtualProtect`, `WriteProcessMemory`.

---

### Category F: `security_apis`
**Purpose**: Dedicated analyst bucket for high-consequence security APIs (process injection, defense evasion, credential dumping, ransomware).

- **Process Injection & Memory Manipulation**:
  - `VirtualAlloc`, `VirtualAllocEx`, `VirtualProtect`, `VirtualProtectEx`, `WriteProcessMemory`, `ReadProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext`, `GetThreadContext`, `ptrace`, `process_vm_writev`, `memfd_create`.
- **Defense Evasion & Anti-Analysis**:
  - `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `OutputDebugString[AW]`, `NtQueryInformationProcess`, `NtSetInformationThread`, `timeGetTime`, `GetTickCount`, `QueryPerformanceCounter`, `amsi.dll`, `AmsiScanBuffer`, `EtwEventWrite`.
- **Credential Harvesting**:
  - `MiniDumpWriteDump`, `LsaRetrievePrivateData`, `SamIConnect`, `LogonUser[AW]`, `OpenProcessToken`, `AdjustTokenPrivileges`, `LookupPrivilegeValue[AW]`, `sekurlsa`, `mimikatz`.
- **Cryptographic & Ransomware Primitives**:
  - `CryptEncrypt`, `CryptDecrypt`, `BCryptEncrypt`, `BCryptDecrypt`, `CryptGenKey`, `CryptAcquireContext[AW]`.

---

## 3. Engine Limits & Resource Safeguards

| Parameter | Default Value | Rationale |
| :--- | :--- | :--- |
| `min_length` | 4 characters | Concordant with GNU Binutils default (`strings -n 4`). |
| `max_string_length` | 1,024 characters | Prevents memory inflation from long unformatted data blocks. |
| `max_strings_stored` | 2,000 strings | Guarantees static JSON response remains bounded (< 500 KB) for frontend responsiveness. |
| `max_scan_bytes` | 100 MB | Scans up to 100 MB in ~2.1s; protects workers from unbounded RAM usage on multi-gigabyte ISOs. |
| `truncation_reporting` | `is_truncated: bool` | Informs analyst if input exceeded storage cap (`strings_count` vs `stored_limit`). |

---

## 4. Known Encodings & Extraction Limitations

1. **UTF-16LE Latin-1 Plane Only**:
   - Matches GNU Binutils default behavior (`strings -a -e l -n 4`), scanning 2-byte units `(lo, 0x00)` where `0x20 <= lo <= 0x7E` and `\t`.
   - Characters outside Latin-1 (e.g. Cyrillic `U+0400`, CJK `U+4E00`) have non-zero high bytes and are not extracted by this pass.
2. **No UTF-16BE (Big-Endian)**:
   - Big-endian UTF-16 is rare in modern x86/ARM executables and is not currently scanned.
3. **No Multibyte UTF-8 Plane Scanning**:
   - UTF-8 runs with non-ASCII multibyte sequences (`0xC0..0xFF`) are not decoded as Unicode code points; only the ASCII subset is extracted.
4. **No Stack Strings or Emulated Strings**:
   - Strings assembled at runtime on the call stack via push/mov instructions are not extracted statically (requires symbolic execution or emulation tools like FLOSS).
5. **No XOR / Obfuscated Strings**:
   - XOR-encoded, RC4-encrypted, or Base64-obfuscated strings require decoding via OutPost's dedicated decoder layer (`backend/app/services/static/decoders/`).
