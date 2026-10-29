# OutPost CLI & Terminal Analyst Workbench

The **OutPost CLI** (`outpost`) is an offline-capable command-line interface and interactive Terminal User Interface (TUI) for malware analysts and incident responders. It provides native command-line access to static binary analysis, RAT configuration decoders, bubblewrap detonation, Sigma rule validation, and YARA hunting.

---

## Installation

The OutPost CLI can be executed directly via the root `./cli.sh` helper, or installed into your active Python environment:

```bash
# Using the wrapper script from repo root
./cli.sh --help

# Or install editable in Python environment
pip install -e ./cli
outpost --help
```

---

## Core Command Reference

### 1. Static Malware Analysis & Dossier
```bash
# Perform deep offline static analysis on a binary or archive
outpost scan ./malware_sample.exe

# Extract strings with minimum length and filter options
outpost scan ./sample.bin --strings --min-len 8

# Output analysis dossier in structured JSON
outpost scan ./sample.bin --json
```

### 2. Configuration Extraction & Decoders
```bash
# Attempt automated extraction and decryption of RAT configs
# Supported: Remcos RAT, AsyncRAT, RedLine Stealer, Cobalt Strike
outpost decode ./suspect_remcos.exe

# Decode with verbose cryptographic key logs
outpost decode ./suspect_asyncrat.exe --verbose
```

### 3. Dynamic Detonation & Syscall Auditing
```bash
# Detonate binary in the isolated bubblewrap sandbox with strace
outpost detonate ./malicious_script.sh --timeout 30

# Inspect run dossier and process tree of a prior detonation
outpost run show dyn_db3a8da614ef
```

### 4. Detection Rules & ATT&CK Hunting
```bash
# List all active Sigma and behavioral detection rules
outpost rules list

# Validate and transpile a Sigma rule file
outpost rules validate ./custom_rule.yml

# Hunt across local binaries with YARA
outpost yara scan ./rules/hunting.yar /path/to/samples/
```

### 5. Threat Watchlist & IOC Search
```bash
# Search for an IP, domain, or SHA256 hash across the vault
outpost search 89.208.107.165

# Pin a critical indicator to the watchlist
outpost watchlist add ip 89.208.107.165 --description "Remcos C2 node"

# View active watchlists
outpost watchlist list
```

### 6. Interactive Terminal Cockpit (TUI)
```bash
# Launch interactive keyboard-driven terminal dashboard
outpost tui
```
