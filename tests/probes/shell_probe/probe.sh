#!/bin/bash
# OutPost Behavioral Probe - Shell Script Ground Truth Sample
#
# Designed exclusively for isolated sandbox baseline tracing and parser validation.
# Performs deterministic, harmless actions:
#   1. Writes to file "probe_shell.tmp"
#   2. Chmods "probe_shell.tmp" to 0600
#   3. Renames "probe_shell.tmp" -> "probe_shell_renamed.tmp"
#   4. Deletes "probe_shell_renamed.tmp"
#   5. Spawns child process via subshell / /bin/sh
#   6. Attempts DNS lookup for non-existent domain "probe-sh.test.invalid"
#   7. Attempts TCP connection to TEST-NET-1 IP 192.0.2.1:80 (RFC 5737)
#   8. Exits cleanly with status 0

echo "=== OutPost Shell Probe Starting ==="

# 1. File write
echo "OutPost shell probe payload data" > probe_shell.tmp

# 2. File chmod
chmod 0600 probe_shell.tmp

# 3. File rename
mv probe_shell.tmp probe_shell_renamed.tmp

# 4. File delete
rm -f probe_shell_renamed.tmp

# 5. Process spawn via subshell / external sh command
/bin/sh -c 'echo "--- Shell Probe Child Process Executing ---"; exit 0'

# 6. DNS lookup attempt (expected to fail in airgap/isolated sandbox)
getent ahosts probe-sh.test.invalid >/dev/null 2>&1 || true

# 7. TCP socket connect attempt (TEST-NET-1, RFC 5737)
timeout 1 bash -c 'echo > /dev/tcp/192.0.2.1/80' >/dev/null 2>&1 || true

echo "=== OutPost Shell Probe Exiting ==="
exit 0
