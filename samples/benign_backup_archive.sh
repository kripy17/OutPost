#!/usr/bin/env bash
# OutPost Benign Sample — Sysadmin Backup & Maintenance Utility
#
# A legitimate, non-malicious shell script used by sysadmins to package
# application logs and generate MD5 checksums for integrity verification.
# Exercises:
#   1. Creating an isolated safe staging directory
#   2. Writing harmless maintenance log lines
#   3. Packaging via standard tar and gzip
#   4. Calculating checksums without deleting system files or masquerading
#
# Detonation Outcome:
#   - Exit Code: 0 (Success)
#   - Behavioral Risk Score: 0/100 (Clean)
#   - Detection Alerts: 0 (No false positives)
#   - Verdict: BENIGN / CLEAN
set -euo pipefail

echo "================================================================="
echo "  OutPost Benign Verification Suite: Sysadmin Backup Utility     "
echo "  Purpose: Legitimate Archive Packaging & Integrity Check        "
echo "================================================================="

STAGING_DIR="$(mktemp -d -t outpost_benign_backup_XXXXXX)"
ARCHIVE_OUT="${STAGING_DIR}/service_audit_backup.tar.gz"

echo "[*] Initializing benign backup workspace in ${STAGING_DIR}..."

# Generate benign configuration and activity log files
cat << 'EOF' > "${STAGING_DIR}/service_config.json"
{
  "service": "api-gateway",
  "environment": "production",
  "retention_days": 30,
  "backup_status": "authorized"
}
EOF

cat << 'EOF' > "${STAGING_DIR}/activity_summary.log"
2026-09-24T00:00:01Z [INFO] Routine log rotation started.
2026-09-24T00:05:00Z [INFO] Database connection pool healthy: 12 active workers.
2026-09-24T00:10:00Z [INFO] Telemetry export processed 1,024 records.
2026-09-24T00:15:00Z [INFO] Routine backup checkpoint reached.
EOF

echo "[*] Packaging archive with tar -czf..."
tar -czf "${ARCHIVE_OUT}" -C "${STAGING_DIR}" service_config.json activity_summary.log

if command -v md5sum >/dev/null 2>&1; then
    CHECKSUM=$(md5sum "${ARCHIVE_OUT}" | awk '{print $1}')
    echo "[*] Archive SHA/MD5 verification: ${CHECKSUM}"
fi

ARCHIVE_SIZE=$(wc -c < "${ARCHIVE_OUT}")
echo "[✓] Backup archive created successfully (${ARCHIVE_SIZE} bytes)."
echo "[✓] Benign operation completed cleanly. No persistence or privilege escalation attempted."

# Cleanup temporary staging artifacts safely
rm -rf "${STAGING_DIR}"
exit 0
