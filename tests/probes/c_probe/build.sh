#!/usr/bin/env bash
# Build script for OutPost C Probe ELF
# Generates deterministic, reproducible ELF binary.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

gcc -O2 -fno-ident -Wl,--build-id=none -o probe_elf main.c

echo "Build complete: $(pwd)/probe_elf"
sha256sum probe_elf
