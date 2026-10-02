#!/usr/bin/env bash
# ==============================================================================
# OutPost: Tier 3 Disposable QEMU Windows MicroVM Setup & Launcher
# ==============================================================================
# Sets up and executes a disposable Windows 10/11 guest sandbox for malware detonation.
# Operates in strict `-snapshot` mode: all filesystem mutations, registry changes,
# and dropped artifacts are discarded when the QEMU instance terminates.
#
# Telemetry is collected by `scripts/guest_agent/outpost_guest_agent.py` running
# inside the guest on forwarded port 8009.
# ==============================================================================

set -euo pipefail

IMAGE_DIR="${OUTPOST_VM_DIR:-$HOME/.outpost/vms}"
IMAGE_FILE="${IMAGE_DIR}/windows10_base.qcow2"
PORT_FORWARD="${OUTPOST_GUEST_PORT:-8009}"
RAM_MB="${OUTPOST_VM_RAM:-4096}"
CORES="${OUTPOST_VM_CORES:-2}"

echo "=========================================================="
echo " OutPost Tier 3: Disposable MicroVM Detonation Launcher"
echo "=========================================================="

command -v qemu-system-x86_64 >/dev/null 2>&1 || {
  echo "[-] Error: qemu-system-x86_64 is not installed."
  echo "    Install with: sudo apt-get install qemu-system-x86 qemu-kvm (Debian/Ubuntu)"
  echo "    Or:           sudo pacman -S qemu-desktop (Arch)"
  exit 1
}

if [[ ! -f "$IMAGE_FILE" ]]; then
  echo "[-] Base image not found at: $IMAGE_FILE"
  echo "[*] Creating placeholder VM directory at: $IMAGE_DIR"
  mkdir -p "$IMAGE_DIR"
  cat << 'EOF'

To complete Tier 3 Windows MicroVM setup:
1. Place a sysprepped Windows 10/11 qcow2 image with Sysmon installed at:
   ~/.outpost/vms/windows10_base.qcow2

2. In the guest VM, configure `scripts/guest_agent/outpost_guest_agent.py` to start on boot:
   python outpost_guest_agent.py

3. Configure OutPost environment:
   export OUTPOST_GUEST_VM_URL="http://127.0.0.1:8009"

EOF
  exit 1
fi

KVM_FLAG=""
if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
  echo "[+] Hardware acceleration (/dev/kvm) detected. Enabling KVM."
  KVM_FLAG="-enable-kvm -cpu host"
else
  echo "[!] Warning: /dev/kvm not accessible. Falling back to TCG emulation."
  KVM_FLAG="-cpu qemu64"
fi

echo "[*] Launching disposable Windows MicroVM in SNAPSHOT mode..."
echo "[*] Forwarding Host 127.0.0.1:${PORT_FORWARD} -> Guest 8009"
echo "[*] All in-guest writes will be discarded on termination."

# Run QEMU in headless or display mode with snapshot isolation
qemu-system-x86_64 \
  $KVM_FLAG \
  -m "${RAM_MB}" \
  -smp "${CORES}" \
  -drive file="${IMAGE_FILE}",format=qcow2,if=virtio,snapshot=on \
  -net nic,model=virtio \
  -net user,hostfwd=tcp:127.0.0.1:${PORT_FORWARD}-:8009 \
  -nographic \
  -daemonize

echo "[+] Guest VM started in background. Waiting for agent readiness on port ${PORT_FORWARD}..."

for i in {1..30}; do
  if curl -s "http://127.0.0.1:${PORT_FORWARD}/health" >/dev/null 2>&1; then
    echo "[+] OutPost Guest Agent is READY at http://127.0.0.1:${PORT_FORWARD}"
    echo "    Export environment to enable Tier 3 in OutPost:"
    echo "    export OUTPOST_GUEST_VM_URL=\"http://127.0.0.1:${PORT_FORWARD}\""
    exit 0
  fi
  sleep 1
done

echo "[!] Timed out waiting for guest agent response. Check guest boot status."
exit 2
