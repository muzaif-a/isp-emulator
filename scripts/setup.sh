#!/usr/bin/env bash
# setup.sh — Install all Ubuntu dependencies for the ISP Network emulator.
# Run once as root before the first `sudo python3 topology.py`.

set -euo pipefail

echo "=== ISP Network emulator — System Setup ==="

# ---- package updates ----
apt-get update -qq

# ---- Mininet ----
if ! command -v mn &>/dev/null; then
    echo "[+] Installing Mininet …"
    apt-get install -y mininet
else
    echo "[ok] Mininet already installed"
fi

# ---- Open vSwitch (required by Mininet) ----
apt-get install -y openvswitch-switch
systemctl start ovsdb-server ovs-vswitchd || true

# ---- WireGuard ----
if ! command -v wg &>/dev/null; then
    echo "[+] Installing WireGuard …"
    apt-get install -y wireguard wireguard-tools
else
    echo "[ok] WireGuard already installed"
fi

# Load WireGuard kernel module
modprobe wireguard && echo "[ok] wireguard module loaded" || echo "[warn] modprobe wireguard failed — may already be built-in"

# ---- Python deps ----
echo "[+] Installing Python packages …"
pip3 install --quiet -r requirements.txt

# ---- Verify ----
echo ""
echo "=== Verification ==="
python3 -c "import mininet; print('[ok] mininet', mininet.VERSION)"
python3 -c "import yaml; print('[ok] PyYAML', yaml.__version__)"
python3 -c "import networkx; print('[ok] networkx', networkx.__version__)"
python3 -c "import pytest; print('[ok] pytest')"
command -v wg && echo "[ok] wg $(wg --version)"
echo ""
echo "=== Setup complete. Run: sudo bash run.sh ==="
