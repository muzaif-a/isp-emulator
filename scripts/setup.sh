#!/usr/bin/env bash
# scripts/setup.sh — Install all dependencies for the ISP Network emulator.
# Run once as root before the first `sudo python3 network/topology.py`.
#
# System packages (apt-get):
#   mininet, openvswitch-switch, wireguard, wireguard-tools,
#   iproute2, iptables, tcpdump, wireshark-common (mergecap), curl,
#   python3, python3-pip
#
# Python packages (pip):
#   see requirements.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== ISP Network Emulator — System Setup ==="
echo ""

# ── System package index ───────────────────────────────────────────────────────
echo "[*] Updating package index …"
apt-get update -qq

# ── Python runtime ─────────────────────────────────────────────────────────────
echo "[*] Installing Python 3 and pip …"
apt-get install -y python3 python3-pip

# ── Mininet ────────────────────────────────────────────────────────────────────
if ! command -v mn &>/dev/null; then
    echo "[+] Installing Mininet …"
    apt-get install -y mininet
else
    echo "[ok] Mininet already installed"
fi

# ── Open vSwitch — required by Mininet ─────────────────────────────────────────
echo "[*] Installing Open vSwitch …"
apt-get install -y openvswitch-switch openvswitch-common
systemctl start ovsdb-server ovs-vswitchd 2>/dev/null || true
echo "[ok] Open vSwitch"

# ── WireGuard VPN ──────────────────────────────────────────────────────────────
if ! command -v wg &>/dev/null; then
    echo "[+] Installing WireGuard …"
    apt-get install -y wireguard wireguard-tools
else
    echo "[ok] WireGuard already installed"
fi
modprobe wireguard 2>/dev/null && echo "[ok] wireguard kernel module loaded" \
    || echo "[warn] modprobe wireguard failed — may be built into kernel"

# ── Network utilities ──────────────────────────────────────────────────────────
echo "[*] Installing network utilities …"
apt-get install -y \
    iproute2 \
    iptables \
    iputils-ping \
    net-tools \
    tcpdump \
    wireshark-common \
    curl \
    dnsutils
echo "[ok] Network utilities"

# ── Traffic control ────────────────────────────────────────────────────────────
echo "[*] Installing traffic control tools …"
apt-get install -y iproute2
# tc is part of iproute2 — verify
command -v tc &>/dev/null && echo "[ok] tc (traffic control)" \
    || echo "[warn] tc not found — TC shaping will not work"

# ── iperf3 — required for NPC bulk behavior ────────────────────────────────────
if ! command -v iperf3 &>/dev/null; then
    echo "[+] Installing iperf3 …"
    apt-get install -y iperf3
else
    echo "[ok] iperf3 already installed"
fi

# ── Python packages via requirements.txt ──────────────────────────────────────
echo ""
echo "[*] Installing Python packages from requirements.txt …"
pip3 install --quiet --upgrade pip
pip3 install --quiet -r "$ROOT/requirements.txt"
echo "[ok] Python packages installed"

# ── Verify system binaries ─────────────────────────────────────────────────────
# Python packages verified implicitly by pip3 install success above.
# Only system binaries need explicit PATH checks.
echo ""
echo "=== Verification ==="

command -v mn       &>/dev/null && echo "[ok] mn       (mininet)" \
    || echo "[FAIL] mn not found — mininet install may have failed"
command -v wg       &>/dev/null && echo "[ok] wg       (wireguard-tools)" \
    || echo "[FAIL] wg not found — wireguard-tools install may have failed"
command -v tc       &>/dev/null && echo "[ok] tc       (iproute2)" \
    || echo "[FAIL] tc not found — iproute2 install may have failed"
command -v iperf3   &>/dev/null && echo "[ok] iperf3   (NPC bulk behavior)" \
    || echo "[FAIL] iperf3 not found"
command -v dig      &>/dev/null && echo "[ok] dig      (NPC dns behavior)" \
    || echo "[FAIL] dig not found — dnsutils install may have failed"
command -v mergecap &>/dev/null && echo "[ok] mergecap (PCAPNG merge)" \
    || echo "[warn] mergecap not found — merge falls back to scapy (slower)"

echo ""
echo "=== Setup complete ==="
echo "Run: sudo mn -c && sudo python3 network/topology.py configs/topology_enterprise.yaml --cli"
