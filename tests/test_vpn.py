"""Integration tests for WireGuard VPN deployment.

Requires Mininet + WireGuard + root.
Run with: sudo pytest tests/test_vpn.py -v
"""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

if os.geteuid() != 0:
    pytest.skip("Mininet tests require root (sudo)", allow_module_level=True)

try:
    from mininet.net import Mininet
except ImportError:
    pytest.skip("Mininet not installed", allow_module_level=True)

from network.topology import ISPTopology

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "configs", "topology.yaml")


@pytest.fixture(scope="module")
def running_topo():
    topo = ISPTopology(CONFIG_PATH)
    topo.start(enable_vpn=True, enable_cli=False)
    yield topo
    topo.stop()


class TestWireGuardInterfaces:

    def test_gateway_wg_interface_exists(self, running_topo):
        """VPN gateway (h2) must have wg0 interface."""
        node = running_topo.net["h2"]
        out = node.cmd("ip link show wg0 2>/dev/null")
        assert "wg0" in out, f"h2 missing wg0:\n{out}"

    def test_client_r1_wg_interface_exists(self, running_topo):
        node = running_topo.net["r1"]
        out = node.cmd("ip link show wg0 2>/dev/null")
        assert "wg0" in out, f"r1 missing wg0:\n{out}"

    def test_client_r3_wg_interface_exists(self, running_topo):
        node = running_topo.net["r3"]
        out = node.cmd("ip link show wg0 2>/dev/null")
        assert "wg0" in out, f"r3 missing wg0:\n{out}"

    def test_gateway_vpn_ip(self, running_topo):
        alloc = running_topo.allocation
        h2_vpn = alloc.get_vpn_ip("h2")
        node = running_topo.net["h2"]
        out = node.cmd("ip addr show wg0 2>/dev/null")
        assert h2_vpn in out, f"h2 wg0 missing VPN IP {h2_vpn}:\n{out}"

    def test_clients_have_vpn_ips(self, running_topo):
        alloc = running_topo.allocation
        for client in ("r1", "r3"):
            vpn_ip = alloc.get_vpn_ip(client)
            node = running_topo.net[client]
            out = node.cmd("ip addr show wg0 2>/dev/null")
            assert vpn_ip in out, f"{client} wg0 missing VPN IP {vpn_ip}:\n{out}"

    def test_wg_interfaces_are_up(self, running_topo):
        for name in ("h2", "r1", "r3"):
            node = running_topo.net[name]
            out = node.cmd("ip link show wg0 2>/dev/null")
            # WireGuard shows as UNKNOWN (valid) when no data has been sent
            assert "UP" in out or "UNKNOWN" in out, (
                f"{name} wg0 not UP:\n{out}"
            )

    def test_wg_peers_configured(self, running_topo):
        """wg show must list at least one peer on gateway and each client."""
        for name in ("h2", "r1", "r3"):
            node = running_topo.net[name]
            out = node.cmd("wg show wg0 peers 2>/dev/null")
            assert out.strip(), f"{name} wg0 has no peers configured"


class TestVPNConnectivity:

    def test_client_r1_pings_gateway(self, running_topo):
        alloc = running_topo.allocation
        h2_vpn = alloc.get_vpn_ip("h2")
        r1 = running_topo.net["r1"]
        out = r1.cmd(f"ping -c 3 -W 3 {h2_vpn} 2>&1")
        assert "0% packet loss" in out or "3 received" in out, (
            f"r1 cannot ping h2 VPN {h2_vpn}:\n{out}"
        )

    def test_client_r3_pings_gateway(self, running_topo):
        alloc = running_topo.allocation
        h2_vpn = alloc.get_vpn_ip("h2")
        r3 = running_topo.net["r3"]
        out = r3.cmd(f"ping -c 3 -W 3 {h2_vpn} 2>&1")
        assert "0% packet loss" in out or "3 received" in out, (
            f"r3 cannot ping h2 VPN {h2_vpn}:\n{out}"
        )

    def test_r1_to_r3_via_vpn(self, running_topo):
        """r1 reaches r3's VPN IP through the encrypted hub-and-spoke tunnel."""
        alloc = running_topo.allocation
        r3_vpn = alloc.get_vpn_ip("r3")
        r1 = running_topo.net["r1"]
        out = r1.cmd(f"ping -c 3 -W 5 {r3_vpn} 2>&1")
        assert "0% packet loss" in out or "3 received" in out, (
            f"r1 cannot reach r3 VPN {r3_vpn}:\n{out}"
        )

    def test_h1_to_h3_via_vpn_path(self, running_topo):
        """h1 (behind r1) can reach h3 (behind r3) through VPN-encrypted path."""
        alloc = running_topo.allocation
        h3_ifaces = alloc.node_interfaces.get("h3", {})
        h3_ips = [ip for ip, _ in h3_ifaces.values() if ip.startswith("192.168.")]
        if not h3_ips:
            pytest.skip("h3 has no LAN IP")
        h1 = running_topo.net["h1"]
        out = h1.cmd(f"ping -c 3 -W 5 {h3_ips[0]} 2>&1")
        assert "0% packet loss" in out or "3 received" in out, (
            f"h1 cannot reach h3 at {h3_ips[0]} via VPN path:\n{out}"
        )

    def test_wg_handshake_completed(self, running_topo):
        """latest-handshakes must be non-zero for all peers on gateway."""
        h2 = running_topo.net["h2"]
        # Trigger traffic to ensure handshakes
        alloc = running_topo.allocation
        for client in ("r1", "r3"):
            vpn_ip = alloc.get_vpn_ip(client)
            h2.cmd(f"ping -c 1 -W 2 {vpn_ip} > /dev/null 2>&1")

        time.sleep(2)
        out = h2.cmd("wg show wg0 latest-handshakes 2>/dev/null")
        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                ts = int(parts[1])
                assert ts > 0, f"Handshake not completed for peer {parts[0]}"
