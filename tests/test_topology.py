"""Integration tests for topology build + routing.

These tests require Mininet and MUST be run with:
    sudo pytest tests/test_topology.py -v

They start a real Mininet instance, so they take ~30–60 seconds.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Guard: skip entire module if not running as root or Mininet unavailable
if os.geteuid() != 0:
    pytest.skip("Mininet tests require root (sudo)", allow_module_level=True)

try:
    from mininet.net import Mininet
except ImportError:
    pytest.skip("Mininet not installed", allow_module_level=True)

from config_loader import load_config
from network.ip_allocator import allocate
from network.topology import ISPTopology

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "configs", "topology.yaml")


@pytest.fixture(scope="module")
def running_topo():
    """Start topology once for all tests in this module."""
    topo = ISPTopology(CONFIG_PATH)
    topo.start(enable_vpn=False, enable_cli=False)
    yield topo
    topo.stop()


# ------------------------------------------------------------------ topology tests

class TestTopologyBuild:

    def test_all_nodes_created(self, running_topo):
        config = running_topo.config
        net = running_topo.net
        for node_cfg in config.nodes:
            assert node_cfg.name in net, f"Node {node_cfg.name} missing from Mininet"

    def test_interface_count_matches_links(self, running_topo):
        """Each node's interface count must equal number of links it participates in."""
        config = running_topo.config
        net = running_topo.net
        link_count = {n.name: 0 for n in config.nodes}
        for a, b in config.links:
            link_count[a] += 1
            link_count[b] += 1

        for node_cfg in config.nodes:
            if node_cfg.is_switch():
                continue  # switches use OVS ports, not eth ifaces
            node = net[node_cfg.name]
            intfs = [i for i in node.intfNames() if i != "lo"]
            # Node may have more if wg0 was added, but at minimum link_count ifaces
            assert len(intfs) >= link_count[node_cfg.name], (
                f"{node_cfg.name}: expected >= {link_count[node_cfg.name]} ifaces, got {intfs}"
            )

    def test_ips_assigned_correctly(self, running_topo):
        allocation = running_topo.allocation
        net = running_topo.net
        for node_name, ifaces in allocation.node_interfaces.items():
            node = net[node_name]
            for iface, (expected_ip, prefix) in ifaces.items():
                out = node.cmd(f"ip addr show {iface} 2>/dev/null")
                assert expected_ip in out, (
                    f"{node_name}/{iface}: expected {expected_ip}, got:\n{out}"
                )

    def test_default_gateways(self, running_topo):
        allocation = running_topo.allocation
        net = running_topo.net
        for node_name, gw_ip in allocation.default_gateways.items():
            node = net[node_name]
            route_table = node.cmd("ip route show default")
            assert gw_ip in route_table, (
                f"{node_name}: default gateway {gw_ip} not in route table:\n{route_table}"
            )


# ------------------------------------------------------------------ connectivity tests

class TestConnectivity:

    def test_intra_lan_h1_r1(self, running_topo):
        """h1 must reach r1 (its LAN gateway)."""
        allocation = running_topo.allocation
        r1_gw_ip = allocation.get_lan_gw_ip("r1")
        assert running_topo.ping("h1", r1_gw_ip), f"h1 cannot ping r1 at {r1_gw_ip}"

    def test_intra_lan_h3_r3(self, running_topo):
        """h3 must reach r3 (its LAN gateway)."""
        allocation = running_topo.allocation
        r3_gw_ip = allocation.get_lan_gw_ip("r3")
        assert running_topo.ping("h3", r3_gw_ip), f"h3 cannot ping r3 at {r3_gw_ip}"

    def test_isp_r1_to_r3(self, running_topo):
        """r1 must reach r3 across the ISP switch."""
        allocation = running_topo.allocation
        r3_isp_ip = allocation.get_isp_ip("r3")
        assert running_topo.ping("r1", r3_isp_ip), f"r1 cannot ping r3 at {r3_isp_ip}"

    def test_cross_lan_h1_to_h3(self, running_topo):
        """h1 must reach h3 across two LANs (requires forwarding on r1, r3)."""
        allocation = running_topo.allocation
        h3_ifaces = allocation.node_interfaces.get("h3", {})
        h3_ips = [ip for ip, _ in h3_ifaces.values() if ip.startswith("192.168.")]
        assert h3_ips, "h3 has no LAN IP in allocation"
        assert running_topo.ping("h1", h3_ips[0]), f"h1 cannot ping h3 at {h3_ips[0]}"

    def test_cross_lan_h3_to_h1(self, running_topo):
        """h3 must reach h1 (reverse path)."""
        allocation = running_topo.allocation
        h1_ifaces = allocation.node_interfaces.get("h1", {})
        h1_ips = [ip for ip, _ in h1_ifaces.values() if ip.startswith("192.168.")]
        assert h1_ips, "h1 has no LAN IP"
        assert running_topo.ping("h3", h1_ips[0]), f"h3 cannot ping h1 at {h1_ips[0]}"

    def test_ip_forwarding_r1(self, running_topo):
        node = running_topo.net["r1"]
        val = node.cmd("cat /proc/sys/net/ipv4/ip_forward").strip()
        assert val == "1", f"r1 ip_forward={val}"

    def test_ip_forwarding_r3(self, running_topo):
        node = running_topo.net["r3"]
        val = node.cmd("cat /proc/sys/net/ipv4/ip_forward").strip()
        assert val == "1", f"r3 ip_forward={val}"

    def test_traceroute_h1_to_h3(self, running_topo):
        """Traceroute from h1 to h3 should pass through r1 and r3."""
        allocation = running_topo.allocation
        h3_ifaces = allocation.node_interfaces.get("h3", {})
        h3_ips = [ip for ip, _ in h3_ifaces.values() if ip.startswith("192.168.")]
        if not h3_ips:
            pytest.skip("h3 has no LAN IP")
        tr = running_topo.traceroute("h1", h3_ips[0])
        r1_gw = allocation.get_lan_gw_ip("r1")
        assert r1_gw in tr, f"r1 LAN IP {r1_gw} not in traceroute:\n{tr}"
