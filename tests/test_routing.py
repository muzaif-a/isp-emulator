"""Integration tests for the routing engine.

Requires Mininet + root.  Run with: sudo pytest tests/test_routing.py -v
"""

import os
import sys
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
    topo.start(enable_vpn=False, enable_cli=False)
    yield topo
    topo.stop()


class TestRoutingEngine:

    def test_r1_has_route_to_lan2(self, running_topo):
        """r1 must have a route toward r3's LAN subnet."""
        alloc = running_topo.allocation
        r3_lan = str(alloc.lan_subnets["r3"])
        route_table = running_topo.net["r1"].cmd("ip route show")
        assert r3_lan in route_table, (
            f"r1 missing route to {r3_lan}:\n{route_table}"
        )

    def test_r3_has_route_to_lan1(self, running_topo):
        """r3 must have a route toward r1's LAN subnet."""
        alloc = running_topo.allocation
        r1_lan = str(alloc.lan_subnets["r1"])
        route_table = running_topo.net["r3"].cmd("ip route show")
        assert r1_lan in route_table, (
            f"r3 missing route to {r1_lan}:\n{route_table}"
        )

    def test_h1_default_route(self, running_topo):
        """h1's default route must point to r1's LAN IP."""
        alloc = running_topo.allocation
        r1_gw = alloc.get_lan_gw_ip("r1")
        route_table = running_topo.net["h1"].cmd("ip route show default")
        assert r1_gw in route_table, (
            f"h1 default route missing r1 ({r1_gw}):\n{route_table}"
        )

    def test_h3_default_route(self, running_topo):
        """h3's default route must point to r3's LAN IP."""
        alloc = running_topo.allocation
        r3_gw = alloc.get_lan_gw_ip("r3")
        route_table = running_topo.net["h3"].cmd("ip route show default")
        assert r3_gw in route_table, (
            f"h3 default route missing r3 ({r3_gw}):\n{route_table}"
        )

    def test_h2_has_routes_to_all_lans(self, running_topo):
        """h2 (VPN gateway) must have routes to both LAN subnets."""
        alloc = running_topo.allocation
        route_table = running_topo.net["h2"].cmd("ip route show")
        for gw_name, subnet in alloc.lan_subnets.items():
            assert str(subnet) in route_table, (
                f"h2 missing route to {gw_name} LAN {subnet}:\n{route_table}"
            )

    def test_no_blackhole_routes(self, running_topo):
        """No node should have a blackhole or unreachable route."""
        for node_cfg in running_topo.config.nodes:
            if node_cfg.is_switch():
                continue
            node = running_topo.net[node_cfg.name]
            table = node.cmd("ip route show")
            assert "blackhole" not in table, f"{node_cfg.name} has blackhole route"
            assert "unreachable" not in table, f"{node_cfg.name} has unreachable route"
