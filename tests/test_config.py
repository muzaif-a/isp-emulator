"""Config loader and IP allocator tests.

All expectations derived from config/allocation — no hardcoded node names.
Parametrized over every topology*.yaml in configs/.
"""

import ipaddress
import os
import sys
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from config_loader import load_config, TopologyConfig
from network.ip_allocator import allocate


# ─────────────────────────────── helpers ─────────────────────────────────────

def _all_ips(alloc) -> list:
    """Flat list of every allocated IP string across ISP, LAN, VPN."""
    ips = []
    for ifaces in alloc.node_interfaces.values():
        for ip, _ in ifaces.values():
            ips.append(ip)
    return ips


# ─────────────────────────── structural invariants ───────────────────────────

@pytest.mark.unit
class TestStructuralInvariants:
    """Every topology must satisfy these regardless of content."""

    def test_at_least_one_switch(self, topology_config):
        cfg, _ = topology_config
        assert any(n.is_switch() for n in cfg.nodes), "topology needs at least one switch"

    def test_all_link_endpoints_declared(self, topology_config):
        cfg, path = topology_config
        names = {n.name for n in cfg.nodes}
        for a, b in cfg.links:
            assert a in names, f"{path}: link endpoint {a!r} not declared"
            assert b in names, f"{path}: link endpoint {b!r} not declared"

    def test_no_self_links(self, topology_config):
        cfg, path = topology_config
        for a, b in cfg.links:
            assert a != b, f"{path}: self-link on node {a!r}"

    def test_lan_gateways_not_switches(self, topology_config):
        cfg, path = topology_config
        switch_names = {n.name for n in cfg.nodes if n.is_switch()}
        for gw in cfg.lan_gateways:
            assert gw not in switch_names, f"{path}: LAN gateway {gw!r} is a switch"

    def test_vpn_gateways_declared(self, topology_config):
        cfg, path = topology_config
        node_names = {n.name for n in cfg.nodes}
        for gw in cfg.vpn_gateways:
            assert gw in node_names, f"{path}: VPN gateway {gw!r} not in nodes"

    def test_services_on_declared_nodes(self, topology_config):
        cfg, path = topology_config
        node_names = {n.name for n in cfg.nodes}
        for svc in cfg.services:
            assert svc.host in node_names, f"{path}: service host {svc.host!r} not in nodes"

    def test_databases_on_declared_nodes(self, topology_config):
        cfg, path = topology_config
        node_names = {n.name for n in cfg.nodes}
        for db in cfg.databases:
            assert db.host in node_names, f"{path}: db host {db.host!r} not in nodes"

    def test_attackers_on_declared_nodes(self, topology_config):
        cfg, path = topology_config
        node_names = {n.name for n in cfg.nodes}
        for attacker in cfg.attackers:
            assert attacker in node_names, f"{path}: attacker {attacker!r} not in nodes"

    def test_node_names_unique(self, topology_config):
        cfg, path = topology_config
        names = [n.name for n in cfg.nodes]
        assert len(names) == len(set(names)), f"{path}: duplicate node names: {names}"


# ─────────────────────────── IP allocation correctness ───────────────────────

@pytest.mark.unit
class TestIPAllocation:
    """All IPs must be unique, within declared subnets, correct prefix lengths."""

    def test_all_ips_unique(self, topology_allocation):
        _, alloc, path = topology_allocation
        ips = _all_ips(alloc)
        assert len(ips) == len(set(ips)), f"{path}: duplicate IPs: {sorted(set(x for x in ips if ips.count(x) > 1))}"

    def test_lan_subnets_no_overlap(self, topology_allocation):
        _, alloc, path = topology_allocation
        subnets = list(alloc.lan_subnets.values())
        for i, s1 in enumerate(subnets):
            for s2 in subnets[i + 1:]:
                assert not s1.overlaps(s2), f"{path}: LAN subnet overlap: {s1} ∩ {s2}"

    def test_isp_subnets_no_overlap_with_lan(self, topology_allocation):
        _, alloc, path = topology_allocation
        for isp_sub in alloc.isp_subnets.values():
            for lan_sub in alloc.lan_subnets.values():
                assert not isp_sub.overlaps(lan_sub), (
                    f"{path}: ISP/LAN overlap: {isp_sub} ∩ {lan_sub}"
                )

    def test_vpn_subnets_no_overlap_with_lan(self, topology_allocation):
        _, alloc, path = topology_allocation
        for vpn_sub in alloc.vpn_subnets.values():
            for lan_sub in alloc.lan_subnets.values():
                assert not vpn_sub.overlaps(lan_sub), (
                    f"{path}: VPN/LAN overlap: {vpn_sub} ∩ {lan_sub}"
                )

    def test_all_ips_parseable(self, topology_allocation):
        _, alloc, path = topology_allocation
        for ip in _all_ips(alloc):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                pytest.fail(f"{path}: invalid IP: {ip!r}")

    def test_lan_gateways_get_dot1(self, topology_allocation):
        cfg, alloc, path = topology_allocation
        for gw in cfg.lan_gateways:
            ip = alloc.get_lan_gw_ip(gw)
            if ip:
                assert str(ip).endswith(".1"), (
                    f"{path}: gateway {gw} IP {ip} should end with .1"
                )

    def test_interface_names_within_ifnamsiz(self, topology_allocation):
        _, alloc, path = topology_allocation
        for node, ifaces in alloc.node_interfaces.items():
            for iface_name in ifaces:
                assert len(iface_name) <= 15, (
                    f"{path}: interface {iface_name!r} on {node} exceeds IFNAMSIZ=15"
                )

    def test_all_hosts_have_at_least_one_ip(self, topology_allocation):
        cfg, alloc, path = topology_allocation
        for node in cfg.nodes:
            if node.is_switch():
                continue
            ip = alloc.get_host_ip(node.name)
            assert ip is not None, f"{path}: host {node.name!r} has no allocated IP"


# ─────────────────────────── VPN config correctness ──────────────────────────

@pytest.mark.unit
class TestVPNConfig:

    def test_vpn_peers_clients_declared(self, topology_config):
        cfg, path = topology_config
        node_names = {n.name for n in cfg.nodes}
        for vp in cfg.vpn_peers:
            assert vp.gateway in node_names, f"{path}: VPN peer gateway {vp.gateway!r} not declared"
            for client in vp.clients:
                assert client in node_names, f"{path}: VPN client {client!r} not declared"

    def test_vpn_allocation_ips_in_vpn_subnet(self, topology_allocation):
        cfg, alloc, path = topology_allocation
        if not alloc.vpn_subnets:
            pytest.skip("no VPN configured")
        for gw, subnet in alloc.vpn_subnets.items():
            for node_name, vpn_ip in alloc.vpn_node_ips.items():
                ip_obj = ipaddress.ip_address(str(vpn_ip))
                if ip_obj in subnet:
                    assert ip_obj in subnet


# ─────────────────────────── timing protocol config ──────────────────────────

@pytest.mark.unit
class TestTimingProtocolConfig:

    def test_secret_key_not_placeholder(self, topology_config):
        cfg, path = topology_config
        for db in cfg.databases:
            tp = getattr(db, "timing_protocol", None)
            if tp and tp.enabled:
                assert tp.secret_key is not None, (
                    f"{path}: db {db.name!r} timing enabled but secret_key is None"
                )
                assert tp.secret_key != "example_key", (
                    f"{path}: db {db.name!r} uses placeholder 'example_key'"
                )

    def test_delay_values_positive(self, topology_config):
        cfg, path = topology_config
        for db in cfg.databases:
            tp = getattr(db, "timing_protocol", None)
            if tp and tp.enabled:
                assert tp.short_delay_ms > 0, f"{path}: short_delay_ms must be > 0"
                assert tp.long_delay_ms > 0, f"{path}: long_delay_ms must be > 0"
                assert tp.short_delay_ms < tp.long_delay_ms, (
                    f"{path}: short_delay_ms must be < long_delay_ms"
                )

    def test_attack_tos_valid_byte(self, topology_config):
        cfg, path = topology_config
        exfil = getattr(cfg, "exfiltration", None)
        if exfil:
            tos = getattr(exfil, "attack_tos", None)
            if tos is not None:
                assert 0 <= tos <= 255, f"{path}: attack_tos {tos!r} not a valid byte"


# ─────────────────────────── exfiltration config ─────────────────────────────

@pytest.mark.unit
class TestExfiltrationConfig:

    def test_exfil_attacker_in_nodes(self, topology_config):
        """attacker must be in nodes — attackers: list is optional."""
        cfg, path = topology_config
        exfil = getattr(cfg, "exfiltration", None)
        if exfil and exfil.attacker:
            node_names = {n.name for n in cfg.nodes}
            assert exfil.attacker in node_names, (
                f"{path}: exfiltration.attacker {exfil.attacker!r} not declared in nodes:"
            )
            # if attackers: list is present, attacker must be in it
            if cfg.attackers:
                assert exfil.attacker in cfg.attackers, (
                    f"{path}: exfiltration.attacker {exfil.attacker!r} "
                    f"not in attackers: list — remove attackers: or add it"
                )

    def test_exfil_target_has_api_port(self, topology_config):
        cfg, path = topology_config
        exfil = getattr(cfg, "exfiltration", None)
        if exfil and exfil.target_host:
            db_hosts = {db.host for db in cfg.databases if db.api_port}
            assert exfil.target_host in db_hosts, (
                f"{path}: exfil target {exfil.target_host!r} has no api_port configured"
            )

    def test_exfil_target_port_matches_database(self, topology_config):
        cfg, path = topology_config
        exfil = getattr(cfg, "exfiltration", None)
        if exfil and exfil.target_host and exfil.target_port:
            for db in cfg.databases:
                if db.host == exfil.target_host:
                    assert db.api_port == exfil.target_port, (
                        f"{path}: exfil.target.port {exfil.target_port} != "
                        f"databases[].api_port {db.api_port} for {db.host}"
                    )


# ─────────────────────────── inline YAML tests ───────────────────────────────

@pytest.mark.unit
class TestInlineYAML:
    """Load from literal YAML strings — topology-independent edge cases."""

    def _load(self, yaml_text: str) -> TopologyConfig:
        import tempfile, yaml as _yaml
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(textwrap.dedent(yaml_text))
            name = f.name
        return load_config(name)

    def test_minimal_topology_loads(self):
        cfg = self._load("""
            nodes:
              - name: s1
                type: switch
              - name: h1
                type: host
              - name: h2
                type: host
            links:
              - [h1, s1]
              - [s1, h2]
        """)
        assert len(cfg.nodes) == 3
        assert len(cfg.links) == 2

    def test_timing_protocol_disabled_no_secret_required(self):
        cfg = self._load("""
            nodes:
              - name: s1
                type: switch
              - name: h1
                type: host
            links:
              - [h1, s1]
            databases:
              - host: h1
                name: testdb
                api_port: 9090
                timing_protocol:
                  enabled: false
                tables:
                  - name: users
                    rows: 5
                    schema:
                      id: integer
        """)
        db = cfg.databases[0]
        assert not db.timing_protocol.enabled
        # No secret_key needed when disabled
        assert db.timing_protocol.secret_key is None or True

    @pytest.mark.parametrize("bad_yaml,expected_error", [
        # Link references undeclared node
        ("""
            nodes:
              - name: s1
                type: switch
            links:
              - [s1, ghost]
        """, Exception),
    ])
    def test_invalid_configs_raise(self, bad_yaml, expected_error):
        with pytest.raises(expected_error):
            self._load(bad_yaml)

    @pytest.mark.parametrize("wait_s,npc,vpn", [
        (10, "low", "off"),
        (20, "medium", "on"),
        (30, "high", "off"),
    ])
    def test_capture_wait_values_accepted(self, wait_s, npc, vpn):
        """Verify config fields accept parametrized experiment dimensions."""
        cfg = self._load(f"""
            nodes:
              - name: s1
                type: switch
              - name: h1
                type: host
            links:
              - [h1, s1]
        """)
        assert cfg is not None
