"""Unit + integration tests for service infrastructure.

Non-Mininet tests (run anywhere):
  * ServiceRegistry     — register, lookup, print
  * ServiceConfig       — port defaults, config parsing
  * Enterprise YAML     — lans expansion, node count

Mininet integration tests (require root + Mininet):
  * Service deployment  — HTTP, SMTP, FTP, Echo
  * Service discovery   — port scanning
  * Cross-LAN service access
"""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config_loader import load_config
from services.service_registry import ServiceRegistry, effective_port, DEFAULT_PORTS


ENTERPRISE_CONFIG = os.path.join(
    os.path.dirname(__file__), "..", "configs", "topology_enterprise.yaml"
)
BASIC_CONFIG = os.path.join(
    os.path.dirname(__file__), "..", "configs", "topology.yaml"
)


# ------------------------------------------------------------------ registry tests

class TestServiceRegistry:

    def test_register_and_retrieve(self):
        reg = ServiceRegistry()
        inst = reg.register("web1", "http", 8080)
        assert inst.host == "web1"
        assert inst.port == 8080
        assert inst.service_type == "http"

    def test_get_services_by_host(self):
        reg = ServiceRegistry()
        reg.register("web1", "http", 8080)
        reg.register("web1", "smtp", 25)
        reg.register("db1", "sqlite", 9090)
        assert len(reg.get_services("web1")) == 2
        assert len(reg.get_services("db1")) == 1

    def test_get_by_type(self):
        reg = ServiceRegistry()
        reg.register("web1", "http", 8080)
        reg.register("web2", "http", 8080)
        reg.register("ftp1", "ftp", 21)
        assert len(reg.get_by_type("http")) == 2
        assert len(reg.get_by_type("ftp")) == 1

    def test_update_status(self):
        reg = ServiceRegistry()
        reg.register("web1", "http", 8080)
        reg.update_status("web1", 8080, "running")
        assert reg.get_services("web1")[0].status == "running"

    def test_resolve(self):
        reg = ServiceRegistry()
        reg.register("web1", "http", 8080)
        found = reg.resolve("web1", "http")
        assert found is not None
        assert found.port == 8080

    def test_resolve_missing(self):
        reg = ServiceRegistry()
        assert reg.resolve("web1", "ftp") is None

    def test_all_endpoints(self):
        reg = ServiceRegistry()
        reg.register("web1", "http", 8080)
        reg.register("db1", "sqlite", 9090)
        eps = reg.all_endpoints()
        assert len(eps) == 2
        hosts = [e["host"] for e in eps]
        assert "web1" in hosts

    def test_print_table_no_crash(self, capsys):
        reg = ServiceRegistry()
        reg.register("web1", "http", 8080)
        reg.print_table()
        out = capsys.readouterr().out
        assert "web1" in out


class TestEffectivePort:

    def test_declared_port_wins(self):
        assert effective_port("http", 9999) == 9999

    def test_default_http_port(self):
        assert effective_port("http", None) == DEFAULT_PORTS["http"]

    def test_default_ftp_port(self):
        assert effective_port("ftp", None) == DEFAULT_PORTS["ftp"]

    def test_unknown_service_fallback(self):
        assert effective_port("unknown_svc", None) == 8080


# ------------------------------------------------------------------ enterprise config tests

class TestEnterpriseConfig:

    def setup_method(self):
        self.config = load_config(ENTERPRISE_CONFIG)

    def test_lans_expansion_creates_nodes(self):
        names = {n.name for n in self.config.nodes}
        # LAN gateways
        assert "r1" in names
        assert "r2" in names
        assert "r3" in names
        # LAN hosts
        assert "h1" in names
        assert "web1" in names
        assert "db1" in names
        assert "h4" in names

    def test_lans_expansion_creates_lan_switches(self):
        lan_sw = [n.name for n in self.config.get_lan_switches()]
        assert "lan_sw_office" in lan_sw
        assert "lan_sw_datacenter" in lan_sw
        assert "lan_sw_branch" in lan_sw

    def test_lan_gateways_auto_registered(self):
        assert "r1" in self.config.lan_gateways
        assert "r2" in self.config.lan_gateways
        assert "r3" in self.config.lan_gateways

    def test_links_created_for_all_lans(self):
        link_set = {(a, b) for a, b in self.config.links} | {(b, a) for a, b in self.config.links}
        # gateway → lan_switch links
        assert ("r1", "lan_sw_office") in link_set or ("lan_sw_office", "r1") in link_set
        # host → lan_switch links
        assert ("h1", "lan_sw_office") in link_set or ("lan_sw_office", "h1") in link_set
        assert ("web1", "lan_sw_datacenter") in link_set or ("lan_sw_datacenter", "web1") in link_set

    def test_services_parsed(self):
        assert len(self.config.services) > 0
        types = [s.type for s in self.config.services]
        assert "http" in types

    def test_databases_parsed(self):
        assert len(self.config.databases) == 1
        db = self.config.databases[0]
        assert db.name == "company"
        assert db.host == "db1"
        assert len(db.tables) == 2

    def test_table_schemas_parsed(self):
        db = self.config.databases[0]
        emp = next(t for t in db.tables if t.name == "employees")
        assert emp.rows == 50
        assert "email" in emp.schema

    def test_deployment_mode_auto(self):
        assert self.config.deployment.mode == "auto"

    def test_vpn_peers_enterprise(self):
        assert len(self.config.vpn_peers) == 1
        vp = self.config.vpn_peers[0]
        assert vp.gateway == "vpnhub"
        assert "r1" in vp.clients
        assert "r2" in vp.clients
        assert "r3" in vp.clients


class TestIPAllocationEnterprise:
    """Verify IP allocation works with LAN switches."""

    def setup_method(self):
        from network.ip_allocator import allocate
        self.config = load_config(ENTERPRISE_CONFIG)
        self.alloc = allocate(self.config)

    def test_lan_subnets_count(self):
        # Enterprise topology has office, datacenter, branch, lab = 4 LANs
        lans_in_config = len(self.config.lan_gateways)
        assert len(self.alloc.lan_subnets) == lans_in_config, (
            f"Expected {lans_in_config} LAN subnets, got {self.alloc.lan_subnets}"
        )

    def test_lan_subnets_are_distinct(self):
        subnets = list(self.alloc.lan_subnets.values())
        assert len(set(str(s) for s in subnets)) == len(subnets)

    def test_hosts_get_lan_ips(self):
        for host in ("h1", "h2", "web1", "db1", "ftp1", "h4", "h5"):
            ifaces = self.alloc.node_interfaces.get(host, {})
            lan_ips = [ip for ip, _ in ifaces.values() if ip.startswith("192.168.")]
            assert lan_ips, f"{host} has no LAN IP in allocation"

    def test_default_gateways_set(self):
        for host in ("h1", "h2", "web1", "db1", "ftp1", "h4", "h5"):
            gw = self.alloc.default_gateways.get(host)
            assert gw is not None, f"{host} has no default gateway"
            assert gw.startswith("192.168."), f"{host} gateway not in LAN range: {gw}"

    def test_hosts_in_same_lan_share_subnet(self):
        # h1 and h2 both in office LAN → same /24
        h1_ips = [ip for ip, _ in self.alloc.node_interfaces.get("h1", {}).values()
                  if ip.startswith("192.168.")]
        h2_ips = [ip for ip, _ in self.alloc.node_interfaces.get("h2", {}).values()
                  if ip.startswith("192.168.")]
        if h1_ips and h2_ips:
            h1_net = ".".join(h1_ips[0].split(".")[:3])
            h2_net = ".".join(h2_ips[0].split(".")[:3])
            assert h1_net == h2_net, f"h1 and h2 not in same /24: {h1_ips[0]} vs {h2_ips[0]}"

    def test_hosts_in_different_lans_different_subnets(self):
        h1_ips = [ip for ip, _ in self.alloc.node_interfaces.get("h1", {}).values()
                  if ip.startswith("192.168.")]
        web1_ips = [ip for ip, _ in self.alloc.node_interfaces.get("web1", {}).values()
                    if ip.startswith("192.168.")]
        if h1_ips and web1_ips:
            h1_net = ".".join(h1_ips[0].split(".")[:3])
            w1_net = ".".join(web1_ips[0].split(".")[:3])
            assert h1_net != w1_net, "h1 and web1 should be in different LANs"

    def test_vpn_ips_assigned_enterprise(self):
        for node in ("vpnhub", "r1", "r2", "r3"):
            vpn_ip = self.alloc.get_vpn_ip(node)
            assert vpn_ip is not None, f"{node} has no VPN IP"


# ------------------------------------------------------------------ Mininet integration

_IS_ROOT = getattr(os, "geteuid", lambda: -1)() == 0
try:
    import mininet  # noqa: F401
    _MININET_OK = True
except ImportError:
    _MININET_OK = False


@pytest.mark.skipif(not _IS_ROOT, reason="requires root")
@pytest.mark.skipif(not _MININET_OK, reason="Mininet not installed")
class TestServiceDeploymentMininet:
    """Start enterprise topology and verify services are reachable."""

    @pytest.fixture(scope="class", autouse=True)
    def running_topo(self):
        from network.topology import ISPTopology
        topo = ISPTopology(ENTERPRISE_CONFIG)
        topo.start(enable_vpn=False, enable_services=True, enable_cli=False)
        yield topo
        topo.stop()

    def test_http_server_listening(self, running_topo):
        """web1 HTTP server must respond to curl."""
        alloc = running_topo.allocation
        web1_ip = alloc.get_host_ip("web1")
        web1 = running_topo.net["web1"]
        out = web1.cmd("curl -sf --max-time 2 http://127.0.0.1:8080/ 2>&1")
        assert "<html" in out.lower() or "ISP" in out, (
            f"HTTP server not responding on web1:\n{out}"
        )

    def test_h1_can_reach_web1_http(self, running_topo):
        """h1 in office LAN must HTTP-reach web1 in datacenter LAN."""
        alloc = running_topo.allocation
        web1_ip = alloc.get_host_ip("web1")
        h1 = running_topo.net["h1"]
        out = h1.cmd(f"curl -sf --max-time 3 http://{web1_ip}:8080/ 2>&1")
        assert "<html" in out.lower() or "ISP" in out or "200" in out, (
            f"h1 cannot reach web1 HTTP at {web1_ip}:8080:\n{out}"
        )

    def test_database_api_responds(self, running_topo):
        """CRUD API on db1 must return JSON for /api/employees."""
        db1 = running_topo.net["db1"]
        out = db1.cmd("curl -sf --max-time 2 http://127.0.0.1:9090/api/employees 2>&1")
        assert "[" in out or "{" in out, (
            f"CRUD API not responding on db1:\n{out}"
        )

    def test_cross_lan_database_access(self, running_topo):
        """h1 must reach db1's CRUD API across LAN boundaries."""
        alloc = running_topo.allocation
        db1_ip = alloc.get_host_ip("db1")
        h1 = running_topo.net["h1"]
        out = h1.cmd(f"curl -sf --max-time 5 http://{db1_ip}:9090/api/employees 2>&1")
        assert "[" in out or "{" in out, (
            f"h1 cannot reach db1 CRUD API at {db1_ip}:9090:\n{out}"
        )
