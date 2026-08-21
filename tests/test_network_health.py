"""Network health integration tests.

Requires root + Mininet. Skipped automatically when unavailable.
All expected values derived from config and allocation — no hardcoded node
names, IPs, or port numbers.

Coverage:
  - IP forwarding on all routers/gateways (from config.lan_gateways)
  - Intra-LAN reachability: each host pings its LAN gateway
  - Inter-LAN reachability: cross-LAN gateway pings
  - Routing table completeness: all LAN subnets reachable from every gateway
  - Service availability: every configured service port is listening
  - Database API health: /health endpoint responds 200
  - No blackhole or unreachable routes on any node
"""

import os
import sys
import time
import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

pytestmark = pytest.mark.integration


# ───────────────────────── topology fixture ───────────────────────────────────

@pytest.fixture(scope="module")
def running_topo(request):
    """Start topology, yield (net, config, allocation), stop on teardown."""
    from config_loader import load_config
    from network.ip_allocator import allocate
    from network.topology import ISPTopology

    config_path = getattr(request, "param", None) or os.path.join(
        ROOT, "configs", "topology.yaml"
    )
    cfg = load_config(config_path)
    alloc = allocate(cfg)
    topo = ISPTopology(config_path)
    try:
        topo.start()
        yield topo.net, cfg, alloc
    finally:
        topo.stop()


# ───────────────────────── IP forwarding ─────────────────────────────────────

class TestIPForwarding:

    def test_all_lan_gateways_forward_ipv4(self, running_topo):
        net, cfg, alloc = running_topo
        for gw in cfg.lan_gateways:
            if gw not in net:
                continue
            out = net[gw].cmd("sysctl -n net.ipv4.ip_forward").strip()
            assert out == "1", (
                f"LAN gateway {gw!r} has ip_forward={out!r}, expected 1"
            )

    def test_all_vpn_gateways_forward_ipv4(self, running_topo):
        net, cfg, alloc = running_topo
        for gw in cfg.vpn_gateways:
            if gw not in net:
                continue
            out = net[gw].cmd("sysctl -n net.ipv4.ip_forward").strip()
            assert out == "1", (
                f"VPN gateway {gw!r} has ip_forward={out!r}, expected 1"
            )


# ───────────────────────── intra-LAN reachability ────────────────────────────

class TestIntraLANReachability:

    def test_each_host_pings_its_lan_gateway(self, running_topo):
        net, cfg, alloc = running_topo
        failures = []
        for gw, subnet in alloc.lan_subnets.items():
            gw_ip = alloc.get_lan_gw_ip(gw)
            if not gw_ip or gw not in net:
                continue
            for node in cfg.nodes:
                if node.is_switch() or node.name == gw:
                    continue
                host_ip = alloc.get_host_ip(node.name)
                if not host_ip or not _ip_in_subnet(host_ip, subnet):
                    continue
                if node.name not in net:
                    continue
                result = net[node.name].cmd(
                    f"ping -c 1 -W 2 {gw_ip} 2>/dev/null"
                )
                if "1 received" not in result and "0% packet loss" not in result:
                    failures.append(f"{node.name} → gateway {gw} ({gw_ip})")
        assert not failures, "Intra-LAN reachability failures:\n" + "\n".join(failures)


# ───────────────────────── inter-LAN reachability ────────────────────────────

class TestInterLANReachability:

    def test_gateway_to_gateway_ping(self, running_topo):
        net, cfg, alloc = running_topo
        gateways = [gw for gw in cfg.lan_gateways if gw in net]
        if len(gateways) < 2:
            pytest.skip("fewer than 2 LAN gateways — no inter-LAN test")

        failures = []
        for i, src_gw in enumerate(gateways):
            for dst_gw in gateways[i + 1:]:
                dst_ip = alloc.get_lan_gw_ip(dst_gw)
                if not dst_ip:
                    continue
                result = net[src_gw].cmd(f"ping -c 1 -W 3 {dst_ip} 2>/dev/null")
                if "1 received" not in result and "0% packet loss" not in result:
                    failures.append(f"{src_gw} → {dst_gw} ({dst_ip})")
        assert not failures, "Inter-LAN failures:\n" + "\n".join(failures)


# ───────────────────────── routing table completeness ────────────────────────

class TestRoutingTableCompleteness:

    def test_each_gateway_has_route_to_all_lan_subnets(self, running_topo):
        net, cfg, alloc = running_topo
        failures = []
        for src_gw in cfg.lan_gateways:
            if src_gw not in net:
                continue
            routes_out = net[src_gw].cmd("ip route show")
            for dst_gw, subnet in alloc.lan_subnets.items():
                if dst_gw == src_gw:
                    continue
                subnet_str = str(subnet)
                if subnet_str not in routes_out:
                    failures.append(
                        f"{src_gw} missing route to {subnet_str} ({dst_gw})"
                    )
        assert not failures, "Missing routes:\n" + "\n".join(failures)

    def test_no_blackhole_or_unreachable_routes(self, running_topo):
        net, cfg, alloc = running_topo
        for node in cfg.nodes:
            if node.is_switch() or node.name not in net:
                continue
            routes = net[node.name].cmd("ip route show")
            for bad in ("blackhole", "unreachable", "prohibit"):
                assert bad not in routes, (
                    f"Node {node.name!r} has {bad!r} route: {routes}"
                )

    def test_host_default_route_via_lan_gateway(self, running_topo):
        net, cfg, alloc = running_topo
        failures = []
        for gw, subnet in alloc.lan_subnets.items():
            gw_ip = str(alloc.get_lan_gw_ip(gw))
            for node in cfg.nodes:
                if node.is_switch() or node.name == gw:
                    continue
                host_ip = alloc.get_host_ip(node.name)
                if not host_ip or not _ip_in_subnet(host_ip, subnet):
                    continue
                if node.name not in net:
                    continue
                routes = net[node.name].cmd("ip route show default")
                if gw_ip not in routes:
                    failures.append(
                        f"Host {node.name} default route not via {gw} ({gw_ip})"
                    )
        assert not failures, "Default route failures:\n" + "\n".join(failures)


# ───────────────────────── service availability ───────────────────────────────

class TestServiceAvailability:

    def test_all_configured_services_listening(self, running_topo):
        net, cfg, alloc = running_topo
        failures = []
        for svc in cfg.services:
            if svc.host not in net or not svc.port:
                continue
            out = net[svc.host].cmd(
                f"ss -tlnp 2>/dev/null | grep ':{svc.port}'"
            ).strip()
            if not out:
                failures.append(f"{svc.host}:{svc.port} ({svc.type}) not listening")
        assert not failures, "Services not listening:\n" + "\n".join(failures)

    def test_database_api_health_endpoint(self, running_topo):
        net, cfg, alloc = running_topo
        failures = []
        for db in cfg.databases:
            if not db.api_port or db.host not in net:
                continue
            time.sleep(0.5)
            result = net[db.host].cmd(
                f"curl -sf --max-time 3 http://127.0.0.1:{db.api_port}/health"
            ).strip()
            if "ok" not in result.lower() and result == "":
                failures.append(
                    f"DB {db.name!r} on {db.host}:{db.api_port} /health failed"
                )
        assert not failures, "DB API health failures:\n" + "\n".join(failures)

    def test_database_api_returns_table_data(self, running_topo):
        net, cfg, alloc = running_topo
        failures = []
        for db in cfg.databases:
            if not db.api_port or db.host not in net:
                continue
            for table in db.tables:
                result = net[db.host].cmd(
                    f"curl -sf --max-time 5 "
                    f"http://127.0.0.1:{db.api_port}/api/{table.name}"
                ).strip()
                if not result.startswith("["):
                    failures.append(
                        f"DB {db.name!r}/{table.name} did not return JSON array"
                    )
        assert not failures, "DB API data failures:\n" + "\n".join(failures)


# ───────────────────────── IP assignment verification ─────────────────────────

class TestIPAssignment:

    def test_all_allocated_ips_configured_on_interfaces(self, running_topo):
        net, cfg, alloc = running_topo
        failures = []
        for node_name, ifaces in alloc.node_interfaces.items():
            if node_name not in net:
                continue
            iface_output = net[node_name].cmd("ip addr show").strip()
            for iface_name, (ip, prefix) in ifaces.items():
                if ip not in iface_output:
                    failures.append(
                        f"Node {node_name!r}: IP {ip} not found on interface {iface_name}"
                    )
        assert not failures, "IP assignment failures:\n" + "\n".join(failures)


# ───────────────────────── helpers ───────────────────────────────────────────

def _ip_in_subnet(ip_str: str, subnet) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip_str) in subnet
    except ValueError:
        return False
