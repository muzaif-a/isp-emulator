"""Automatic routing engine for ISP Network emulator.

Installs static routes on every router and host based solely on the
AllocationResult.  No IP addresses or interface names appear in this
file — all data comes from the allocator at runtime.

Routing policy
--------------
Hosts        : one default route via their LAN gateway.
LAN gateways : routes to every foreign LAN subnet via the peer gateway's
               ISP IP.  Also a default route if no other default exists.
VPN nodes    : after WireGuard is up, vpn_manager adds overlay routes.
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mininet.net import Mininet

from config_loader import TopologyConfig
from .ip_allocator import AllocationResult

logger = logging.getLogger(__name__)


def configure_routes(
    net: "Mininet",
    config: TopologyConfig,
    allocation: AllocationResult,
) -> None:
    """Install all static routes on every node in the topology.

    Order:
    1. Host default gateways.
    2. Inter-LAN routes on gateway routers.
    3. ISP-node routes (VPN gateways etc.).
    4. Manual static route overrides from YAML 'routes:' section —
       these run last so they can override any auto-generated route.
    """
    _configure_host_defaults(net, config, allocation)
    _configure_gateway_routes(net, config, allocation)
    _configure_isp_node_routes(net, config, allocation)
    if config.static_routes:
        _apply_manual_routes(net, config)


# ------------------------------------------------------------------- internals

def _configure_host_defaults(
    net: "Mininet",
    config: TopologyConfig,
    allocation: AllocationResult,
) -> None:
    """Set default gateway on every non-gateway host."""
    for node_cfg in config.get_hosts():
        name = node_cfg.name
        if config.is_lan_gateway(name) or config.is_vpn_gateway(name):
            continue  # handled separately
        gw = allocation.default_gateways.get(name)
        if not gw:
            logger.warning("%s has no default gateway in allocation", name)
            continue
        node = net[name]
        _run(node, f"ip route add default via {gw}")
        logger.debug("%s: default via %s", name, gw)


def _configure_gateway_routes(
    net: "Mininet",
    config: TopologyConfig,
    allocation: AllocationResult,
) -> None:
    """Add inter-LAN routes on every LAN gateway.

    For each LAN gateway R, for every OTHER LAN gateway R2:
      R learns R2's LAN subnet reachable via R2's ISP IP.
    """
    for gw_name in config.lan_gateways:
        gw_node = net[gw_name]
        my_lan = allocation.lan_subnets.get(gw_name)

        for peer_gw in config.lan_gateways:
            if peer_gw == gw_name:
                continue
            peer_subnet = allocation.lan_subnets.get(peer_gw)
            peer_isp_ip = allocation.get_isp_ip(peer_gw)
            if peer_subnet and peer_isp_ip:
                _run(gw_node, f"ip route add {peer_subnet} via {peer_isp_ip}")
                logger.debug(
                    "%s: route %s via %s (%s)", gw_name, peer_subnet, peer_isp_ip, peer_gw
                )

        # NOTE: VPN overlay subnet routes (172.16.x/24) are intentionally NOT
        # added here.  Adding them via the ISP nexthop creates a conflicting
        # route that races with the wg0 route vpn_manager installs later.
        # Traffic to VPN IPs must only leave via wg0 (encrypted); routing.py
        # has no knowledge of which interface WireGuard will use.


def _configure_isp_node_routes(
    net: "Mininet",
    config: TopologyConfig,
    allocation: AllocationResult,
) -> None:
    """Add LAN reachability routes on non-gateway ISP nodes (e.g. VPN gateways).

    A VPN gateway (like h2) sits on the ISP subnet and needs to know
    how to reach each LAN subnet in order to forward VPN traffic.
    """
    for node_cfg in config.nodes:
        name = node_cfg.name
        if node_cfg.is_switch():
            continue
        if config.is_lan_gateway(name):
            continue  # already done above
        # Check if this node is on an ISP subnet (has a 10.x IP)
        if not allocation.get_isp_ip(name):
            continue

        node = net[name]
        for gw_name, lan_subnet in allocation.lan_subnets.items():
            gw_isp_ip = allocation.get_isp_ip(gw_name)
            if gw_isp_ip:
                _run(node, f"ip route add {lan_subnet} via {gw_isp_ip}")
                logger.debug(
                    "%s: ISP route to LAN %s via %s (%s)",
                    name, lan_subnet, gw_isp_ip, gw_name,
                )


def _apply_manual_routes(net: "Mininet", config: TopologyConfig) -> None:
    """Apply YAML 'routes:' overrides using 'ip route replace'."""
    for route in config.static_routes:
        try:
            node = net[route.node]
        except KeyError:
            logger.warning("Manual route: unknown node %r — skipping", route.node)
            continue
        out = _run(node, f"ip route replace {route.destination} via {route.via}")
        logger.info(
            "Manual route: %s → %s via %s", route.node, route.destination, route.via
        )


def dump_route_tables(
    net: "Mininet",
    config: TopologyConfig,
) -> dict:
    """Return a dict of node_name -> routing table string."""
    tables = {}
    for node_cfg in config.nodes:
        if node_cfg.is_switch():
            continue
        node = net[node_cfg.name]
        tables[node_cfg.name] = node.cmd("ip route show")
    return tables


# ------------------------------------------------------------------ utilities

def _run(node, cmd: str) -> str:
    out = node.cmd(cmd)
    if out.strip():
        logger.debug("%s cmd=%r out=%r", node.name, cmd, out.strip())
    return out
