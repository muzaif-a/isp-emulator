"""Dynamic IP allocation for ISP Network emulator.

Phase 2 changes (backward compatible)
--------------------------------------
* _allocate_lan recognises auto-generated LAN switches (is_lan_switch=True).

Phase 3 changes
---------------
* Automatic interface-name generation respecting Linux IFNAMSIZ (15 chars).
  Node names longer than 9 chars (e.g. lan_sw_office) get a short alias
  derived from word-initials + a sequential counter.  Short names (≤9 chars)
  are used as-is.  The alias table is exposed in AllocationResult.node_aliases.
"""

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from config_loader import TopologyConfig, NodeConfig
from errors import EmulatorError

logger = logging.getLogger(__name__)

_IP = str
_Prefix = int
_IfaceMap = Dict[str, Tuple[_IP, _Prefix]]

# Maximum node-name length that is safe for interface naming.
# Safe = node_name + "-eth99" ≤ IFNAMSIZ (15).
# 15 - len("-eth99") = 15 - 6 = 9.
_SAFE_NAME_LEN = 9


@dataclass
class AllocationResult:
    """Complete IP allocation for one topology."""

    # node_name -> {iface_name -> (ip, prefix_len)}
    node_interfaces: Dict[str, _IfaceMap] = field(default_factory=dict)

    # switch_name -> IPv4Network (ISP subnet)
    isp_subnets: Dict[str, ipaddress.IPv4Network] = field(default_factory=dict)

    # gateway_name -> IPv4Network (LAN subnet)
    lan_subnets: Dict[str, ipaddress.IPv4Network] = field(default_factory=dict)

    # vpn_gateway_name -> IPv4Network (VPN subnet)
    vpn_subnets: Dict[str, ipaddress.IPv4Network] = field(default_factory=dict)

    # node_name -> default gateway IP (hosts only)
    default_gateways: Dict[str, _IP] = field(default_factory=dict)

    # (node_a, node_b) -> (iface_on_a, iface_on_b)
    link_interfaces: Dict[Tuple[str, str], Tuple[str, str]] = field(default_factory=dict)

    # node_name -> VPN overlay IP
    vpn_node_ips: Dict[str, _IP] = field(default_factory=dict)

    # node_name -> short alias used for interface naming (equals node_name when ≤9 chars)
    node_aliases: Dict[str, str] = field(default_factory=dict)

    # ---------------------------------------------------------------- helpers

    def get_isp_ip(self, node_name: str) -> Optional[_IP]:
        for ip, _ in self.node_interfaces.get(node_name, {}).values():
            if ip.startswith("10."):
                return ip
        return None

    def get_lan_gw_ip(self, gateway_name: str) -> Optional[_IP]:
        for ip, _ in self.node_interfaces.get(gateway_name, {}).values():
            if ip.startswith("192.168."):
                return ip
        return None

    def get_vpn_ip(self, node_name: str) -> Optional[_IP]:
        return self.vpn_node_ips.get(node_name)

    def get_iface_for_link(self, node: str, peer: str) -> Optional[str]:
        """Return the interface name on *node* for the link to *peer*."""
        key = (node, peer) if (node, peer) in self.link_interfaces else (peer, node)
        if key not in self.link_interfaces:
            return None
        iface_a, iface_b = self.link_interfaces[key]
        return iface_a if key[0] == node else iface_b

    def get_host_ip(self, node_name: str) -> Optional[_IP]:
        """Return any non-loopback IP of node (for service addressing)."""
        for ip, _ in self.node_interfaces.get(node_name, {}).values():
            if not ip.startswith("127."):
                return ip
        return None

    def get_node_for_alias(self, alias: str) -> str:
        for node_name, node_alias in self.node_aliases.items():
            if node_alias == alias:
                return node_name
        return alias


# ---------------------------------------------------------------------- public

def allocate(config: TopologyConfig) -> AllocationResult:
    """Run the full allocation pipeline and return an AllocationResult."""
    result = AllocationResult()

    # Aliases must be computed before interface names
    aliases = _assign_aliases(config.nodes)
    result.node_aliases = aliases
    result.link_interfaces = _compute_iface_names(config, aliases)

    _allocate_isp(config, result)
    _allocate_lan(config, result)
    _allocate_vpn(config, result)

    logger.info(
        "Allocation done: %d ISP, %d LAN, %d VPN subnets",
        len(result.isp_subnets),
        len(result.lan_subnets),
        len(result.vpn_subnets),
    )
    return result


# ------------------------------------------------------------------- internals

def _assign_aliases(nodes: List[NodeConfig]) -> Dict[str, str]:
    """Map each node name to a short alias used for Linux interface naming.

    Rules:
    - len(name) ≤ _SAFE_NAME_LEN (9): alias = name unchanged.
    - len(name) > 9: alias = word-initials[:4] + sequential-counter.

    The alias satisfies: len(alias) ≤ 9, so alias + "-eth99" ≤ 15 = IFNAMSIZ.
    Aliases are deterministic (depend only on config node order) and unique.
    """
    aliases: Dict[str, str] = {}
    used: set = set()
    initials_counter: Dict[str, int] = {}

    # First pass: claim short names (they alias to themselves)
    for node in nodes:
        if len(node.name) <= _SAFE_NAME_LEN:
            aliases[node.name] = node.name
            used.add(node.name)

    # Second pass: generate aliases for long names
    for node in nodes:
        if len(node.name) > _SAFE_NAME_LEN:
            # Word-initials from underscore/hyphen/digit boundaries
            parts = re.split(r'[^a-z0-9]+', node.name.lower())
            initials = "".join(p[0] for p in parts if p)[:4]
            if not initials:
                # Fallback: first 4 alphanumeric chars
                initials = re.sub(r'[^a-z0-9]', '', node.name.lower())[:4] or "n"

            # Find unique alias (handle collisions via incrementing counter)
            idx = initials_counter.get(initials, 0) + 1
            candidate = f"{initials}{idx}"
            while candidate in used:
                idx += 1
                candidate = f"{initials}{idx}"

            initials_counter[initials] = idx
            aliases[node.name] = candidate
            used.add(candidate)
            logger.debug("Interface alias: %s -> %s", node.name, candidate)

    return aliases


def _compute_iface_names(
    config: TopologyConfig,
    aliases: Dict[str, str],
) -> Dict[Tuple[str, str], Tuple[str, str]]:
    """Predict Mininet interface names using short aliases.

    Interface name format: {alias}-eth{n}
    Maximum length: 9 + 1 + 3 + 2 = 15 chars (alias + '-' + 'eth' + port).
    """
    link_count: Dict[str, int] = {n.name: 0 for n in config.nodes}
    link_ifaces: Dict[Tuple[str, str], Tuple[str, str]] = {}

    for link in config.links:
        a, b = link[0], link[1]
        alias_a = aliases.get(a, a)
        alias_b = aliases.get(b, b)
        iface_a = f"{alias_a}-eth{link_count[a]}"
        iface_b = f"{alias_b}-eth{link_count[b]}"

        if len(iface_a) > 15:
            raise EmulatorError("R010",
                f"{iface_a!r} ({len(iface_a)} chars) — node {a!r} alias {alias_a!r} is too long")
        if len(iface_b) > 15:
            raise EmulatorError("R010",
                f"{iface_b!r} ({len(iface_b)} chars) — node {b!r} alias {alias_b!r} is too long")

        link_count[a] += 1
        link_count[b] += 1
        link_ifaces[(a, b)] = (iface_a, iface_b)

    return link_ifaces


def _set_iface(result: AllocationResult, node: str, iface: str, ip: str, prefix: int) -> None:
    result.node_interfaces.setdefault(node, {})[iface] = (ip, prefix)


def _allocate_isp(config: TopologyConfig, result: AllocationResult) -> None:
    """Assign ISP IPs to all non-switch nodes touching each ISP switch."""
    isp_pool = _subnet_pool(config.settings.isp_base_network, new_prefix=24)

    for switch in config.get_switches():          # only ISP switches (not LAN switches)
        try:
            subnet = next(isp_pool)
        except StopIteration:
            raise EmulatorError("R001",
                f"increase settings.isp_base_network — ran out of /24s for {switch.name}")
        result.isp_subnets[switch.name] = subnet
        hosts_iter = subnet.hosts()

        for neighbor in config.get_neighbors(switch.name):
            node = config.get_node(neighbor)
            if node is None or node.is_switch():
                continue
            ip = str(next(hosts_iter))
            iface = result.get_iface_for_link(neighbor, switch.name)
            if iface:
                _set_iface(result, neighbor, iface, ip, subnet.prefixlen)
                logger.debug("ISP: %s %s %s/%d", neighbor, iface, ip, subnet.prefixlen)


def _allocate_lan(config: TopologyConfig, result: AllocationResult) -> None:
    """Assign LAN IPs to each lan_gateway and its downstream hosts.

    Phase 2: if a gateway connects to a LAN switch (is_lan_switch=True),
    all hosts behind that switch share the same /24.
    Phase 1: direct gateway-to-host links (existing behaviour).
    """
    lan_pool = _subnet_pool(config.settings.lan_base_network, new_prefix=24)

    for gw_name in config.lan_gateways:
        try:
            subnet = next(lan_pool)
        except StopIteration:
            raise EmulatorError("R001",
                f"increase settings.lan_base_network — ran out of /24s for gateway {gw_name}")
        result.lan_subnets[gw_name] = subnet
        hosts_iter = subnet.hosts()
        gw_ip = str(next(hosts_iter))   # gateway always gets first host IP (.1)

        # Detect LAN switch among gateway's neighbours
        lan_switch: Optional[str] = None
        for neighbor in config.get_neighbors(gw_name):
            node = config.get_node(neighbor)
            if node and node.is_switch() and node.is_lan_switch:
                lan_switch = neighbor
                break

        if lan_switch:
            # ---- Phase 2 path: gateway → LAN switch → hosts ----
            gw_iface = result.get_iface_for_link(gw_name, lan_switch)
            if gw_iface:
                _set_iface(result, gw_name, gw_iface, gw_ip, subnet.prefixlen)
                logger.debug("LAN GW (sw): %s %s %s/%d", gw_name, gw_iface, gw_ip, subnet.prefixlen)

            for host_name in config.get_neighbors(lan_switch):
                node = config.get_node(host_name)
                if node is None or node.is_switch():
                    continue   # skip the gateway itself (already done) and switches
                if host_name == gw_name:
                    continue
                host_iface = result.get_iface_for_link(host_name, lan_switch)
                if host_iface:
                    host_ip = str(next(hosts_iter))
                    _set_iface(result, host_name, host_iface, host_ip, subnet.prefixlen)
                    result.default_gateways[host_name] = gw_ip
                    logger.debug(
                        "LAN host (sw): %s %s %s/%d gw=%s",
                        host_name, host_iface, host_ip, subnet.prefixlen, gw_ip,
                    )

        else:
            # ---- Phase 1 path: gateway → direct host links ----
            for neighbor in config.get_neighbors(gw_name):
                node = config.get_node(neighbor)
                if node is None or node.is_switch():
                    continue

                gw_iface = result.get_iface_for_link(gw_name, neighbor)
                host_iface = result.get_iface_for_link(neighbor, gw_name)

                if gw_iface:
                    _set_iface(result, gw_name, gw_iface, gw_ip, subnet.prefixlen)
                if host_iface:
                    host_ip = str(next(hosts_iter))
                    _set_iface(result, neighbor, host_iface, host_ip, subnet.prefixlen)
                    result.default_gateways[neighbor] = gw_ip
                    logger.debug(
                        "LAN host (direct): %s %s %s/%d gw=%s",
                        neighbor, host_iface, host_ip, subnet.prefixlen, gw_ip,
                    )


def _allocate_vpn(config: TopologyConfig, result: AllocationResult) -> None:
    """Assign VPN overlay IPs for every vpn_peers group."""
    vpn_pool = _subnet_pool(config.settings.vpn_base_network, new_prefix=24)

    for vp in config.vpn_peers:
        try:
            subnet = next(vpn_pool)
        except StopIteration:
            raise EmulatorError("R002",
                f"increase settings.vpn_base_network — ran out of /24s for gateway {vp.gateway}")
        result.vpn_subnets[vp.gateway] = subnet
        hosts_iter = subnet.hosts()

        gw_ip = str(next(hosts_iter))
        result.vpn_node_ips[vp.gateway] = gw_ip
        logger.debug("VPN GW: %s vpn=%s", vp.gateway, gw_ip)

        for client in vp.clients:
            client_ip = str(next(hosts_iter))
            result.vpn_node_ips[client] = client_ip
            logger.debug("VPN client: %s vpn=%s", client, client_ip)


def _subnet_pool(base: str, new_prefix: int):
    """Infinite generator of /new_prefix subnets carved from base."""
    return ipaddress.IPv4Network(base).subnets(new_prefix=new_prefix)
