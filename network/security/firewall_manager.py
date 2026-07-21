"""Optional Firewall Manager — iptables or nftables.

SAFETY CONTRACT
---------------
* Firewall is DISABLED by default (security.firewall.enabled: false).
* When enabled: rules are backed up before any change.
* Connectivity is validated immediately after applying rules.
* If ANY connectivity check fails, rules are automatically rolled back.
* Existing routing and WireGuard VPN NAT rules are preserved after flush.

Architecture
------------
FirewallManager.apply()
  → _backup_all()        — save iptables-save per node
  → _apply_all()         — flush + write allow-rules per router
  → _validate()          — test basic connectivity
      ✓ pass → done
      ✗ fail → _rollback_all() + raise FirewallRollbackError
"""

import logging
import time
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from mininet.net import Mininet

from config_loader import TopologyConfig, FirewallConfig
from ..ip_allocator import AllocationResult
from services.service_registry import ServiceRegistry

logger = logging.getLogger(__name__)


class FirewallRollbackError(Exception):
    """Raised when firewall rules break connectivity and are rolled back."""


class FirewallManager:
    """Manages iptables/nftables rules on all routers and VPN gateways."""

    def __init__(
        self,
        net: "Mininet",
        config: TopologyConfig,
        allocation: AllocationResult,
        registry: Optional[ServiceRegistry] = None,
    ) -> None:
        self.net = net
        self.config = config
        self.allocation = allocation
        self.registry = registry or ServiceRegistry()
        self._backups: Dict[str, str] = {}   # node_name -> iptables-save output

    # ----------------------------------------------------------------- public

    def apply(self) -> None:
        """Apply firewall rules if enabled; no-op otherwise."""
        fw = self.config.security.firewall
        if not fw.enabled:
            logger.info("Firewall disabled — skipping")
            return

        logger.info("Applying firewall (backend=%s policy=%s) …", fw.backend, fw.policy)

        self._backup_all()
        try:
            self._apply_all(fw)
            logger.info("Firewall rules applied; validating connectivity …")
            if not self._validate():
                raise FirewallRollbackError("Connectivity check failed after firewall rules")
            logger.info("Firewall check passed")
        except FirewallRollbackError:
            logger.error("Firewall broke connectivity — rolling back …")
            self._rollback_all()
            logger.warning("Rollback complete. Firewall NOT active.")
            raise
        except Exception as exc:
            logger.error("Unexpected error during firewall apply: %s", exc)
            self._rollback_all()
            raise

    def flush(self) -> None:
        """Remove all custom rules on all routers (restore permissive state)."""
        for name in self._router_names():
            node = self.net[name]
            self._flush_node(node)

    # --------------------------------------------------------------- backup / restore

    def _backup_all(self) -> None:
        for name in self._router_names():
            node = self.net[name]
            rules = node.cmd("iptables-save 2>/dev/null")
            self._backups[name] = rules
            logger.debug("Backed up iptables on %s (%d chars)", name, len(rules))

    def _rollback_all(self) -> None:
        for name, rules in self._backups.items():
            node = self.net[name]
            if not rules.strip():
                self._flush_node(node)
                continue
            # Write rules to tmp file and restore
            backup_path = f"/tmp/fw_backup_{name}.txt"
            with open(backup_path, "w") as fh:
                fh.write(rules)
            out = node.cmd(f"iptables-restore < {backup_path} 2>&1")
            if out.strip():
                logger.warning("iptables-restore on %s: %s", name, out.strip())
            else:
                logger.info("Rolled back iptables on %s", name)

    # --------------------------------------------------------------- rule application

    def _apply_all(self, fw: FirewallConfig) -> None:
        """Apply rules on all routers."""
        for name in self._router_names():
            node = self.net[name]
            self._flush_node(node)
            if fw.policy == "restrictive":
                self._apply_restrictive(node, fw)
            else:
                self._apply_permissive(node, fw)
            # _flush_node wipes the nat table; re-apply MASQUERADE for VPN gateways
            if self.config.vpn_config.nat and self.config.is_vpn_gateway(name):
                vpn_net = self.config.settings.vpn_base_network
                lan_net = self.config.settings.lan_base_network
                node.cmd(f"iptables -t nat -A POSTROUTING -s {vpn_net} -j MASQUERADE 2>/dev/null")
                node.cmd(f"iptables -t nat -A POSTROUTING -s {lan_net} -j MASQUERADE 2>/dev/null")
                logger.info("Re-applied VPN NAT/MASQUERADE on %s after firewall flush", name)

    def _flush_node(self, node) -> None:
        """Reset node to accept-all state."""
        node.cmd("iptables -F 2>/dev/null")
        node.cmd("iptables -t nat -F 2>/dev/null")
        node.cmd("iptables -P INPUT ACCEPT 2>/dev/null")
        node.cmd("iptables -P FORWARD ACCEPT 2>/dev/null")
        node.cmd("iptables -P OUTPUT ACCEPT 2>/dev/null")

    def _apply_restrictive(self, node, fw: FirewallConfig) -> None:
        """Restrictive policy: DROP by default, allow established + declared services."""
        # Allow loopback
        node.cmd("iptables -A INPUT -i lo -j ACCEPT")
        node.cmd("iptables -A OUTPUT -o lo -j ACCEPT")

        # Allow established / related
        node.cmd("iptables -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT")
        node.cmd("iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT")
        node.cmd("iptables -A OUTPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT")

        # Allow ICMP (ping)
        node.cmd("iptables -A INPUT   -p icmp -j ACCEPT")
        node.cmd("iptables -A FORWARD -p icmp -j ACCEPT")
        node.cmd("iptables -A OUTPUT  -p icmp -j ACCEPT")

        # Allow WireGuard UDP
        vpn_port = self.config.settings.vpn_port
        node.cmd(f"iptables -A INPUT   -p udp --dport {vpn_port} -j ACCEPT")
        node.cmd(f"iptables -A OUTPUT  -p udp --sport {vpn_port} -j ACCEPT")

        # Allow declared service ports (FORWARD only — routers are in-path)
        allowed_ports = self._collect_service_ports()
        for port, proto in allowed_ports:
            p = "tcp" if proto != "udp" else "udp"
            node.cmd(f"iptables -A FORWARD -p {p} --dport {port} -j ACCEPT")
            node.cmd(f"iptables -A FORWARD -p {p} --sport {port} -j ACCEPT")
            logger.debug("FW allow: %s FORWARD %s:%d", node.name, p, port)

        # Allow DNS (always)
        node.cmd("iptables -A FORWARD -p udp --dport 53 -j ACCEPT")
        node.cmd("iptables -A FORWARD -p tcp --dport 53 -j ACCEPT")

        # Default DROP
        node.cmd("iptables -P FORWARD DROP")
        logger.info("Restrictive firewall applied on %s", node.name)

    def _apply_permissive(self, node, fw: FirewallConfig) -> None:
        """Permissive policy: ACCEPT all, log suspicious."""
        node.cmd("iptables -P INPUT   ACCEPT")
        node.cmd("iptables -P FORWARD ACCEPT")
        node.cmd("iptables -P OUTPUT  ACCEPT")
        logger.info("Permissive firewall applied on %s (no restrictions)", node.name)

    def _collect_service_ports(self) -> List[tuple]:
        """Return list of (port, proto) from the service registry."""
        ports = []
        for svc in self.registry.get_services():
            proto = "udp" if svc.service_type in ("dns", "custom_udp", "echo") else "tcp"
            ports.append((svc.port, proto))
        return ports

    # --------------------------------------------------------------- checks

    def _validate(self) -> bool:
        """Ping across LANs to confirm routing still works through firewall."""
        ok = True
        gw_names = list(self.allocation.lan_subnets.keys())
        for i, gw1 in enumerate(gw_names):
            for gw2 in gw_names[i + 1:]:
                gw2_isp = self.allocation.get_isp_ip(gw2)
                if not gw2_isp:
                    continue
                node = self.net[gw1]
                out = node.cmd(f"ping -c 1 -W 2 {gw2_isp} 2>&1")
                if "1 received" not in out and "0% packet loss" not in out:
                    logger.warning("FW check FAIL: %s → %s (%s)", gw1, gw2, gw2_isp)
                    ok = False
        return ok

    # ---------------------------------------------------------------- helpers

    def _router_names(self) -> List[str]:
        names = list(self.config.lan_gateways) + list(self.config.vpn_gateways)
        return list(dict.fromkeys(names))   # deduplicate, preserve order
