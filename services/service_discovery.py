"""Automatic service discovery.

Scans every non-switch node for listening TCP/UDP ports and attempts to
identify the service by banner or protocol.  Updates the ServiceRegistry
with discovered services.

Used in 'hybrid' deployment mode where users start services manually and
the framework discovers them automatically.
"""

import logging
import socket
import time
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from mininet.net import Mininet

from config_loader import TopologyConfig
from network.ip_allocator import AllocationResult
from services.service_registry import ServiceRegistry, ServiceInstance

logger = logging.getLogger(__name__)

# Ports to probe during auto-discovery
_PROBE_PORTS = [
    21,    # FTP
    22,    # SSH
    25,    # SMTP
    53,    # DNS (UDP)
    80,    # HTTP
    443,   # HTTPS
    7,     # Echo
    8080, 8443, 8888, 9090, 9000, 9001,
]

# Banner fingerprints → service type
_BANNERS = {
    b"220":      "smtp",
    b"220-":     "ftp",
    b"SSH-":     "ssh",
    b"HTTP/":    "http",
    b"<!DOCTYPE": "http",
    b"<html":    "http",
}


class ServiceDiscovery:
    """Probes hosts and registers discovered services."""

    def __init__(
        self,
        net: "Mininet",
        config: TopologyConfig,
        allocation: AllocationResult,
        registry: ServiceRegistry,
    ) -> None:
        self.net = net
        self.config = config
        self.allocation = allocation
        self.registry = registry

    # ----------------------------------------------------------------- public

    def discover_all(self) -> None:
        """Scan every non-switch host and register found services."""
        logger.info("Starting service discovery …")
        for node_cfg in self.config.nodes:
            if node_cfg.is_switch():
                continue
            self._discover_node(node_cfg.name)
        logger.info("Discovery complete")
        self.registry.print_table()

    # --------------------------------------------------------------- internals

    def _discover_node(self, node_name: str) -> None:
        node = self.net[node_name]

        # Use ss to list all listening ports (fast, inside namespace)
        out = node.cmd("ss -tlnp 2>/dev/null; ss -ulnp 2>/dev/null").strip()
        open_ports = self._parse_ss(out)

        for port, proto in open_ports.items():
            if self._already_registered(node_name, port):
                continue
            service_type = self._identify(node, port, proto)
            if service_type:
                # Avoid duplicate registration
                if not self._already_registered(node_name, port):
                    inst = self.registry.register(node_name, service_type, port)
                    inst.status = "running"
                    logger.debug(
                        "Discovered: %s %s/%d", node_name, service_type, port
                    )

    def _parse_ss(self, ss_output: str) -> Dict[int, str]:
        """Parse `ss -tlnp` + `ss -ulnp` output into {port: 'tcp'|'udp'}."""
        found: Dict[int, str] = {}
        proto = "tcp"
        for line in ss_output.splitlines():
            line = line.strip()
            if not line or line.startswith("Netid"):
                if "udp" in line.lower():
                    proto = "udp"
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            if parts[0] in ("tcp", "TCP"):
                proto = "tcp"
            elif parts[0] in ("udp", "UDP"):
                proto = "udp"
            # Local address column is parts[4] → "0.0.0.0:8080"
            addr_col = parts[4] if len(parts) > 4 else ""
            if ":" in addr_col:
                try:
                    port = int(addr_col.rsplit(":", 1)[-1])
                    if port > 0:
                        found[port] = proto
                except ValueError:
                    pass
        return found

    def _identify(self, node, port: int, proto: str) -> Optional[str]:
        """Try to identify a service by probing the port."""
        # DNS (UDP 53) — special case
        if port == 53 and proto == "udp":
            return "dns"

        # SSH port 22
        if port == 22:
            return "ssh"

        # Try TCP banner grab
        node_ip = self._get_node_ip(node.name)
        if not node_ip:
            return self._guess_by_port(port)

        # Banner grab via nc inside the node's namespace
        out = node.cmd(
            f"timeout 1 nc -w 1 127.0.0.1 {port} 2>/dev/null | head -c 64 | xxd 2>/dev/null || "
            f"timeout 1 nc -w 1 127.0.0.1 {port} </dev/null 2>/dev/null | head -c 64"
        )
        # HTTP probe
        http_out = node.cmd(
            f"timeout 1 curl -sf --max-time 1 http://127.0.0.1:{port}/ 2>/dev/null | head -c 64"
        ).strip()
        if http_out:
            return "http"

        return self._guess_by_port(port)

    @staticmethod
    def _guess_by_port(port: int) -> Optional[str]:
        mapping = {
            21: "ftp", 22: "ssh", 25: "smtp", 53: "dns",
            80: "http", 443: "https", 7: "echo",
            8080: "http", 8443: "https",
            9090: "sqlite", 9000: "custom_tcp", 9001: "custom_udp",
        }
        return mapping.get(port)

    def _get_node_ip(self, node_name: str) -> Optional[str]:
        return self.allocation.get_host_ip(node_name)

    def _already_registered(self, host: str, port: int) -> bool:
        for svc in self.registry.get_services(host):
            if svc.port == port:
                return True
        return False
