"""Service Registry — tracks running services across the topology."""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Default ports for well-known services
DEFAULT_PORTS = {
    "http":       8080,
    "https":      8443,
    "ftp":        21,
    "smtp":       25,
    "dns":        53,
    "ssh":        22,
    "echo":       7,
    "sqlite":     9090,
    "database":   9090,
    "custom_tcp": 9000,
    "custom_udp": 9001,
}


@dataclass
class ServiceInstance:
    """One running service on one host."""
    host: str
    service_type: str
    port: int
    pid: str = ""           # PID string from host.cmd output (best-effort)
    status: str = "unknown" # running | failed | unknown


@dataclass
class ServiceRegistry:
    """Central registry for all deployed services."""
    _entries: List[ServiceInstance] = field(default_factory=list)

    def register(self, host: str, service_type: str, port: int, pid: str = "") -> ServiceInstance:
        inst = ServiceInstance(host=host, service_type=service_type, port=port, pid=pid)
        self._entries.append(inst)
        logger.info("Registered: %s/%s on port %d (pid=%s)", host, service_type, port, pid or "?")
        return inst

    def get_services(self, host: Optional[str] = None) -> List[ServiceInstance]:
        if host:
            return [e for e in self._entries if e.host == host]
        return list(self._entries)

    def get_by_type(self, service_type: str) -> List[ServiceInstance]:
        return [e for e in self._entries if e.service_type == service_type]

    def update_status(self, host: str, port: int, status: str) -> None:
        for e in self._entries:
            if e.host == host and e.port == port:
                e.status = status

    def print_table(self) -> None:
        """Print formatted service registry table."""
        print(f"\n{'HOST':<14} {'SERVICE':<14} {'PORT':<8} {'STATUS'}")
        print("-" * 50)
        for e in sorted(self._entries, key=lambda x: (x.host, x.port)):
            print(f"  {e.host:<12}  {e.service_type:<12}  {e.port:<6}  {e.status}")
        print()

    def resolve(self, host: str, service_type: str) -> Optional[ServiceInstance]:
        """Find the first running instance of service_type on host."""
        for e in self._entries:
            if e.host == host and e.service_type == service_type:
                return e
        return None

    def all_endpoints(self) -> List[Dict]:
        """Return list of {host, ip, service, port} dicts (ip filled by caller)."""
        return [
            {"host": e.host, "service": e.service_type, "port": e.port}
            for e in self._entries
        ]


def effective_port(service_type: str, declared_port: Optional[int]) -> int:
    """Return declared port if given, else the well-known default."""
    if declared_port:
        return declared_port
    return DEFAULT_PORTS.get(service_type, 8080)
