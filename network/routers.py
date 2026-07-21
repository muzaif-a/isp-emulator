"""LinuxRouter — Mininet Node with IP forwarding enabled.

Any node declared as type 'router' or any node in lan_gateways is
instantiated as LinuxRouter so it can forward packets between subnets.
"""

import logging
from mininet.node import Node

logger = logging.getLogger(__name__)


class LinuxRouter(Node):
    """A Mininet host that enables IPv4 forwarding on startup.

    Behaves identically to a normal host in every way except that
    net.ipv4.ip_forward is set to 1, making it capable of routing.
    """

    def config(self, **params) -> None:  # type: ignore[override]
        super().config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")
        logger.debug("IP forwarding ON: %s", self.name)

    def terminate(self) -> None:
        self.cmd("sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1")
        super().terminate()
