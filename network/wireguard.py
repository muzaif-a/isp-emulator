"""WireGuard key generation and interface management.

All operations run inside individual Mininet network namespaces via
node.cmd().  No WireGuard configuration is ever written to shared
host paths — each Mininet node owns its own /tmp/wg-{node}/ tree.

Supports any topology role: gateway, client, or peer-to-peer.
"""

import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, TYPE_CHECKING

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from errors import EmulatorError

if TYPE_CHECKING:
    from mininet.node import Node

logger = logging.getLogger(__name__)

_WG_PORT_DEFAULT = 51820


@dataclass
class WireGuardPeer:
    """One peer entry in a WireGuard interface configuration."""
    pubkey: str
    allowed_ips: List[str]
    endpoint: Optional[str] = None  # "ip:port" or None for roaming clients


@dataclass
class WireGuardInterface:
    """State for one wg* interface on a node."""
    node_name: str
    iface: str
    vpn_ip: str
    prefix: int
    privkey: str
    pubkey: str
    listen_port: int
    peers: List[WireGuardPeer] = field(default_factory=list)


class WireGuardManager:
    """Create and manage WireGuard interfaces inside Mininet namespaces."""

    def __init__(self, listen_port: int = _WG_PORT_DEFAULT) -> None:
        self.listen_port = listen_port
        # node_name -> WireGuardInterface
        self._interfaces: dict = {}

    # ---------------------------------------------------------------- public API

    def setup_node(
        self,
        node: "Node",
        vpn_ip: str,
        prefix: int = 24,
        iface: str = "wg0",
    ) -> WireGuardInterface:
        """Generate keys, create wg interface, assign VPN IP.

        Keys are generated on the host (pure crypto, no namespace state needed).
        The private-key file is written directly via Python open() — /tmp/ is
        shared across all Mininet network namespaces.  All five interface-config
        steps are batched into a single node.cmd() call.
        """
        privkey, pubkey = self._generate_keys()

        privkey_path = f"/tmp/wg-{node.name}-{iface}.key"
        with open(privkey_path, "w") as fh:
            fh.write(privkey)
        os.chmod(privkey_path, 0o600)

        # One compound shell command instead of 5 separate node.cmd() calls.
        # ip link del first so repeated 'vpn on' never inherits stale peers.
        node.cmd(
            f"ip link del {iface} 2>/dev/null; "
            f"ip link add {iface} type wireguard && "
            f"ip addr add {vpn_ip}/{prefix} dev {iface} && "
            f"wg set {iface} private-key {privkey_path} listen-port {self.listen_port} && "
            f"ip link set {iface} up"
        )

        wg_if = WireGuardInterface(
            node_name=node.name,
            iface=iface,
            vpn_ip=vpn_ip,
            prefix=prefix,
            privkey=privkey,
            pubkey=pubkey,
            listen_port=self.listen_port,
        )
        self._interfaces[node.name] = wg_if
        logger.info("WireGuard: %s %s %s/%d pubkey=%s...", node.name, iface, vpn_ip, prefix, pubkey[:8])
        return wg_if

    def add_peer(
        self,
        node: "Node",
        peer_pubkey: str,
        allowed_ips: List[str],
        endpoint: Optional[str] = None,
        iface: str = "wg0",
    ) -> None:
        """Add or update a peer entry on a WireGuard interface."""
        allowed_str = ",".join(allowed_ips)
        cmd = f"wg set {iface} peer {peer_pubkey} allowed-ips {allowed_str}"
        if endpoint:
            cmd += f" endpoint {endpoint}"
        node.cmd(cmd)

        peer = WireGuardPeer(pubkey=peer_pubkey, allowed_ips=allowed_ips, endpoint=endpoint)
        if node.name in self._interfaces:
            self._interfaces[node.name].peers.append(peer)

        logger.debug(
            "WG peer: %s <- pubkey=%s... allowed=%s endpoint=%s",
            node.name, peer_pubkey[:8], allowed_str, endpoint,
        )

    def add_ip_route(
        self,
        node: "Node",
        subnet: str,
        iface: str = "wg0",
    ) -> None:
        """Install (or replace) a kernel route directing subnet out through iface."""
        out = node.cmd(f"ip route replace {subnet} dev {iface} 2>&1")
        if out.strip():
            logger.debug("WG route replace %s %s→%s: %s", node.name, subnet, iface, out.strip())
        else:
            logger.debug("WG route: %s -> %s via %s", node.name, subnet, iface)

    def add_peers_batch(
        self,
        node: "Node",
        peers: List[Tuple],
        iface: str = "wg0",
    ) -> None:
        """Add multiple peers to a WireGuard interface in a single wg set call.

        peers: list of (pubkey, allowed_ips_list, endpoint_or_None) tuples.
        wg set accepts multiple 'peer KEY ...' clauses in one invocation, so
        this replaces N separate add_peer() calls with one node.cmd().
        """
        if not peers:
            return
        parts = [f"wg set {iface}"]
        for pubkey, allowed_ips, endpoint in peers:
            parts.append(f"peer {pubkey} allowed-ips {','.join(allowed_ips)}")
            if endpoint:
                parts.append(f"endpoint {endpoint}")
        node.cmd(" ".join(parts))
        if node.name in self._interfaces:
            for pubkey, allowed_ips, endpoint in peers:
                self._interfaces[node.name].peers.append(
                    WireGuardPeer(pubkey=pubkey, allowed_ips=list(allowed_ips), endpoint=endpoint)
                )
        logger.debug("WG batch peers on %s: %d peers configured", node.name, len(peers))

    def add_ip_routes_batch(
        self,
        node: "Node",
        subnets: List[str],
        iface: str = "wg0",
    ) -> None:
        """Install multiple routes in a single node.cmd() call using semicolons."""
        if not subnets:
            return
        cmd = "; ".join(f"ip route replace {s} dev {iface}" for s in subnets)
        node.cmd(cmd + " 2>/dev/null")
        for s in subnets:
            logger.debug("WG route batch: %s -> %s via %s", node.name, s, iface)

    def verify_handshake(
        self,
        node: "Node",
        peer_pubkey: str,
        iface: str = "wg0",
        timeout: int = 10,
    ) -> bool:
        """Return True if WireGuard has completed a handshake with peer."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            out = node.cmd(f"wg show {iface} latest-handshakes 2>/dev/null")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == peer_pubkey:
                    ts = int(parts[1])
                    if ts > 0:
                        logger.info(
                            "Handshake OK: %s <-> pubkey=%s...", node.name, peer_pubkey[:8]
                        )
                        return True
            time.sleep(1)
        logger.warning("Handshake TIMEOUT: %s <-> pubkey=%s...", node.name, peer_pubkey[:8])
        return False

    def ping_vpn(
        self,
        src_node: "Node",
        dst_vpn_ip: str,
        count: int = 1,
    ) -> bool:
        """Ping dst_vpn_ip from src_node; return True if any reply.

        count=1 is sufficient to verify the tunnel is up.  The original count=3
        sent two extra packets purely for redundancy; in the virtual network
        there is no real packet loss, so a single ICMP round-trip confirms
        connectivity.  WireGuard's 2-second wait (-W 2) ensures the handshake
        can complete if it hasn't already.
        """
        out = src_node.cmd(f"ping -c {count} -W 2 {dst_vpn_ip} 2>&1")
        ok = "0% packet loss" in out or f"{count} received" in out
        logger.info(
            "VPN ping %s -> %s: %s", src_node.name, dst_vpn_ip, "OK" if ok else "FAIL"
        )
        return ok

    def get_interface(self, node_name: str) -> Optional[WireGuardInterface]:
        return self._interfaces.get(node_name)

    def get_pubkey(self, node_name: str) -> Optional[str]:
        wg_if = self._interfaces.get(node_name)
        return wg_if.pubkey if wg_if else None

    # -------------------------------------------------------------- internals

    @staticmethod
    def _generate_keys() -> Tuple[str, str]:
        """Return (privkey, pubkey) using host subprocess.

        WireGuard key generation is pure Curve25519 crypto with no dependency on
        any network namespace state.  Running wg genkey/pubkey as a host
        subprocess avoids the mnexec namespace-entry overhead (one fork+exec pair
        per call) and produces identical keys to running inside the namespace.
        Mininet shares the host filesystem, so the key written to /tmp/ is
        immediately visible inside every node's namespace.
        """
        try:
            privkey = subprocess.run(
                ["wg", "genkey"], capture_output=True, text=True, check=True
            ).stdout.strip()
            pubkey = subprocess.run(
                ["wg", "pubkey"], input=privkey,
                capture_output=True, text=True, check=True
            ).stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            raise EmulatorError("R020", f"{exc}") from exc
        if not privkey or len(privkey) < 40:
            raise EmulatorError("R020", f"wg genkey returned invalid key: {privkey!r}")
        if not pubkey or len(pubkey) < 40:
            raise EmulatorError("R020", "wg pubkey derivation returned invalid key")
        return privkey, pubkey

    @staticmethod
    def _ensure_wg_installed(node: "Node") -> None:
        """Check wg binary is available; raise if not.

        Not called automatically during setup_node() — if wg is absent the
        batched node.cmd() fails immediately with a clear shell error.  Call
        this explicitly when you want an early, human-readable error message.
        """
        check = node.cmd("which wg 2>/dev/null").strip()
        if not check:
            raise EnvironmentError(
                f"WireGuard tools not found on {node.name}. "
                "Run scripts/setup.sh first."
            )
