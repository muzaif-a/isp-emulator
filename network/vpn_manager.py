"""VPN orchestration — deploys hub-and-spoke WireGuard from config.

This module reads vpn_peers from the topology config and:
  1. Generates keys for every VPN participant.
  2. Configures the VPN gateway as hub (accepts all clients).
  3. Configures each client to reach the gateway (and other LANs through it).
  4. Adds kernel routing entries so encrypted traffic leaves via wg0.
  5. Triggers a handshake by pinging across the tunnel.
  6. Verifies connectivity.

Adding a new VPN role requires only a config change — no code edits.
"""

import logging
import threading
import time as _time
from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:
    from mininet.net import Mininet

from config_loader import TopologyConfig, VPNPeerConfig
from .ip_allocator import AllocationResult
from .wireguard import WireGuardManager

logger = logging.getLogger(__name__)


class VPNManager:
    """Orchestrates WireGuard deployment across the Mininet topology."""

    def __init__(
        self,
        net: "Mininet",
        config: TopologyConfig,
        allocation: AllocationResult,
    ) -> None:
        self.net = net
        self.config = config
        self.allocation = allocation
        self.wg = WireGuardManager(listen_port=config.settings.vpn_port)
        self.last_deploy_timing: Dict[str, float] = {}
        self.last_verify_timing: float = 0.0

    # ----------------------------------------------------------------- public

    def deploy(self) -> None:
        """Full VPN deployment pipeline."""
        logger.info("=== VPN Deployment Start ===")

        for vp in self.config.vpn_peers:
            self._deploy_peer_group(vp)

        logger.info("=== VPN Deployment Complete ===")

    def verify(self) -> bool:
        """Verify VPN connectivity across all peer groups; return True if all pass."""
        all_ok = True
        for vp in self.config.vpn_peers:
            ok = self._verify_peer_group(vp)
            all_ok = all_ok and ok
        return all_ok

    # --------------------------------------------------------------- internals

    def _deploy_peer_group(self, vp: VPNPeerConfig) -> None:
        """Set up one hub-and-spoke group.

        Optimised vs the original:
        • Gateway sysctl (3 cmds) → 1 batched cmd
        • Client sysctl (2 cmds) → 1 batched cmd, run in parallel across clients
        • setup_node (7 cmds each) → 1 batched cmd each, run in parallel
        • Gateway wg set peer (N cmds) → 1 batched multi-peer wg set cmd
        • Client wg set + ip route (per-client multiple cmds) → batched per client,
          run in parallel across clients
        • sleep(3) → sleep(1) — handshakes complete in <100 ms in virtual network
        """
        _t0 = _time.perf_counter()

        gw_name = vp.gateway
        gw_vpn_ip = self.allocation.get_vpn_ip(gw_name)
        vpn_subnet = self.allocation.vpn_subnets.get(gw_name)
        if not gw_vpn_ip or not vpn_subnet:
            logger.error("No VPN allocation for gateway %s — skipping", gw_name)
            return

        gw_node = self.net[gw_name]
        gw_isp_ip = self.allocation.get_isp_ip(gw_name)
        mode = self.config.vpn_config.mode

        # ── Stage 1: Gateway init (1 cmd instead of 3 sysctl + N interface cmds) ──
        gw_node.cmd(
            "sysctl -w net.ipv4.ip_forward=1 "
            "net.ipv4.conf.all.rp_filter=0 "
            "net.ipv4.conf.default.rp_filter=0 > /dev/null 2>&1"
        )
        logger.info("Setting up VPN gateway: %s (%s)", gw_name, gw_vpn_ip)
        self.wg.setup_node(gw_node, vpn_ip=gw_vpn_ip)

        if self.config.vpn_config.nat:
            vpn_net = self.config.settings.vpn_base_network
            lan_net = self.config.settings.lan_base_network
            # Masquerade only for non-LAN destinations so VPN client IPs remain
            # visible to hosts inside the LAN (e.g. db1 sees the attacker's VPN IP).
            gw_node.cmd(
                f"iptables -t nat -A POSTROUTING -s {vpn_net} ! -d {lan_net} -j MASQUERADE 2>/dev/null; "
                f"iptables -t nat -A POSTROUTING -s {lan_net} ! -d {lan_net} -j MASQUERADE 2>/dev/null"
            )
            logger.info("VPN NAT/MASQUERADE enabled on %s (LAN excluded)", gw_name)

        gw_pubkey = self.wg.get_pubkey(gw_name)
        _t_gw = _time.perf_counter()

        # ── Stage 2: All client interfaces in parallel ────────────────────────
        # Each client runs on a different Mininet node (different network namespace
        # and different shell process), so concurrent node.cmd() calls are safe.
        # WireGuardManager._interfaces uses node.name as key; Python dict writes
        # with distinct keys are GIL-protected — no conflict between threads.
        client_info: List[Dict] = []
        _ci_lock = threading.Lock()
        _errors: List = []
        _err_lock = threading.Lock()

        def _setup_client(client_name: str) -> None:
            try:
                client_vpn_ip = self.allocation.get_vpn_ip(client_name)
                if not client_vpn_ip:
                    logger.error("No VPN IP for client %s — skipping", client_name)
                    return
                client_node = self.net[client_name]
                client_isp_ip = self.allocation.get_isp_ip(client_name)
                client_lan_subnet = self.allocation.lan_subnets.get(client_name)

                logger.info("Setting up VPN client: %s (%s)", client_name, client_vpn_ip)
                client_node.cmd(
                    "sysctl -w net.ipv4.conf.all.rp_filter=0 "
                    "net.ipv4.conf.default.rp_filter=0 > /dev/null 2>&1"
                )
                self.wg.setup_node(client_node, vpn_ip=client_vpn_ip)
                client_pubkey = self.wg.get_pubkey(client_name)
                with _ci_lock:
                    client_info.append({
                        "name": client_name,
                        "node": client_node,
                        "vpn_ip": client_vpn_ip,
                        "isp_ip": client_isp_ip,
                        "lan_subnet": client_lan_subnet,
                        "pubkey": client_pubkey,
                    })
            except Exception as exc:
                with _err_lock:
                    _errors.append((client_name, exc))

        threads = [threading.Thread(target=_setup_client, args=(cn,), daemon=True)
                   for cn in vp.clients]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for cn, exc in _errors:
            logger.error("Client setup failed for %s: %s", cn, exc)
        _t_clients = _time.perf_counter()

        # ── Stage 3: Gateway peers — one batched wg set for all clients ───────
        # wg set accepts multiple 'peer KEY ...' clauses in one invocation, so
        # N sequential add_peer() calls collapse into a single node.cmd().
        gw_peers = []
        for ci in client_info:
            if not ci["pubkey"]:
                continue
            is_site = bool(ci["lan_subnet"])
            client_allowed = [f"{ci['vpn_ip']}/32"]
            if mode in ("site_to_site", "hybrid") and is_site:
                client_allowed.append(str(ci["lan_subnet"]))
            client_endpoint = (
                f"{ci['isp_ip']}:{self.config.settings.vpn_port}"
                if ci["isp_ip"] else None
            )
            gw_peers.append((ci["pubkey"], client_allowed, client_endpoint))
        self.wg.add_peers_batch(gw_node, gw_peers)
        _t_gw_peers = _time.perf_counter()

        # ── Stage 4: Client peers + routes — parallel across clients ──────────
        # Each client configures its own wg0 peer entry and installs its routes.
        # All operations are on distinct nodes → no concurrent cmd() on same node.
        gw_endpoint = (
            f"{gw_isp_ip}:{self.config.settings.vpn_port}" if gw_isp_ip else None
        )

        def _wire_client(ci: Dict) -> None:
            try:
                if not ci["pubkey"]:
                    return
                is_site = bool(ci["lan_subnet"])

                # What this client routes via the gateway
                gw_allowed = [str(vpn_subnet)]
                if mode in ("site_to_site", "hybrid") and is_site:
                    for other_gw, other_subnet in self.allocation.lan_subnets.items():
                        if other_gw != ci["name"]:
                            gw_allowed.append(str(other_subnet))
                elif mode == "remote_access":
                    for other_subnet in self.allocation.lan_subnets.values():
                        gw_allowed.append(str(other_subnet))

                self.wg.add_peer(
                    ci["node"],
                    peer_pubkey=gw_pubkey,
                    allowed_ips=gw_allowed,
                    endpoint=gw_endpoint,
                )

                # Kernel routes — batched into one node.cmd()
                route_subnets = [str(vpn_subnet)]
                if mode in ("site_to_site", "hybrid") and is_site:
                    for other_gw, other_subnet in self.allocation.lan_subnets.items():
                        if other_gw != ci["name"]:
                            route_subnets.append(str(other_subnet))
                elif mode == "remote_access":
                    for other_subnet in self.allocation.lan_subnets.values():
                        route_subnets.append(str(other_subnet))
                self.wg.add_ip_routes_batch(ci["node"], route_subnets)
                # Real masquerade: replace LAN src IP with VPN IP for wg0 traffic.
                # db1 then sees the VPN IP directly — no code-level substitution needed.
                ci["node"].cmd(
                    "iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE 2>/dev/null"
                )
                logger.info("Client MASQUERADE on wg0 enabled: %s", ci["name"])
            except Exception as exc:
                logger.error("Client wiring failed for %s: %s", ci["name"], exc)

        # Gateway routes for site clients (batched into one cmd).
        # Included in the same thread pool as client wiring — gw_node is not
        # used by any _wire_client thread, so there is no concurrent cmd()
        # conflict on the gateway node.
        gw_route_subnets = [
            str(ci["lan_subnet"])
            for ci in client_info
            if ci["lan_subnet"] and mode in ("site_to_site", "hybrid")
        ]

        def _gw_routes() -> None:
            self.wg.add_ip_routes_batch(gw_node, gw_route_subnets)

        threads = [threading.Thread(target=_wire_client, args=(ci,), daemon=True)
                   for ci in client_info]
        threads.append(threading.Thread(target=_gw_routes, daemon=True))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        _t_routes = _time.perf_counter()

        # ── Stage 5: Trigger handshakes ───────────────────────────────────────
        logger.info("Triggering WireGuard handshakes …")
        for ci in client_info:
            ci["node"].cmd(f"ping -c 1 -W 2 {gw_vpn_ip} > /dev/null 2>&1 &")
        _time.sleep(1)  # 1 s is ample in a virtual network; handshakes < 100 ms
        _t_done = _time.perf_counter()

        self.last_deploy_timing = {
            "gateway_init":       _t_gw      - _t0,
            "client_init":        _t_clients  - _t_gw,
            "gateway_peers":      _t_gw_peers - _t_clients,
            "client_wire_routes": _t_routes   - _t_gw_peers,
            "handshake_trigger":  _t_done     - _t_routes,
            "n_clients":          len(client_info),
        }
        logger.info("=== VPN deploy %.2fs ===", _t_done - _t0)

    def _verify_peer_group(self, vp: VPNPeerConfig) -> bool:
        """Ping VPN IPs across all peer pairs; return True if all pass.

        All pings run in parallel threads.  A per-node lock serialises
        concurrent cmd() calls on the same Mininet node (which shares a shell
        process) while allowing pings from different source nodes to run
        simultaneously.  ping count=1 is enough to confirm a tunnel is up.
        """
        _t0 = _time.perf_counter()
        gw_name = vp.gateway
        gw_vpn_ip = self.allocation.get_vpn_ip(gw_name)
        gw_node = self.net[gw_name]

        # Collect all (src_node, dst_ip) pairs
        tasks: List[tuple] = []
        for client_name in vp.clients:
            client_vpn_ip = self.allocation.get_vpn_ip(client_name)
            client_node = self.net[client_name]
            tasks.append((client_node, gw_vpn_ip))   # client → gateway
            tasks.append((gw_node, client_vpn_ip))   # gateway → client

        for i, c1_name in enumerate(vp.clients):
            for c2_name in vp.clients[i + 1:]:
                c2_vpn = self.allocation.get_vpn_ip(c2_name)
                tasks.append((self.net[c1_name], c2_vpn))

        # Per-node locks prevent concurrent cmd() on the same Mininet node
        node_locks: Dict[str, threading.Lock] = {}
        for src_node, _ in tasks:
            if src_node.name not in node_locks:
                node_locks[src_node.name] = threading.Lock()

        results: List[bool] = []
        _res_lock = threading.Lock()

        def _ping(src_node, dst_ip: str) -> None:
            with node_locks[src_node.name]:
                ok = self.wg.ping_vpn(src_node, dst_ip)
            with _res_lock:
                results.append(ok)

        threads = [threading.Thread(target=_ping, args=(src, dst), daemon=True)
                   for src, dst in tasks]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.last_verify_timing = _time.perf_counter() - _t0
        return all(results) if results else True
