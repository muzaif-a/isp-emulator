"""Runtime VPN controller — turn WireGuard on/off without rebuilding topology.

Reuses VPNManager for actual WireGuard operations so all key generation,
peer wiring, and route installation logic stays in one place.

Lifecycle
---------
VPNController is created by ISPTopology after the initial VPN deploy.
It holds a reference to the Mininet net, config, and allocation so it
can tear down and redeploy WireGuard at any time.
"""

import logging
import threading
import time as _time
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from mininet.net import Mininet

from config_loader import TopologyConfig
from .ip_allocator import AllocationResult

logger = logging.getLogger(__name__)


class VPNController:
    """Runtime VPN management without topology rebuild."""

    def __init__(
        self,
        net: "Mininet",
        config: TopologyConfig,
        allocation: AllocationResult,
    ) -> None:
        self.net = net
        self.config = config
        self.allocation = allocation
        self._active: bool = False
        self._vpn_manager = None    # recreated on each turn_on()

    # ------------------------------------------------------------------ public

    def mark_active(self) -> None:
        """Call after ISPTopology's initial VPN deploy to record state."""
        self._active = True

    def is_active(self) -> bool:
        return self._active

    # -------------------------------------------------------------- status

    def status(self) -> Dict:
        """Return per-node VPN status dict."""
        result: Dict = {"active": self._active, "nodes": {}}
        for name in self.config.all_vpn_participants():
            node = self.net[name]
            link_out = node.cmd("ip link show wg0 2>/dev/null").strip()
            handshakes = node.cmd("wg show wg0 latest-handshakes 2>/dev/null").strip()
            hs_lines = [l for l in handshakes.splitlines() if l.strip()]
            live = sum(
                1 for l in hs_lines
                if len(l.split()) >= 2 and l.split()[1].isdigit() and int(l.split()[1]) > 0
            )
            result["nodes"][name] = {
                "interface_up": "wg0" in link_out,
                "handshakes_live": live,
                "total_peers": len(hs_lines),
            }
        return result

    def print_status(self) -> None:
        """Print formatted VPN status table to stdout."""
        st = self.status()
        active_str = "ACTIVE" if st["active"] else "INACTIVE"
        print(f"\n[VPN] Status: {active_str}")
        print(f"  {'Node':<14} {'wg0 UP':<10} {'Live / Total peers'}")
        print("  " + "-" * 42)
        for name, info in sorted(st["nodes"].items()):
            up = "yes" if info["interface_up"] else "no"
            peers = f"{info['handshakes_live']} / {info['total_peers']}"
            print(f"  {name:<14} {up:<10} {peers}")
        print()

    # -------------------------------------------------------------- control

    def turn_off(self) -> None:
        """Remove WireGuard interfaces and VPN routes from every participant."""
        print("[VPN] Turning OFF …", flush=True)
        self._purge_wg_state()
        self._active = False
        print("[VPN] OFF — traffic now uses normal ISP routing.", flush=True)

    def turn_on(self) -> None:
        """Redeploy WireGuard VPN from scratch using VPNManager.

        Always removes existing wg0 interfaces before deploying so that
        repeated 'vpn on' calls never accumulate stale peers.
        Prints a per-stage timing table after completion.
        """
        if not self.config.vpn_peers:
            print("[VPN] No vpn_peers configured — nothing to start.", flush=True)
            return

        _t_start = _time.perf_counter()

        # Remove all existing WireGuard state regardless of _active flag.
        self._purge_wg_state()
        _t_purge = _time.perf_counter()

        print("[VPN] Turning ON …", flush=True)
        from .vpn_manager import VPNManager
        self._vpn_manager = VPNManager(self.net, self.config, self.allocation)
        self._vpn_manager.deploy()
        _t_deploy = _time.perf_counter()

        ok = self._vpn_manager.verify()
        _t_verify = _time.perf_counter()

        self._active = True

        # ── Timing table ──────────────────────────────────────────────────────
        dt = self._vpn_manager.last_deploy_timing
        n = int(dt.get("n_clients", 0))
        _total = _t_verify - _t_start
        print(
            f"\n[VPN] Startup profiling:\n"
            f"  Purge existing state ........ {_t_purge - _t_start:6.2f}s\n"
            f"  Gateway init ................ {dt.get('gateway_init', 0):6.2f}s\n"
            f"  Client init (×{n}, parallel) .. {dt.get('client_init', 0):6.2f}s\n"
            f"  Gateway peer config ......... {dt.get('gateway_peers', 0):6.2f}s\n"
            f"  Client wire+routes (parallel) {dt.get('client_wire_routes', 0):6.2f}s\n"
            f"  Handshake trigger+wait ...... {dt.get('handshake_trigger', 0):6.2f}s\n"
            f"  Verification (parallel) ..... {self._vpn_manager.last_verify_timing:6.2f}s\n"
            f"  {'─'*38}\n"
            f"  Total ....................... {_total:6.2f}s\n",
            flush=True,
        )

        if ok:
            print("[VPN] ON — all peers connected.", flush=True)
        else:
            print("[VPN] ON — some peers may not be connected (run 'vpn status').", flush=True)

    def _purge_wg_state(self) -> None:
        """Delete all wg0 interfaces and stale VPN routes unconditionally.

        Called before every deployment so that repeated 'vpn on' calls start
        with a clean slate — no peer accumulation, no stale routes.

        All per-node deletions are batched into a single node.cmd() using
        semicolons, reducing N×M sequential calls to one call per participant.
        """
        # Collect all subnets to delete (same set for every node)
        vpn_subnets = [
            str(self.allocation.vpn_subnets[vp.gateway])
            for vp in self.config.vpn_peers
            if vp.gateway in self.allocation.vpn_subnets
        ]
        lan_subnets = [str(s) for s in self.allocation.lan_subnets.values()]

        parts = ["ip link del wg0 2>/dev/null"]
        for s in vpn_subnets:
            parts.append(f"ip route del {s} 2>/dev/null")
        for s in lan_subnets:
            parts.append(f"ip route del {s} dev wg0 2>/dev/null")
        parts.append("iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE 2>/dev/null")
        compound = "; ".join(parts) + "; true"

        # All participants are on independent Mininet nodes (different shells),
        # so concurrent cmd() calls are safe.
        threads: List[threading.Thread] = [
            threading.Thread(
                target=lambda n=name: self.net[n].cmd(compound),
                daemon=True,
            )
            for name in self.config.all_vpn_participants()
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def restart(self) -> None:
        """Tear down VPN and bring it back up."""
        print("[VPN] Restarting …", flush=True)
        self.turn_off()
        self.turn_on()
        print("[VPN] Restart complete.", flush=True)
