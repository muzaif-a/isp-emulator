"""
NPC multi-application traffic orchestrator.

Starts one thread per NPC host. Each thread selects behaviors from a
CAIDA-weighted table (scaled by intensity) and executes them inside the
Mininet host's network namespace.

Intensity → ρ (link utilisation):
  low    → 0.20–0.30   clean watermark
  medium → 0.50–0.70   mild jitter
  high   → 0.90–1.00+  noisy rhythm

CLI usage (via ISPCli):
  npc start [--intensity low|medium|high]
  npc stop
  npc status
"""

import logging
import os
import random
import threading
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from mininet.net import Mininet

from . import behaviors as _beh
from .intensity import INTER_ARRIVAL_S, WEIGHTS

logger = logging.getLogger(__name__)

# Max concurrent heavy processes (FTP / SMTP / Bulk): min(cpu_count-2, 4)
_MAX_HEAVY = max(1, min(4, (os.cpu_count() or 4) - 2))

# Behaviors that count toward the heavy-process cap
_HEAVY = {"ftp", "smtp", "bulk"}


class NPCManager:
    """Round-based NPC traffic orchestrator."""

    def __init__(self, net, allocation, host_intensity: Dict[str, str] = None) -> None:
        self.net            = net
        self.allocation     = allocation
        self._host_intensity: Dict[str, str] = host_intensity or {}

        self._intensity: Optional[str] = None   # None = per-host default
        self._threads:   Dict[str, threading.Thread] = {}
        self._stops:     Dict[str, threading.Event]  = {}
        self._stats:     Dict[str, Dict]             = {}
        self._running    = False
        self._heavy_sem  = threading.Semaphore(_MAX_HEAVY)

        # Resolve service IPs once at construction
        self._web1_ip  = allocation.get_host_ip("web1") or "127.0.0.1"
        self._ftp1_ip  = allocation.get_host_ip("ftp1") or "127.0.0.1"
        self._dns1_ip  = allocation.get_host_ip("dns1") or "127.0.0.1"
        self._db1_ip   = allocation.get_host_ip("db1")  or "127.0.0.1"
        self._echo_ip  = allocation.get_host_ip("h1")   or "127.0.0.1"

    # ------------------------------------------------------------------ public

    def start(self, intensity: Optional[str] = None) -> None:
        if self._running:
            print("[NPC] Already running. Use 'npc stop' first.")
            return

        if intensity and intensity not in WEIGHTS:
            print(f"[NPC] Unknown intensity '{intensity}'. Use: low | medium | high")
            return
        self._intensity = intensity

        present = [h for h in self._host_intensity if h in self.net]
        if not present:
            print("[NPC] No NPC hosts found in topology.")
            return

        # Start iperf3 servers on every NPC host for bulk behavior
        for h in present:
            self.net[h].cmd("pkill iperf3 2>/dev/null; iperf3 -s -D -p 5201 > /dev/null 2>&1")

        self._running = True
        for host in present:
            host_intensity = self._intensity or self._host_intensity.get(host, "medium")
            stop_ev = threading.Event()
            self._stops[host] = stop_ev
            self._stats[host] = {"intensity": host_intensity, "rounds": 0, "counts": {}}

            t = threading.Thread(
                target=self._host_loop,
                args=(host, host_intensity, stop_ev),
                daemon=True,
                name=f"npc-{host}",
            )
            self._threads[host] = t
            t.start()

        label = self._intensity or "per-host"
        print(f"[NPC] Started {len(present)} NPC hosts. Intensity: {label}. "
              f"Max heavy procs: {_MAX_HEAVY}.")

    def stop(self) -> None:
        if not self._running:
            print("[NPC] Not running.")
            return
        for ev in self._stops.values():
            ev.set()
        for t in self._threads.values():
            t.join(timeout=15)
        self._threads.clear()
        self._stops.clear()
        self._running = False
        print("[NPC] Stopped.")

    def status(self) -> None:
        if not self._running:
            print("[NPC] Not running.")
            return
        print(f"[NPC] Running.  Max heavy: {_MAX_HEAVY}")
        print(f"{'Host':<8} {'Intensity':<8} {'Rounds':>7}  Top behaviors")
        for host, stat in self._stats.items():
            top = sorted(stat["counts"].items(), key=lambda x: -x[1])[:4]
            top_str = "  ".join(f"{b}={n}" for b, n in top) or "-"
            print(f"  {host:<6}  {stat['intensity']:<8}  {stat['rounds']:>6}   {top_str}")

    def is_running(self) -> bool:
        return self._running

    def get_host_intensity(self, host: str) -> str:
        return self._intensity or self._host_intensity.get(host, "medium")

    # -------------------------------------------------------------- internals

    def _host_loop(
        self, host: str, intensity: str, stop_ev: threading.Event
    ) -> None:
        weights_map = WEIGHTS.get(intensity, WEIGHTS["medium"])
        node        = self.net[host]
        stat        = self._stats[host]

        behavior_names   = [b for b, w in weights_map.items() if w > 0]
        behavior_weights = [weights_map[b] for b in behavior_names]

        # Peer IPs for bulk behavior
        peers = [
            self.allocation.get_host_ip(h)
            for h in self._host_intensity
            if h != host and h in self.net and self.allocation.get_host_ip(h)
        ]

        # Priming phase: fire each non-idle service behavior once immediately
        # so every capture window contains at least one DNS, HTTP, SMTP, FTP etc.
        # Skips bulk (iperf3 takes 5s) and idle. Heavy semaphore still applies.
        _prime_order = ["http", "dns", "db", "echo", "smtp", "ftp"]
        for _b in _prime_order:
            if stop_ev.is_set():
                break
            if _b in behavior_names:
                try:
                    self._run(node, _b, peers)
                except Exception as exc:
                    logger.debug("[NPC] %s/prime/%s error: %s", host, _b, exc)

        while not stop_ev.is_set():
            behavior = random.choices(behavior_names, weights=behavior_weights, k=1)[0]
            stat["rounds"] += 1
            stat["counts"][behavior] = stat["counts"].get(behavior, 0) + 1

            try:
                self._run(node, behavior, peers)
            except Exception as exc:
                logger.debug("[NPC] %s/%s error: %s", host, behavior, exc)

            wait = self._sample_inter_arrival(behavior)
            stop_ev.wait(timeout=wait)

    def _run(self, node, behavior: str, peers: list) -> None:
        heavy = behavior in _HEAVY
        if heavy:
            if not self._heavy_sem.acquire(blocking=False):
                return   # at concurrent cap — skip this round
        try:
            if behavior == "http":
                _beh.http(node, self._web1_ip)
            elif behavior == "dns":
                _beh.dns(node, self._dns1_ip)
            elif behavior == "db":
                _beh.db_query(node, self._db1_ip)
            elif behavior == "smtp":
                _beh.smtp(node, self._web1_ip)
            elif behavior == "ftp":
                _beh.ftp(node, self._ftp1_ip)
            elif behavior == "bulk" and peers:
                _beh.bulk(node, random.choice(peers))
            elif behavior == "echo":
                _beh.echo(node, self._echo_ip)
            elif behavior == "idle":
                _beh.idle(node)
        finally:
            if heavy:
                self._heavy_sem.release()

    @staticmethod
    def _sample_inter_arrival(behavior: str) -> float:
        mean = INTER_ARRIVAL_S.get(behavior, 10)
        if behavior == "ftp":
            return random.uniform(8, 20)
        if behavior == "smtp":
            return random.uniform(5, 15)
        return random.expovariate(1 / mean)
