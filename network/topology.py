"""Mininet topology builder — Phase 1 + Phase 2.

Reads config + allocation and constructs the network:
  1. Creates all nodes (switches, LinuxRouters, hosts).
  2. Adds links in config order (so interface indices match ip_allocator).
  3. Assigns IPs from allocation to every interface.
  4. Configures routing (ip route).
  5. Optionally deploys WireGuard VPN.
  6. [Phase 2] Deploys databases (SQLite + synthetic data + CRUD API).
  7. [Phase 2] Deploys / discovers services.
  8. [Phase 2] Applies optional firewall rules (with auto-rollback).

Usage
-----
    from topology import ISPTopology
    topo = ISPTopology("configs/topology.yaml")
    topo.start()
    topo.cli()       # interactive Mininet shell
    topo.stop()

    # Enterprise:
    topo = ISPTopology("configs/topology_enterprise.yaml")
    topo.start(enable_vpn=True, enable_services=True, enable_firewall=True)
"""

import logging
import subprocess
import sys
from pathlib import Path
from typing import Optional, TYPE_CHECKING

# Ensure the project root is in sys.path regardless of how this file is invoked:
#   python3 network/topology.py ...      (direct script — only network/ is in path)
#   python3 -m network.topology ...      (module mode  — root already in path)
#   import network.topology              (package import — __init__.py already set path)
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from mininet.net import Mininet
from mininet.node import OVSSwitch, Host, Node
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI


class _NullController(Node):
    """Placeholder controller — no binary required.

    Modern OVS (Ubuntu 22.04/24.04) removed the standalone ovs-controller
    binary.  Mininet's API still expects a controller object in self.controllers
    for switch.start(controllers) to work correctly.

    This class satisfies that contract without starting any external process.
    OVS switches use failMode='standalone' and act as L2 learning switches
    entirely on their own — no OpenFlow controller is needed.
    """

    def start(self) -> None:
        pass

    def stop(self, deleteIntfs: bool = False) -> None:
        pass

    def checkListening(self) -> None:
        pass

from config_loader import load_config, TopologyConfig
from errors import EmulatorError
from network.ip_allocator import allocate, AllocationResult
from network.routers import LinuxRouter
from network.routing import configure_routes, dump_route_tables
from network.vpn_manager import VPNManager
from network.vpn_controller import VPNController
from network.capture_manager import CaptureManager
from debug import (
    setup_logging,
    print_topology,
    print_allocation,
    print_iface_aliases,
    print_routing_table,
)

# Phase 2 imports (optional — import only when needed to avoid hard dep on Mininet)
try:
    from services.database.database_manager import DatabaseManager
    from services.service_manager import ServiceManager
    from services.service_registry import ServiceRegistry
    from services.service_discovery import ServiceDiscovery
    from network.security.firewall_manager import FirewallManager
    _PHASE2_AVAILABLE = True
except ImportError:
    _PHASE2_AVAILABLE = False

try:
    from network.npc.npc_manager import NPCManager
    _NPC_AVAILABLE = True
except ImportError:
    _NPC_AVAILABLE = False


def _tos_exfil_script(ip: str, port: int, endpoint: str, tos: int = 0x10) -> str:
    """Python script executed inside the attacker's Mininet namespace.

    Sets IP_TOS at the socket level before connect() so only this specific
    socket carries TOS marking. No host-wide iptables rule is added, so
    concurrent NPC traffic produces unmarked packets and cannot trigger a
    spurious timing session.
    """
    return (
        "import socket, http.client, sys\n"
        "class _TOS(http.client.HTTPConnection):\n"
        "    def connect(self):\n"
        "        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        f"        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, {tos})\n"
        "        self.sock.settimeout(self.timeout)\n"
        "        self.sock.connect((self.host, self.port))\n"
        f"c = _TOS('{ip}', {port}, timeout=10)\n"
        f"c.request('GET', '{endpoint}')\n"
        "r = c.getresponse(); r.read(); print(r.status)\n"
    )


logger = logging.getLogger(__name__)


# -------------------------------------------------------------------- ISP CLI

class ISPCli(CLI):
    """Mininet CLI extended with VPN management and capture commands.

    Extra commands
    --------------
    vpn status|on|off|restart   — runtime WireGuard management
    capture status|merge|csv    — packet capture management
    """

    def __init__(
        self,
        net: "Mininet",
        vpn_controller: Optional["VPNController"] = None,
        capture_manager: Optional["CaptureManager"] = None,
        npc_manager=None,
        exfil_config=None,
        allocation=None,
        config=None,
        **kwargs,
    ) -> None:
        self._vpn_ctrl    = vpn_controller
        self._cap_mgr     = capture_manager
        self._npc_mgr     = npc_manager
        self._exfil_cfg   = exfil_config
        self._allocation  = allocation
        self._config      = config
        # inject on/off state — tracks current timing protocol state across calls
        self._inject_active:   bool           = False
        self._inject_short_ms: Optional[float] = None
        self._inject_long_ms:  Optional[float] = None
        super().__init__(net, **kwargs)

    def do_vpn(self, line: str) -> None:
        """VPN runtime control: vpn status | vpn on | vpn off | vpn restart"""
        if not self._vpn_ctrl:
            print("VPN controller not available (no vpn_peers in config)")
            return
        cmd = line.strip().lower()
        if cmd == "status":
            self._vpn_ctrl.print_status()
        elif cmd == "on":
            self._vpn_ctrl.turn_on()
        elif cmd == "off":
            self._vpn_ctrl.turn_off()
        elif cmd == "restart":
            self._vpn_ctrl.restart()
        else:
            print("Usage: vpn status|on|off|restart")

    def do_capture(self, line: str) -> None:
        """Packet capture: capture start|stop|status|merge|parseToCsv|clean|update"""
        if not self._cap_mgr:
            print("Capture manager not available")
            return
        parts = line.split()
        cmd = parts[0].lower() if parts else ""

        if cmd == "start":
            if self._cap_mgr.is_running():
                print("Capture already running — stop it first")
            else:
                if not self._cap_mgr._tc_commands:
                    self._auto_apply_tc(seed=42)
                self._cap_mgr.start()
        elif cmd == "stop":
            self._cap_mgr.stop()
        elif cmd == "status":
            self._cap_mgr.status()
        elif cmd == "merge":
            # capture merge <file1> [file2 ...] <session_id>
            # last arg is the session_id — output: dataset/pcapng/<session_id>.pcapng
            if len(parts) < 3:
                print("Usage: capture merge <file1> [file2 ...] <session_id>")
                return
            self._cap_mgr.merge(pcap_files=parts[1:-1], session_id=parts[-1])
        elif cmd == "parsetocsv":
            # capture parseToCsv <merged.pcapng>
            if len(parts) < 2:
                print("Usage: capture parseToCsv <merged.pcapng>")
                return
            self._cap_mgr.parseToCsv(pcap_file=parts[1])
        elif cmd == "clean":
            self._cap_mgr.clean()
        elif cmd == "update":
            self._cap_mgr.update()
        else:
            print("Usage: capture start|stop|status|merge|parsetocsv|clean|update")

    def do_npc(self, line: str) -> None:
        """NPC background traffic: npc start [--intensity low|medium|high] | npc stop | npc status"""
        if not self._npc_mgr:
            print("NPC manager not available.")
            return
        parts = line.split()
        cmd   = parts[0].lower() if parts else ""

        if cmd == "start":
            intensity = None
            for flag in ("--intensity", "-intensity"):
                if flag in parts:
                    idx = parts.index(flag)
                    if idx + 1 < len(parts):
                        intensity = parts[idx + 1]
                    break
            self._npc_mgr.start(intensity=intensity)
        elif cmd == "stop":
            self._npc_mgr.stop()
        elif cmd == "status":
            self._npc_mgr.status()
        else:
            print("Usage: npc start [--intensity low|medium|high] | npc stop | npc status")

    def _auto_apply_tc(self, seed: int = 42) -> None:
        """Auto-apply default TC profile (seed 42) when capture starts with no TC set."""
        from network.hardware import tc_generator
        if not self._config:
            return
        tc_cfg = getattr(self._config, "traffic_control", None)
        if not tc_cfg or not tc_cfg.interfaces:
            return
        device_classes = getattr(self._config, "device_classes", {})
        alias_map = {}
        if self._allocation:
            alias_map = {v: k for k, v in self._allocation.node_aliases.items()}
        profile = tc_generator.generate(tc_cfg, device_classes, alias_map, seed=seed)
        if not profile.commands:
            return
        def _prun(node, c: str) -> None:
            proc = node.popen(c, shell=True)
            proc.communicate()

        applied = 0
        for iface, cmd in profile.commands.items():
            alias = iface.rsplit("-eth", 1)[0]
            node_name = alias_map.get(alias, alias)
            try:
                node = self.mn[node_name]
                _prun(node, f"tc qdisc del dev {iface} root 2>/dev/null || true")
                _prun(node, cmd)
                applied += 1
            except KeyError:
                pass
        print(f"[TC] Auto-applied default TC profile (seed={seed}) to "
              f"{applied}/{len(profile.commands)} interface(s).", flush=True)
        if self._cap_mgr:
            self._cap_mgr.set_tc_profile(profile.commands)

    def do_apply(self, line: str) -> None:
        """Apply TC netem rules to interfaces from traffic_control config: apply tc [--seed N]"""
        from network.hardware import tc_generator

        parts = line.split()
        if not parts or parts[0].lower() != "tc":
            print("Usage: apply tc [--seed N]")
            return

        if self._cap_mgr and self._cap_mgr.is_running():
            print("[TC] Cannot update network profile during active capture session. "
                  "Run 'capture stop' first.")
            return

        seed = None
        if "--seed" in parts:
            idx = parts.index("--seed")
            if idx + 1 < len(parts):
                try:
                    seed = int(parts[idx + 1])
                except ValueError:
                    print("[TC] --seed must be an integer.")
                    return

        if not self._config:
            print("[TC] No config available.")
            return

        tc_cfg = getattr(self._config, "traffic_control", None)
        if not tc_cfg or not tc_cfg.interfaces:
            print("[TC] No traffic_control config in YAML — nothing to apply.")
            return

        device_classes = getattr(self._config, "device_classes", {})
        alias_map = {}
        if self._allocation:
            alias_map = {v: k for k, v in self._allocation.node_aliases.items()}

        profile = tc_generator.generate(tc_cfg, device_classes, alias_map, seed=seed)

        if not profile.commands:
            print("[TC] No interfaces matched device_classes — nothing applied.")
            return

        def _prun(node, c: str) -> None:
            proc = node.popen(c, shell=True)
            proc.communicate()

        applied = 0
        for iface, cmd in profile.commands.items():
            alias = iface.rsplit("-eth", 1)[0]
            node_name = alias_map.get(alias, alias)
            try:
                node = self.mn[node_name]
                _prun(node, f"tc qdisc del dev {iface} root 2>/dev/null || true")
                _prun(node, cmd)
                applied += 1
            except KeyError:
                print(f"[TC] Node '{node_name}' (iface={iface}) not in topology — skipped.")

        seed_str = f"  seed={seed}" if seed is not None else ""
        print(f"[TC] Applied TC rules to {applied}/{len(profile.commands)} interface(s).{seed_str}")

        if self._cap_mgr:
            self._cap_mgr.set_tc_profile(profile.commands)

    def do_exfil(self, line: str) -> None:
        """HTTP GET to DB — TOS-marked (on) or plain (off).

        Usage:
          exfil on            — GET with TOS=0x10  (attack traffic, label=1)
          exfil off           — GET with TOS=0     (normal traffic, label=0)
          exfil on --dry-run  — print selection without running

        Both modes discover attackers + databases from all configs/topology*.yaml
        files and pick a random attacker + victim + endpoint.

        TOS is scoped to the socket only — no host-wide iptables rule.
        """
        import random
        import time
        from pathlib import Path
        from config_loader import load_config

        tokens = line.split()
        dry_run = "--dry-run" in tokens
        mode_tokens = [t for t in tokens if t != "--dry-run"]

        if not mode_tokens or mode_tokens[0] not in ("on", "off"):
            print("[exfil] Usage: exfil on|off [--dry-run]", flush=True)
            return

        mode = mode_tokens[0]

        config_dir = Path(__file__).resolve().parent.parent / "configs"
        yaml_files = sorted(config_dir.glob("topology*.yaml"))

        while True:
            exfil_cfg = getattr(self._config, "exfiltration", None)
            cfg_attacker = getattr(exfil_cfg, "attacker", None)

            # Step 1: Build attacker pool.
            # If exfiltration.attacker is set, use it directly — attackers: list
            # is not required. If not set, fall back to the attackers: list
            # aggregated across all topology YAMLs.
            if cfg_attacker and cfg_attacker in self.mn:
                attackers = [cfg_attacker]
            else:
                raw_attackers: list = list(getattr(self._config, "attackers", []))
                for yaml_path in yaml_files:
                    try:
                        cfg = load_config(str(yaml_path))
                        raw_attackers.extend(cfg.attackers)
                    except Exception:
                        continue
                attackers = [a for a in dict.fromkeys(raw_attackers) if a in self.mn]

            # Step 2: Resolve victim IPs from current config databases
            victims = []
            seen_hosts: set = set()
            for db in getattr(self._config, "databases", []):
                if not db.api_port or db.host in seen_hosts or db.host not in self.mn:
                    continue
                victim_ip = self._allocation.get_host_ip(db.host) if self._allocation else None
                if not victim_ip:
                    continue
                victims.append({
                    "host": db.host,
                    "ip": victim_ip,
                    "port": db.api_port,
                    "tables": [t.name for t in db.tables],
                })
                seen_hosts.add(db.host)

            # Step 3: Check attackers and victims exist
            if not attackers or not victims:
                print("[exfil] No attackers or victim DBs. Waiting 10s …", flush=True)
                time.sleep(10)
                continue

            # Step 4: Filter victims with non-empty tables
            filtered_victims = [v for v in victims if v["tables"]]

            # Step 5: Check filtered victims have tables
            if not filtered_victims:
                print("[exfil] No victim DB has tables. Waiting 10s …", flush=True)
                time.sleep(10)
                continue

            # Step 6: Selection — exfil_cfg/cfg_attacker already resolved above
            cfg_target    = getattr(exfil_cfg, "target_host", None)
            cfg_endpoints = getattr(exfil_cfg, "endpoints", None) or []

            attacker_name = attackers[0] if len(attackers) == 1 else random.choice(attackers)
            victim = (
                next((v for v in filtered_victims if v["host"] == cfg_target), None)
                if cfg_target else None
            ) or random.choice(filtered_victims)

            # Endpoint: from exfiltration config, else random table
            if cfg_endpoints:
                endpoint = random.choice(cfg_endpoints)
            else:
                endpoint = f"/api/{random.choice(victim['tables'])}"

            # on=TOS-marked (attack), off=plain (normal)
            tos = getattr(exfil_cfg, "attack_tos", 0x10) if mode == "on" else 0

            port = victim["port"]
            ip   = victim["ip"]

            print(
                f"[exfil] mode={mode}  attacker={attacker_name}  victim={victim['host']}:{port}"
                f"  endpoint={endpoint}  ip={ip}  tos={hex(tos)}",
                flush=True,
            )

            if dry_run:
                print("[exfil] dry-run — not executing.")
                return

            node = self.mn[attacker_name]

            # Step 7: Run GET inside attacker's network namespace.
            proc = node.popen(
                [sys.executable, "-c", _tos_exfil_script(ip, port, endpoint, tos)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            out, _ = proc.communicate()
            result = out.decode().strip() if out else ""

            print(f"[exfil] Done. HTTP status: {result}", flush=True)
            return

    def do_inject(self, line: str) -> None:
        """Runtime timing protocol toggle for all victim DBs.

        Usage:
          inject on                              — enable with YAML defaults
          inject on --short-delay 30 --long-delay 80  — enable with custom delays
          inject off                             — disable timing protocol

        No-op when called with same state and same params already active.
        """
        import shlex

        tokens = shlex.split(line.strip()) if line.strip() else []
        cmd = tokens[0].lower() if tokens else ""

        if cmd not in ("on", "off"):
            print("Usage: inject on [--short-delay MS --long-delay MS] | inject off")
            return

        # YAML defaults from current config (first timing-enabled DB)
        yaml_short: float = 20.0
        yaml_long:  float = 50.0
        if self._config:
            for db in getattr(self._config, "databases", []):
                tp = getattr(db, "timing_protocol", None)
                if tp and getattr(tp, "enabled", False):
                    yaml_short = float(getattr(tp, "short_delay_ms", 20.0))
                    yaml_long  = float(getattr(tp, "long_delay_ms",  50.0))
                    break

        if cmd == "off":
            target_enabled = False
            # keep current delays (or YAML defaults if never set)
            target_short = self._inject_short_ms if self._inject_short_ms is not None else yaml_short
            target_long  = self._inject_long_ms  if self._inject_long_ms  is not None else yaml_long
        else:
            target_enabled = True
            target_short = yaml_short
            target_long  = yaml_long
            i = 1
            while i < len(tokens):
                if tokens[i] == "--short-delay" and i + 1 < len(tokens):
                    target_short = float(tokens[i + 1]); i += 2
                elif tokens[i] == "--long-delay" and i + 1 < len(tokens):
                    target_long = float(tokens[i + 1]); i += 2
                else:
                    i += 1

        # No-op check: same enabled state AND same delays
        same = (
            self._inject_active == target_enabled
            and self._inject_short_ms is not None
            and abs(self._inject_short_ms - target_short) < 0.001
            and self._inject_long_ms  is not None
            and abs(self._inject_long_ms  - target_long)  < 0.001
        )
        if same:
            state_str = "on" if target_enabled else "off"
            print(f"[inject] Already {state_str} with same params — no change.", flush=True)
            return

        # Push to all victim DB APIs running in current net
        updated = 0
        if self._config and self._allocation:
            payload = (
                f'{{"enabled":{str(target_enabled).lower()},'
                f'"short_delay_ms":{target_short},'
                f'"long_delay_ms":{target_long}}}'
            )
            for db in getattr(self._config, "databases", []):
                if not db.api_port or db.host not in self.mn:
                    continue
                victim_ip = self._allocation.get_host_ip(db.host)
                if not victim_ip:
                    continue
                node = self.mn[db.host]
                node.cmd(
                    f"curl -sf -X POST http://127.0.0.1:{db.api_port}/timing/set "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{payload}' -o /dev/null 2>/dev/null || true"
                )
                updated += 1

        # Update CLI state
        self._inject_active   = target_enabled
        self._inject_short_ms = target_short
        self._inject_long_ms  = target_long

        if target_enabled:
            print(
                f"[inject] ON — short_delay={target_short}ms  long_delay={target_long}ms"
                f"  ({updated} DB(s) updated)",
                flush=True,
            )
        else:
            print(
                f"[inject] OFF — timing disabled  short_delay={target_short}ms"
                f"  long_delay={target_long}ms  ({updated} DB(s) updated)",
                flush=True,
            )


class ISPTopology:
    """Builds, runs, and tears down the complete ISP + Enterprise emulator."""

    def __init__(self, config_path: str = "configs/topology.yaml") -> None:
        self.config_path = config_path
        self.config: Optional[TopologyConfig] = None
        self.allocation: Optional[AllocationResult] = None
        self.net: Optional[Mininet] = None
        self._vpn_manager: Optional[VPNManager] = None
        # Phase 2
        self.service_registry: Optional["ServiceRegistry"] = None
        self._db_manager: Optional["DatabaseManager"] = None
        self._svc_manager: Optional["ServiceManager"] = None
        self._fw_manager: Optional["FirewallManager"] = None
        # Phase 3
        self._vpn_controller: Optional[VPNController] = None
        self._capture_manager: Optional[CaptureManager] = None
        self._npc_manager = None

    # ----------------------------------------------------------------- lifecycle

    def start(
        self,
        enable_vpn: bool = True,
        enable_cli: bool = False,
        enable_services: bool = True,    # Phase 2
        enable_firewall: bool = False,   # Phase 2 (default off — config also gates it)
    ) -> None:
        """Build the network, start it, configure routing, deploy VPN + services."""
        import traceback as _tb
        import sys as _sys

        # ── STEP 1: load config ─────────────────────────────────────────────
        print("[DBG-1] Loading config …", flush=True)
        try:
            self.config = load_config(self.config_path)
            print(f"[DBG-1] Config OK: {len(self.config.nodes)} nodes, "
                  f"{len(self.config.links)} links", flush=True)
        except EmulatorError as e:
            e.print_and_exit()
        except Exception:
            print("[DBG-1] EXCEPTION in load_config:", flush=True)
            _tb.print_exc()
            raise

        setup_logging(self.config.settings.log_level)
        # Suppress Mininet's verbose startup chatter (*** Starting switches etc.)
        # Use "output" not "warning" — "warning" also kills CLI output() calls.
        setLogLevel("output")
        print_topology(self.config)

        # ── STEP 2: allocate IPs ────────────────────────────────────────────
        print("[DBG-2] Allocating IPs …", flush=True)
        try:
            self.allocation = allocate(self.config)
            print(f"[DBG-2] Allocation OK", flush=True)
        except Exception:
            print("[DBG-2] EXCEPTION in allocate:", flush=True)
            _tb.print_exc()
            raise
        print_allocation(self.allocation)
        print_iface_aliases(self.allocation)

        # ── Validate TC interface names against allocation aliases ───────────
        tc_cfg = getattr(self.config, "traffic_control", None)
        if tc_cfg and tc_cfg.interfaces:
            all_aliases = set(self.allocation.node_aliases.values())
            all_nodes   = {n.name for n in self.config.nodes}
            known = all_aliases | all_nodes
            for iface in tc_cfg.interfaces:
                node_part = iface.rsplit("-eth", 1)[0]
                if node_part not in known:
                    print(f"[WARN] traffic_control.{iface!r}: "
                          f"node {node_part!r} not found in topology — "
                          f"interface will be skipped. Check spelling or add to nodes:",
                          flush=True)

        # ── STEP 3: build Mininet object ────────────────────────────────────
        print("[DBG-3] Building Mininet topology …", flush=True)
        try:
            self.net = self._build_network()
        except Exception:
            print("[DBG-3] EXCEPTION in _build_network:", flush=True)
            _tb.print_exc()
            raise

        built_nodes = list(self.net.keys())
        print(f"[DBG-3] net.keys()       = {built_nodes}", flush=True)
        print(f"[DBG-3] len(net.hosts)   = {len(self.net.hosts)}", flush=True)
        print(f"[DBG-3] len(net.switches)= {len(self.net.switches)}", flush=True)
        print(f"[DBG-3] len(net.links)   = {len(self.net.links)}", flush=True)
        print(f"[DBG-3] net.values()     = {list(self.net.values())}", flush=True)

        # ── STEP 4: start Mininet ───────────────────────────────────────────
        print("[DBG-4] Calling net.start() …", flush=True)
        try:
            self.net.start()
            print("[DBG-4] net.start() returned", flush=True)
        except Exception:
            print("[DBG-4] EXCEPTION in net.start():", flush=True)
            _tb.print_exc()
            raise

        # ── STEP 5: verify node processes ───────────────────────────────────
        print("[DBG-5] Verifying node processes …", flush=True)
        for node in self.net.values():
            pid = getattr(node, "pid", None)
            print(f"[DBG-5]   {node.name:10s}  pid={pid}", flush=True)

        print(f"[DBG-5] hosts   after start: {self.net.hosts}", flush=True)
        print(f"[DBG-5] switches after start: {self.net.switches}", flush=True)
        print(f"[DBG-5] links   after start: {self.net.links}", flush=True)

        # ── STEP 6: assign IPs ──────────────────────────────────────────────
        print("[DBG-6] Assigning IPs …", flush=True)
        try:
            self._assign_ips()
            print("[DBG-6] IPs assigned", flush=True)
        except Exception:
            print("[DBG-6] EXCEPTION in _assign_ips:", flush=True)
            _tb.print_exc()
            raise

        # ── STEP 7: configure routing ───────────────────────────────────────
        print("[DBG-7] Configuring routes …", flush=True)
        try:
            configure_routes(self.net, self.config, self.allocation)
            print("[DBG-7] Routes configured", flush=True)
        except Exception:
            print("[DBG-7] EXCEPTION in configure_routes:", flush=True)
            _tb.print_exc()
            raise
        self._log_route_tables()

        # ── STEP 8: VPN ─────────────────────────────────────────────────────
        # vpn_config.enabled overrides the enable_vpn flag (YAML wins)
        _vpn_should_run = enable_vpn and self.config.vpn_peers and self.config.vpn_config.enabled
        if _vpn_should_run:
            print("[DBG-8] Deploying WireGuard VPN …", flush=True)
            try:
                self._vpn_manager = VPNManager(self.net, self.config, self.allocation)
                self._vpn_manager.deploy()
                vpn_ok = self._vpn_manager.verify()
                print(f"[DBG-8] VPN deploy complete, ok={vpn_ok}", flush=True)
                # Create VPNController so the CLI can manage VPN at runtime
                self._vpn_controller = VPNController(
                    self.net, self.config, self.allocation
                )
                self._vpn_controller.mark_active()
            except Exception:
                print("[DBG-8] EXCEPTION during VPN deploy (non-fatal):", flush=True)
                _tb.print_exc()
        elif self.config.vpn_peers:
            # VPN configured but disabled via YAML — create controller in off state
            self._vpn_controller = VPNController(self.net, self.config, self.allocation)

        # ── STEP 9: Phase 2 ─────────────────────────────────────────────────
        if enable_services and _PHASE2_AVAILABLE:
            print("[DBG-9] Phase 2 deployment …", flush=True)
            try:
                self._deploy_phase2(enable_firewall=enable_firewall)
                print("[DBG-9] Phase 2 done", flush=True)
            except Exception:
                print("[DBG-9] EXCEPTION in Phase 2 (non-fatal):", flush=True)
                _tb.print_exc()

        # ── STEP 10: Traffic capture ─────────────────────────────────────────
        self._capture_manager = CaptureManager(
            self.net, self.config, self.allocation,
            capture_cfg=self.config.capture_config,
            yaml_path=self.config_path,
        )
        print("[CAPTURE] Manual capture mode enabled. Use 'capture start' in CLI to begin capturing.", flush=True)

        # ── STEP 10b: NPC manager ────────────────────────────────────────────
        if _NPC_AVAILABLE:
            self._npc_manager = NPCManager(self.net, self.config, self.allocation, self.config.npc_hosts)
            print("[NPC] Ready. Use 'npc start [--intensity low|medium|high]' in CLI.", flush=True)

        # Wire NPC manager into capture manager (enables capture stop → npc stop)
        if self._capture_manager and self._npc_manager:
            self._capture_manager.set_npc_manager(self._npc_manager)

        # Wire VPN controller into capture manager (enables vpn: bool in schema)
        if self._capture_manager and self._vpn_controller:
            self._capture_manager.set_vpn_controller(self._vpn_controller)

        # ── STEP 11: CLI ─────────────────────────────────────────────────────
        if enable_cli:
            print("[DBG-10] About to enter CLI …", flush=True)
            print(f"[DBG-10] net.hosts   = {self.net.hosts}", flush=True)
            print(f"[DBG-10] net.switches= {self.net.switches}", flush=True)
            print(f"[DBG-10] net.links   = {self.net.links}", flush=True)
            self.cli()

    def exfil(self) -> bool:
        """Programmatic TOS exfiltration — discovers all topology configs, picks
        random attacker + victim + table, sends TOS-marked GET request.
        Returns True if attack executed, False if net/allocation unavailable.
        Retries every 10s when no attackers or victim DBs are found.
        """
        import random
        import time
        from pathlib import Path
        from config_loader import load_config

        if not self.allocation or not self.net:
            return False

        config_dir = Path(__file__).resolve().parent.parent / "configs"
        yaml_files = sorted(config_dir.glob("topology*.yaml"))

        while True:
            exfil_cfg = getattr(self.config, "exfiltration", None)
            cfg_attacker = getattr(exfil_cfg, "attacker", None)

            # Step 1: Build attacker pool — exfiltration.attacker takes precedence.
            # attackers: list not required when exfiltration.attacker is set.
            if cfg_attacker and cfg_attacker in self.net:
                attackers = [cfg_attacker]
            else:
                raw_attackers: list = list(getattr(self.config, "attackers", []))
                for yaml_path in yaml_files:
                    try:
                        cfg = load_config(str(yaml_path))
                        raw_attackers.extend(cfg.attackers)
                    except Exception:
                        continue
                attackers = [a for a in dict.fromkeys(raw_attackers) if a in self.net]

            # Step 2: Filter to hosts in current net; resolve victim IPs

            victims = []
            seen_hosts: set = set()
            for db in getattr(self.config, "databases", []):
                if not db.api_port or db.host in seen_hosts or db.host not in self.net:
                    continue
                victim_ip = self.allocation.get_host_ip(db.host)
                if not victim_ip:
                    continue
                victims.append({
                    "host": db.host,
                    "ip": victim_ip,
                    "port": db.api_port,
                    "tables": [t.name for t in db.tables],
                })
                seen_hosts.add(db.host)

            # Step 3: Check attackers and victims exist
            if not attackers or not victims:
                print("[exfil] Attack not possible — no attackers or victim DBs. "
                      "Waiting 10s …", flush=True)
                time.sleep(10)
                continue

            # Step 4: Filter victims with non-empty tables
            filtered_victims = [v for v in victims if v["tables"]]

            # Step 5: Check filtered victims have tables
            if not filtered_victims:
                print("[exfil] Exfil attempt failed — no victim DB has tables. "
                      "Waiting 10s …", flush=True)
                time.sleep(10)
                continue

            # Step 6: Selection — exfil_cfg/cfg_attacker already resolved above
            cfg_target    = getattr(exfil_cfg, "target_host", None)
            cfg_endpoints = getattr(exfil_cfg, "endpoints", None) or []

            attacker_name = attackers[0] if len(attackers) == 1 else random.choice(attackers)
            victim = (
                next((v for v in filtered_victims if v["host"] == cfg_target), None)
                if cfg_target else None
            ) or random.choice(filtered_victims)

            if cfg_endpoints:
                endpoint = random.choice(cfg_endpoints)
            else:
                endpoint = f"/api/{random.choice(victim['tables'])}"

            # TOS from exfiltration config — attacker-side marking
            tos = getattr(exfil_cfg, "attack_tos", 0x10)

            port = victim["port"]
            ip   = victim["ip"]

            print(
                f"[exfil] {attacker_name} → {victim['host']}:{port}{endpoint}"
                f"  ip={ip}  tos={hex(tos)}",
                flush=True,
            )

            node = self.net[attacker_name]

            proc = node.popen(
                [sys.executable, "-c", _tos_exfil_script(ip, port, endpoint, tos)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            proc.communicate()
            return True

    def apply_tc(self, seed: int = None) -> bool:
        """Apply TC (TBF+netem) rules to all configured interfaces.

        Args:
            seed: random seed for reproducible profiles; None = random per call.

        Returns True if at least one interface was configured.
        """
        from network.hardware import tc_generator

        if not self.config or not self.net:
            return False

        tc_cfg = getattr(self.config, "traffic_control", None)
        if not tc_cfg or not tc_cfg.interfaces:
            return False

        device_classes = getattr(self.config, "device_classes", {})
        alias_map = {}
        if self.allocation:
            alias_map = {v: k for k, v in self.allocation.node_aliases.items()}

        profile = tc_generator.generate(tc_cfg, device_classes, alias_map, seed=seed)
        if not profile.commands:
            return False

        applied = 0
        for iface, cmd in profile.commands.items():
            alias = iface.rsplit("-eth", 1)[0]
            node_name = alias_map.get(alias, alias)
            try:
                node = self.net[node_name]
                node.cmd(f"tc qdisc del dev {iface} root 2>/dev/null || true")
                node.cmd(cmd)
                applied += 1
            except KeyError:
                pass

        if self._capture_manager:
            self._capture_manager.set_tc_profile(profile.commands)

        seed_str = f" seed={seed}" if seed is not None else " (random)"
        print(f"[TC] Applied to {applied}/{len(profile.commands)} interface(s).{seed_str}",
              flush=True)
        return applied > 0

    def stop(self) -> None:
        """Tear down the Mininet network and finalise captures."""
        if self._svc_manager:
            try:
                self._svc_manager.stop_all()
            except Exception:
                pass
        if self._npc_manager and self._npc_manager.is_running():
            try:
                self._npc_manager.stop()
            except Exception:
                pass
        # Stop captures, merge pcaps, export CSV — respect YAML config flags
        if self._capture_manager:
            try:
                self._capture_manager.stop()
                self._capture_manager.teardown_tc()   # clean TC on exit
                self._capture_manager.status()
            except Exception as exc:
                logger.warning("Capture finalisation error: %s", exc)
        if self.net:
            self.net.stop()
            logger.info("Mininet stopped")

    def cli(self) -> None:
        """Open interactive Mininet CLI."""
        if self.net is None:
            print("[DBG-CLI] ERROR: self.net is None — cannot open CLI", flush=True)
            return
        node_count = len(list(self.net.keys()))
        print(f"[DBG-CLI] node_count={node_count}", flush=True)
        print(f"[DBG-CLI] net.hosts={self.net.hosts}", flush=True)
        print(f"[DBG-CLI] net.switches={self.net.switches}", flush=True)
        if node_count == 0:
            print("[DBG-CLI] ERROR: net has 0 nodes — NOT entering CLI", flush=True)
            return
        # Restore Mininet log level so CLI output() calls are visible.
        # setLogLevel("warning") was used to quiet startup noise, but it also
        # silences Mininet's OUTPUT level (25) which CLI uses for all results.
        setLogLevel("output")
        print(f"[DBG-CLI] Entering CLI(net) with {node_count} nodes …", flush=True)
        ISPCli(
            self.net,
            vpn_controller=self._vpn_controller,
            capture_manager=self._capture_manager,
            npc_manager=self._npc_manager,
            exfil_config=self.config.exfiltration,
            allocation=self.allocation,
            config=self.config,
        )
        print("[DBG-CLI] CLI exited", flush=True)

    # -------------------------------------------------------- Phase 2 deployment

    def _deploy_phase2(self, enable_firewall: bool = False) -> None:
        """Deploy databases, services, and optional firewall."""
        self.service_registry = ServiceRegistry()

        # Databases
        if self.config.databases:
            logger.info("[Phase 2] Deploying databases …")
            self._db_manager = DatabaseManager()
            self._db_manager.deploy_all(self.net, self.config)
            self._db_manager.verify_all(self.config)

        # Services
        if self.config.services or self.config.databases:
            mode = self.config.deployment.mode
            logger.info("[Phase 2] Service deployment mode: %s", mode)
            self._svc_manager = ServiceManager(self.net, self.config, self.service_registry)

            if mode == "auto":
                self._svc_manager.deploy_all()
            elif mode == "hybrid":
                logger.info("Hybrid mode: deploy auto-services, then discover others")
                self._svc_manager.deploy_all()
                discovery = ServiceDiscovery(
                    self.net, self.config, self.allocation, self.service_registry
                )
                discovery.discover_all()
            elif mode == "manual":
                logger.info(
                    "Manual mode: network configured. Start services yourself in CLI."
                )

            self.service_registry.print_table()

        # Firewall (optional)
        if enable_firewall and self.config.security.firewall.enabled:
            logger.info("[Phase 2] Applying firewall rules …")
            self._fw_manager = FirewallManager(
                self.net, self.config, self.allocation, self.service_registry
            )
            try:
                self._fw_manager.apply()
            except Exception as exc:
                logger.error("Firewall failed (rolled back): %s", exc)

    # --------------------------------------------------------------- network build

    def _build_network(self) -> Mininet:
        """Instantiate all nodes and links.

        Ubuntu 22.04+ / Open vSwitch 2.17+ dropped ovs-controller.
        We use _NullController (a no-op placeholder) + failMode='standalone'
        so every OVS switch acts as a self-contained L2 learning switch.
        _NullController satisfies Mininet's switch.start(controllers) call
        without requiring any external binary.
        """
        import traceback as _tb

        print("[DBG-BN] Creating Mininet object …", flush=True)
        net = Mininet(
            controller=_NullController,   # no-op placeholder, no binary needed
            switch=OVSSwitch,
            link=TCLink,
            autoSetMacs=True,
            autoStaticArp=False,
        )
        print(f"[DBG-BN] Mininet object created: {net}", flush=True)
        print(f"[DBG-BN] controllers: {net.controllers}", flush=True)

        # Create nodes
        for node_cfg in self.config.nodes:
            try:
                if node_cfg.is_switch():
                    net.addSwitch(node_cfg.name, failMode="standalone", dpid=node_cfg.dpid)
                    print(f"[DBG-BN] + switch   {node_cfg.name}  dpid={node_cfg.dpid}", flush=True)

                elif node_cfg.is_router() or self.config.is_lan_gateway(node_cfg.name):
                    net.addHost(node_cfg.name, cls=LinuxRouter, ip="127.0.0.1/8")
                    print(f"[DBG-BN] + router   {node_cfg.name}", flush=True)

                else:
                    if self.config.is_vpn_gateway(node_cfg.name):
                        net.addHost(node_cfg.name, cls=LinuxRouter, ip="127.0.0.1/8")
                        print(f"[DBG-BN] + vpn-gw  {node_cfg.name}", flush=True)
                    else:
                        net.addHost(node_cfg.name, ip="127.0.0.1/8")
                        print(f"[DBG-BN] + host    {node_cfg.name}", flush=True)

            except Exception:
                print(f"[DBG-BN] EXCEPTION adding node {node_cfg.name}:", flush=True)
                _tb.print_exc()
                raise

        print(f"[DBG-BN] All nodes added. keys={list(net.keys())}", flush=True)

        # Add links in config order (preserves eth interface indices)
        for link in self.config.links:
            a, b = link[0], link[1]
            # Use pre-computed short interface names (respects IFNAMSIZ ≤ 15)
            iface_a = self.allocation.get_iface_for_link(a, b)
            iface_b = self.allocation.get_iface_for_link(b, a)
            try:
                net.addLink(net[a], net[b], intfName1=iface_a, intfName2=iface_b)
                print(f"[DBG-BN] + link  {a}({iface_a}) <-> {b}({iface_b})", flush=True)
            except Exception:
                print(f"[DBG-BN] EXCEPTION adding link {a}({iface_a})<->{b}({iface_b}):", flush=True)
                _tb.print_exc()
                raise

        print(f"[DBG-BN] All links added. "
              f"hosts={len(net.hosts)} switches={len(net.switches)} "
              f"links={len(net.links)}", flush=True)
        return net

    # --------------------------------------------------------------- IP assignment

    def _assign_ips(self) -> None:
        """Set IP/prefix on every pre-allocated interface."""
        for node_name, ifaces in self.allocation.node_interfaces.items():
            node = self.net[node_name]
            for iface_name, (ip, prefix) in ifaces.items():
                # Flush placeholder loopback IP Mininet may have assigned
                node.cmd(f"ip addr flush dev {iface_name} 2>/dev/null || true")
                node.cmd(f"ip addr add {ip}/{prefix} dev {iface_name}")
                node.cmd(f"ip link set {iface_name} up")
                logger.debug("IP: %s %s %s/%d", node_name, iface_name, ip, prefix)

    # --------------------------------------------------------------------- debug

    def _log_route_tables(self) -> None:
        tables = dump_route_tables(self.net, self.config)
        for node_name, table in tables.items():
            print_routing_table(node_name, table)

    # ------------------------------------------------------------------ test API

    def ping(self, src: str, dst_ip: str, count: int = 3) -> bool:
        """Return True if src can ping dst_ip."""
        node = self.net[src]
        out = node.cmd(f"ping -c {count} -W 2 {dst_ip}")
        return "0% packet loss" in out or f"{count} received" in out

    def traceroute(self, src: str, dst_ip: str) -> str:
        """Return traceroute output from src to dst_ip."""
        return self.net[src].cmd(f"traceroute -n -w 1 -m 10 {dst_ip}")


# ---------------------------------------------------------------------- CLI entry

def main() -> None:
    import sys
    import traceback as _tb

    print(f"[DBG-MAIN] argv={sys.argv}", flush=True)
    config_path = sys.argv[1] if len(sys.argv) > 1 else "configs/topology.yaml"
    enable_vpn = "--no-vpn" not in sys.argv
    enable_cli = "--cli" in sys.argv
    print(f"[DBG-MAIN] config={config_path}  enable_vpn={enable_vpn}  enable_cli={enable_cli}", flush=True)

    topo = ISPTopology(config_path)
    print("[DBG-MAIN] ISPTopology object created", flush=True)
    try:
        topo.start(enable_vpn=enable_vpn, enable_cli=enable_cli)
        if not enable_cli:
            print("[DBG-MAIN] Network running. Ctrl+C to stop.", flush=True)
            import time
            while True:
                time.sleep(60)
    except KeyboardInterrupt:
        print("[DBG-MAIN] KeyboardInterrupt — shutting down", flush=True)
    except Exception:
        print("[DBG-MAIN] UNHANDLED EXCEPTION in start():", flush=True)
        _tb.print_exc()
    finally:
        print("[DBG-MAIN] Calling topo.stop()", flush=True)
        topo.stop()


if __name__ == "__main__":
    main()
