"""Packet Capture Framework — Capture Engine.

Two modes
---------
  automatic — capture stop triggers the full pipeline automatically.
  manual    — user controls every stage via CLI commands.

Automatic workflow (automatic: true in YAML):
    capture start → traffic → capture stop
    (stop → merge PCAPNG → feature selection → CSV → schema.json → cleanup)

Manual workflow (automatic: false in YAML):
    capture start → traffic → capture stop          (schema: pcapng url only)
    capture merge <file1> ... <session_id>          (merge to dataset/pcapng/)
    capture parsetocsv <pcapng_filename>            (CSV + schema csv url added)

File format: PCAPNG throughout.
  dataset/tmp/     — per-interface PCAPNG: <session_id>_<device>_<iface>.pcapng
  dataset/pcapng/  — merged PCAPNG: <session_id>.pcapng
  dataset/csv/     — parsed CSV: <session_id>.csv
  dataset/schema.json — session registry

Components
----------
  Capture Engine           — this file
  Feature Selection Engine — featureselection/feature_selector.py
  CSV Parser               — parserapi/csv_parser.py
  Session Registry         — dataset/schema.json
"""

import glob
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from mininet.net import Mininet

from config_loader import CaptureConfig, TopologyConfig
from .ip_allocator import AllocationResult

logger = logging.getLogger(__name__)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CaptureManager:
    """Capture Engine.

    Owns: session IDs, device/interface discovery, AsyncSniffer lifecycle,
    per-interface PCAPNG writing, merge, pipeline orchestration.

    Does NOT own: feature extraction, CSV serialization, schema.json content.
    """

    def __init__(
        self,
        net: "Mininet",
        config: TopologyConfig,
        allocation: AllocationResult,
        capture_cfg: Optional[CaptureConfig] = None,
        yaml_path: Optional[str] = None,
    ) -> None:
        self.net = net
        self.config = config
        self.allocation = allocation
        self.cfg = capture_cfg or CaptureConfig()
        self._yaml_path = yaml_path or os.path.join(_ROOT, "configs", "topology.yaml")

        self._session_id: Optional[str] = None
        self._sniffers: Dict[str, Dict] = {}
        self._running: bool = False
        self._start_time: Optional[float] = None

        self._npc_manager = None          # set via set_npc_manager()
        self._vpn_controller = None       # set via set_vpn_controller()
        self._tc_commands: Dict[str, str] = {}

        # Ensure required directories exist
        self._ensure_dirs()

    # ------------------------------------------------------------------ public

    def set_npc_manager(self, npc_manager) -> None:
        self._npc_manager = npc_manager

    def set_vpn_controller(self, vpn_controller) -> None:
        self._vpn_controller = vpn_controller

    def set_tc_profile(self, commands: Dict[str, str]) -> None:
        self.teardown_tc()   # remove old rules before applying new profile
        self._tc_commands = dict(commands)
        # network_profile.json is written only at capture start, not here

    def teardown_tc(self) -> None:
        """Remove all active TC rules (called on apply tc override or topology stop)."""
        if not self._tc_commands or not self.net:
            return
        for iface in self._tc_commands:
            alias = iface.rsplit("-eth", 1)[0]
            node_name = self.allocation.get_node_for_alias(alias)
            try:
                proc = self.net[node_name].popen(
                    f"tc qdisc del dev {iface} root 2>/dev/null || true",
                    shell=True,
                )
                proc.communicate()
            except Exception:
                pass
        print(
            f"[CAPTURE] TC rules removed from {len(self._tc_commands)} interface(s).",
            flush=True,
        )
        self._tc_commands = {}

    def start(self) -> int:
        """Generate session ID, discover interfaces, start AsyncSniffer per interface."""
        if self._running:
            print("[CAPTURE] Already running. Use 'capture stop' first.", flush=True)
            return 0

        self._session_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        os.makedirs(self._tmp_dir(), exist_ok=True)

        if self._tc_commands:
            self._write_network_profile(self._session_id, self._tc_commands)

        interfaces = self._discover_interfaces()
        if not interfaces:
            raise RuntimeError(
                "CaptureManager: no interfaces found — check 'devices' in YAML."
            )

        self._sniffers = {}
        for device_name, iface in interfaces:
            node = self.net[device_name]
            pcapng_path = self._iface_pcapng_path(device_name, iface)
            proc = node.popen(
                [sys.executable, "-c", _SNIFFER_SCRIPT, iface, pcapng_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            self._sniffers[f"{device_name}_{iface}"] = {
                "process": proc,
                "device": device_name,
                "interface": iface,
                "pcapng": pcapng_path,
            }

        self._running = True
        self._start_time = time.time()
        count = len(self._sniffers)
        print(
            f"[CAPTURE] Session {self._session_id} started on {count} interface(s).",
            flush=True,
        )
        return count

    def stop(self) -> bool:
        """Stop sniffers and flush buffers.

        Manual mode:    terminates captures, writes schema with pcapng URL.
        Automatic mode: terminates captures, then runs full pipeline
                        (merge → feature selection → CSV → schema → cleanup).
        """
        if not self._running:
            print("[CAPTURE] Not running.", flush=True)
            return False

        for entry in self._sniffers.values():
            _terminate(entry.get("process"))

        self._running = False
        time.sleep(0.5)  # allow subprocesses to flush and write

        # Stop NPC background traffic
        if self._npc_manager and self._npc_manager.is_running():
            self._npc_manager.stop()

        written = [
            e["pcapng"]
            for e in self._sniffers.values()
            if os.path.exists(e["pcapng"])
        ]
        if written:
            print(f"[CAPTURE] Interface PCAPNGs written: {len(written)}", flush=True)
            for p in written:
                print(f"  {p}", flush=True)

        if self.cfg.automatic:
            self._run_automatic_pipeline(written)
        else:
            # Manual mode: write initial schema entry with pcapng URL only.
            # User may later call 'capture merge' and 'capture parsetocsv'.
            timing_protocol = self._build_runtime_metadata()
            self._append_schema_record(
                self._session_id, timing_protocol,
                url={self.cfg.merged: "text/pcapng"},
            )
            print(
                f"[CAPTURE] Stopped. Use 'capture merge' and 'capture parsetocsv' "
                f"to complete the pipeline.",
                flush=True,
            )

        self._tc_commands = {}

        return True

    def status(self) -> None:
        """Print capture status — never stops capture."""
        elapsed = ""
        if self._start_time:
            elapsed = f"{int(time.time() - self._start_time)} seconds"

        print("\nCapture Status", flush=True)
        print(f"\nSession ID:\n  {self._session_id or '(none)'}", flush=True)
        print(f"\nState:\n  {'Running' if self._running else 'Stopped'}", flush=True)
        print(f"\nMode:\n  {'automatic' if self.cfg.automatic else 'manual'}", flush=True)

        devices = list(dict.fromkeys(e["device"] for e in self._sniffers.values()))
        print("\nDevices:", flush=True)
        for d in devices:
            print(f"  {d}", flush=True)

        print("\nInterfaces:", flush=True)
        for e in self._sniffers.values():
            print(f"  {e['interface']}", flush=True)

        print(f"\nActive Captures:\n  {len(self._sniffers)}", flush=True)
        print(f"\nOutput Directory:\n  {self._tmp_dir()}", flush=True)

        if elapsed:
            print(f"\nElapsed Time:\n  {elapsed}", flush=True)

    def is_running(self) -> bool:
        return self._running

    def merge(self, pcap_files: List[str], session_id: str) -> str:
        """Merge PCAPNG files into dataset/pcapng/<session_id>.pcapng.

        Args:
            pcap_files: list of input PCAPNG filenames or paths.
                        Files are resolved in order:
                          1. as-is (absolute or relative to cwd)
                          2. relative to project root
                          3. in dataset/tmp/ (most likely location)
            session_id: stem for the output file; output goes to
                        dataset/pcapng/<session_id>.pcapng.
                        Must equal the session_id used during capture start
                        so that schema.json entries can be matched.
        """
        resolved = []
        for f in pcap_files:
            if os.path.exists(f):
                resolved.append(f)
            elif os.path.exists(os.path.join(_ROOT, f)):
                resolved.append(os.path.join(_ROOT, f))
            else:
                tmp_candidate = os.path.join(self._tmp_dir(), os.path.basename(f))
                if os.path.exists(tmp_candidate):
                    resolved.append(tmp_candidate)
                else:
                    print(f"[CAPTURE] Warning: input file not found: {f}", flush=True)

        if not resolved:
            print("[CAPTURE] No valid input files for merge.", flush=True)
            return ""

        merged_dir = os.path.join(_ROOT, self.cfg.merged)
        os.makedirs(merged_dir, exist_ok=True)
        out = os.path.join(merged_dir, f"{session_id}.pcapng")

        _merge_pcapng(resolved, out)
        print(f"[CAPTURE] Merged → {out}", flush=True)
        return out

    def parseToCsv(self, pcap_file: str) -> str:
        """Run Feature Selection Engine + CSV Parser on a PCAPNG file.

        Input file is resolved in order:
          1. as-is
          2. in dataset/pcapng/ (most likely location after merge)
          3. relative to project root

        Output: dataset/csv/<stem>.csv
        Updates schema.json: adds 'dataset/csv' URL to the matching session entry.
        """
        resolved = self._resolve_pcapng(pcap_file)
        if not resolved:
            print(f"[CAPTURE] File not found: {pcap_file}", flush=True)
            return ""

        if not self.cfg.parser_endpoints:
            print(
                "[CAPTURE] No parser configured — add 'parser.endpoint' to YAML capture section.",
                flush=True,
            )
            return ""

        stem = os.path.splitext(os.path.basename(resolved))[0]
        csv_path = self._run_feature_selection_pipeline(resolved, stem)

        if csv_path and os.path.exists(csv_path):
            print(f"[CAPTURE] CSV → {csv_path}", flush=True)
            self._upsert_schema_url(stem, {self.cfg.csv_dir: "text/csv"})
        else:
            print("[CAPTURE] CSV generation failed.", flush=True)

        return csv_path or ""

    def update(self) -> None:
        """Reload schema configuration from YAML without performing a capture."""
        self.reload_schema_configuration()

    def reload_schema_configuration(self) -> None:
        """Re-read schema configuration from YAML and update runtime config."""
        try:
            import yaml
            with open(self._yaml_path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
            schema_raw = (raw.get("capture") or {}).get("schema") or {}
            update_folder = schema_raw.get("update_folder", "").strip()
            mimetype = schema_raw.get("mimetype", "").strip()
            if update_folder:
                self.cfg.schema_update_folder = update_folder
            if mimetype:
                self.cfg.schema_mimetype = mimetype
            print(
                f"[CAPTURE] Schema configuration reloaded: folder={self.cfg.schema_update_folder}"
                f"  mimetype={self.cfg.schema_mimetype}",
                flush=True,
            )
        except Exception as exc:
            print(f"[CAPTURE] reload_schema_configuration failed: {exc}", flush=True)

    def clean(self) -> None:
        """Remove per-interface PCAPNG files from dataset/tmp/ for the current session.

        Does NOT delete:
          dataset/pcapng/<session_id>.pcapng
          dataset/csv/<session_id>.csv
          dataset/schema.json
        """
        if not self._session_id:
            print("[CAPTURE] No session to clean.", flush=True)
            return

        tmp_dir = self._tmp_dir()
        pattern = os.path.join(tmp_dir, f"{self._session_id}*")
        files = glob.glob(pattern)

        if not files:
            print("[CAPTURE] Nothing to clean.", flush=True)
            return

        removed = 0
        for f in files:
            try:
                os.remove(f)
                removed += 1
            except Exception as exc:
                print(f"[CAPTURE] Could not remove {f}: {exc}", flush=True)

        print(f"[CAPTURE] Cleaned {removed} temporary file(s) from {tmp_dir}", flush=True)

    # ------------------------------------------------------ automatic pipeline

    def _run_automatic_pipeline(self, interface_pcapngs: List[str]) -> None:
        """Full pipeline: merge → feature selection → CSV → schema → cleanup."""
        if not interface_pcapngs:
            print("[CAPTURE] No interface PCAPNGs — skipping pipeline.", flush=True)
            return

        session_id = self._session_id

        # 1. Merge
        merged_dir = os.path.join(_ROOT, self.cfg.merged)
        os.makedirs(merged_dir, exist_ok=True)
        merged_path = os.path.join(merged_dir, f"{session_id}.pcapng")
        _merge_pcapng(interface_pcapngs, merged_path)
        print(f"[CAPTURE] Merged → {merged_path}", flush=True)

        # 2. Build metadata for schema
        timing_protocol = self._build_runtime_metadata()

        # 3. Parse to CSV if parser is configured
        csv_path = None
        if self.cfg.parser_endpoints:
            csv_path = self._run_feature_selection_pipeline(merged_path, session_id)
            if csv_path and os.path.exists(csv_path):
                print(f"[CAPTURE] CSV → {csv_path}", flush=True)
            else:
                print("[CAPTURE] CSV generation failed — skipping CSV schema entry.", flush=True)
                csv_path = None

        # 4. Write schema
        url: Dict = {self.cfg.merged: "text/pcapng"}
        if csv_path:
            url[self.cfg.csv_dir] = "text/csv"
        self._append_schema_record(session_id, timing_protocol, url=url)

        # 5. Cleanup
        if self.cfg.cleanup_enabled:
            self.clean()

    def _run_feature_selection_pipeline(
        self, pcapng_path: str, session_id: str
    ) -> Optional[str]:
        """Run feature selector then parser. Returns CSV path. No schema side effects."""
        dataset_path = self._run_feature_selector(pcapng_path, session_id)
        if not dataset_path or not os.path.exists(dataset_path):
            return None
        return self._run_parser(dataset_path, session_id)

    # ---------------------------------------------------------------- internals

    def _ensure_dirs(self) -> None:
        """Create required directories if they do not exist."""
        for rel in [
            self.cfg.sessiondir,
            self.cfg.merged,
            self.cfg.csv_dir,
            "dataset",
        ]:
            os.makedirs(os.path.join(_ROOT, rel), exist_ok=True)

    def _tmp_dir(self) -> str:
        return os.path.join(_ROOT, self.cfg.sessiondir)

    def _iface_pcapng_path(self, device: str, iface: str) -> str:
        safe = iface.replace("/", "_")
        return os.path.join(
            self._tmp_dir(), f"{self._session_id}_{device}_{safe}.pcapng"
        )

    def _merged_pcapng_path(self, session_id: str) -> str:
        return os.path.join(_ROOT, self.cfg.merged, f"{session_id}.pcapng")

    def _schema_path(self) -> str:
        return os.path.join(_ROOT, "dataset", "schema.json")

    def _network_profile_path(self) -> str:
        return os.path.join(_ROOT, "dataset", "network_profile.json")

    def _write_network_profile(self, session_id: str, commands: Dict[str, str]) -> None:
        """Append or update {session_id: {device: tc_cmd}} in dataset/network_profile.json."""
        path = self._network_profile_path()
        records: List[Dict] = []
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, list):
                    records = loaded
            except Exception:
                records = []

        for record in records:
            if isinstance(record, dict) and session_id in record:
                record[session_id] = commands
                break
        else:
            records.append({session_id: commands})

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2)
        print(f"[CAPTURE] network_profile.json updated (session={session_id}).", flush=True)

    def _resolve_pcapng(self, pcap_file: str) -> Optional[str]:
        """Resolve a PCAPNG filename/path to an absolute path."""
        if os.path.exists(pcap_file):
            return pcap_file
        # Try in dataset/pcapng/
        candidate = os.path.join(_ROOT, self.cfg.merged, pcap_file)
        if os.path.exists(candidate):
            return candidate
        # Try relative to project root
        candidate2 = os.path.join(_ROOT, pcap_file)
        if os.path.exists(candidate2):
            return candidate2
        return None

    def _discover_interfaces(self) -> List[Tuple[str, str]]:
        result: List[Tuple[str, str]] = []
        if not self.cfg.devices:
            raise ValueError(
                "CaptureManager: 'devices' list is empty — add device names to "
                "capture.devices in YAML."
            )
        for device_name in self.cfg.devices:
            try:
                node = self.net[device_name]
            except Exception:
                logger.warning("[CAPTURE] Device %r not found in net — skipping.", device_name)
                continue
            for iface in node.intfList():
                name = getattr(iface, "name", "")
                if name and name != "lo" and not name.startswith("wg") and (device_name, name) not in result:
                    result.append((device_name, name))
        return result

    def _run_feature_selector(self, pcapng_path: str, session_id: str) -> Optional[str]:
        """Launch Feature Selection Engine with sys.executable."""
        if not self.cfg.feature_selector_endpoints:
            print("[CAPTURE] No feature_selector configured — skipping feature extraction.", flush=True)
            return None

        endpoint_rel = self.cfg.feature_selector_endpoints[0]
        endpoint = os.path.join(_ROOT, endpoint_rel)
        if not os.path.exists(endpoint):
            print(f"[CAPTURE] Feature selector not found: {endpoint}", flush=True)
            return None
        try:
            proc = subprocess.Popen(
                [sys.executable, endpoint, pcapng_path, session_id, self._yaml_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout_data, stderr_data = proc.communicate(timeout=300)

            if stderr_data.strip():
                for line in stderr_data.splitlines():
                    print(line, flush=True)

            if proc.returncode != 0:
                print(
                    "[CAPTURE] Feature Selection failed — skipping CSV and schema update.",
                    flush=True,
                )
                return None

            lines = [line.strip() for line in stdout_data.splitlines() if line.strip()]
            return lines[-1] if lines else None

        except subprocess.TimeoutExpired:
            proc.kill()
            print("[CAPTURE] Feature selector timed out.", flush=True)
            return None
        except Exception as exc:
            print(f"[CAPTURE] Feature selector exception: {exc}", flush=True)
            return None

    def _run_parser(self, dataset_path: str, session_id: str) -> Optional[str]:
        """Launch CSV Parser with sys.executable."""
        if not self.cfg.parser_enabled:
            print("[CAPTURE] Parser disabled (parser.enabled: false) — skipping CSV generation.", flush=True)
            return None
        if not self.cfg.parser_endpoints:
            print("[CAPTURE] No parser configured — skipping CSV generation.", flush=True)
            return None

        endpoint_rel = self.cfg.parser_endpoints[0]
        endpoint = os.path.join(_ROOT, endpoint_rel)
        if not os.path.exists(endpoint):
            print(f"[CAPTURE] Parser not found: {endpoint}", flush=True)
            return None
        try:
            result = subprocess.run(
                [sys.executable, endpoint, dataset_path, session_id, self._yaml_path],
                capture_output=True, text=True, timeout=120,
            )
            if result.stderr.strip():
                for line in result.stderr.splitlines():
                    print(f"[PARSER] {line}", flush=True)
            if result.returncode != 0:
                print("[CAPTURE] CSV Parser failed — skipping schema update.", flush=True)
                return None
            return result.stdout.strip() or None
        except Exception as exc:
            print(f"[CAPTURE] Parser exception: {exc}", flush=True)
            return None

    def _build_runtime_metadata(self) -> List[Dict]:
        """Return timing_protocol list — one entry per TOS-marked attacker request."""
        sessions = self._load_timing_protocol_sessions()

        db_cfg = self._primary_database_with_api()
        db_ip = self.allocation.get_host_ip(db_cfg.host) if db_cfg else None
        db_port = db_cfg.api_port if db_cfg else None
        fallback_dest = f"{db_ip}:{db_port}" if db_ip and db_port else "127.0.0.1:9090"

        npc_intensity = self._resolve_npc_intensity()

        vpn_active = False
        if self._vpn_controller is not None:
            try:
                vpn_active = bool(self._vpn_controller.is_active())
            except Exception:
                vpn_active = False

        result = []
        for s in sessions:
            raw_src = s.get("src") or "127.0.0.1"
            if vpn_active:
                src = self._vpn_ip_for_lan_src(raw_src) or raw_src
            else:
                src = raw_src
            _ep = s.get("exfiltrated_data_packets")
            result.append({
                "enabled":                    bool(s.get("enabled", False)),
                "vpn":                        vpn_active,
                "intensity":                  npc_intensity,
                "src":                        src,
                "dest":                       s.get("dest") or fallback_dest,
                "secret_key":                 s.get("secret_key"),
                "start_timestamp":            s.get("start_timestamp")
                                              or s.get("timestamp"),
                "end_timestamp":              s.get("end_timestamp"),
                "nonces_used":                s.get("nonces_used") or [],
                "exfiltrated_data_packets":   _ep if _ep is not None
                                              else s.get("total_data_packets"),
                "rhythm":                     s.get("rhythm") or [],
                "short_delay_ms":             float(s.get("short_delay_ms") or 20.0),
                "long_delay_ms":              float(s.get("long_delay_ms")  or 50.0),
            })
        return result

    def _vpn_ip_for_lan_src(self, lan_ip: str) -> Optional[str]:
        """Map a LAN src IP (192.x.x.x) to its VPN representation (172.x.x.x).

        For remote_access VPN: attacker node has its own VPN IP — return that.
        For site_to_site VPN: attacker is behind a gateway router — return the
        gateway's WireGuard IP so VPN sessions show 172.x.x.x in schema.json.
        """
        try:
            alloc = self.allocation
            # Reverse-map LAN IP → node name
            attacker_node = None
            for node_name, ifaces in alloc.node_interfaces.items():
                for ip, _prefix in ifaces.values():
                    if ip == lan_ip:
                        attacker_node = node_name
                        break
                if attacker_node:
                    break
            if not attacker_node:
                return None

            # Direct VPN client (remote_access mode — node has own WG IP)
            vpn_ip = alloc.vpn_node_ips.get(attacker_node)
            if vpn_ip:
                return str(vpn_ip)

            # Site-to-site: find gateway for this host's LAN subnet
            gw_ip = alloc.default_gateways.get(attacker_node)
            if not gw_ip:
                return None

            # Reverse-map gateway IP → gateway node name
            gw_node = None
            for node_name, ifaces in alloc.node_interfaces.items():
                for ip, _prefix in ifaces.values():
                    if ip == str(gw_ip):
                        gw_node = node_name
                        break
                if gw_node:
                    break
            if not gw_node:
                return None

            gw_vpn_ip = alloc.vpn_node_ips.get(gw_node)
            return str(gw_vpn_ip) if gw_vpn_ip else None
        except Exception:
            return None

    def _load_timing_protocol_sessions(self) -> List[Dict]:
        """Read timing metadata file. Returns list — one dict per attacker request."""
        db_cfg = self._primary_database_with_api()
        if not db_cfg:
            return []

        meta_path = f"/tmp/timing_{db_cfg.host}_{db_cfg.name}.json"
        if not os.path.exists(meta_path):
            tp = getattr(db_cfg, "timing_protocol", None)
            if tp and tp.enabled:
                return [{
                    "enabled": True, "secret_key": "example_key",
                    "timestamp": None, "nonces_used": [],
                    "total_data_packets": None, "rhythm": [],
                    "src": None, "dest": None,
                }]
            return []

        try:
            with open(meta_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            # New format: {"sessions": [...]}
            if "sessions" in data:
                return data["sessions"]
            # Old format: single dict — wrap for backward compat
            return [data]
        except Exception as exc:
            logger.warning("[CAPTURE] Failed reading timing metadata %s: %s", meta_path, exc)
            return []

    def _resolve_npc_intensity(self) -> str:
        """Return NPC intensity for this session. Global > per-host majority > 'medium'."""
        if not self._npc_manager:
            return "medium"
        intensity = getattr(self._npc_manager, "_intensity", None)
        if not intensity:
            host_map = getattr(self._npc_manager, "_host_intensity", {})
            vals = list(host_map.values())
            if vals:
                intensity = max(set(vals), key=vals.count)
        return intensity or "medium"

    def _primary_database_with_api(self):
        for db_cfg in getattr(self.config, "databases", []):
            if db_cfg.api_port:
                return db_cfg
        return None

    def _append_schema_record(
        self,
        session_id: str,
        timing_protocol: List[Dict],
        url: Optional[Dict] = None,
    ) -> None:
        """Append or update a session entry in dataset/schema.json.

        If session_id already exists, merges new url entries into the existing
        record without creating a duplicate. If not found, creates a new record.

        Args:
            session_id: unique session identifier.
            timing_protocol: list of timing protocol entry dicts (each self-contained
                             with src, dest, enabled, rhythm, etc.).
            url: dict of {folder_path: mime_type} entries, e.g.
                 {"dataset/pcapng": "text/pcapng"}.
                 Defaults to {cfg.merged: "text/pcapng"}.
        """
        schema_path = self._schema_path()
        os.makedirs(os.path.dirname(schema_path), exist_ok=True)
        records: List[Dict] = []

        if os.path.exists(schema_path):
            try:
                with open(schema_path, "r", encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, list):
                    records = loaded
            except Exception:
                records = []

        new_url = url if url is not None else {self.cfg.merged: "text/pcapng"}

        # Upsert: merge url into existing record for this session_id.
        for record in records:
            if not isinstance(record, dict):
                continue
            if record.get("session_id") == session_id:
                existing_url = record.get("url")
                if isinstance(existing_url, dict):
                    existing_url.update(new_url)
                else:
                    record["url"] = new_url
                _write_schema(records, schema_path)
                print(
                    f"[CAPTURE] schema.json updated (session={session_id}).",
                    flush=True,
                )
                return

        # New session: create a fresh record.
        records.append({
            "session_id":      session_id,
            "topology":        os.path.basename(self._yaml_path),
            "url":             new_url,
            "timing_protocol": timing_protocol,
        })
        _write_schema(records, schema_path)
        print(f"[CAPTURE] schema.json updated (session={session_id}).", flush=True)

    def _upsert_schema_url(self, session_id: str, url_update: Dict) -> None:
        """Add url entries to an existing schema record for session_id.

        If no matching record is found, logs a warning — the record must have
        been created first by _append_schema_record (e.g. at capture stop).
        """
        schema_path = self._schema_path()
        if not os.path.exists(schema_path):
            print(
                f"[CAPTURE] Warning: schema.json not found — cannot update URL for "
                f"session {session_id}.",
                flush=True,
            )
            return

        records: List[Dict] = []
        try:
            with open(schema_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, list):
                records = loaded
        except Exception as exc:
            print(f"[CAPTURE] Warning: could not read schema.json: {exc}", flush=True)
            return

        for record in records:
            if isinstance(record, dict) and record.get("session_id") == session_id:
                existing_url = record.get("url", {})
                if isinstance(existing_url, dict):
                    existing_url.update(url_update)
                    record["url"] = existing_url
                else:
                    record["url"] = url_update
                _write_schema(records, schema_path)
                print(
                    f"[CAPTURE] schema.json updated (session={session_id}, "
                    f"added {list(url_update.keys())}).",
                    flush=True,
                )
                return

        print(
            f"[CAPTURE] Warning: no schema entry for session {session_id} — "
            f"URL not updated. Merge must use the exact session_id from 'capture start'.",
            flush=True,
        )


# -------------------------------------------------------------------- helpers


def normalize_timing_protocol(tp) -> List[Dict]:
    """Backward compat: convert legacy dict to list-of-one."""
    if isinstance(tp, dict):
        return [tp]
    if isinstance(tp, list):
        return tp
    return []


def load_schema_by_session(schema_path: str, session_id: str) -> Optional[Dict]:
    """Load a schema.json record by session_id (never by index)."""
    try:
        with open(schema_path, "r", encoding="utf-8") as fh:
            records = json.load(fh)
        for r in records:
            if isinstance(r, dict) and r.get("session_id") == session_id:
                r["timing_protocol"] = normalize_timing_protocol(
                    r.get("timing_protocol", [])
                )
                return r
    except Exception:
        pass
    return None


def _write_schema(records: List[Dict], path: str) -> None:
    """Write schema.json with standard indent=2 formatting.

    Exception: rhythm arrays are serialized on a single line with no spaces.
    """
    raw = json.dumps(records, indent=2)
    compacted = re.sub(
        r'"rhythm":\s*(\[[^\]]*\])',
        lambda m: '"rhythm": [' + ",".join(re.findall(r"\d+", m.group(1))) + "]",
        raw,
        flags=re.DOTALL,
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(compacted)


def _merge_pcapng(pcapng_files: List[str], output_path: str) -> None:
    """Merge PCAPNG files chronologically using mergecap.

    Falls back to Scapy PcapReader + wrpcap if mergecap is unavailable.
    """
    result = subprocess.run(
        ["mergecap", "-w", output_path] + pcapng_files,
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.warning(
            "[CAPTURE] mergecap failed (%s): %s — falling back to Scapy merge.",
            result.returncode, result.stderr.strip(),
        )
        _merge_pcap_fallback(pcapng_files, output_path)
    else:
        if result.stderr.strip():
            logger.debug("[CAPTURE] mergecap: %s", result.stderr.strip())


def _merge_pcap_fallback(files: List[str], output_path: str) -> None:
    """Fallback: read all files via Scapy PcapReader, sort by timestamp, write PCAP."""
    from scapy.all import PcapReader, wrpcap
    packets = []
    for f in files:
        try:
            packets.extend(list(PcapReader(f)))
        except Exception as exc:
            logger.warning("[CAPTURE] Could not read %s: %s", f, exc)
    packets.sort(key=lambda p: float(p.time))
    wrpcap(output_path, packets)


_SNIFFER_SCRIPT = r"""
import signal, sys, struct

iface = sys.argv[1]
pcapng_path = sys.argv[2]

# Inline minimal PCAPNG writer — streams EPBs to disk as packets arrive.
# No packet accumulation in RAM: SHB+IDB written at open, one EPB per packet.
OPT_END = struct.pack('<HH', 0, 0)

def _pad4(n):
    return (4 - n % 4) % 4

def _opt(code, value):
    p = _pad4(len(value))
    return struct.pack('<HH', code, len(value)) + value + b'\x00' * p

def _blk(type_, body):
    total = 12 + len(body)
    return struct.pack('<II', type_, total) + body + struct.pack('<I', total)

def _open_pcapng(path, iface_name, link_type=1):
    f = open(path, 'wb')
    shb_body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1) + OPT_END
    f.write(_blk(0x0A0D0D0A, shb_body))
    idb_body = struct.pack('<HHI', link_type, 0, 65535)
    idb_body += _opt(2, iface_name.encode('utf-8')) + OPT_END
    f.write(_blk(0x00000001, idb_body))
    f.flush()
    return f

def _write_epb(f, pkt):
    raw = bytes(pkt)
    pad = _pad4(len(raw))
    ts_us = int(float(pkt.time) * 1_000_000)
    epb_body = struct.pack('<IIIII', 0, ts_us >> 32, ts_us & 0xFFFFFFFF, len(raw), len(raw))
    epb_body += raw + b'\x00' * pad + OPT_END
    f.write(_blk(0x00000006, epb_body))

# Open file immediately so it exists on disk before the slow scapy import.
_f = _open_pcapng(pcapng_path, iface)

from scapy.all import AsyncSniffer

def _on_packet(pkt):
    _write_epb(_f, pkt)

sniffer = AsyncSniffer(iface=iface, store=False, prn=_on_packet)

def _stop(signum, frame):
    sniffer.stop()
    _f.flush()
    _f.close()
    raise SystemExit(0)

signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)
sniffer.start()
signal.pause()
"""


def _terminate(process) -> None:
    if process is None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            process.send_signal(sig)
            process.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue
        except Exception:
            return
