"""Configuration loader for ISP Network emulator — Phase 1 + Phase 2.

Reads a YAML topology file and returns strongly-typed dataclasses.
Backward compatible: existing topology.yaml files work unchanged.

New in Phase 2
--------------
  lans        : high-level LAN definition (auto-creates nodes + links)
  services    : service deployment declarations
  databases   : SQLite database + synthetic-data declarations
  deployment  : auto | manual | hybrid mode
  security    : optional firewall management
"""

import hashlib
import logging
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from errors import EmulatorError

logger = logging.getLogger(__name__)


# ================================================================ node / link

def dpid_from_name(name: str) -> str:
    """Deterministic 16-hex-digit DPID derived from switch name via SHA-256.

    Properties:
      * Deterministic — same name always produces the same DPID.
      * Unique — SHA-256 collision probability is negligible for any
        realistic number of switches.
      * Valid — OVS requires a non-zero 64-bit integer; SHA-256 of any
        non-empty string is never all-zeros.
      * Works for any name (lan_sw_office, core_switch, edge-east, …).
    """
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


@dataclass
class NodeConfig:
    """A single network node."""
    name: str
    type: str           # 'host' | 'router' | 'switch'
    is_lan_switch: bool = False  # True for auto-generated LAN switches
    dpid: Optional[str] = None  # 16 hex chars; auto-generated for switches

    def is_switch(self) -> bool:
        return self.type == "switch"

    def is_router(self) -> bool:
        return self.type == "router"

    def is_host(self) -> bool:
        return self.type == "host"


@dataclass
class VPNConfig:
    """Global VPN settings declared in the 'vpn:' YAML section.

    Supports two YAML formats:

    Legacy (still accepted):
        vpn_gateways: [vpnhub]
        vpn_peers:
          - gateway: vpnhub
            clients: [r1, r2]

    New (auto-populates vpn_gateways / vpn_peers):
        vpn:
          enabled: true
          mode: site_to_site   # site_to_site | remote_access | hybrid
          server:
            node: vpnhub
          peers: [r1, r2]      # site_to_site / hybrid gateway peers
          clients: [h1, h2]    # remote_access / hybrid host clients
    """
    enabled: bool = True
    mode: str = "site_to_site"      # site_to_site | remote_access | hybrid
    topology: str = "hub-spoke"     # kept for backward compat
    server_node: Optional[str] = None
    peers: List[str] = field(default_factory=list)    # gateway-level peers
    clients: List[str] = field(default_factory=list)  # host-level clients
    nat: bool = False               # MASQUERADE VPN client traffic at gateway


@dataclass
class VPNPeerConfig:
    """Hub-and-spoke VPN relationship."""
    gateway: str
    clients: List[str] = field(default_factory=list)


@dataclass
class Settings:
    """Global emulator knobs."""
    isp_base_network: str = "10.0.0.0/8"
    lan_base_network: str = "192.168.0.0/16"
    vpn_base_network: str = "172.16.0.0/12"
    vpn_port: int = 51820
    log_level: str = "INFO"


# ================================================================ Phase 2 additions

@dataclass
class LANDefinition:
    """High-level LAN description — auto-expands into nodes + links."""
    name: str
    gateway: str
    hosts: List[str]
    isp_switch: Optional[str] = None   # which ISP switch this LAN gateway connects to


@dataclass
class ServiceConfig:
    """One service running on one host."""
    host: str
    type: str       # http | https | ftp | smtp | dns | sqlite | ssh | echo |
                    # custom_tcp | custom_udp
    port: Optional[int] = None      # override default port
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TableConfig:
    """One table in a synthetic database."""
    name: str
    rows: int
    schema: Dict[str, str]          # column_name -> generator_type
    indexes: List[str] = field(default_factory=list)


@dataclass
class DatabaseConfig:
    """One SQLite database with synthetic data and optional CRUD API."""
    host: str
    name: str
    engine: str = "sqlite"
    tables: List[TableConfig] = field(default_factory=list)
    api_port: Optional[int] = None  # if set, start CRUD REST API on this port
    timing_protocol: "TimingProtocolConfig" = field(default_factory=lambda: TimingProtocolConfig())


@dataclass
class ExfiltrationConfig:
    attacker:    Optional[str]  = None
    target_host: Optional[str]  = None
    target_port: Optional[int]  = None
    endpoints:   List[str]      = field(default_factory=list)
    attack_tos:  int            = 0x10  # IP TOS byte the attacker stamps on packets


@dataclass
class TimingProtocolConfig:
    """Timing protocol trigger configuration for database API responses."""
    enabled: bool = False
    secret_key: Optional[str] = None
    short_delay_ms: float = 20.0   # bit=0 inter-packet delay (ms)
    long_delay_ms: float = 50.0    # bit=1 inter-packet delay (ms)


@dataclass
class TCInterfaceConfig:
    area: str = "lan"


@dataclass
class TCLinkConfig:
    interfaces: List[str] = field(default_factory=list)
    medium: str = "fiber"


@dataclass
class TrafficControlConfig:
    interfaces: Dict[str, "TCInterfaceConfig"] = field(default_factory=dict)
    links: List["TCLinkConfig"] = field(default_factory=list)

    def get_medium_for_iface(self, iface: str) -> str:
        for link in self.links:
            if iface in link.interfaces:
                return link.medium
        return "fiber"


@dataclass
class DeploymentConfig:
    """Deployment mode."""
    mode: str = "auto"   # auto | manual | hybrid


@dataclass
class FirewallConfig:
    """Firewall settings."""
    enabled: bool = False
    policy: str = "restrictive"     # restrictive | permissive
    backend: str = "iptables"       # iptables | nftables


@dataclass
class SecurityConfig:
    """Security settings."""
    firewall: FirewallConfig = field(default_factory=FirewallConfig)


@dataclass
class StaticRoute:
    """A manually declared static route applied after auto-routing."""
    node: str
    destination: str    # CIDR, e.g. '192.168.5.0/24'
    via: str            # nexthop IP


@dataclass
class LinkCapture:
    """A specific interface to capture in link-scope mode."""
    node: str
    iface: str          # e.g. 'r1-eth0', 'wg0'


@dataclass
class CaptureConfig:
    """Packet capture configuration declared in the 'capture:' YAML section.

    New schema (topology.yaml):
        capture.automatic         — true|false (replaces mode: automatic|manual)
        capture.mode              — backward compat alias for automatic
        capture.sessiondir        — per-interface PCAP staging directory
        capture.merged            — merged PCAP output folder
        capture.csv_dir           — CSV output folder
        capture.parser            — parser endpoints and output dirs
        capture.feature_selector  — feature selector script(s)
        capture.feature_selection — column → module:function map
        capture.cleanup           — cleanup options
        devices                   — list of Mininet node names
    """
    automatic: bool = True
    mode: str = "automatic"                  # derived from automatic; kept for compat
    sessiondir: str = "dataset/tmp"
    merged: str = "dataset/pcapng"
    csv_dir: str = "dataset/csv"
    feature_selector_endpoint: str = "featureselection/feature_selector.py"   # compat
    feature_selector_endpoints: List[str] = field(default_factory=list)
    parser_enabled: bool = True              # set to false to skip pcapng→csv
    parser_endpoint: str = ""                # compat
    parser_endpoints: List[str] = field(default_factory=list)
    parser_dirs: List[str] = field(default_factory=list)
    schema_update_folder: str = "dataset/pcapng"    # compat
    schema_mimetype: str = "text/pcapng"            # compat
    schema_file: str = "dataset/schema.json"
    network_profile_file: str = "dataset/network_profile.json"
    cleanup_enabled: bool = False
    devices: List[str] = field(default_factory=list)


# ================================================================ topology root

@dataclass
class TopologyConfig:
    """Complete parsed topology — Phase 1 + Phase 2."""

    # Phase 1 (core network)
    nodes: List[NodeConfig]
    links: List[Tuple[str, str]]
    lan_gateways: List[str]
    vpn_gateways: List[str]
    vpn_peers: List[VPNPeerConfig]
    settings: Settings = field(default_factory=Settings)

    # Phase 2 (enterprise services)
    lans: List[LANDefinition] = field(default_factory=list)
    services: List[ServiceConfig] = field(default_factory=list)
    databases: List[DatabaseConfig] = field(default_factory=list)
    deployment: DeploymentConfig = field(default_factory=DeploymentConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    vpn_config: VPNConfig = field(default_factory=VPNConfig)
    static_routes: List[StaticRoute] = field(default_factory=list)
    capture_config: CaptureConfig = field(default_factory=CaptureConfig)
    device_classes: Dict[str, str] = field(default_factory=dict)
    npc_hosts:      Dict[str, str] = field(default_factory=dict)
    npc_weights:    Dict[str, Dict[str, int]] = field(default_factory=dict)
    exfiltration:   "ExfiltrationConfig" = field(default_factory=lambda: ExfiltrationConfig())
    traffic_control: "TrafficControlConfig" = field(default_factory=lambda: TrafficControlConfig())
    attackers:      List[str] = field(default_factory=list)

    # ---------------------------------------------------------------- helpers

    def get_node(self, name: str) -> Optional[NodeConfig]:
        for n in self.nodes:
            if n.name == name:
                return n
        return None

    def get_switches(self) -> List[NodeConfig]:
        return [n for n in self.nodes if n.is_switch() and not n.is_lan_switch]

    def get_lan_switches(self) -> List[NodeConfig]:
        return [n for n in self.nodes if n.is_switch() and n.is_lan_switch]

    def get_routers(self) -> List[NodeConfig]:
        return [n for n in self.nodes if n.is_router()]

    def get_hosts(self) -> List[NodeConfig]:
        return [n for n in self.nodes if n.is_host()]

    def get_neighbors(self, node_name: str) -> List[str]:
        result = []
        for a, b in self.links:
            if a == node_name:
                result.append(b)
            elif b == node_name:
                result.append(a)
        return result

    def is_lan_gateway(self, name: str) -> bool:
        return name in self.lan_gateways

    def is_vpn_gateway(self, name: str) -> bool:
        return name in self.vpn_gateways

    def get_vpn_clients(self, gateway: str) -> List[str]:
        for vp in self.vpn_peers:
            if vp.gateway == gateway:
                return list(vp.clients)
        return []

    def get_vpn_gateway_for(self, client: str) -> Optional[str]:
        for vp in self.vpn_peers:
            if client in vp.clients:
                return vp.gateway
        return None

    def all_vpn_participants(self) -> List[str]:
        participants = set(self.vpn_gateways)
        for vp in self.vpn_peers:
            participants.update(vp.clients)
        return list(participants)

    def get_services_for(self, host: str) -> List[ServiceConfig]:
        return [s for s in self.services if s.host == host]

    def get_database_for(self, host: str) -> Optional[DatabaseConfig]:
        for db in self.databases:
            if db.host == host:
                return db
        return None


# ================================================================ loader

def load_config(path: str) -> TopologyConfig:
    """Load and validate topology.yaml, returning a TopologyConfig."""
    config_path = Path(path)
    if not config_path.exists():
        raise EmulatorError("E000", f"path: {path}")

    logger.info("Loading configuration from %s", path)

    with open(config_path) as fh:
        raw = yaml.safe_load(fh)

    # ---- Phase 1 fields ----
    nodes: List[NodeConfig] = []
    for n in raw.get("nodes", []):
        node = NodeConfig(name=n["name"], type=n["type"])
        if node.is_switch():
            # Use YAML-supplied dpid if present, else derive from name
            raw_dpid = n.get("dpid")
            node.dpid = _normalise_dpid(raw_dpid) if raw_dpid else dpid_from_name(n["name"])
        nodes.append(node)
    links: List[Tuple[str, str]] = [
        tuple(lnk) for lnk in raw.get("links", [])  # type: ignore[misc]
    ]

    raw_settings = raw.get("settings", {})
    settings = Settings(
        isp_base_network=raw_settings.get("isp_base_network", "10.0.0.0/8"),
        lan_base_network=raw_settings.get("lan_base_network", "192.168.0.0/16"),
        vpn_base_network=raw_settings.get("vpn_base_network", "172.16.0.0/12"),
        vpn_port=raw_settings.get("vpn_port", 51820),
        log_level=raw_settings.get("log_level", "INFO"),
    )
    vpn_peers = [
        VPNPeerConfig(gateway=p["gateway"], clients=p.get("clients", []))
        for p in raw.get("vpn_peers", [])
    ]

    # ---- Phase 2 fields ----
    lans = [
        LANDefinition(
            name=l["name"],
            gateway=l["gateway"],
            hosts=l.get("hosts", []),
            isp_switch=l.get("isp_switch"),
        )
        for l in raw.get("lans", [])
    ]
    services = [
        ServiceConfig(
            # Accept both 'host:' (legacy) and 'node:' (new) — node: takes precedence
            host=s.get("node") or s.get("host") or "",
            type=s["type"],
            port=s.get("port"),
            options=s.get("options", {}),
        )
        for s in raw.get("services", [])
    ]
    databases = _parse_databases(raw.get("databases", []))

    raw_deploy = raw.get("deployment", {})
    deployment = DeploymentConfig(mode=raw_deploy.get("mode", "auto"))

    raw_sec = raw.get("security", {})
    raw_fw = raw_sec.get("firewall", {})
    security = SecurityConfig(
        firewall=FirewallConfig(
            enabled=raw_fw.get("enabled", False),
            policy=raw_fw.get("policy", "restrictive"),
            backend=raw_fw.get("backend", "iptables"),
        )
    )

    raw_vpn_cfg = raw.get("vpn", {})
    raw_vpn_server = raw_vpn_cfg.get("server", {})
    vpn_config = VPNConfig(
        enabled=bool(raw_vpn_cfg["enabled"]) if raw_vpn_cfg.get("enabled") is not None else False,
        mode=raw_vpn_cfg.get("mode", "site_to_site"),
        topology=raw_vpn_cfg.get("topology", "hub-spoke"),
        server_node=raw_vpn_server.get("node") if raw_vpn_server else None,
        peers=raw_vpn_cfg.get("peers", []),
        clients=raw_vpn_cfg.get("clients", []),
        nat=bool(raw_vpn_cfg.get("nat", False)),
    )

    # Manual static route overrides (applied after auto-routing)
    static_routes = [
        StaticRoute(
            node=r["node"],
            destination=r["destination"],
            via=r["via"],
        )
        for r in raw.get("routes", [])
    ]

    # Capture configuration — devices list is top-level in the new schema
    capture_config = _parse_capture_config(
        raw.get("capture", {}),
        raw.get("devices", []),
    )

    # Resolve vpn_gateways and vpn_peers from legacy top-level fields
    vpn_gateways_list = list(raw.get("vpn_gateways", []))
    vpn_peers_list = list(vpn_peers)  # already parsed above

    # NEW: if vpn.server.node + vpn.peers/clients are defined, auto-populate
    if vpn_config.server_node:
        _merge_vpn_config(vpn_config, vpn_gateways_list, vpn_peers_list)

    config = TopologyConfig(
        nodes=nodes,
        links=links,
        lan_gateways=list(raw.get("lan_gateways", [])),
        vpn_gateways=vpn_gateways_list,
        vpn_peers=vpn_peers_list,
        settings=settings,
        lans=lans,
        services=services,
        databases=databases,
        deployment=deployment,
        security=security,
        vpn_config=vpn_config,
        static_routes=static_routes,
        capture_config=capture_config,
        device_classes=dict(raw.get("device_classes", {})),
        npc_hosts=dict(raw.get("npc", {}).get("hosts", {})),
        npc_weights={
            intensity: dict(weights)
            for intensity, weights in raw.get("npc", {}).get("weights", {}).items()
        },
        exfiltration=_parse_exfiltration(raw.get("exfiltration", {})),
        traffic_control=_parse_traffic_control(raw.get("traffic_control", {})),
        attackers=list(raw.get("attackers", [])),
    )

    # Expand lans → nodes + links + lan_gateways (Phase 2)
    if config.lans:
        _expand_lans(config)

    _validate(config)
    logger.info(
        "Config OK: %d nodes, %d links, %d LAN GWs, %d VPN GWs, %d services, %d DBs",
        len(config.nodes), len(config.links), len(config.lan_gateways),
        len(config.vpn_gateways), len(config.services), len(config.databases),
    )
    return config


def _parse_exfiltration(raw: dict) -> "ExfiltrationConfig":
    target = raw.get("target", {})
    return ExfiltrationConfig(
        attacker    = raw.get("attacker"),
        target_host = target.get("host"),
        target_port = int(target["port"]) if "port" in target else None,
        endpoints   = list(raw.get("endpoints", [])),
        attack_tos  = int(raw.get("attack_tos", 0x10)),
    )


def _parse_traffic_control(raw: dict) -> "TrafficControlConfig":
    if not raw:
        return TrafficControlConfig()
    interfaces: Dict[str, TCInterfaceConfig] = {}
    links: List[TCLinkConfig] = []
    for key, val in raw.items():
        if key == "links":
            for link_raw in (val or []):
                ifaces = list(link_raw.get("interfaces", []))
                medium = link_raw.get("medium", "fiber")
                links.append(TCLinkConfig(interfaces=ifaces, medium=medium))
        else:
            area = val.get("area", "lan") if isinstance(val, dict) else "lan"
            interfaces[key] = TCInterfaceConfig(area=area)
    return TrafficControlConfig(interfaces=interfaces, links=links)


def _parse_databases(raw_dbs: list) -> List[DatabaseConfig]:
    result = []
    for db in raw_dbs:
        tables = []
        for t in db.get("tables", []):
            tables.append(TableConfig(
                name=t["name"],
                rows=t.get("rows", 10),
                schema=t.get("schema", {}),
                indexes=t.get("indexes", []),
            ))
        result.append(DatabaseConfig(
            host=db["host"],
            name=db["name"],
            engine=db.get("engine", "sqlite"),
            tables=tables,
            api_port=db.get("api_port"),
            timing_protocol=TimingProtocolConfig(
                enabled=db.get("timing_protocol", {}).get("enabled", False),
                secret_key=db.get("timing_protocol", {}).get("secret_key"),
                short_delay_ms=float(db.get("timing_protocol", {}).get("short_delay_ms", 20.0)),
                long_delay_ms=float(db.get("timing_protocol", {}).get("long_delay_ms", 50.0)),
            ),
        ))
    return result


def _parse_capture_config(raw_capture: dict, raw_devices: list) -> "CaptureConfig":
    """Parse 'capture:' section into CaptureConfig.

    Supports both old format (mode: automatic) and new format (automatic: true).
    Parser endpoints and feature selector can be a string or a list.
    """
    # automatic/mode — new key 'automatic' takes precedence over 'mode'
    explicit_automatic = raw_capture.get("automatic")
    if explicit_automatic is not None:
        automatic = bool(explicit_automatic)
        mode = "automatic" if automatic else "manual"
    else:
        mode = raw_capture.get("mode", "automatic")
        automatic = (mode != "manual")

    # directory defaults
    sessiondir = raw_capture.get("sessiondir", "dataset/tmp").rstrip("/")
    merged = raw_capture.get("merged", "dataset/pcapng").rstrip("/")

    # parser section — endpoint can be string or list; dir can be string or list
    parser_raw = raw_capture.get("parser") or {}
    parser_enabled = bool(parser_raw.get("enabled", True))
    parser_endpoint_raw = parser_raw.get("endpoint", "")
    if isinstance(parser_endpoint_raw, str) and parser_endpoint_raw.strip():
        parser_endpoints = [parser_endpoint_raw.strip()]
    elif isinstance(parser_endpoint_raw, list):
        parser_endpoints = [e.strip() for e in parser_endpoint_raw if e and str(e).strip()]
    else:
        parser_endpoints = []

    parser_dir_raw = parser_raw.get("dir", [])
    if isinstance(parser_dir_raw, str) and parser_dir_raw.strip():
        parser_dirs = [parser_dir_raw.strip()]
    elif isinstance(parser_dir_raw, list):
        parser_dirs = [d.strip() for d in parser_dir_raw if d and str(d).strip()]
    else:
        parser_dirs = []

    csv_dir = parser_dirs[0] if parser_dirs else "dataset/csv"

    # feature_selector — string or list
    fs_raw = raw_capture.get("feature_selector", "")
    if isinstance(fs_raw, str) and fs_raw.strip():
        feature_selector_endpoints = [fs_raw.strip()]
    elif isinstance(fs_raw, list):
        feature_selector_endpoints = [e.strip() for e in fs_raw if e and str(e).strip()]
    else:
        feature_selector_endpoints = []

    # devices: prefer capture.devices; fall back to top-level devices list
    devices_in_capture = raw_capture.get("devices", []) or []
    devices = list(devices_in_capture) if devices_in_capture else list(raw_devices)

    # cleanup: absent section → don't clean; present section → honour enabled flag
    cleanup_section = raw_capture.get("cleanup")
    if cleanup_section is None:
        cleanup_enabled = False
    else:
        cleanup_raw = cleanup_section or {}
        cleanup_enabled = bool(cleanup_raw.get("enabled", True))

    # schema section (backward compat only — url keys are now derived from folder paths)
    schema_raw = raw_capture.get("schema") or {}
    schema_update_folder = schema_raw.get("update_folder", merged)
    schema_mimetype = schema_raw.get("mimetype", "text/pcapng")
    schema_file = schema_raw.get("file", "dataset/schema.json")
    network_profile_file = schema_raw.get("network_profile", "dataset/network_profile.json")

    # backward compat single-string endpoint fields
    feature_selector_endpoint = (
        feature_selector_endpoints[0] if feature_selector_endpoints
        else "featureselection/feature_selector.py"
    )
    parser_endpoint = parser_endpoints[0] if parser_endpoints else ""

    return CaptureConfig(
        automatic=automatic,
        mode=mode,
        sessiondir=sessiondir,
        merged=merged,
        csv_dir=csv_dir,
        parser_enabled=parser_enabled,
        feature_selector_endpoint=feature_selector_endpoint,
        feature_selector_endpoints=feature_selector_endpoints,
        parser_endpoint=parser_endpoint,
        parser_endpoints=parser_endpoints,
        parser_dirs=parser_dirs if parser_dirs else [csv_dir],
        schema_update_folder=schema_update_folder,
        schema_mimetype=schema_mimetype,
        schema_file=schema_file,
        network_profile_file=network_profile_file,
        cleanup_enabled=cleanup_enabled,
        devices=devices,
    )


def _merge_vpn_config(
    vpn_config: "VPNConfig",
    vpn_gateways: list,
    vpn_peers: list,
) -> None:
    """Populate vpn_gateways and vpn_peers from the new-style vpn: section.

    Merges with any legacy top-level vpn_gateways / vpn_peers already parsed.
    """
    server = vpn_config.server_node
    if server and server not in vpn_gateways:
        vpn_gateways.append(server)

    all_clients = list(vpn_config.peers) + list(vpn_config.clients)
    if not all_clients:
        return

    # Merge into existing peer entry for this gateway, or create one
    existing = next((vp for vp in vpn_peers if vp.gateway == server), None)
    if existing:
        for c in all_clients:
            if c not in existing.clients:
                existing.clients.append(c)
    else:
        vpn_peers.append(VPNPeerConfig(gateway=server, clients=all_clients))


def _normalise_dpid(raw: str) -> str:
    """Validate and zero-pad a DPID string from YAML to exactly 16 hex chars."""
    raw = raw.strip().lower().lstrip("0x")
    if not all(c in "0123456789abcdef" for c in raw):
        raise EmulatorError("E019", f"dpid={raw!r} — only 0-9 a-f allowed")
    if len(raw) > 16:
        raise EmulatorError("E019", f"dpid={raw!r} — {len(raw)} chars, max 16")
    return raw.zfill(16)


def _expand_lans(config: TopologyConfig) -> None:
    """Expand lans section into nodes, links, and lan_gateways in-place.

    Idempotent: skips nodes/links that already exist.
    Creates a LAN switch (lan_sw_{name}) between the gateway and its hosts
    so the entire LAN shares one /24 subnet.
    """
    existing_names = {n.name for n in config.nodes}
    existing_links = set(config.links)

    def add_node(name: str, ntype: str, is_lan_sw: bool = False) -> None:
        if name not in existing_names:
            node = NodeConfig(name=name, type=ntype, is_lan_switch=is_lan_sw)
            if ntype == "switch":
                node.dpid = dpid_from_name(name)
            config.nodes.append(node)
            existing_names.add(name)

    def add_link(a: str, b: str) -> None:
        key = (a, b)
        rev = (b, a)
        if key not in existing_links and rev not in existing_links:
            config.links.append(key)
            existing_links.add(key)

    for lan in config.lans:
        # Gateway router
        add_node(lan.gateway, "router")

        # Internal LAN switch (auto-created)
        sw_name = f"lan_sw_{lan.name}"
        add_node(sw_name, "switch", is_lan_sw=True)

        # Host nodes
        for h in lan.hosts:
            add_node(h, "host")

        # Links: isp_switch ↔ gateway ↔ lan_switch ↔ each host
        if not lan.isp_switch:
            raise EmulatorError("E001", f"LAN '{lan.name}' — add isp_switch: <switch_name>")
        add_link(lan.isp_switch, lan.gateway)
        add_link(lan.gateway, sw_name)
        for h in lan.hosts:
            add_link(sw_name, h)

        # Register gateway
        if lan.gateway not in config.lan_gateways:
            config.lan_gateways.append(lan.gateway)

    logger.debug("lans expansion done: %d nodes, %d links", len(config.nodes), len(config.links))


_VALID_NODE_TYPES       = {"host", "router", "switch"}
_VALID_SERVICE_TYPES    = {"http", "https", "ftp", "smtp", "dns", "echo",
                           "ssh", "custom_tcp", "custom_udp"}
_VALID_GENERATOR_TYPES  = {"integer", "int", "float", "first_name", "last_name",
                           "username", "email", "phone", "department", "salary",
                           "product", "product_name", "category", "price",
                           "address", "city", "country", "boolean", "bool",
                           "text", "uuid", "date", "timestamp"}
_VALID_VPN_MODES        = {"site_to_site", "remote_access", "hybrid"}
_VALID_DEPLOY_MODES     = {"auto", "manual", "hybrid"}
_VALID_FW_POLICIES      = {"restrictive", "permissive"}
_VALID_FW_BACKENDS      = {"iptables", "nftables"}
_VALID_NPC_INTENSITIES  = {"low", "medium", "high"}


def _validate(config: TopologyConfig) -> None:
    """Raise EmulatorError on any structural inconsistency."""
    import ipaddress as _ip
    names = {n.name for n in config.nodes}

    for a, b in config.links:
        for name in (a, b):
            if name not in names:
                raise EmulatorError("E003", f"node {name!r} — declare it under nodes:")

    for gw in config.lan_gateways:
        if gw not in names:
            raise EmulatorError("E004", f"gateway {gw!r} — declare it under nodes:")
        node = config.get_node(gw)
        if node and node.is_switch():
            raise EmulatorError("E005", f"{gw!r} has type: switch — change to router or host")

    for gw in config.vpn_gateways:
        if gw not in names:
            raise EmulatorError("E006", f"gateway {gw!r} — declare it under nodes:")

    for vp in config.vpn_peers:
        if vp.gateway not in names:
            raise EmulatorError("E007", f"gateway {vp.gateway!r} — declare it under nodes:")
        for client in vp.clients:
            if client not in names:
                raise EmulatorError("E008", f"client {client!r} — declare it under nodes:")

    for svc in config.services:
        if svc.host not in names:
            raise EmulatorError("E009", f"host {svc.host!r} — declare it under nodes:")

    for db in config.databases:
        if db.host not in names:
            raise EmulatorError("E010", f"host {db.host!r} — declare it under nodes:")
        tp = getattr(db, "timing_protocol", None)
        if tp and tp.enabled and not tp.secret_key:
            raise EmulatorError("E011",
                f"db '{db.name}' on {db.host} — add secret_key under timing_protocol:")
        if tp and tp.enabled and tp.secret_key:
            if tp.short_delay_ms >= tp.long_delay_ms:
                raise EmulatorError("E012",
                    f"db '{db.name}': short_delay_ms={tp.short_delay_ms} "
                    f">= long_delay_ms={tp.long_delay_ms}")

    exfil = getattr(config, "exfiltration", None)
    if exfil:
        if exfil.attacker:
            if config.attackers and exfil.attacker not in config.attackers:
                # attackers: list declared but exfil.attacker not in it
                raise EmulatorError("E013",
                    f"{exfil.attacker!r} — add it to attackers: list or remove the attackers: section")
            if exfil.attacker not in names:
                # no attackers: list — validate directly against nodes
                raise EmulatorError("E030",
                    f"exfiltration.attacker={exfil.attacker!r} — declare it under nodes:")
        if exfil.target_host:
            db_hosts_with_api = {db.host for db in config.databases if db.api_port}
            if exfil.target_host not in db_hosts_with_api:
                raise EmulatorError("E014",
                    f"{exfil.target_host!r} — add api_port under databases[].host: {exfil.target_host}")
        if exfil.target_host and exfil.target_port:
            for db in config.databases:
                if db.host == exfil.target_host and db.api_port != exfil.target_port:
                    raise EmulatorError("E016",
                        f"exfiltration.target.port={exfil.target_port} but "
                        f"databases[host={db.host}].api_port={db.api_port}")
        tos = getattr(exfil, "attack_tos", None)
        if tos is not None and not (0 <= tos <= 255):
            raise EmulatorError("E015", f"attack_tos={tos} — must be 0–255 (0x00–0xFF)")

    if config.vpn_config.enabled and not config.vpn_config.server_node:
        raise EmulatorError("E018",
            "set vpn.server.node: <gateway_name> or set vpn.enabled: false")

    # ── Node types ────────────────────────────────────────────────────────────
    for node in config.nodes:
        if node.type not in _VALID_NODE_TYPES:
            raise EmulatorError("E038",
                f"node {node.name!r} has type={node.type!r}")

    # ── Settings CIDR formats ─────────────────────────────────────────────────
    for field, value in [
        ("isp_base_network",  config.settings.isp_base_network),
        ("lan_base_network",  config.settings.lan_base_network),
        ("vpn_base_network",  config.settings.vpn_base_network),
    ]:
        try:
            _ip.IPv4Network(value, strict=False)
        except ValueError:
            raise EmulatorError("E039", f"settings.{field}: {value!r}")

    # ── VPN mode ──────────────────────────────────────────────────────────────
    if config.vpn_config.mode not in _VALID_VPN_MODES:
        raise EmulatorError("E032", f"vpn.mode={config.vpn_config.mode!r}")

    # ── Deployment mode ───────────────────────────────────────────────────────
    if config.deployment.mode not in _VALID_DEPLOY_MODES:
        raise EmulatorError("E035", f"deployment.mode={config.deployment.mode!r}")

    # ── Firewall policy / backend ─────────────────────────────────────────────
    fw = config.security.firewall
    if fw.enabled:
        if fw.policy not in _VALID_FW_POLICIES:
            raise EmulatorError("E033", f"firewall.policy={fw.policy!r}")
        if fw.backend not in _VALID_FW_BACKENDS:
            raise EmulatorError("E034", f"firewall.backend={fw.backend!r}")

    # ── Service types and port ranges ─────────────────────────────────────────
    host_ports: Dict[str, set] = {}
    for svc in config.services:
        if svc.type not in _VALID_SERVICE_TYPES:
            raise EmulatorError("E021", f"services[host={svc.host}] type={svc.type!r}")
        if svc.port is not None:
            if not (1 <= svc.port <= 65535):
                raise EmulatorError("E043",
                    f"services[host={svc.host}, type={svc.type}] port={svc.port}")
            if svc.port in host_ports.get(svc.host, set()):
                raise EmulatorError("E022",
                    f"host={svc.host!r} port={svc.port} used by two services")
            host_ports.setdefault(svc.host, set()).add(svc.port)

    # ── Database api_port range and table generator types ────────────────────
    for db in config.databases:
        if db.api_port is not None and not (1 <= db.api_port <= 65535):
            raise EmulatorError("E042",
                f"databases[host={db.host}, name={db.name}] api_port={db.api_port}")
        tp = getattr(db, "timing_protocol", None)
        if tp and tp.enabled:
            if tp.short_delay_ms <= 0 or tp.long_delay_ms <= 0:
                raise EmulatorError("E044",
                    f"db '{db.name}': short={tp.short_delay_ms}ms long={tp.long_delay_ms}ms")
        for table in db.tables:
            for col, gen_type in table.schema.items():
                if col == "id":
                    continue
                if gen_type.lower() not in _VALID_GENERATOR_TYPES:
                    raise EmulatorError("E023",
                        f"db '{db.name}' table '{table.name}' column '{col}': "
                        f"type={gen_type!r}")

    # ── Attackers declared in nodes ───────────────────────────────────────────
    for attacker in config.attackers:
        if attacker not in names:
            raise EmulatorError("E030",
                f"{attacker!r} — declare it under nodes:")

    # ── NPC host intensities ──────────────────────────────────────────────────
    for host, intensity in config.npc_hosts.items():
        if intensity not in _VALID_NPC_INTENSITIES:
            raise EmulatorError("E037",
                f"npc.hosts.{host}: {intensity!r}")

    # ── NPC weights — keys must be valid intensities, values non-negative ints ─
    _VALID_NPC_BEHAVIORS = {"http", "bulk", "dns", "ftp", "smtp", "db", "echo", "idle"}
    for intensity, weights in config.npc_weights.items():
        if intensity not in _VALID_NPC_INTENSITIES:
            raise EmulatorError("E037",
                f"npc.weights.{intensity!r} — invalid intensity key")
        for behavior, weight in weights.items():
            if behavior not in _VALID_NPC_BEHAVIORS:
                raise EmulatorError("E049",
                    f"npc.weights.{intensity}.{behavior!r} — unknown behavior. "
                    f"Valid: {sorted(_VALID_NPC_BEHAVIORS)}")
            if not isinstance(weight, int) or weight < 0:
                raise EmulatorError("E049",
                    f"npc.weights.{intensity}.{behavior}: {weight!r} — must be non-negative int")

    # ── Static routes node references and CIDR format ────────────────────────
    for route in getattr(config, "static_routes", []):
        if route.node not in names:
            raise EmulatorError("E027",
                f"routes[node={route.node!r}] — declare it under nodes:")
        try:
            _ip.IPv4Network(route.destination, strict=False)
        except ValueError:
            raise EmulatorError("E028",
                f"routes[node={route.node}] destination={route.destination!r} is not valid CIDR")
        try:
            _ip.ip_address(route.via)
        except ValueError:
            raise EmulatorError("E028",
                f"routes[node={route.node}] via={route.via!r} is not a valid IP")

    # ── capture.devices cross-check against declared nodes ───────────────────
    for device in config.capture_config.devices:
        if device not in names:
            raise EmulatorError("E017",
                f"capture.devices: {device!r} not declared in nodes:")

    # ── device_classes keys must reference declared nodes ────────────────────
    for dc_node in config.device_classes:
        if dc_node not in names:
            raise EmulatorError("E045",
                f"device_classes.{dc_node!r} — node not declared in nodes:")

    # ── traffic_control interface names — validated at topology build time ───
    # TC interface names use Mininet aliases (e.g. 'lss1-eth0' for 'lan_sw_sitea')
    # which are only computed by ip_allocator. Cannot validate here without allocation.

    # ── vpn_peers.clients — no duplicates ─────────────────────────────────────
    for vp in config.vpn_peers:
        seen = set()
        for client in vp.clients:
            if client in seen:
                raise EmulatorError("E047",
                    f"vpn_peers[gateway={vp.gateway}].clients: {client!r} listed twice")
            seen.add(client)

    # ── npc.hosts keys must reference declared nodes ─────────────────────────
    for npc_host in config.npc_hosts:
        if npc_host not in names:
            raise EmulatorError("E048",
                f"npc.hosts.{npc_host!r} — node not declared in nodes:")

    if not config.get_switches():
        raise EmulatorError("E002", "add at least one node with type: switch")
