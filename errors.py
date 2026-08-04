"""Structured error codes for ISP Emulator configuration and startup failures.

Every error prints:
  - What went wrong (plain English)
  - Exactly where in your YAML file
  - The exact lines to add or change
  - Guide.md section for full documentation

Usage:
    raise EmulatorError("E011", "db 'victimdb' on h3")

Catching at startup:
    except EmulatorError as e:
        e.print_and_exit()
"""

import sys


# ─────────────────── registry ────────────────────────────────────────────────
# Each entry: (problem, yaml_key, guide_section, fix_snippet)
# fix_snippet: plain text shown under "Fix:" — include YAML examples where
# helpful so the user can fix without opening Guide.md.

REGISTRY = {

    # ── Config — file loading ────────────────────────────────────────────────
    "E000": (
        "Config file not found.",
        "command-line argument / auto-gen.yaml → selected:",
        "Guide.md §2 Running the Emulator",
        "Check the path you passed:\n"
        "    sudo python3 network/topology.py <path>\n"
        "The file must exist relative to the project root.",
    ),

    # ── Config — topology structure ──────────────────────────────────────────
    "E001": (
        "A LAN entry is missing 'isp_switch'.",
        "lans[].isp_switch",
        "Guide.md §3.3 lans  →  E001",
        "Add 'isp_switch' to every entry under lans::\n\n"
        "    lans:\n"
        "      - name: office\n"
        "        gateway: r1\n"
        "        isp_switch: s1    # ← add this, must be a declared switch node\n"
        "        hosts: [h1, h2]",
    ),

    "E002": (
        "Topology has no ISP switch node.",
        "nodes[]",
        "Guide.md §3.1 nodes  →  E002",
        "Add at least one switch to nodes::\n\n"
        "    nodes:\n"
        "      - name: s1\n"
        "        type: switch      # ← at least one switch required",
    ),

    "E003": (
        "A link references a node that is not declared in nodes:.",
        "links[]",
        "Guide.md §3.2 links  →  E003",
        "Either declare the missing node under nodes:, or remove the link.\n\n"
        "    nodes:\n"
        "      - name: <missing_node>   # ← add this\n"
        "        type: host\n\n"
        "    links:\n"
        "      - [h1, <missing_node>]",
    ),

    "E004": (
        "A lan_gateway references a node that is not declared in nodes:.",
        "lan_gateways[]",
        "Guide.md §3.3 lans  →  E004",
        "Declare the missing node under nodes::\n\n"
        "    nodes:\n"
        "      - name: r1          # ← add the missing gateway here\n"
        "        type: router",
    ),

    "E005": (
        "A lan_gateway is a switch — it must be a router or host.",
        "lan_gateways[]",
        "Guide.md §3.3 lans  →  E005",
        "Change the node type to 'router' or 'host', or remove it from lan_gateways::\n\n"
        "    nodes:\n"
        "      - name: r1\n"
        "        type: router      # ← change from 'switch'",
    ),

    "E006": (
        "A vpn_gateway references a node that is not declared in nodes:.",
        "vpn_gateways[]",
        "Guide.md §3.4 vpn  →  E006",
        "Declare the VPN gateway node under nodes::\n\n"
        "    nodes:\n"
        "      - name: vpnhub     # ← add the missing VPN gateway\n"
        "        type: host",
    ),

    "E007": (
        "A vpn_peers gateway references a node that is not declared in nodes:.",
        "vpn_peers[].gateway",
        "Guide.md §3.5 vpn_peers  →  E007",
        "Declare the gateway node under nodes:, or fix the gateway name in vpn_peers::\n\n"
        "    vpn_peers:\n"
        "      - gateway: vpnhub  # ← must match a declared node name",
    ),

    "E008": (
        "A vpn_peers client references a node that is not declared in nodes:.",
        "vpn_peers[].clients",
        "Guide.md §3.5 vpn_peers  →  E008",
        "Declare the client node under nodes:, or remove it from vpn_peers.clients::\n\n"
        "    vpn_peers:\n"
        "      - gateway: vpnhub\n"
        "        clients:\n"
        "          - h1            # ← must match a declared node name",
    ),

    "E009": (
        "A service is configured on a host that is not declared in nodes:.",
        "services[].node",
        "Guide.md §3.6 services  →  E009",
        "Declare the host node under nodes:, or fix the 'node:' value in services::\n\n"
        "    services:\n"
        "      - node: web1       # ← must match a declared node name\n"
        "        type: http\n"
        "        port: 8080",
    ),

    "E010": (
        "A database is configured on a host that is not declared in nodes:.",
        "databases[].host",
        "Guide.md §3.7 databases  →  E010",
        "Declare the host node under nodes:, or fix the 'host:' value in databases::\n\n"
        "    databases:\n"
        "      - host: db1        # ← must match a declared node name\n"
        "        name: mydb",
    ),

    "E011": (
        "timing_protocol is enabled but secret_key is not set.",
        "databases[].timing_protocol.secret_key",
        "Guide.md §3.7 databases → timing_protocol  →  E011",
        "Add a secret_key under timing_protocol::\n\n"
        "    databases:\n"
        "      - host: db1\n"
        "        timing_protocol:\n"
        "          enabled: true\n"
        "          secret_key: your-real-secret-here   # ← add this line\n\n"
        "Do NOT use 'example_key' — use a unique value per topology.",
    ),

    "E012": (
        "short_delay_ms must be strictly less than long_delay_ms.",
        "databases[].timing_protocol.short_delay_ms / long_delay_ms",
        "Guide.md §3.7 databases → timing_protocol  →  E012",
        "Fix the delay values so short < long. The gap should exceed the\n"
        "maximum jitter on the network path::\n\n"
        "    timing_protocol:\n"
        "      short_delay_ms: 20.0   # bit=0 delay\n"
        "      long_delay_ms:  50.0   # bit=1 delay  (must be > short_delay_ms)",
    ),

    "E013": (
        "exfiltration.attacker is not listed in the attackers: section.",
        "exfiltration.attacker",
        "Guide.md §3.16 exfiltration  →  E013",
        "Either add the node to attackers:, or change exfiltration.attacker to match::\n\n"
        "    attackers:\n"
        "      - h1               # ← this must include the exfiltration.attacker value\n\n"
        "    exfiltration:\n"
        "      attacker: h1       # ← must be listed above",
    ),

    "E014": (
        "exfiltration.target.host does not have api_port configured.",
        "exfiltration.target.host  /  databases[].api_port",
        "Guide.md §3.16 exfiltration  →  E014",
        "Add api_port to the matching database entry::\n\n"
        "    databases:\n"
        "      - host: db1\n"
        "        api_port: 9090   # ← add this line",
    ),

    "E015": (
        "attack_tos must be an integer between 0 and 255.",
        "exfiltration.attack_tos",
        "Guide.md §3.16 exfiltration  →  E015",
        "Set attack_tos to a valid byte value::\n\n"
        "    exfiltration:\n"
        "      attack_tos: 0x10   # ← valid range: 0x00–0xFF (0–255)",
    ),

    "E016": (
        "exfiltration.target.port does not match the database's api_port.",
        "exfiltration.target.port  /  databases[].api_port",
        "Guide.md §3.16 exfiltration  →  E016",
        "Make both values the same::\n\n"
        "    databases:\n"
        "      - host: db1\n"
        "        api_port: 9090     # ← must match below\n\n"
        "    exfiltration:\n"
        "      target:\n"
        "        host: db1\n"
        "        port: 9090         # ← must match above",
    ),

    "E017": (
        "capture.devices is empty or references a node not in the topology.",
        "capture.devices",
        "Guide.md §3.10 capture  →  E017",
        "Add node names to capture.devices. Every name must exist in nodes::\n\n"
        "    capture:\n"
        "      devices:\n"
        "        - h1      # ← add nodes you want to capture traffic from\n"
        "        - r1\n"
        "        - db1",
    ),

    "E018": (
        "VPN is enabled but vpn.server.node is not set.",
        "vpn.server.node",
        "Guide.md §3.4 vpn  →  E018",
        "Set vpn.server.node to the VPN gateway node name, or disable VPN::\n\n"
        "    vpn:\n"
        "      enabled: true\n"
        "      server:\n"
        "        node: vpnhub   # ← add this, must be a declared node\n\n"
        "    # or to disable VPN:\n"
        "    vpn:\n"
        "      enabled: false",
    ),

    "E019": (
        "Node dpid is invalid — must be 1 to 16 hexadecimal characters.",
        "nodes[].dpid",
        "Guide.md §3.1 nodes  →  E019",
        "Fix or remove the dpid value::\n\n"
        "    nodes:\n"
        "      - name: s1\n"
        "        type: switch\n"
        "        dpid: 0000000000000001   # ← 1–16 hex chars, or omit to auto-generate",
    ),

    # ── Runtime — IP allocation ──────────────────────────────────────────────
    "R001": (
        "LAN subnet pool is exhausted — too many LAN gateways for the configured network.",
        "settings.lan_base_network",
        "Guide.md §3.12 settings  →  R001",
        "Expand the LAN base network in settings::\n\n"
        "    settings:\n"
        "      lan_base_network: '192.168.0.0/12'   # ← was /16, increase prefix range\n\n"
        "Or reduce the number of LAN gateways in the topology.",
    ),

    "R002": (
        "VPN subnet pool is exhausted — too many VPN peer groups for the configured network.",
        "settings.vpn_base_network",
        "Guide.md §3.12 settings  →  R002",
        "Expand the VPN base network in settings::\n\n"
        "    settings:\n"
        "      vpn_base_network: '172.16.0.0/10'   # ← was /12, increase prefix range\n\n"
        "Or reduce the number of VPN peer groups.",
    ),

    "R010": (
        "A generated interface name exceeds Linux's 15-character limit (IFNAMSIZ).",
        "nodes[]  (node name too long)",
        "Guide.md §3.1 nodes  →  R010",
        "Shorten the node name. Names up to 9 characters are always safe.\n"
        "The emulator auto-shortens longer names but the alias must still fit.\n\n"
        "    nodes:\n"
        "      - name: r1          # ← use short names (≤ 9 chars is always safe)\n"
        "        type: router\n\n"
        "    # instead of:\n"
        "      - name: my_very_long_router_name   # ← too long",
    ),

    # ── Runtime — WireGuard ──────────────────────────────────────────────────
    "R020": (
        "WireGuard key generation failed — the 'wg' tool is missing or broken.",
        "(system — not a YAML issue)",
        "Guide.md §1 Installation  →  R020",
        "Install WireGuard tools and retry::\n\n"
        "    sudo apt-get install wireguard wireguard-tools\n\n"
        "Then verify: wg --version",
    ),

    # ── Config — enum / range validation ────────────────────────────────────
    "E021": (
        "Unknown service type.",
        "services[].type",
        "Guide.md §3.6 services  →  E021",
        "Use one of the supported service types::\n\n"
        "    services:\n"
        "      - node: web1\n"
        "        type: http       # ← valid: http | https | ftp | smtp | dns |\n"
        "                         #          echo | ssh | custom_tcp | custom_udp",
    ),
    "E022": (
        "Two services on the same host share the same port.",
        "services[].port",
        "Guide.md §3.6 services  →  E022",
        "Give each service on the same host a unique port::\n\n"
        "    services:\n"
        "      - node: web1\n"
        "        type: http\n"
        "        port: 8080\n"
        "      - node: web1\n"
        "        type: smtp\n"
        "        port: 25       # ← must differ from 8080",
    ),
    "E023": (
        "Unknown column generator type in database table schema.",
        "databases[].tables[].schema",
        "Guide.md §3.7 databases → table schema  →  E023",
        "Use a supported generator type::\n\n"
        "    schema:\n"
        "      id:         integer    # ← valid types: integer, float, first_name,\n"
        "      name:       first_name #   last_name, email, phone, department,\n"
        "      email:      email      #   salary, product, category, price,\n"
        "      salary:     salary     #   address, city, country, boolean,\n"
        "                             #   text, uuid, date, timestamp",
    ),
    "E027": (
        "A static route references a node that is not declared in nodes:.",
        "routes[].node",
        "Guide.md §3.17 routes  →  E027",
        "Fix the node name or add it to nodes::\n\n"
        "    routes:\n"
        "      - node: r1          # ← must match a declared node\n"
        "        destination: 10.0.0.0/24\n"
        "        via: 10.0.0.1",
    ),
    "E028": (
        "A static route has an invalid destination CIDR or via IP address.",
        "routes[].destination / routes[].via",
        "Guide.md §3.17 routes  →  E028",
        "Use valid IPv4 CIDR and IP::\n\n"
        "    routes:\n"
        "      - node: r1\n"
        "        destination: 192.168.5.0/24   # ← valid CIDR\n"
        "        via: 10.0.0.1                 # ← valid IPv4",
    ),
    "E030": (
        "An attacker node is not declared in nodes:.",
        "attackers[]",
        "Guide.md §3.15 attackers  →  E030",
        "Declare the attacker node under nodes::\n\n"
        "    nodes:\n"
        "      - name: h1          # ← must exist here\n"
        "        type: host\n\n"
        "    attackers:\n"
        "      - h1",
    ),
    "E032": (
        "Invalid VPN mode.",
        "vpn.mode",
        "Guide.md §3.4 vpn  →  E032",
        "Use one of the supported VPN modes::\n\n"
        "    vpn:\n"
        "      mode: remote_access  # ← valid: site_to_site | remote_access | hybrid",
    ),
    "E033": (
        "Invalid firewall policy.",
        "security.firewall.policy",
        "Guide.md §3.9 security  →  E033",
        "Use one of the supported policies::\n\n"
        "    security:\n"
        "      firewall:\n"
        "        policy: restrictive  # ← valid: restrictive | permissive",
    ),
    "E034": (
        "Invalid firewall backend.",
        "security.firewall.backend",
        "Guide.md §3.9 security  →  E034",
        "Use one of the supported backends::\n\n"
        "    security:\n"
        "      firewall:\n"
        "        backend: iptables   # ← valid: iptables | nftables",
    ),
    "E035": (
        "Invalid deployment mode.",
        "deployment.mode",
        "Guide.md §3.8 deployment  →  E035",
        "Use one of the supported deployment modes::\n\n"
        "    deployment:\n"
        "      mode: auto   # ← valid: auto | manual | hybrid",
    ),
    "E037": (
        "Invalid NPC host intensity value.",
        "npc.hosts",
        "Guide.md §3.13 npc  →  E037",
        "Use one of the supported intensity levels::\n\n"
        "    npc:\n"
        "      hosts:\n"
        "        h1: medium   # ← valid: low | medium | high",
    ),
    "E038": (
        "Invalid node type.",
        "nodes[].type",
        "Guide.md §3.1 nodes  →  E038",
        "Use one of the supported node types::\n\n"
        "    nodes:\n"
        "      - name: r1\n"
        "        type: router  # ← valid: host | router | switch",
    ),
    "E039": (
        "Invalid CIDR notation in network settings.",
        "settings.isp_base_network / lan_base_network / vpn_base_network",
        "Guide.md §3.12 settings  →  E039",
        "Use valid IPv4 CIDR notation::\n\n"
        "    settings:\n"
        "      isp_base_network: '10.0.0.0/8'        # ← valid CIDR\n"
        "      lan_base_network: '192.168.0.0/16'\n"
        "      vpn_base_network: '172.16.0.0/12'",
    ),
    "E042": (
        "Database api_port is out of valid range (must be 1–65535).",
        "databases[].api_port",
        "Guide.md §3.7 databases  →  E042",
        "Set a valid port number::\n\n"
        "    databases:\n"
        "      - host: db1\n"
        "        api_port: 9090   # ← must be 1–65535",
    ),
    "E043": (
        "Service port is out of valid range (must be 1–65535).",
        "services[].port",
        "Guide.md §3.6 services  →  E043",
        "Set a valid port number::\n\n"
        "    services:\n"
        "      - node: web1\n"
        "        type: http\n"
        "        port: 8080     # ← must be 1–65535",
    ),
    "E044": (
        "Timing delay values must be greater than zero.",
        "databases[].timing_protocol.short_delay_ms / long_delay_ms",
        "Guide.md §3.7 databases → timing_protocol  →  E044",
        "Set positive delay values::\n\n"
        "    timing_protocol:\n"
        "      short_delay_ms: 20.0   # ← must be > 0\n"
        "      long_delay_ms:  50.0   # ← must be > 0",
    ),

    "E045": (
        "device_classes references a node not declared in nodes:.",
        "device_classes",
        "Guide.md §3.14 device_classes  →  E045",
        "Fix the node name or declare it under nodes::\n\n"
        "    device_classes:\n"
        "      r1: lan_router     # ← must match a declared node name",
    ),
    "E046": (
        "traffic_control interface references a node not declared in nodes:.",
        "traffic_control.interfaces",
        "Guide.md §3.11 traffic_control  →  E046",
        "Fix the interface name — the part before '-eth' must be a declared node::\n\n"
        "    traffic_control:\n"
        "      r1-eth0: {area: lan}   # ← 'r1' must be in nodes:",
    ),
    "E047": (
        "vpn_peers.clients contains a duplicate node name.",
        "vpn_peers[].clients",
        "Guide.md §3.5 vpn_peers  →  E047",
        "Remove the duplicate entry from clients::\n\n"
        "    vpn_peers:\n"
        "      - gateway: vpnhub\n"
        "        clients:\n"
        "          - h1    # ← each client must appear once only",
    ),
    "E048": (
        "npc.hosts references a node not declared in nodes:.",
        "npc.hosts",
        "Guide.md §3.13 npc  →  E048",
        "Fix the host name or declare it under nodes::\n\n"
        "    npc:\n"
        "      hosts:\n"
        "        h1: medium   # ← 'h1' must be in nodes:",
    ),
    "E049": (
        "npc.weights contains an unknown behavior name or invalid weight value.",
        "npc.weights",
        "Guide.md §3.13 npc  →  E049",
        "Valid behaviors: http, bulk, dns, ftp, smtp, db, echo, idle.\n"
        "All weights must be non-negative integers::\n\n"
        "    npc:\n"
        "      weights:\n"
        "        high:\n"
        "          http: 65\n"
        "          bulk: 15\n"
        "          dns: 8\n"
        "          idle: 0    # ← non-negative int, known behavior name",
    ),

    # ── Runtime — services ───────────────────────────────────────────────────
    "R101": (
        "Timing protocol is enabled but secret_key is None at runtime.",
        "databases[].timing_protocol.secret_key",
        "Guide.md §3.7 databases → timing_protocol  →  R101",
        "Set a real secret_key in your YAML before starting::\n\n"
        "    timing_protocol:\n"
        "      enabled: true\n"
        "      secret_key: your-real-secret-here   # ← must not be empty",
    ),
}


# ─────────────────── exception class ─────────────────────────────────────────

class EmulatorError(Exception):
    """Structured config/runtime error — prints problem, location, and exact fix."""

    def __init__(self, code: str, detail: str = "") -> None:
        entry = REGISTRY.get(code)
        if entry:
            self.code          = code
            self.problem       = entry[0]
            self.yaml_key      = entry[1]
            self.guide_section = entry[2]
            self.fix_hint      = entry[3]
        else:
            self.code          = code
            self.problem       = "Unknown error"
            self.yaml_key      = "unknown"
            self.guide_section = "Guide.md §10 Error Codes"
            self.fix_hint      = ""
        self.detail = detail
        super().__init__(self._full_message())

    def _full_message(self) -> str:
        W = 62
        bar = "─" * W
        lines = [
            f"\n{bar}",
            f"  ISP Emulator  [{self.code}]",
            f"{bar}",
            f"",
            f"  Problem : {self.problem}",
        ]
        if self.detail:
            lines.append(f"  Where   : {self.detail}")
        lines += [
            f"",
            f"  Fix     : {self._indent_fix(self.fix_hint)}",
            f"",
            f"  YAML key: {self.yaml_key}",
            f"  Guide   : {self.guide_section}",
            f"{bar}\n",
        ]
        return "\n".join(lines)

    @staticmethod
    def _indent_fix(text: str) -> str:
        """Indent continuation lines of the fix hint to align under 'Fix :'."""
        if not text:
            return ""
        lines = text.splitlines()
        indent = " " * 10  # len("  Fix     : ")
        return ("\n" + indent).join(lines)

    def print_and_exit(self, exit_code: int = 1) -> None:
        print(self._full_message(), file=sys.stderr, flush=True)
        sys.exit(exit_code)


def raise_config_error(code: str, detail: str = "") -> None:
    raise EmulatorError(code, detail)
