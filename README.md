# ISP Emulator

A Mininet-based ISP/enterprise network emulator that generates labeled network-traffic datasets for machine-learning research into covert-channel (timing-watermark) detection.

For usage, configuration syntax, and CLI commands, see [Guide.md](Guide.md).

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Quick Start](#2-quick-start)
3. [Directory Structure](#3-directory-structure)
4. [Architecture](#4-architecture)
5. [Execution Flow](#5-execution-flow)
6. [Network Subsystem](#6-network-subsystem)
7. [VPN Subsystem](#7-vpn-subsystem)
8. [Traffic Control Subsystem](#8-traffic-control-subsystem)
9. [Services Subsystem](#9-services-subsystem)
10. [NPC Subsystem](#10-npc-subsystem)
11. [Capture Subsystem](#11-capture-subsystem)
12. [Exfiltration Subsystem](#12-exfiltration-subsystem)
13. [Session Registry — schema.json](#13-session-registry--schemajson)
14. [Configuration System](#14-configuration-system)
15. [Error System](#15-error-system-errorspy)
16. [Automation Runner](#16-automation-runner)
17. [Data Flow](#16-data-flow)
18. [Design Philosophy](#18-design-philosophy)
19. [Development Workflow](#19-development-workflow)
20. [Contribution Guide](#20-contribution-guide)
21. [Included Topology Variants](#21-included-topology-variants)

---

## 1. Project Overview

The emulator builds a virtual network using Mininet with Open vSwitch (OVS) switches and Linux network namespaces. On top of the network:

- **WireGuard VPN** tunnels raised and lowered at runtime without topology rebuild.
- **NPC background traffic** (HTTP, DNS, FTP, SMTP, iperf3, echo) at controllable utilisation: low (ρ≈0.2), medium (ρ≈0.6), high (ρ≈0.95).
- **SQLite databases** with a CRUD REST API and an embedded timing-channel covert protocol that encodes a deterministic bitstream into inter-packet delays.
- **Per-interface PCAPNG capture** merged, feature-extracted, and serialised to CSV.
- **Session registry** (`dataset/schema.json`) records every session with timing-protocol metadata, NPC intensity, VPN state, and rhythm (transmitted bit sequence).
- **Automation runner** (`scripts/auto_gen.py`) drives the interactive CLI via pexpect to produce large labeled datasets across all combinations of topology × VPN × NPC × timing × exfiltration.

**Supported platform:** Ubuntu 22.04 LTS. Mininet requires Linux kernel networking features (network namespaces, veth pairs, OVS bridges).

---

## 2. Quick Start

```bash
# Install all system and Python dependencies (Ubuntu 22.04)
sudo bash scripts/setup.sh

# Clean any stale Mininet state
sudo mn -c

# Run a topology interactively (requires root)
sudo python3 network/topology.py configs/topology_enterprise.yaml --cli

# Run automated experiment generation (requires root)
sudo python3 scripts/auto_gen.py --config configs/auto-gen.yaml

# Run unit/physics tests (no root needed)
python3 -m pytest tests/ -q
```

**System packages installed by `setup.sh`:** `mininet`, `openvswitch-switch`, `wireguard`, `wireguard-tools`, `iproute2` (`tc`), `iptables`, `tcpdump`, `wireshark-common` (`mergecap`), `iperf3`, `dnsutils` (`dig`), `curl`

**Python packages (`requirements.txt`):** `PyYAML`, `scapy`, `pexpect`, `pytest`, `pytest-timeout`

---

## 3. Directory Structure

```
isp-emulator/
├── config_loader.py              YAML → typed dataclasses
├── errors.py                     Structured error codes (E000–R101) with inline fix hints
├── mechanism.md                  Physics formulas: TBF+netem, NPC traffic, timing protocol
├── debug.py                      Coloured console output
├── requirements.txt              Python package dependencies
│
├── configs/
│   ├── topology.yaml             Default attacker/victim topology
│   ├── topology_enterprise.yaml  Multi-LAN enterprise
│   ├── topology_dmz_segmented.yaml  Three-zone security
│   ├── topology_remote_worker.yaml  Remote worker VPN
│   ├── topology_three_site.yaml  Three-site WAN
│   ├── topology_wan_isp.yaml     WAN/ISP backbone
│   ├── topology_insider_threat.yaml  Insider threat
│   └── auto-gen.yaml             Experiment automation config
│
├── network/
│   ├── topology.py               Mininet builder + ISPCli (entry point)
│   ├── ip_allocator.py           IP and interface allocation
│   ├── routing.py                Static routing engine
│   ├── routers.py                LinuxRouter node class
│   ├── vpn_manager.py            WireGuard deployment orchestrator
│   ├── vpn_controller.py         Runtime VPN on/off/restart
│   ├── wireguard.py              WireGuard primitives
│   ├── capture_manager.py        Packet capture engine + schema.json writer
│   └── npc/
│       ├── npc_manager.py        NPC traffic orchestrator
│       ├── behaviors.py          Per-protocol behavior implementations
│       └── intensity.py          Behavior weight tables
│
├── services/
│   ├── service_manager.py        Service deployment orchestrator
│   ├── service_registry.py       Registry of running services
│   ├── service_discovery.py      Scan for undeclared running services
│   └── database/
│       ├── database_manager.py   SQLite + REST API + application-layer watermark injector
│       ├── synthetic_data.py     Row generation from schema
│       ├── generators.py         Per-field synthetic data generators
│       ├── schema_builder.py     SQLite DDL builder
│       └── timing_protocol.py    Timing-channel config dataclass
│
├── scripts/
│   ├── auto_gen.py               Experiment automation runner (pexpect)
│   ├── analyze_watermark.py      IPD-based watermark survival analysis
│   └── setup.sh                  System dependency installer
│
├── dataset/
│   ├── schema.json               Session registry
│   ├── network_profile.json      Per-session TC command log
│   ├── pcapng/                   Merged PCAPNG files (permanent)
│   ├── csv/                      Parsed CSV files (permanent)
│   └── tmp/                      Per-interface staging PCAPNGs (ephemeral)
│
```

---

## 4. Architecture

```
    ┌───────────────────────────────────────────────┐
    │  scripts/auto_gen.py (pexpect CLI driver)     │  ← batch mode
    │  Cartesian product × repeat                   │
    │  mn -c → spawn topology.py → CLI             │
    └───────────┬───────────────────────────────────┘
                │ spawn subprocess (PTY)
┌───────────────▼─────────────────────────────────┐
│  network/topology.py (ISPTopology + ISPCli)     │  ← interactive mode
│  Mininet lifecycle + extended CLI commands       │
└────┬──────┬──────┬──────┬──────┬────────────────┘
     │      │      │      │      │
  Config  IP    Route  VPN   Svc/DB  Capture/NPC
  Loader Alloc Engine Mgr   Mgr      Mgr
     │      │      │      │      │      │
┌────▼──────▼──────▼──────▼──────▼──────▼──────────┐
│  Mininet + Open vSwitch                           │
│  Linux network namespaces (one per node)          │
└───────────────────────────────────────────────────┘
```

**Configuration layer:** `config_loader.py` reads YAML and returns a typed `TopologyConfig` dataclass tree. All other components consume this; none read YAML directly at runtime (except the feature selector and CSV parser subprocesses, which re-read `feature_selection` column config).

**Network layer:** `ip_allocator.py` computes all IPs and interface names from `TopologyConfig`. `topology.py` uses Mininet with OVS switches (`failMode=standalone`, no external controller) and `TCLink`. Routers use `LinuxRouter` (Host with IP forwarding). VPN gateways use `LinuxRouter`.

**Subprocess layer:** capture sniffers, feature selector, and CSV parser all run as separate OS processes communicating via files and stdout. This isolates Scapy's global state from the main process.

---

## 5. Execution Flow

### Startup (ISPTopology.start)

1. `load_config()` — parse YAML → `TopologyConfig`. Expand `lans:` if present; validate.
2. `allocate()` — assign node aliases, interface names, ISP/LAN/VPN subnets.
3. `_build_network()` — Mininet: `addSwitch` (OVS, `failMode=standalone`), `addHost` (LinuxRouter or Host), `addLink` (TCLink).
4. `net.start()` — bring up OVS bridges and node processes.
5. `_assign_ips()` — `ip addr add` on every pre-allocated interface.
6. `configure_routes()` — host defaults, inter-LAN routes, ISP-node routes, manual overrides.
7. VPN deploy — `VPNManager.deploy()` if `vpn.enabled` and peers configured. Creates `VPNController` for runtime control.
8. Phase 2 — `DatabaseManager`, `ServiceManager`, optional `FirewallManager`.
9. `CaptureManager` and `NPCManager` created and wired together.
10. `ISPCli(net)` — interactive CLI if `--cli` flag.

### Shutdown (ISPTopology.stop)

1. `ServiceManager.stop_all()`
2. `NPCManager.stop()`
3. `CaptureManager.stop()` — runs pipeline if automatic mode.
4. `CaptureManager.teardown_tc()` — remove TC qdiscs.
5. `net.stop()`

---

## 6. Network Subsystem

### IP Allocator (`network/ip_allocator.py`)

Pure allocation logic — no Mininet calls.

- **ISP allocation:** one /24 per ISP switch from `isp_base_network`. Sequential host IPs to adjacent non-switch nodes.
- **LAN allocation:** one /24 per `lan_gateway` from `lan_base_network`. Gateway gets `.1`. If a LAN switch (from `lans:` expansion) is adjacent, all its downstream hosts share the same /24. Otherwise direct gateway-to-host links.
- **VPN allocation:** one /24 per `vpn_peers` group from `vpn_base_network`. Gateway gets `.1`, clients get sequential IPs.

Result: `AllocationResult` — `node_interfaces`, `isp_subnets`, `lan_subnets`, `vpn_subnets`, `default_gateways`, `link_interfaces`, `vpn_node_ips`, `node_aliases`.

### Interface Naming

IFNAMSIZ = 15 chars. `{node_name}-eth{N}` must fit. Nodes longer than 9 chars get an alias: word-initials[:4] + sequential counter (e.g. `lan_sw_office` → `lso1`). Aliases are deterministic and unique within a topology.

### Routing Engine (`network/routing.py`)

Installed after network startup, before VPN:

1. **Host defaults:** `ip route add default via {gw_ip}` for every non-gateway host.
2. **Inter-LAN routes:** for each LAN gateway, `ip route add {peer_lan_subnet} via {peer_isp_ip}` for every other gateway.
3. **ISP-node routes:** for VPN gateways and other ISP nodes, routes to each LAN subnet via the gateway's ISP IP.
4. **Manual overrides:** `ip route replace` from `routes:` YAML section. Applied last.

VPN overlay routes (172.16.x/24) are NOT added here — they are installed by `vpn_manager.py` via wg0.

---

## 7. VPN Subsystem

### VPN Manager (`network/vpn_manager.py`)

Deploys hub-and-spoke WireGuard. Optimised for parallelism — stages 2 and 4 run concurrent threads across nodes.

**Stages:**
1. Gateway: sysctl IP forwarding (batched cmd), `wg genkey | wg pubkey`, `ip link add wg0`.
2. All clients (parallel threads): key generation and wg0 interface setup.
3. Gateway peers: one batched `wg set wg0 peer KEY ... peer KEY ...` command for all clients.
4. Client peer + routes (parallel): each client gets its gateway peer config and kernel routes. Gateway gets return routes.
5. Handshake trigger: each client pings gateway VPN IP. Sleep 1 s.

**Mode routing:**
- `site_to_site`: client allowed-IPs = `{client_vpn_ip}/32 + {client_lan_subnet}`. Gateway routes client LAN via wg0.
- `remote_access`: client allowed-IPs = `{client_vpn_ip}/32`. All LAN subnets route via gateway.
- `hybrid`: `peers` get site-to-site; `clients` get remote-access.

**NAT:** if `vpn.nat: true`:
- Each VPN client node gets `iptables MASQUERADE -o wg0` — outbound traffic via wg0 uses the VPN IP as source.
- Gateway masquerades only non-LAN traffic (`! -d lan_base_network`) — LAN destinations see the real VPN IP, enabling per-session VPN detection from packet evidence.
- Cleanup: wg0 masquerade rule removed on `vpn off`.

### VPN Controller (`network/vpn_controller.py`)

Runtime VPN management. `turn_on()` creates a fresh `VPNManager` and calls `deploy() + verify()`. `turn_off()` removes all wg0 interfaces and routes in parallel threads. Prints per-stage timing table after every `turn_on()`.

---

## 8. Traffic Control Subsystem

TC parameters are declared in the YAML `traffic_control` section and parsed by `config_loader.py` into `TCParams` dataclasses. Mininet applies them via `TCLink` during `addLink()` — no external tc_generator script.

**Per-link parameters (all from YAML):**
- `bw`: bandwidth Mbit/s (TBF token bucket)
- `delay`: propagation delay string, e.g. `"10ms"` (netem)
- `jitter`: delay variance string (netem)
- `loss`: packet loss percentage (netem)
- `max_queue_size`: txqueue length in packets

**Queuing delay and emergent jitter** arise from NPC traffic filling the TBF queue. No random synthetic impairments — all values are deterministic from YAML.

TC commands are recorded per session in `dataset/network_profile.json`.

---

## 9. Services Subsystem

### Service Manager (`services/service_manager.py`)

Deploys Python-based services inside Mininet node namespaces via `node.popen()`. Service scripts are embedded as string literals and written to `/tmp/` before execution. Registers each running service in `ServiceRegistry`.

**Modes:** `auto` deploys all declared services; `hybrid` also runs `ServiceDiscovery` to scan for undeclared ones; `manual` skips deployment entirely.

### Database Manager (`services/database/database_manager.py`)

For each `DatabaseConfig`:
1. `schema_builder.py` generates DDL (`CREATE TABLE` statements).
2. `synthetic_data.py` generates rows using `generators.py`.
3. Data inserted via Python's `sqlite3`.
4. Flask REST API started on `api_port` (if configured): `GET /api/{table}` returns all rows; `POST /timing/set` updates timing channel state.

### Timing Protocol (`services/database/timing_protocol.py`)

Deterministic covert timing channel.

**Mechanism:** `SHA-512(secret_key:start_timestamp:nonce)` generates a 512-bit pool. `start_timestamp` is the Unix timestamp of the first TOS-marked packet — acts as a session-unique salt so keystreams from the same key differ per session. Each bit: 0 → sleep `short_delay_ms`; 1 → sleep `long_delay_ms`. On pool exhaustion, nonce increments and a new digest is computed.

**Metadata accumulated per request:** rhythm (bit sequence), nonces used, packet count, start/end timestamps, src/dest IPs.

**Detection:** observer measures inter-packet delays (IPDs). IPDs ≈ `short_delay_ms` → bit=0; IPDs ≈ `long_delay_ms` → bit=1. Decoded bitstream matches `SHA-512(key:t0:1)` given known key and recorded `start_timestamp`.

See `mechanism.md §15` for full formulas and signal-to-noise analysis.

State file: `/tmp/timing_{host}_{db}.json`. Read by `CaptureManager` at `capture stop` to populate `schema.json`.

`/timing/set` endpoint enables `inject on/off` to enable/disable the channel at runtime.

### Synthetic Data Generator (`services/database/generators.py`)

Pure Python, no external dependencies. `generate(field_type, context)` returns a realistic value. `context` (row built so far) enables coherent multi-field generation (email derived from first_name + last_name if both present in context).

---

## 10. NPC Subsystem

`network/npc/` — round-based background traffic generator.

**Thread model:** one daemon thread per NPC host.

**Priming phase:** fires `http`, `dns`, `db`, `echo`, `smtp`, `ftp` behaviors once immediately so every capture window contains at least one of each protocol.

**Main loop:** `random.choices(behavior_names, weights)` selects behavior → execute → sample inter-arrival → `stop_event.wait(timeout)`.

**Heavy-behavior cap:** `ftp`, `smtp`, `bulk` count as heavy. `threading.Semaphore(min(4, cpu_count-2))` limits concurrent heavy processes. If semaphore not acquired non-blocking, round is skipped.

**Behavior implementations** (`network/npc/behaviors.py`):

| Behavior | Implementation | Inter-arrival |
|----------|---------------|---------------|
| `http` | `curl GET http://{http_node_ip}:{port}/` | expovariate(1/5) |
| `dns` | `dig @{dns_node_ip} {nodename}.local` | expovariate(1/4) |
| `db_query` | `curl GET http://{db_ip}:{port}/{endpoint}` | expovariate(1/3) |
| `smtp` | Python `smtplib`, lognormal(8,3) KB body | uniform(5,15) |
| `ftp` | Python `ftplib`, uniform(0.1,5) MB | uniform(8,20) |
| `bulk` | `iperf3 -u -b {2-8}M -t 5` | expovariate(1/15) |
| `echo` | Python TCP socket, uniform(8,512) B | expovariate(1/8) |
| `idle` | no-op | expovariate(1/10) |

Service IPs resolved at startup from `services:` and `databases:` sections by service type — no hardcoded node names. DNS query domains are `{nodename}.local` for every node in the topology. Behaviors are silently skipped if the required service type is absent from the YAML.

NPC is automatically stopped when `capture stop` is called.

---

## 11. Capture Subsystem

### Capture Engine (`network/capture_manager.py`)

**Session ID:** `datetime.now().strftime("%Y%m%d_%H%M%S_%f")`.

**Sniffer processes:** for each `(device, interface)` pair, spawns:

```python
node.popen([sys.executable, "-c", _SNIFFER_SCRIPT, iface, pcapng_path])
```

The sniffer script (embedded in `_SNIFFER_SCRIPT`):
1. Opens PCAPNG file immediately (before importing Scapy) — file exists on disk before any packets arrive.
2. Imports `AsyncSniffer`.
3. Writes packets as PCAPNG Enhanced Packet Blocks (EPBs) as they arrive — no RAM accumulation.
4. SIGTERM/SIGINT handler flushes and closes cleanly.

**Automatic pipeline** (when `automatic: true`):
1. `mergecap -w {out} {inputs}` — falls back to `scapy.PcapReader + wrpcap` if `mergecap` unavailable.
2. Read `/tmp/timing_<host>_<db>.json` — runtime session data (rhythm, packet count, timestamps) written by the DB watermark injector.
3. Upsert `dataset/schema.json` with merged PCAP path + timing session data.
4. `clean()` if `cleanup.enabled`.

---

## 12. Exfiltration Subsystem

**TOS marking:** attacker sends HTTP GET with `IP_TOS = exfiltration.attack_tos` applied at the socket level before `connect()` (default `0x10`). Scoped to this socket only — concurrent NPC database traffic is never marked.

**Attacker selection:** if `exfiltration.attacker` is set in the YAML, that node is used directly — no `attackers:` list required. If not set, aggregates `attackers:` from all `configs/topology*.yaml` files and picks randomly.

**Victim discovery:** from current config's `databases:` list only (avoids hostname collisions across topologies). If `exfiltration.target.host` is set, that database is used directly.

**Endpoint selection:** from `exfiltration.endpoints` if set; otherwise `/api/{table_name}` for a random table.

**TOS byte:** from `exfiltration.attack_tos` in YAML (default `0x10`). Applied at socket level before `connect()` — all TCP packets on the exfil connection (SYN, data, FIN) carry TOS=0x10.

**Watermark injection:** the DB REST API server (running inside the DB node's network namespace) embeds a scapy TOS sniffer and a watermark injector. On TOS SYN detection: `new_session()` preloads the SHA-512 bitstream. On `GET /backup`: waits for session to arm, sends 512B chunks with `clock_nanosleep` delay after each chunk — delay encodes bit_i from the SHA-512 stream. On FIN: `finalize_session()` snapshots rhythm + packet count to `/tmp/timing_<host>_<db>.json`.

---

## 13. Session Registry — schema.json

`dataset/schema.json` — JSON array, one record per capture session.

```json
{
  "session_id": "20260821_024254_805997",
  "topology": "topology_enterprise.yaml",
  "pcapng": "dataset/pcapng/20260821_024254_805997.pcapng",
  "timing_protocol": {
    "conf_atc_ip": "192.168.0.3",
    "victim_ip": "192.168.1.3:9090",
    "secret_key": "enterprise-company-covert-key",
    "short_delay_ms": 20.0,
    "long_delay_ms": 50.0,
    "sessions": [
      {
        "attacker_ip": "172.16.0.2",
        "start_timestamp": 1787260380.70,
        "end_timestamp": 1787260381.80,
        "exfiltrated_data_packets": 20,
        "rhythm": [1,1,0,0,1,0,1,1,0,1,1,0,0,1,0,1,1,0,1,0]
      }
    ]
  },
  "experiment": {
    "vpn": "on",
    "exfil": "on",
    "run": 1
  }
}
```

**Field sources — all real network evidence:**

| Field | Source |
|-------|--------|
| `conf_atc_ip` | Attacker node's LAN IP from `ip_allocator` (ground truth) |
| `attacker_ip` | Actual `pkt[IP].src` seen by DB scapy sniffer (may be VPN tunnel IP) |
| `start_timestamp` | Real `pkt.time` from first TOS-marked SYN |
| `end_timestamp` | Real `time.time()` when FIN arrives and session finalized |
| `exfiltrated_data_packets` | Count of 512B chunks sent through watermark injector |
| `rhythm` | Actual bits from SHA-512 keystream consumed during transfer |

`sessions` is an array — one entry per attacker TCP connection. Empty for `exfil=off` captures.

`dataset/network_profile.json` records exact TC commands per session: `[{session_id: {iface: tc_cmd}}]`.

---

## 14. Configuration System

`config_loader.load_config(path)` → `TopologyConfig`.

**Steps:**
1. `yaml.safe_load()`.
2. Parse Phase 1: `nodes`, `links`, `settings`, `vpn_peers`.
3. Parse Phase 2: `lans`, `services`, `databases`, `deployment`, `security`, `vpn`, `routes`, `capture`, `device_classes`, `npc.hosts`, `exfiltration`, `traffic_control`, `attackers` (optional).
4. If `vpn.server.node` set: `_merge_vpn_config()` auto-populates `vpn_gateways` and `vpn_peers`.
5. If `lans` declared: `_expand_lans()` creates nodes, links, gateways in-place.
6. `_validate()` raises `EmulatorError` (from `errors.py`) on structural violations. Each error carries a code (E000–R101), the exact YAML key, an inline fix snippet, and a Guide.md §10 reference.

**Key behaviours:**
- `node:` and `host:` both accepted as service host key; `node:` takes precedence.
- `capture.automatic:` supersedes `capture.mode:`.
- `capture.devices` falls back to top-level `devices:` key.
- DPID: YAML value normalised to 16 hex digits; if absent, SHA-256(name)[:16] used (deterministic, never zero).

---

## 15. Error System (`errors.py`)

All configuration and runtime failures raise `EmulatorError` instead of bare Python exceptions. Each error prints:

```
──────────────────────────────────────────────────────────────
  ISP Emulator  [E011]
──────────────────────────────────────────────────────────────

  Problem : timing_protocol is enabled but secret_key is not set.
  Where   : db 'victimdb' on host h3

  Fix     : Add a secret_key under timing_protocol::
              timing_protocol:
                enabled: true
                secret_key: your-real-secret-here   ← add this line

  YAML key: databases[].timing_protocol.secret_key
  Guide   : Guide.md §3.7 databases → timing_protocol  →  E011
──────────────────────────────────────────────────────────────
```

Error codes: **E000–E019** (config structure), **E021–E044** (enum/range validation), **R001–R020** (runtime IP/WireGuard), **R101** (service startup). Full list: `Guide.md §10 Error Codes`.

---

## 16. Automation Runner

`scripts/auto_gen.py` — experiment isolation via pexpect.

**Why isolation matters:** Mininet accumulates global state (OVS bridges, iptables rules, namespaces). Reusing a session leaks state across experiment conditions, introducing bias into the dataset.

**Isolation guarantee:** `mn -c` before and after every experiment; fresh `topology.py --cli` subprocess per experiment; pexpect `expect_exact("mininet> ")` synchronises on prompt state.

**Timing constants (preregistered — do not change):**

| Constant | Value | Purpose |
|----------|-------|---------|
| NPC warmup | 10 s | Links primed before capture |
| Pre-action window | 5 s | Baseline traffic before exfil/label divergence |
| Startup timeout | 240 s | VPN + DB deploy time |
| Capture stop timeout | 300 s | Merge + feature selection + CSV |
| Exit timeout | 90 s | Topology teardown |

**Progress file:** `.auto_gen_progress.json` — sorted list of completed `Combo.key()` strings. Key encodes: `topology=X|vpn=Y|npc=Z|inject=A|exfil=B|wait=C|run=N`. `--resume` skips completed keys. File deleted on full successful run.

See [Guide.md](Guide.md#4-auto-genyaml--experiment-automation-language) for configuration syntax.

---

## 16. Data Flow

```
topology.yaml
      ↓
config_loader.load_config()
      ↓  TopologyConfig
ip_allocator.allocate()
      ↓  AllocationResult (IPs, interfaces, subnets)
topology._build_network()      → Mininet net
      ↓
topology._assign_ips()         → ip addr add
      ↓
routing.configure_routes()     → ip route add
      ↓
vpn_manager.deploy()           → wg set peer, ip route (wg0)
      ↓
database_manager.deploy_all()  → sqlite3 + Flask API in node namespace
      ↓
service_manager.deploy_all()   → HTTP/FTP/SMTP/DNS/echo in namespaces
      ↓
apply tc ──→ TCLink (Mininet) ──→ tc qdisc add ... tbf + netem
                  ↓
           dataset/network_profile.json
      ↓
npc start ──→ NPCManager threads ──→ curl/dig/ftplib/smtplib/iperf3
      ↓
capture start ──→ AsyncSniffer subprocesses (one per interface)
                        ↓
                  dataset/tmp/{session}_*.pcapng
      ↓
inject on ──→ POST /timing/set ──→ TimingProtocol.enabled = true
      ↓
exfil ──→ TOS-marked GET ──→ API response with timing delays
               ↓
         /tmp/timing_{host}_{db}.json
      ↓
capture stop
      ├── mergecap ──→ dataset/pcapng/{session}.pcapng
      ├── schema.json ──→ upsert {session_id, topology, pcapng, timing_protocol, experiment}
      └── clean() ──→ rm dataset/tmp/{session}_*.pcapng
```

---

## 18. Design Philosophy

**No global state leakage between experiments.** `auto_gen.py` runs `mn -c` before and after every experiment. `VPNController.turn_on()` always purges wg0 before deploying.

**All addresses derived, never hardcoded.** `ip_allocator.py` is the single source for every IP, prefix, and interface name.

**Subprocesses for capture and pipeline.** Sniffers, feature selector, and CSV parser are separate OS processes. Scapy global state is isolated. Pipeline stages are independently replaceable.

**Deterministic DPID.** SHA-256(name)[:16] produces the same OVS bridge identifier for the same topology YAML across runs. Manual override is supported.

**Interface naming enforced at allocation time.** The 9-character alias rule is applied in `ip_allocator.py` before any Mininet calls — length violations are caught before the network is built.

**Config is the source of truth.** Every subsystem reads only from `TopologyConfig` and `AllocationResult`. No subsystem re-reads YAML at runtime except the feature selector and CSV parser subprocesses.

---

## 19. Development Workflow

```bash
# Install dependencies
sudo bash scripts/setup.sh

# Run a topology interactively (requires root)
sudo mn -c
sudo python3 network/topology.py configs/topology_enterprise.yaml --cli

# Run automated batch (requires root)
sudo mn -c
sudo python3 scripts/auto_gen.py --config configs/auto-gen.yaml

# Dry-run: preview experiment plan
python3 scripts/auto_gen.py --config configs/auto-gen.yaml --dry-run

# Clean stale Mininet state
sudo mn -c
```

---

## 20. Contribution Guide

**New topology:** copy an existing YAML, modify, test with `sudo python3 network/topology.py configs/my_new.yaml --cli`. `_validate()` raises `EmulatorError` with code + YAML key + inline fix on any structural violation. See `Guide.md §10` for all error codes.

**New service type:** add deployment function in `services/service_manager.py`. Add type to `ServiceConfig.type` docs in `config_loader.py`.

**New NPC behavior:** see [Guide.md — Developer Recipes](Guide.md#9-developer-recipes).

**New feature column:** see [Guide.md — Developer Recipes](Guide.md#9-developer-recipes).

**Timing protocol changes:** edit `services/database/timing_protocol.py` for logic; edit `config_loader.py` defaults for new YAML keys. Do not modify frozen values in `configs/preregistration.yaml`.

---

## 21. Included Topology Variants

| File | Description |
|------|-------------|
| `topology.yaml` | Default: attacker (h2) and victim (h3) via ISP switch and VPN hub. SQLite DB on h3 with timing protocol. |
| `topology_enterprise.yaml` | Multi-LAN: office, datacenter, branch, lab LANs. Hub-and-spoke WireGuard. Full service stack. |
| `topology_dmz_segmented.yaml` | Three-zone security: external → DMZ → internal. Restrictive firewall. Tests watermark survival through multi-hop routing. |
| `topology_remote_worker.yaml` | Remote worker in `remote_access` VPN mode. Attacker behind a home router. |
| `topology_three_site.yaml` | Three corporate sites via WAN ISP backbone. Site-to-site VPN. |
| `topology_wan_isp.yaml` | WAN/ISP backbone with multiple ISP nodes and long-haul links. |
| `topology_insider_threat.yaml` | Insider threat: attacker inside the corporate LAN, no VPN for exfil. |

---

*For configuration syntax, CLI commands, and usage examples, see [Guide.md](Guide.md).*  
*For physics formulas (TBF+netem, NPC traffic model, timing protocol), see [mechanism.md](mechanism.md).*
