# ISP Emulator — User Guide

Language manual for configuration, CLI commands, and experiment automation.
For architecture and internals, see [README.md](README.md).

---

## Table of Contents

1. [Installation](#1-installation)
2. [Running the Emulator](#2-running-the-emulator)
3. [Topology YAML — Configuration Language](#3-topology-yaml--configuration-language)
   - 3.1 [nodes](#31-nodes)
   - 3.2 [links](#32-links)
   - 3.3 [lans](#33-lans)
   - 3.4 [vpn](#34-vpn)
   - 3.5 [vpn_gateways / vpn_peers (legacy)](#35-vpn_gateways--vpn_peers-legacy)
   - 3.6 [services](#36-services)
   - 3.7 [databases](#37-databases)
   - 3.8 [deployment](#38-deployment)
   - 3.9 [security](#39-security)
   - 3.10 [capture](#310-capture)
   - 3.11 [traffic_control](#311-traffic_control)
   - 3.12 [settings](#312-settings)
   - 3.13 [npc](#313-npc)
   - 3.14 [device_classes](#314-device_classes)
   - 3.15 [attackers](#315-attackers)
   - 3.16 [exfiltration](#316-exfiltration)
   - 3.17 [routes](#317-routes)
4. [auto-gen.yaml — Experiment Automation Language](#4-auto-genyaml--experiment-automation-language)
   - 4.1 [selected](#41-selected)
   - 4.2 [repeat](#42-repeat)
   - 4.3 [vpn](#43-vpn)
   - 4.4 [npc](#44-npc)
   - 4.5 [inject](#45-inject)
   - 4.6 [exfil](#46-exfil)
   - 4.7 [wait](#47-wait)
   - 4.8 [Combination generation](#48-combination-generation)
5. [CLI Language](#5-cli-language)
   - 5.1 [vpn](#51-vpn)
   - 5.2 [capture](#52-capture)
   - 5.3 [npc](#53-npc)
   - 5.4 [inject](#54-inject)
   - 5.5 [exfil](#55-exfil)
   - 5.6 [apply](#56-apply)
   - 5.7 [Standard Mininet commands](#57-standard-mininet-commands)
6. [Configuration Examples](#6-configuration-examples)
7. [Common Mistakes](#7-common-mistakes)
8. [Best Practices](#8-best-practices)
9. [Developer Recipes](#9-developer-recipes)
10. [Error Codes](#10-error-codes)

---

## 1. Installation

### System requirements

Ubuntu 22.04 LTS (other Linux distributions may work; Windows and macOS are not supported for topology emulation).

### Automated install (recommended)

```bash
sudo bash scripts/setup.sh
```

Installs all system and Python packages, loads the WireGuard kernel module, and verifies the installation.

### Manual — system packages

```bash
sudo apt-get install -y \
    python3 python3-pip \
    mininet \
    openvswitch-switch openvswitch-common \
    wireguard wireguard-tools \
    iproute2 iptables \
    iputils-ping net-tools \
    tcpdump wireshark-common \
    curl dnsutils iperf3
```

| Package | Purpose |
|---------|---------|
| `mininet` | Network emulation framework |
| `openvswitch-switch` | OVS bridges (required by Mininet) |
| `wireguard wireguard-tools` | WireGuard VPN kernel module + `wg` CLI |
| `iproute2` | `ip`, `tc` — routing and traffic control |
| `iptables` | NAT/masquerade rules |
| `tcpdump` | Low-level packet capture |
| `wireshark-common` | `mergecap` for PCAPNG merging |
| `iperf3` | NPC bulk traffic behavior |
| `dnsutils` | `dig` for NPC DNS behavior |

### Manual — Python packages

```bash
pip3 install -r requirements.txt
pip3 install scapy          # required for packet capture and feature extraction
```

Or run the included setup script (requires root):

```bash
sudo bash scripts/setup.sh
```

### Verify

```bash
mn --version
wg --version
python3 -c "import mininet, yaml, scapy, pexpect; print('OK')"
```

---

## 2. Running the Emulator

Both modes require root. Run `sudo mn -c` first to clean up any stale Mininet state from previous sessions.

### Interactive mode

Start a single topology and drop into the extended CLI:

```bash
sudo mn -c
sudo python3 network/topology.py configs/topology_enterprise.yaml --cli
```

Builds the Mininet network, deploys services and databases, then opens the CLI where `capture`, `npc`, `vpn`, `inject`, `exfil`, and `apply` commands are available.

Any topology YAML in `configs/` can be used:

```bash
sudo python3 network/topology.py configs/topology.yaml --cli
sudo python3 network/topology.py configs/topology_dmz_segmented.yaml --cli
```

### Batch mode

Run the automated experiment generator across all combinations in `auto-gen.yaml`:

```bash
sudo mn -c
sudo python3 scripts/auto_gen.py --config configs/auto-gen.yaml
```

Every experiment runs in full isolation (`mn -c` before and after each one).

Dry run — preview the experiment plan without executing:

```bash
python3 scripts/auto_gen.py --config configs/auto-gen.yaml --dry-run
```

Resume an interrupted run:

```bash
sudo python3 scripts/auto_gen.py --config configs/auto-gen.yaml --resume
```

---

## 3. Topology YAML — Configuration Language

Every topology is a YAML mapping. All keys are optional unless noted.

**Minimum valid topology:**

```yaml
nodes:
  - name: s1
    type: switch
  - name: h1
    type: host
  - name: h2
    type: host
links:
  - [h1, s1]
  - [s1, h2]
```

Validation rules enforced by `_validate()`:
- All link endpoints must be declared nodes.
- All `lan_gateways` must be declared nodes and must not be switches.
- All `vpn_gateways` must be declared nodes.
- All `vpn_peers` gateways and clients must be declared nodes.
- All `services` and `databases` hosts must be declared nodes.
- At least one ISP switch must exist.

---

### 3.1 nodes

```yaml
nodes:
  - name: s1
    type: switch
    dpid: 0000000000000001   # optional

  - name: r1
    type: router

  - name: h1
    type: host
```

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `name` | string | yes | — | Unique node identifier. |
| `type` | string | yes | — | `switch`, `router`, or `host`. |
| `dpid` | string | no | SHA-256(name)[:16] | OVS datapath ID. 1–16 hex digits; zero-padded to 16. |

Node names longer than 9 characters receive a short alias for Linux interface naming (IFNAMSIZ=15). Alias: word-initials[:4] + sequential counter. Example: `lan_sw_office` → `lso1`.

---

### 3.2 links

```yaml
links:
  - [h2, r1]
  - [r1, s1]
  - [s1, vpnhub]
```

Each entry is `[node_a, node_b]`. Order matters — the allocator assigns interface numbers in declaration order, which must match `traffic_control` interface names.

---

### 3.3 lans

Auto-creates a router, a LAN switch (`lan_sw_{name}`), host nodes, and links.

```yaml
lans:
  - name: office
    gateway: r1
    isp_switch: s1
    hosts:
      - h1
      - h2
```

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `name` | string | yes | — | LAN identifier. LAN switch named `lan_sw_{name}`. |
| `gateway` | string | yes | — | Router node. Auto-created if not in `nodes`. |
| `isp_switch` | string | **yes** | — | ISP switch this LAN connects to. Must match a declared switch node. |
| `hosts` | list[string] | no | `[]` | Host nodes. Auto-created. |

Links created: `isp_switch ↔ gateway ↔ lan_sw_{name} ↔ each host`.
Gateway auto-registered in `lan_gateways`. Expansion is idempotent.

---

### 3.4 vpn

New-style VPN configuration. When `server.node` is set, `vpn_gateways` and `vpn_peers` are auto-populated.

```yaml
vpn:
  enabled: true
  mode: site_to_site      # site_to_site | remote_access | hybrid
  nat: true
  server:
    node: vpnhub
  peers:                  # gateway-level peers (entire LAN tunnels)
    - r1
    - r2
  clients:                # host-level direct clients
    - h2
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Deploy WireGuard on startup. |
| `mode` | string | `site_to_site` | VPN mode (see below). |
| `nat` | bool | `false` | When `true`: gateway masquerades VPN traffic to non-LAN destinations only. Each VPN client node also masquerades its LAN IP as its VPN IP on `wg0`, so hosts inside the network see the real VPN IP of the attacker — not the gateway IP and not the LAN IP. |
| `server.node` | string | — | VPN hub node name. |
| `peers` | list[string] | `[]` | LAN gateway peers (site-to-site / hybrid). |
| `clients` | list[string] | `[]` | Host-level VPN clients (remote_access / hybrid). |

**Modes:**

| Mode | Behaviour |
|------|-----------|
| `site_to_site` | Each peer is a LAN gateway; entire LAN subnet tunnels through VPN. |
| `remote_access` | Each client is an individual host; all LAN subnets route via gateway. |
| `hybrid` | `peers` get site-to-site; `clients` get remote-access. |

---

### 3.5 vpn_gateways / vpn_peers (legacy)

Accepted alongside or instead of the new `vpn:` section. Merged if both present.

```yaml
vpn_gateways:
  - vpnhub

vpn_peers:
  - gateway: vpnhub
    clients:
      - r1
      - h2
```

---

### 3.6 services

Services deployed automatically in `auto` or `hybrid` deployment mode.

```yaml
services:
  - node: web1          # also accepted: host: web1
    type: http
    port: 8080

  - node: ftp1
    type: ftp
    port: 21

  - node: web1
    type: smtp
    port: 25

  - node: dns1
    type: dns
    port: 53
    options:
      reply_ip: "10.0.0.1"

  - node: r1
    type: ssh
    port: 22

  - node: h1
    type: echo
    port: 7
    options:
      proto: tcp
```

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `node` | string | yes | — | Host running the service. (`host:` is a legacy alias.) |
| `type` | string | yes | — | Service type (see below). |
| `port` | integer | no | Type default | Override default port. |
| `options` | mapping | no | `{}` | Service-specific options. |

**Supported types:**

| type | Default port | Notes |
|------|-------------|-------|
| `http` | 8080 | Python `HTTPServer` |
| `https` | 443 | HTTP with TLS |
| `ftp` | 21 | Anonymous FTP uploads |
| `smtp` | 25 | SMTP acceptor, logs to `/tmp/smtp.log` |
| `dns` | 53 | UDP DNS responder; `reply_ip` sets A record response |
| `ssh` | 22 | `sshd` |
| `echo` | 7 | TCP/UDP echo; `proto: tcp` (default) or `proto: udp` |
| `custom_tcp` | — | Custom TCP server |
| `custom_udp` | — | Custom UDP server |

---

### 3.7 databases

SQLite database with auto-generated synthetic data and a CRUD REST API.

```yaml
databases:
  - host: db1
    name: company
    engine: sqlite
    api_port: 9090
    timing_protocol:
      enabled: true
      secret_key: your-real-secret-here   # required — never use a placeholder
      type: auto          # net-flow | app-flow | auto (default)
      short_delay_ms: 20
      long_delay_ms: 50
    tables:
      - name: employees
        rows: 50
        schema:
          id: integer
          first_name: first_name
          last_name: last_name
          email: email
          department: department
          salary: salary
        indexes:
          - id
```

**Database keys:**

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `host` | string | yes | — | Node where the database runs. |
| `name` | string | yes | — | Database filename stem. |
| `engine` | string | no | `sqlite` | Only `sqlite` supported. |
| `api_port` | integer | no | — | If set, starts a CRUD REST API on this port. |
| `timing_protocol` | mapping | no | disabled | Timing-channel configuration. |

**timing_protocol keys:**

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `enabled` | bool | no | `false` | Activate timing channel. |
| `secret_key` | string | **yes if enabled** | — | SHA-512 key for deterministic bit generation. No default — must be explicitly set. |
| `type` | string | no | `auto` | Watermark engine: `net-flow` (NFQUEUE, requires root + python3-netfilterqueue), `app-flow` (HTTP handler sleep), `auto` (try net-flow, fall back to app-flow). |
| `short_delay_ms` | float | no | `20.0` | Inter-packet delay for bit=0 (ms). |
| `long_delay_ms` | float | no | `50.0` | Inter-packet delay for bit=1 (ms). |

**table keys:**

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `name` | string | yes | — | Table name. Also the API endpoint `/api/{name}`. |
| `rows` | integer | no | `10` | Rows to generate. |
| `schema` | mapping | yes | — | `column_name: generator_type`. |
| `indexes` | list[string] | no | `[]` | Columns to index. |

**Schema generator types:**

| Type | Output |
|------|--------|
| `integer` / `int` | Random int 1–100,000 |
| `float` | Random float 0.0–10,000.0 |
| `first_name` | Random first name |
| `last_name` | Random last name |
| `username` | `firstname.lastname{NN}` (context-aware) |
| `email` | `firstname.lastname@domain` (context-aware) |
| `phone` | Phone number string |
| `department` | Department name |
| `salary` | Salary float 28,000–180,000 |
| `product` | Product name |
| `category` | Category name |
| `price` | Price float 0.99–9,999.99 |
| `address` | Street address |
| `city` | City name |
| `country` | Country name |
| `boolean` | `True` or `False` |
| `text` | Short random text |
| `uuid` | UUID v4 string |
| `date` | Date string YYYY-MM-DD |
| `timestamp` | Unix timestamp integer |

`id` column is always sequential (1, 2, 3…) regardless of declared type.

**REST API endpoints** (when `api_port` is set):
- `GET /api/{table}` — all rows as JSON.
- `POST /timing/set` — `{"enabled": bool, "short_delay_ms": N, "long_delay_ms": N}` — updates timing channel at runtime.

---

### 3.8 deployment

```yaml
deployment:
  mode: auto     # auto | manual | hybrid
```

| Mode | Behaviour |
|------|-----------|
| `auto` | All declared services and databases start automatically. |
| `manual` | Network configured; start services yourself in the CLI. |
| `hybrid` | Services auto-deployed; `ServiceDiscovery` scans for additional running services. |

Default: `auto`.

---

### 3.9 security

```yaml
security:
  firewall:
    enabled: false
    policy: restrictive     # restrictive | permissive
    backend: iptables       # iptables | nftables
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Apply firewall rules. |
| `policy` | string | `restrictive` | `restrictive`: drop by default, allow declared services. `permissive`: allow by default. |
| `backend` | string | `iptables` | `iptables` or `nftables`. |

---

### 3.10 capture

```yaml
capture:
  automatic: true       # true | false
  # mode: automatic     # backward-compat alias

  sessiondir: dataset/tmp
  merged:     dataset/pcapng

  devices:
    - h2
    - r1
    - vpnhub

  cleanup:
    enabled: true

  parser:
    enabled: false
    endpoint:
      - network/parserapi/csv_parser.py
    dir:
      - dataset/csv

  feature_selector:
    - network/featureselection/feature_selector.py

  feature_selection:
    DEVICE:           network/featureselectionapi.py:get_device
    INTERFACE:        network/featureselectionapi.py:get_interface
    FRAME_NO:         network/featureselectionapi.py:get_frame_number
    TIMESTAMP:        network/featureselectionapi.py:get_timestamp
    SOURCE:           network/featureselectionapi.py:get_source
    DESTINATION:      network/featureselectionapi.py:get_destination
    PROTOCOL:         network/featureselectionapi.py:get_protocol
    LENGTH:           network/featureselectionapi.py:get_length
    SOURCE_PORT:      network/featureselectionapi.py:get_source_port
    DESTINATION_PORT: network/featureselectionapi.py:get_destination_port
    INFO:             network/featureselectionapi.py:get_info
```

**Top-level keys:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `automatic` | bool | `true` | `true`: `capture stop` triggers full pipeline automatically. `false`: each step run manually. |
| `mode` | string | `automatic` | Backward-compat alias. `mode: manual` = `automatic: false`. `automatic:` takes precedence. |
| `sessiondir` | string | `dataset/tmp` | Per-interface PCAPNG staging directory. |
| `merged` | string | `dataset/pcapng` | Merged PCAPNG output directory. |
| `devices` | list[string] | `[]` | Node names to capture. Can also appear at top level (backward compat). |

**schema keys** (nested under `capture.schema`):

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `file` | string | `dataset/schema.json` | Path to the schema JSON output file. |
| `network_profile` | string | `dataset/network_profile.json` | Path to the network profile JSON (TC commands per session). |
| `update_folder` | string | same as `merged` | Folder watched for new merged PCAPNGs to trigger schema update. |
| `mimetype` | string | `text/pcapng` | MIME type recorded in schema records. |

**cleanup keys:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` if section present | Delete per-interface PCAPNGs after pipeline. Merged PCAPNG, CSV, schema.json always kept. |

If `cleanup:` section is absent, cleanup is disabled.

**parser keys:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Set `false` to skip CSV generation. |
| `endpoint` | string or list | — | CSV parser script path(s). First entry used. |
| `dir` | string or list | `dataset/csv` | CSV output directory. |

**feature_selector:** String or list. First entry used. Path relative to project root.

**feature_selection:** `COLUMN_NAME: module_path:function_name`. Function signature: `def fn(packet) -> str`. Injected packet attributes:

| Attribute | Value |
|-----------|-------|
| `packet._device` | Device name (from PCAPNG `if_name`, e.g. `r1`) |
| `packet._interface` | Interface name (e.g. `r1-eth0`) |
| `packet._frame_number` | Integer frame counter |
| `packet.time` | Full-precision `Decimal` timestamp |

**Built-in feature functions** (`network/featureselectionapi.py`):

| Function | Returns |
|----------|---------|
| `get_device` | Device name |
| `get_interface` | Interface name |
| `get_frame_number` | Frame number string |
| `get_timestamp` | `YYYY-MM-DD HH:MM:SS.NNNNNNNNN` |
| `get_source` | Source IP / MAC |
| `get_destination` | Destination IP / MAC |
| `get_protocol` | `TCP`, `UDP`, `ICMP`, `DNS`, `ARP`, `IPv6`, etc. |
| `get_length` | Packet length in bytes |
| `get_source_port` | TCP/UDP source port |
| `get_destination_port` | TCP/UDP destination port |
| `get_info` | Wireshark-style info string |
| `get_tos` | IP TOS field as integer string |
| `get_is_attack` | `1` if `IP.tos == exfiltration.attack_tos`, `0` otherwise. TOS value read from `ATTACK_TOS` env var set by capture_manager from YAML. |
| `get_ttl` | IP TTL |

---

### 3.11 traffic_control

Per-interface TC shaping (TBF rate limit + netem physical delay).

```yaml
traffic_control:
  s1-eth0:     {area: man}
  r1-eth0:     {area: man}
  r1-eth1:     {area: lan}
  h1-eth0:     {area: lan}

  links:
    - interfaces: [r1-eth1, h1-eth0]
      medium: copper
    - interfaces: [s1-eth0, r1-eth0]
      medium: fiber
```

**area values and physical parameters:**

| Area | Bandwidth | Distance | Use case |
|------|-----------|----------|----------|
| `pan` | 1–100 Mbps | 0.001–0.01 km | Personal area |
| `lan` | 100–10,000 Mbps | 0.01–1.0 km | Office LAN |
| `can` | 1,000–10,000 Mbps | 1–5 km | Campus |
| `man` | 1,000–100,000 Mbps | 5–50 km | Metro / ISP backbone |
| `wan` | 10–100,000 Mbps | 50–20,000 km | Wide area |
| `isp_access` | 10–100 Mbps | 0.1–10 km | ISP last mile |
| `isp_enterprise` | 100–1,000 Mbps | 1–50 km | ISP enterprise |

**medium values:**

| Medium | Propagation speed |
|--------|------------------|
| `fiber` | 200,000 km/s |
| `copper` | 200,000 km/s |
| `wireless` | 300,000 km/s |

TC uses a seeded RNG — same seed = same profile. Default seed when `capture start` auto-applies TC: `42`.

---

### 3.12 settings

```yaml
settings:
  isp_base_network: "10.0.0.0/8"
  lan_base_network: "192.168.0.0/16"
  vpn_base_network: "172.16.0.0/12"
  vpn_port: 51820
  log_level: "INFO"
```

| Key | Default | Description |
|-----|---------|-------------|
| `isp_base_network` | `10.0.0.0/8` | /24 blocks carved per ISP switch. |
| `lan_base_network` | `192.168.0.0/16` | /24 blocks carved per LAN gateway. |
| `vpn_base_network` | `172.16.0.0/12` | /24 blocks carved per VPN peer group. |
| `vpn_port` | `51820` | WireGuard UDP listen port. |
| `log_level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. |

IP allocation: sequential /24 subnets. Gateway gets `.1`; hosts get `.2`, `.3`, ...

---

### 3.13 npc

Background NPC traffic host map.

```yaml
npc:
  hosts:
    h2:   high
    h4:   medium
    h5:   medium
    lab1: low
```

Values: `low`, `medium`, `high`. Per-host defaults; overridden by `npc start --intensity`.

| Intensity | Link utilisation ρ | Active rounds |
|-----------|-------------------|---------------|
| `low` | 0.20–0.30 | ~20% |
| `medium` | 0.50–0.70 | ~60% |
| `high` | 0.90–1.00+ | ~95%+ |

Behavior mix (CAIDA-derived): HTTP 65%, Bulk 15%, DNS 8%, FTP 5%, SMTP 5%, DB 2%, Echo 1%.

NPC resolves service targets at startup from `services:` and `databases:` sections — no hardcoded node names. It finds the first node of each type: `http` → web traffic and SMTP, `ftp` → FTP, `dns` → DNS, `echo` → echo. DB REST endpoint comes from the first entry in `databases:`. DNS query domains are derived from actual topology node names as `{name}.local`. Behaviors are silently skipped if the required service type is absent from `services:`.

**Optional: `npc.weights` — override CAIDA behavior mix per intensity**

Specify only the behaviors you want to change. Unspecified behaviors keep CAIDA defaults.

```yaml
npc:
  hosts:
    h2: high
  weights:
    high:               # only overrides 'high' intensity
      http: 80          # more HTTP-heavy topology
      # bulk: 15        # ← not listed = keeps CAIDA default (15)
      # dns: 8          # ← not listed = keeps CAIDA default (8)
      # all others unchanged
```

| Behavior | Valid values | Default (CAIDA) |
|----------|-------------|-----------------|
| `http` | int ≥ 0 | low=13, medium=39, high=65 |
| `bulk` | int ≥ 0 | low=3, medium=9, high=15 |
| `dns` | int ≥ 0 | low=2, medium=5, high=8 |
| `ftp` | int ≥ 0 | low=1, medium=3, high=5 |
| `smtp` | int ≥ 0 | low=1, medium=3, high=5 |
| `db` | int ≥ 0 | low=1, medium=1, high=2 |
| `echo` | int ≥ 0 | low=0, medium=1, high=2 |
| `idle` | int ≥ 0 | low=79, medium=39, high=0 |

Omitting `npc.weights:` entirely uses full CAIDA defaults — no override needed for standard experiments.

---

### 3.14 device_classes

Maps node names to device class strings for TC profile generation.

```yaml
device_classes:
  s1:     isp_backbone_switch
  r1:     lan_router
  vpnhub: vpn_concentrator
  web1:   datacenter_server
  h1:     lan_host
```

**Valid device classes:**

| Class | Processing delay | netem distribution |
|-------|-----------------|-------------------|
| `lan_host` | 0.01–0.1 ms | `normal` |
| `lan_switch` | 0.05–0.5 ms | `normal` |
| `lan_router` | 0.05–0.5 ms | `normal` |
| `isp_backbone_switch` | 0.1–1.0 ms | `paretonormal` |
| `wan_router` | 0.02–0.5 ms | `paretonormal` |
| `vpn_concentrator` | 0.1–3.0 ms | `normal` |
| `datacenter_server` | 0.01–0.5 ms | `normal` |

---

### 3.15 attackers

**Optional.** Only needed when `exfiltration.attacker` is NOT set and you want `exfil` to pick randomly from a declared pool.

```yaml
attackers:
  - h2
  - h4
```

When `exfiltration.attacker` is set, this section is not required — the exfil command uses `exfiltration.attacker` directly and ignores the pool. If both are present, `exfiltration.attacker` must be in this list (error E013 fires otherwise).

---

### 3.16 exfiltration

Pins the exfil command to specific attacker, target, and endpoints. When set, `exfil` uses these values directly — no `attackers:` list required. When `attacker` is absent, `exfil` selects randomly from `attackers:` (filtered to nodes in current net).

```yaml
exfiltration:
  attacker: h1              # node that initiates the exfil connection
  target:
    host: db1               # database node to target
    port: 9090              # API port (must match databases[].api_port)
  endpoints:
    - /api/employees
    - /api/products
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `attacker` | string | — | Node that initiates the exfil connection. Falls back to random from `attackers:` if absent. |
| `target.host` | string | — | Database node to target. Falls back to random from `databases:` if absent. |
| `target.port` | int | — | API port. Must match `databases[].api_port`. |
| `endpoints` | list[string] | — | REST paths to request. Falls back to `/api/{table}` for each table. |
| `attack_tos` | int | `0x10` | IP TOS byte the attacker stamps on packets. Server sniffer and feature extractor use this same value. Change consistently if you need a different marking. |

`attack_tos` belongs here (attacker behavior) not in `timing_protocol` (server behavior).

---

### 3.17 routes

Manual static route overrides applied after auto-routing.

```yaml
routes:
  - node: r1
    destination: 192.168.99.0/24
    via: 10.0.0.99
```

| Key | Required | Description |
|-----|----------|-------------|
| `node` | yes | Node to install the route on. |
| `destination` | yes | CIDR destination. |
| `via` | yes | Nexthop IP. |

Installed with `ip route replace` — overrides any auto-computed route.

---

## 4. auto-gen.yaml — Experiment Automation Language

Drives `scripts/auto_gen.py`. Specifies which topologies to use and which conditions to vary. All fields are required.

```yaml
selected:
  - configs/topology_enterprise.yaml
repeat: 1
vpn:    [on, off]
npc:    [low, medium, high]
inject: [on, off]
exfil:  [true]
wait:   [10]
```

---

### 4.1 selected

```yaml
selected:
  - configs/topology_enterprise.yaml
  - configs/topology_dmz_segmented.yaml
```

List of topology YAML paths relative to project root. Every path is validated before any experiment starts.

---

### 4.2 repeat

```yaml
repeat: 3
```

Integer >= 1. Number of times each combination runs. Must be a scalar — `repeat: [3]` is invalid.

---

### 4.3 vpn

```yaml
vpn:
  - on
  - off
```

Maps to `vpn on` / `vpn off` in the CLI. Uses a custom YAML loader that prevents `on`/`off` being coerced to booleans.

---

### 4.4 npc

```yaml
npc:
  - low
  - medium
  - high
```

Maps to `npc start --intensity {value}`.

---

### 4.5 inject

```yaml
inject:
  - on
  - off
```

Maps to `inject on` / `inject off`.

---

### 4.6 exfil

```yaml
exfil:
  - true    # exfil command runs → label=1
  - false   # baseline wait → label=0
```

---

### 4.7 wait

Capture window duration in seconds.

**Fixed list** — each value is a separate experiment dimension:

```yaml
wait: [10]
wait: [10, 20, 30]
```

**Fixed policy:**

```yaml
wait:
  fixed: 15

# or:
wait:
  mode: fixed
  value: 15
```

**Random policy** — sampled independently per experiment:

```yaml
wait:
  random:
    min: 10
    max: 30

# or:
wait:
  mode: random
  min: 10
  max: 30
```

Random produces label `random:10-30` in the Cartesian product. Actual sampled value varies per experiment.

Constraints: list values must be non-negative integers; `random.min` ≤ `random.max`.

CLI overrides: `--fixed-time N`, `--min-time N --max-time N`. Cannot combine `--fixed-time` with range flags.

---

### 4.8 Combination generation

Full Cartesian product of all list fields × `repeat`.

```
topologies × vpn × npc × inject × exfil × wait × repeat
```

Example — current `configs/auto-gen.yaml` (one option per dimension):
```
1 topo × 1 vpn × 1 npc × 1 inject × 1 exfil × 1 wait × repeat=1 = 1 experiment
```

Example — full dataset (uncomment all options, repeat=3):
```
2 topo × 2 vpn × 3 npc × 2 inject × 2 exfil × 2 wait × 3 = 288 experiments
```

| Combo | Label | Meaning |
|-------|-------|---------|
| exfil=true, inject=on | 1 | Attack + watermark |
| exfil=false, inject=on | 0 | Baseline (no attack) |
| exfil=true, inject=off | 1 | Attack, no watermark |
| vpn=on | — | Traffic via WireGuard tunnel |
| npc=low/medium/high | — | Channel noise level |

Each experiment is fully isolated: `mn -c` before and after; fresh `topology.py --cli` subprocess; pexpect CLI driver.

Experiment command sequence:
```
vpn on|off
apply tc
npc start --intensity {level}
inject on|off
sleep 10  (NPC warmup)
capture start
sleep 5   (pre-action window)
exfil     (if exfil=true, label=1)
  OR
sleep N   (if exfil=false, label=0)
capture stop
exit
```

Progress saved to `.auto_gen_progress.json`. Use `--resume` to skip completed experiments after interruption.

---

## 5. CLI Language

Commands typed at the `mininet> ` prompt inside `network/topology.py --cli`.

---

### 5.1 vpn

```
vpn status|on|off|restart
```

| Subcommand | Description |
|------------|-------------|
| `vpn status` | Per-node WireGuard status (interface up, live handshakes). |
| `vpn on` | Deploy WireGuard from scratch. Purges existing wg0 state first. Prints per-stage timing. |
| `vpn off` | Remove wg0 interfaces and VPN routes. Traffic reverts to ISP routing. |
| `vpn restart` | `vpn off` then `vpn on`. |

---

### 5.2 capture

```
capture start|stop|status|merge|parsetocsv|clean|update
```

| Subcommand | Description |
|------------|-------------|
| `capture start` | Start AsyncSniffer per interface. If no TC applied yet, auto-applies seed=42. |
| `capture stop` | Stop sniffers. Automatic mode: merge → feature select → CSV → schema → cleanup. Also stops NPC. |
| `capture status` | Print session ID, state, mode, devices, active count, elapsed time. |
| `capture merge <file1> [...] <session_id>` | Merge PCAPNGs manually. Last arg is session_id. |
| `capture parsetocsv <merged.pcapng>` | Run feature selection + CSV parsing on a merged file. |
| `capture clean` | Delete per-interface staging files for current session. |
| `capture update` | Reload schema config from YAML without capturing. |

---

### 5.3 npc

```
npc start [--intensity low|medium|high]
npc stop
npc status
```

| Subcommand | Description |
|------------|-------------|
| `npc start` | Start one thread per NPC host. Starts `iperf3 -s` on each for bulk behavior. |
| `npc start --intensity high` | Override per-host defaults with global intensity. |
| `npc stop` | Signal all threads to stop (join timeout: 15 s). |
| `npc status` | Per-host table: intensity, rounds, top behaviors. |

---

### 5.4 inject

```
inject on [--short-delay MS] [--long-delay MS]
inject off
```

POSTs `{"enabled": bool, "short_delay_ms": N, "long_delay_ms": N}` to every running DB API. No-op if called with the same parameters already active.

---

### 5.5 exfil

```
exfil [--dry-run]
```

Selection priority:
1. Uses `exfiltration.attacker` and `exfiltration.target.*` from YAML if set — no `attackers:` list needed.
2. Falls back to random from `attackers:` list (aggregated across all `configs/topology*.yaml`) if `exfiltration.attacker` is absent.

Sends TOS-marked HTTP GET with `IP_TOS = exfiltration.attack_tos` at socket level (default `0x10`), scoped to this connection only. Concurrent NPC traffic is never marked.

`--dry-run`: print selection without executing. Retries every 10 s if no attacker or victim found.

---

### 5.6 apply

```
apply tc [--seed N]
```

Generate and apply TBF+netem TC rules from `traffic_control` config. Cannot run while capture is active. Same seed always produces identical TC parameters.

---

### 5.7 Standard Mininet commands

| Command | Description |
|---------|-------------|
| `pingall` | Ping all hosts |
| `ping h1 h2` | Ping between two hosts |
| `xterm h1` | Open terminal on h1 |
| `h1 <cmd>` | Run shell command in h1's namespace |
| `links` | Show all links |
| `nodes` | List all nodes |
| `net` | Show network connections |
| `dump` | Dump node info |
| `iperf` | TCP iperf test |
| `exit` | Exit CLI and tear down network |
| `help` | List all commands |

---

## 6. Configuration Examples

### Minimal two-host topology

```yaml
nodes:
  - name: s1
    type: switch
  - name: h1
    type: host
  - name: h2
    type: host
links:
  - [h1, s1]
  - [s1, h2]
settings:
  isp_base_network: "10.0.0.0/8"
  lan_base_network: "192.168.0.0/16"
  vpn_base_network: "172.16.0.0/12"
capture:
  automatic: true
  devices: [h1, h2]
```

### Attacker/victim scenario (default topology)

```yaml
nodes:
  - name: s1
    type: switch
  - name: r1
    type: router
  - name: r3
    type: router
  - name: h2
    type: host
  - name: vpnhub
    type: host
  - name: h3
    type: host

links:
  - [h2, r1]
  - [r1, s1]
  - [s1, vpnhub]
  - [s1, r3]
  - [r3, h3]

lan_gateways: [r1, r3]
vpn_gateways: [vpnhub]
vpn_peers:
  - gateway: vpnhub
    clients: [h2]

vpn:
  enabled: false
  mode: remote_access
  nat: true

exfiltration:
  attacker: h2
  target:
    host: h3
    port: 9090
  endpoints:
    - /api/users
  attack_tos: 0x10

services:
  - node: h3
    type: http
    port: 8080

databases:
  - host: h3
    name: victimdb
    engine: sqlite
    api_port: 9090
    timing_protocol:
      enabled: true
      secret_key: your-real-secret-here
      type: auto          # net-flow | app-flow | auto (default)
    tables:
      - name: users
        rows: 50
        schema:
          id: integer
          username: username
          email: email

deployment:
  mode: auto

npc:
  hosts:
    h2: medium

capture:
  automatic: true
  devices: [h2, r1, vpnhub, r3, h3]
  cleanup:
    enabled: true
  feature_selection:
    DEVICE:    network/featureselectionapi.py:get_device
    SOURCE:    network/featureselectionapi.py:get_source
    DEST:      network/featureselectionapi.py:get_destination
    PROTOCOL:  network/featureselectionapi.py:get_protocol
    LENGTH:    network/featureselectionapi.py:get_length
    IS_ATTACK: network/featureselectionapi.py:get_is_attack

settings:
  isp_base_network: "10.0.0.0/8"
  lan_base_network: "192.168.0.0/16"
  vpn_base_network: "172.16.0.0/12"
```

### auto-gen.yaml — full experiment batch

```yaml
selected:
  - configs/topology_enterprise.yaml
  - configs/topology_dmz_segmented.yaml

repeat: 3

vpn:    [on, off]
npc:    [low, medium, high]
inject: [on, off]
exfil:  [true, false]
wait:   [10]
```

Total: 2 × 2 × 3 × 2 × 2 × 1 × 3 = 144 experiments.

---

## 7. Common Mistakes

**No ISP switch declared.**
```yaml
# WRONG — _validate() raises: "Topology must have at least one ISP switch"
nodes:
  - name: h1
    type: host
```

**Link references undeclared node.**
```yaml
links:
  - [h1, s1]   # WRONG if h1 not in nodes:
```

**lan_gateway is a switch.**
```yaml
lan_gateways:
  - s1   # WRONG — must be router or host
```

**LAN switch name collision.** `lans` auto-creates `lan_sw_{name}`. Do not also declare it in `nodes:`.

**Interface names in traffic_control use full node name, not alias.** Nodes with names > 9 chars get aliases. Use the alias-based interface name (`lso1-eth0`, not `lan_sw_office-eth0`).

**`repeat` as a list.**
```yaml
repeat: [3]   # WRONG
repeat: 3     # correct
```

**`apply tc` after `capture start` is blocked.** Apply TC before starting capture.

**`capture merge` session_id must match `capture start`.** Mismatches create orphan schema.json entries.

**Parser not configured but `capture stop` tries to run it.** Set `parser.enabled: false` or add `parser.endpoint`.

---

## 8. Best Practices

- Apply TC before starting NPC: `apply tc` → `npc start`. NPC traffic must flow through conditioned interfaces from the start.
- Use `inject on` before `capture start` for labeled captures.
- Use a fixed seed for reproducible profiles: `apply tc --seed 42`.
- Set `cleanup.enabled: true` for batch runs — staging files accumulate quickly.
- Set `parser.enabled: false` if CSV is not needed — feature selection is the slow step.
- Use `--resume` for interrupted batch runs.
- Use `--dry-run` to verify auto-gen.yaml before a long run.

---

## 9. Developer Recipes

### Add a custom feature column

Create a module anywhere (e.g. project root):

```python
# my_features.py
from scapy.all import IP

def get_dscp(packet) -> str:
    if IP in packet:
        return str(packet[IP].tos >> 2)
    return ""
```

Reference in topology YAML:

```yaml
capture:
  feature_selection:
    DSCP:   my_features.py:get_dscp
    SOURCE: network/featureselectionapi.py:get_source
```

### Add a new NPC behavior

1. Add function to `network/npc/behaviors.py`.
2. Add weights to all three intensity levels in `network/npc/intensity.py`.
3. Add mean inter-arrival to `INTER_ARRIVAL_S`.
4. Dispatch in `NPCManager._run()`.

### Run a topology programmatically

```python
from network.topology import ISPTopology

topo = ISPTopology("configs/topology_enterprise.yaml")
topo.start(enable_vpn=True, enable_services=True)

topo.apply_tc(seed=42)
topo._npc_manager.start(intensity="medium")
topo._capture_manager.start()
topo.exfil()
topo._capture_manager.stop()
topo.stop()
```

### Read a schema.json session

```python
from network.capture_manager import load_schema_by_session

record = load_schema_by_session("dataset/schema.json", "20260722_083000_123456")
print(record["timing_protocol"])
```

### Parse a PCAPNG file

```python
from network.pcapng_reader import PcapNgFile
from scapy.all import Ether

with PcapNgFile("dataset/pcapng/20260722_083000_123456.pcapng") as f:
    for pkt in f:
        scapy_pkt = Ether(pkt.data)
        print(pkt.device, pkt.interface_name, scapy_pkt.summary())
```

---

## 10. Error Codes

When the emulator encounters a configuration or runtime problem it prints a structured error block:

```
────────────────────────────────────────────────────────────
  ISP Emulator Error  [E011]
────────────────────────────────────────────────────────────
  Problem   : timing_protocol enabled but secret_key is not set
  Detail    : db 'victimdb' on h3 — add secret_key under timing_protocol:
  YAML key  : timing_protocol.secret_key
  Guide.md  : §3.7 databases → timing_protocol
────────────────────────────────────────────────────────────
  Run:  grep -A 20 '§3.7 databases → timing_protocol' Guide.md
────────────────────────────────────────────────────────────
```

Every code maps to a YAML key and a Guide section. Use the `Run:` command to jump straight to the fix.

---

### E000 — Config file not found

**YAML key:** `selected` / config path  
**Fix:** Check the path passed to `sudo python3 network/topology.py <path>`. The file must exist relative to the project root.

---

### E001 — LAN missing `isp_switch`

**YAML key:** `lans[].isp_switch`  
**Fix:** Add `isp_switch: <switch_name>` to every entry under `lans:`. The value must match a node declared with `type: switch`.

```yaml
lans:
  - name: office
    gateway: r1
    isp_switch: s1    # ← required
    hosts: [h1, h2]
```

---

### E002 — No ISP switch

**YAML key:** `nodes[]`  
**Fix:** Add at least one node with `type: switch`. See §3.1.

---

### E003 — Link references undeclared node

**YAML key:** `links[]`  
**Fix:** Declare the missing node under `nodes:` before referencing it in `links:`. See §3.2.

---

### E004 — `lan_gateway` references unknown node

**YAML key:** `lan_gateways[]`  
**Fix:** Add the node to `nodes:` or remove it from `lan_gateways:`. See §3.3.

---

### E005 — `lan_gateway` is a switch

**YAML key:** `lan_gateways[]`  
**Fix:** LAN gateways must be `type: router` or `type: host`. Change the node type or remove it from `lan_gateways:`.

---

### E006 — `vpn_gateway` references unknown node

**YAML key:** `vpn_gateways[]`  
**Fix:** Declare the node under `nodes:` first. See §3.4.

---

### E007 — VPN peer gateway unknown

**YAML key:** `vpn_peers[].gateway`  
**Fix:** The gateway name must match a declared node. See §3.5.

---

### E008 — VPN peer client unknown

**YAML key:** `vpn_peers[].clients`  
**Fix:** The client name must match a declared node. See §3.5.

---

### E009 — Service host not declared

**YAML key:** `services[].node`  
**Fix:** Add the host node to `nodes:` or fix the `node:` value under `services:`. See §3.6.

---

### E010 — Database host not declared

**YAML key:** `databases[].host`  
**Fix:** Add the host node to `nodes:` or fix the `host:` value under `databases:`. See §3.7.

---

### E011 — `timing_protocol` enabled but no `secret_key`

**YAML key:** `timing_protocol.secret_key`  
**Fix:** Add a non-empty `secret_key` under `timing_protocol:`. Never use `"example_key"` in production.

```yaml
timing_protocol:
  enabled: true
  secret_key: your-real-secret-here   # ← required when enabled: true
  type: auto                           # net-flow | app-flow | auto (default)
```

---

### E012 — `short_delay_ms` ≥ `long_delay_ms`

**YAML key:** `timing_protocol.short_delay_ms` / `long_delay_ms`  
**Fix:** `short_delay_ms` must be strictly less than `long_delay_ms`. The gap must exceed the maximum jitter on the path.

---

### E013 — `exfiltration.attacker` not in `attackers:`

**YAML key:** `exfiltration.attacker`  
**Fix:** Three options:

1. Remove the `attackers:` section entirely — it is not required when `exfiltration.attacker` is set:
```yaml
# remove attackers: block
exfiltration:
  attacker: h2
```

2. Add the node to `attackers:`:
```yaml
attackers:
  - h2      # ← must include exfiltration.attacker value
exfiltration:
  attacker: h2
```

3. Change `exfiltration.attacker` to match a node already in `attackers:`.

---

### E014 — `exfiltration.target.host` has no `api_port`

**YAML key:** `exfiltration.target.host`  
**Fix:** Add `api_port: <port>` to the matching entry under `databases:`. See §3.7.

---

### E015 — `attack_tos` out of range

**YAML key:** `exfiltration.attack_tos`  
**Fix:** Set `attack_tos` to an integer between `0` and `255` (e.g., `0x10`). See §3.16.

---

### E016 — `exfiltration.target.port` mismatch

**YAML key:** `exfiltration.target.port`  
**Fix:** The port in `exfiltration.target.port` must equal `databases[host=<target>].api_port`. Fix one or the other.

---

### E017 — Capture device not found or empty

**YAML key:** `capture.devices`  
**Fix:** Add node names to `capture.devices`. Every name must match a node declared in `nodes:`. See §3.10.

---

### E018 — VPN enabled but `vpn.server.node` not set

**YAML key:** `vpn.server.node`  
**Fix:** Either set `vpn.server.node: <gateway_name>` or set `vpn.enabled: false`.

```yaml
vpn:
  enabled: true
  server:
    node: vpnhub    # ← required when enabled: true
```

---

### E019 — Invalid `dpid`

**YAML key:** `nodes[].dpid`  
**Fix:** `dpid` must be 1–16 hexadecimal characters (`0-9`, `a-f`). Omit it to auto-generate from the node name.

---

### E021 — Unknown service type

**YAML key:** `services[].type`  
**Fix:** Use a supported type: `http | https | ftp | smtp | dns | echo | ssh | custom_tcp | custom_udp`

---

### E022 — Port conflict on same host

**YAML key:** `services[].port`  
**Fix:** Two services on the same host share a port. Give each a unique `port:` value.

---

### E023 — Unknown database column generator type

**YAML key:** `databases[].tables[].schema`  
**Fix:** Use a supported generator type. Valid types: `integer`, `int`, `float`, `first_name`, `last_name`, `username`, `email`, `phone`, `department`, `salary`, `product`, `category`, `price`, `address`, `city`, `country`, `boolean`, `text`, `uuid`, `date`, `timestamp`.

---

### E027 — Static route node not declared

**YAML key:** `routes[].node`  
**Fix:** Declare the node under `nodes:` or remove the route entry. See §3.17.

---

### E028 — Static route invalid CIDR or IP

**YAML key:** `routes[].destination` / `routes[].via`  
**Fix:** Use valid IPv4 CIDR (`10.0.0.0/24`) and valid IPv4 nexthop (`10.0.0.1`).

---

### E030 — Attacker not in nodes

**YAML key:** `attackers[]` or `exfiltration.attacker`  
**Fix:** Declare the attacker node under `nodes:`, or remove it from `attackers:`.

---

### E032 — Invalid VPN mode

**YAML key:** `vpn.mode`  
**Fix:** Use one of: `site_to_site | remote_access | hybrid`

---

### E033 — Invalid firewall policy

**YAML key:** `security.firewall.policy`  
**Fix:** Use one of: `restrictive | permissive`

---

### E034 — Invalid firewall backend

**YAML key:** `security.firewall.backend`  
**Fix:** Use one of: `iptables | nftables`

---

### E035 — Invalid deployment mode

**YAML key:** `deployment.mode`  
**Fix:** Use one of: `auto | manual | hybrid`

---

### E037 — Invalid NPC intensity

**YAML key:** `npc.hosts`  
**Fix:** Use one of: `low | medium | high` per host.

---

### E038 — Invalid node type

**YAML key:** `nodes[].type`  
**Fix:** Use one of: `host | router | switch`

---

### E039 — Invalid CIDR in settings

**YAML key:** `settings.isp_base_network` / `lan_base_network` / `vpn_base_network`  
**Fix:** Use valid IPv4 CIDR notation (e.g., `10.0.0.0/8`, `192.168.0.0/16`).

---

### E042 — `api_port` out of range

**YAML key:** `databases[].api_port`  
**Fix:** Set `api_port` to a value between `1` and `65535`.

---

### E043 — Service `port` out of range

**YAML key:** `services[].port`  
**Fix:** Set `port` to a value between `1` and `65535`.

---

### E044 — Timing delay not positive

**YAML key:** `databases[].timing_protocol.short_delay_ms` / `long_delay_ms`  
**Fix:** Both delays must be `> 0`. Typical values: `short_delay_ms: 20.0`, `long_delay_ms: 50.0`.

---

### E045 — `device_classes` references unknown node

**YAML key:** `device_classes`  
**Fix:** Every key must match a node declared under `nodes:`. Remove the entry or add the node.

---

### E046 — `traffic_control` interface references unknown node

**YAML key:** `traffic_control.interfaces`  
**Note:** Validated at topology build time (after alias computation), not at config load. A `[WARN]` is printed at startup — the interface is silently skipped. Check the node part (before `-eth`) matches a declared node name or its Mininet alias.

---

### E047 — Duplicate client in `vpn_peers`

**YAML key:** `vpn_peers[].clients`  
**Fix:** Each client must appear once only in the `clients:` list.

---

### E048 — `npc.hosts` references unknown node

**YAML key:** `npc.hosts`  
**Fix:** Every host key must match a node declared under `nodes:`.

---

### E049 — `npc.weights` unknown behavior or invalid weight

**YAML key:** `npc.weights`  
**Fix:** Use only supported behavior names (`http`, `bulk`, `dns`, `ftp`, `smtp`, `db`, `echo`, `idle`) and non-negative integer weights.

---

### R001 — LAN subnet pool exhausted

**YAML key:** `settings.lan_base_network`  
**Fix:** Increase the `lan_base_network` range (e.g., change `/16` to `/12`) or reduce the number of LAN gateways. See §3.12.

---

### R002 — VPN subnet pool exhausted

**YAML key:** `settings.vpn_base_network`  
**Fix:** Increase the `vpn_base_network` range or reduce the number of VPN peer groups. See §3.12.

---

### R010 — Interface name exceeds IFNAMSIZ=15

**YAML key:** `nodes[]`  
**Fix:** Shorten the node name. Linux limits interface names to 15 characters. The emulator auto-aliases names longer than 9 chars but the alias itself must fit. Node names ≤ 9 characters are safe.

---

### R020 — WireGuard key generation failed

**YAML key:** *(system)*  
**Fix:** Install WireGuard tools: `sudo apt-get install wireguard wireguard-tools`. See §1 Installation.

---

### R101 — Timing protocol `secret_key` is `None` at runtime

**YAML key:** `databases[].timing_protocol.secret_key`  
**Fix:** Same as E011 — set a non-empty `secret_key` in the YAML before starting the emulator.

---

*For architecture and internals, see [README.md](README.md).*  
*For physics formulas (TBF+netem, NPC traffic model, timing protocol), see [mechanism.md](mechanism.md).*
