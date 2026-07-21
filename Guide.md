# ISP Emulator — User Guide

Language manual for configuration, CLI commands, and experiment automation.
For architecture and internals, see [README.md](README.md).

---

## Table of Contents

1. [Installation](#1-installation)
2. [run.sh — Entry Point](#2-runsh--entry-point)
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

---

## 1. Installation

### System requirements

Ubuntu 22.04 LTS (other Linux distributions may work; Windows and macOS are not supported for topology emulation).

### System packages

```bash
sudo apt-get install -y \
    mininet \
    openvswitch-switch \
    wireguard \
    wireguard-tools \
    python3 \
    python3-pip \
    iproute2 \
    iptables \
    iputils-ping \
    net-tools \
    tcpdump \
    wireshark-common \
    curl
```

### Python packages

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

## 2. run.sh — Entry Point

`run.sh` is the single command interface. It detects its execution context automatically.

### Context detection

| Context | Detection | Behaviour |
|---------|-----------|-----------|
| Host machine, Docker installed and image exists | No `/.dockerenv`, `docker` on PATH, image found | Launches Docker container with bind-mounted `dataset/` |
| Inside Docker container | `/.dockerenv` present or `/proc/1/cgroup` matches | Runs directly as root |
| Native Linux, no Docker | No `/.dockerenv`, no `docker` on PATH | Runs directly (must be root) |

### Usage

```
./run.sh [topology.yaml]
```

**No argument — automated experiment generation:**

```bash
./run.sh
```

Runs `scripts/auto_gen.py --config configs/auto-gen.yaml`. Generates a labeled dataset across all combinations defined in `auto-gen.yaml`.

**With a topology YAML — interactive topology CLI:**

```bash
./run.sh configs/topology_enterprise.yaml
./run.sh configs/topology.yaml
./run.sh configs/topology_dmz_segmented.yaml
```

Cleans up any stale Mininet state, then starts `network/topology.py <yaml> --cli`. Drops into the interactive Mininet CLI where capture, NPC, VPN, and exfil commands are available.

### When Docker is active

`run.sh` runs the container with these flags automatically:

```bash
docker run --rm -it \
    --privileged \
    --network host \
    -v "$(pwd)/dataset:/opt/isp-emulator/dataset" \
    isp-emulator [topology.yaml]
```

Dataset output lands in `./dataset/` on the host immediately as it is written — no copying needed after the container exits.

**If the image does not exist:**

```
[error] Docker image 'isp-emulator' not found.

Build it first:
    docker build -t isp-emulator .
```

### Native Linux (no Docker)

```bash
sudo ./run.sh
sudo ./run.sh configs/topology_enterprise.yaml
```

`sudo` is required because Mininet creates Linux network namespaces.

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
| `isp_switch` | string | no | `s1` | ISP switch this LAN connects to. |
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
| `nat` | bool | `false` | `iptables MASQUERADE` for VPN traffic at gateway. |
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
      secret_key: example_key
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

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Activate timing channel. |
| `secret_key` | string | `example_key` | SHA-512 key for deterministic bit generation. |
| `short_delay_ms` | float | `20.0` | Inter-packet delay for bit=0 (ms). |
| `long_delay_ms` | float | `50.0` | Inter-packet delay for bit=1 (ms). |

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
| `email` | `firstname.lastname@domain` (context-aware) |
| `phone` | Phone number string |
| `department` | Department name |
| `salary` | Salary integer |
| `product` | Product name |
| `category` | Category name |
| `price` | Price float |
| `address` | Street address |
| `city` | City name |
| `country` | Country name |
| `boolean` | `True` or `False` |
| `text` | Short random text |
| `uuid` | UUID v4 string |
| `date` | Date string |
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
| `get_is_attack` | `1` if TOS=0x10, `0` otherwise |
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

NPC resolves service IPs at startup: `web1` (HTTP/SMTP), `ftp1` (FTP), `dns1` (DNS), `db1` (DB API), `h1` (echo). Missing nodes are skipped.

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

```yaml
attackers:
  - h2
  - h4
```

Nodes eligible as exfil sources. `exfil` picks randomly from this list (filtered to nodes present in current net). Attacker traffic marked with `IP_TOS=0x10` at socket level.

---

### 3.16 exfiltration

Fallback parameters if automatic DB discovery fails.

```yaml
exfiltration:
  attacker: h1
  target:
    host: db1
    port: 9090
  endpoints:
    - /api/employees
    - /api/products
```

In practice, `exfil` discovers victims from `databases:` at runtime.

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

Example with defaults (`configs/auto-gen.yaml`):
```
1 × 2 × 3 × 2 × 1 × 1 × 1 = 12 experiments
```

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

Picks random attacker (from `attackers:` in all `configs/topology*.yaml`) and random victim database (from current config's `databases:`). Sends TOS-marked HTTP GET (`IP_TOS=0x10` at socket level, scoped to this connection only).

`--dry-run`: print selection without executing. Retries every 10 s if no attackers or victims found.

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

attackers: [h2]

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
      secret_key: example_key
    tables:
      - name: users
        rows: 50
        schema:
          id: integer
          username: text
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

*For architecture and internals, see [README.md](README.md).*
