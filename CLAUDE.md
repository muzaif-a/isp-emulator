# ISP Emulator — CLAUDE.md

Mininet-based ISP/enterprise network emulator. Generates labeled PCAPNG + CSV datasets for ML research on covert timing-channel detection.

**Run requires root (Mininet/OVS). Ubuntu 22.04 only.**

---

## Entry Points

| Command | Purpose |
|---------|---------|
| `sudo python3 network/topology.py configs/<X>.yaml --cli` | Interactive mode |
| `sudo python3 scripts/auto_gen.py --config configs/auto-gen.yaml` | Batch automation |
| `sudo mn -c` | Clean stale Mininet state (run before/after every experiment) |
| `python3 -m pytest tests/ -q` | Unit tests (no root) |

---

## Key Files

| File | Role |
|------|------|
| `config_loader.py` | YAML → `TopologyConfig` dataclass (single source of truth) |
| `errors.py` | `EmulatorError` E000–R101 with inline fix hints |
| `network/topology.py` | Mininet builder + `ISPCli` (main entry point) |
| `network/ip_allocator.py` | All IPs/interfaces computed here; never hardcoded elsewhere |
| `network/routing.py` | Static routing engine (host defaults, inter-LAN, ISP-node) |
| `network/vpn_manager.py` | Hub-and-spoke WireGuard deploy (parallel threads) |
| `network/vpn_controller.py` | Runtime `vpn on/off` |
| `network/capture_manager.py` | Sniffer subprocesses + merge/feature/CSV pipeline |
| `network/hardware/tc_generator.py` | TBF+netem TC commands; seed 42 default |
| `network/npc/npc_manager.py` | Background NPC traffic orchestrator |
| `network/npc/behaviors.py` | http/dns/db/smtp/ftp/bulk/echo/idle implementations |
| `services/database/database_manager.py` | SQLite + Flask REST API in node namespace |
| `services/database/timing_protocol.py` | SHA-512 covert timing channel |
| `services/database/generators.py` | Synthetic row data (no external deps) |
| `network/featureselection/feature_selector.py` | Subprocess: PCAPNG → JSON dataset |
| `network/parserapi/csv_parser.py` | Subprocess: JSON → CSV |
| `network/pcapng_reader.py` | Pure-Python PCAPNG parser (SHB/IDB/EPB/SPB) |
| `scripts/auto_gen.py` | pexpect CLI driver; `mn -c` isolation per experiment |
| `dataset/schema.json` | Session registry (one record per capture) |
| `dataset/network_profile.json` | TC commands per session |
| `configs/preregistration.yaml` | Frozen timing constants — do not edit |

---

## Architecture

```
auto_gen.py (pexpect)
    └── topology.py (ISPTopology + ISPCli)
            ├── config_loader → TopologyConfig
            ├── ip_allocator → AllocationResult
            ├── routing.py
            ├── vpn_manager / vpn_controller
            ├── database_manager + timing_protocol
            ├── service_manager
            ├── capture_manager
            │       ├── sniffer subprocesses (per iface)
            │       ├── feature_selector.py (subprocess)
            │       └── csv_parser.py (subprocess)
            └── npc_manager (daemon threads)
```

---

## Subsystem Notes

**Config:** `config_loader.py` is sole YAML reader at runtime. All other modules consume `TopologyConfig` / `AllocationResult`. Feature selector and CSV parser re-read YAML `feature_selection` section only.

**IP allocation:** `ip_allocator.py` pure logic — no Mininet calls. ISP /24s from `isp_base_network`, LAN /24s from `lan_base_network`, VPN /24s from `vpn_base_network`. Node aliases enforced if name >9 chars (IFNAMSIZ=15).

**VPN:** hub-and-spoke WireGuard. Modes: `site_to_site`, `remote_access`, `hybrid`. NAT optional. `VPNController.turn_on()` always purges wg0 before deploying.

**TC:** TBF (bandwidth) + netem (propagation delay only). Queuing delay, jitter, loss are emergent from NPC load. Same seed → identical profile.

**NPC:** one daemon thread per host. Priming phase fires all protocols once. Heavy cap: semaphore(min(4, cpu-2)).

**Timing channel:** `SHA-512(key:t0:nonce)` → bitstream. bit=0 → `short_delay_ms` sleep; bit=1 → `long_delay_ms` sleep. `t0` = real timestamp of first TOS-marked packet.

**Capture pipeline:** sniffers write PCAPNG EPBs directly to disk. `capture stop` → mergecap → feature_selector → csv_parser → schema.json upsert.

**Exfiltration label:** TOS byte `0x10` (configurable). `featureapi.get_is_attack()` returns `"1"` for matching packets via `ATTACK_TOS` env var.

**Error system:** `EmulatorError(code, yaml_key, fix_snippet)`. E000–E019 config structure; E021–E044 enum/range; R001–R020 runtime IP/WireGuard; R101 service startup.

**auto_gen.py isolation:** `mn -c` before+after every experiment. Progress saved in `.auto_gen_progress.json`. `--resume` skips completed combos.

---

## Topology Variants

| Config | Description |
|--------|-------------|
| `topology.yaml` | Default: attacker h2, victim h3, single ISP switch |
| `topology_enterprise.yaml` | Multi-LAN: office/datacenter/branch/lab, hub-and-spoke VPN |
| `topology_dmz_segmented.yaml` | 3-zone: external/DMZ/internal, restrictive firewall |
| `topology_remote_worker.yaml` | `remote_access` VPN mode, attacker behind home router |
| `topology_three_site.yaml` | 3 corporate sites, WAN ISP backbone, site-to-site VPN |
| `topology_wan_isp.yaml` | WAN/ISP backbone, multiple ISP nodes, long-haul links |
| `topology_insider_threat.yaml` | Attacker inside corporate LAN, no VPN for exfil |

---

## Development Rules

- New topology: copy YAML, test with `--cli`. `_validate()` raises `EmulatorError` on violations.
- New service: add to `service_manager.py` + `ServiceConfig.type` docs in `config_loader.py`.
- New NPC behavior: see `Guide.md §9`.
- New feature column: see `Guide.md §9`.
- Timing protocol changes: edit `timing_protocol.py` + `config_loader.py` defaults. Never touch `configs/preregistration.yaml`.
- Do not add hardcoded IPs — all addresses flow from `ip_allocator.py`.
