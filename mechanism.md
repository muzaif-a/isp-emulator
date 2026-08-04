# TC Mechanism — Physics, Formulas, and TBF+netem Relationship

This document explains exactly how traffic shaping works in the emulator,
why each formula is used, and how TBF and netem interact to produce
realistic network behaviour.

---

## 1. Architecture Overview

Every interface gets two chained qdiscs:

```
Packet in
    │
    ▼
┌─────────────────────────────────┐
│  TBF  (root qdisc, handle 1:)  │  ← rate limiter
│  rate, burst, latency           │
└────────────────┬────────────────┘
                 │ packets dequeued at rate R
                 ▼
┌─────────────────────────────────┐
│  netem  (child, parent 1:1)    │  ← physical delay + jitter
│  delay, jitter, distribution    │
└─────────────────────────────────┘
                 │
                 ▼
            Wire / NIC
```

**TBF controls WHEN packets leave** (bandwidth).  
**netem controls HOW LONG they sit in the pipe** (propagation physics).

They are chained: a packet passes through TBF first, gets rate-limited,
then immediately enters netem which adds the physical transmission delay.

---

## 2. Total Observed Latency

What a real receiver measures as RTT has four physical components:

```
L_total = L_prop + L_proc + L_infra + L_queue
```

| Term | Source | emulator responsibility |
|------|--------|------------------------|
| `L_prop` | Speed-of-light in medium over distance | netem `delay` |
| `L_proc` | Device forwarding/switching latency | netem `delay` |
| `L_infra` | Optical amplifiers, metro equipment | netem `delay` |
| `L_queue` | TBF queue fill under load | emerges from NPC traffic |

The emulator injects `L_prop + L_proc + L_infra` deterministically via netem.
`L_queue` is not injected — it **emerges naturally** when NPC traffic fills
the TBF token bucket. This is the key design principle: queue delay is not
simulated, it is caused.

---

## 3. Propagation Delay — Physics Formula

Electromagnetic signals travel at a fraction of the speed of light in
vacuum (`c = 300,000 km/s`), reduced by the refractive index of the medium.

```
L_prop (ms) = (d / v) × 1000
```

| Symbol | Meaning |
|--------|---------|
| `d` | Link distance in km, sampled uniformly from area bounds |
| `v` | Signal speed in km/s for the medium |
| `1000` | Converts seconds → milliseconds |

**Medium speeds (from tc_thresholds.json):**

| Medium | Speed (km/s) | Refractive index vs vacuum |
|--------|-------------|---------------------------|
| `fiber` | 200,000 | ~1.5 (glass core) |
| `copper` | 200,000 | ~1.5 (coaxial dielectric) |
| `wireless` | 300,000 | ~1.0 (free space, near-c) |

**Distance bounds by area (from tc_thresholds.json):**

| Area | Distance range (km) | Real-world analogy |
|------|--------------------|--------------------|
| `pan` | 0.001 – 0.01 | Bluetooth, USB |
| `lan` | 0.01 – 1.0 | Office floor, building |
| `can` | 1.0 – 5.0 | Campus |
| `man` | 5.0 – 50.0 | City, metro |
| `wan` | 50.0 – 20,000 | Country, continent |
| `isp_access` | 0.1 – 10.0 | Last-mile ISP |
| `isp_enterprise` | 1.0 – 50.0 | ISP backbone short-haul |

**Example — fiber LAN at 0.5 km:**
```
L_prop = (0.5 / 200,000) × 1000 = 0.0025 ms
```

**Example — fiber WAN at 5,000 km:**
```
L_prop = (5000 / 200,000) × 1000 = 25 ms
```

---

## 4. Processing Delay — Device Hardware Formula

Every network device takes finite time to process a packet in hardware:
lookup, switching fabric, output queue scheduling.

```
L_proc (ms) = lerp(processing_ms[device_class], U(0,1))
```

where `lerp(bounds, f) = bounds[0] + f × (bounds[1] - bounds[0])`.

**Device class bounds (from tc_thresholds.json):**

| Device class | Min (ms) | Max (ms) | Physical basis |
|-------------|---------|---------|----------------|
| `lan_host` | 0.01 | 0.10 | NIC interrupt + kernel stack |
| `lan_switch` | 0.05 | 0.50 | Cut-through or store-and-forward switch |
| `lan_router` | 0.05 | 0.50 | Software forwarding, ACL lookup |
| `isp_backbone_switch` | 0.10 | 1.00 | Deep TCAM, OTN framing |
| `wan_router` | 0.02 | 0.50 | ASIC forwarding, MPLS pop/push |
| `vpn_concentrator` | 0.10 | 3.00 | Crypto engine (AES-GCM, ChaCha20) |
| `datacenter_server` | 0.01 | 0.50 | DPDK or kernel TCP stack |

`vpn_concentrator` is highest because WireGuard's ChaCha20-Poly1305
encryption runs per-packet even on hardware with dedicated crypto engines.

---

## 5. Infrastructure Overhead — Optical/Metro Equipment

Long-distance and metro links traverse optical amplifiers (EDFAs),
regenerators, and multiplexers that introduce near-constant but
non-negligible fixed delays.

```
L_infra (ms) = lerp(infrastructure_overhead_ms[area], U(0,1))
```

**Overhead bounds by area (from tc_thresholds.json):**

| Area | Min (ms) | Max (ms) | Source |
|------|---------|---------|--------|
| `pan` | 0.0 | 0.1 | No infrastructure |
| `lan` | 0.0 | 0.5 | Patch panels, switch fabrics |
| `can` | 0.5 | 2.0 | Campus distribution layer |
| `man` | 1.0 | 10.0 | Metro OTN muxponders |
| `wan` | 2.0 | 20.0 | EDFA amplifiers, OEO regenerators |
| `isp_access` | 2.0 | 15.0 | DSLAM, CMTS, OLT processing |
| `isp_enterprise` | 1.0 | 8.0 | PE routers, MPLS label operations |

---

## 6. Base Delay (netem input)

The three physical components are summed and injected as netem's
deterministic delay:

```
delay_ms = L_prop + L_proc + L_infra
```

netem applies this delay to every packet, regardless of load.
This is the **propagation floor** — the minimum latency the link will
ever achieve even with zero congestion.

---

## 7. Jitter — Physical Variance Formula

Jitter in real networks comes from:
- Thermal noise in amplifiers (EDFA ASE noise)
- Clock synchronisation error (SDH/SONET pointer adjustments)
- Packet scheduling micro-variations in hardware queues

It is proportional to the infrastructure overhead, not to propagation:

```
jitter_ms = max(0.01 ms,  L_infra × U(0.02, 0.10))
```

**Reasoning:**
- Pure propagation delay (`L_prop`) is determined by physics — it does
  not vary packet to packet.
- Processing delay (`L_proc`) is nearly constant for ASIC forwarding.
- Infrastructure overhead (`L_infra`) varies because amplifier gain,
  mux scheduling, and clock adjustments are not perfectly stable.
- The variance is 2–10% of `L_infra` — small but non-zero.
- Floor of 0.01 ms prevents netem receiving a zero jitter value which
  some kernels interpret as disabling the jitter distribution.

**Example — MAN link with L_infra = 5 ms:**
```
jitter_ms = 5 × U(0.02, 0.10) ∈ [0.10, 0.50] ms
```

---

## 8. Jitter Distribution

netem supports several statistical distributions for the delay variation.
The emulator selects based on device class:

```
distribution = tc_thresholds.json["distribution"][device_class]
```

| Device class | Distribution | Reasoning |
|-------------|-------------|-----------|
| `lan_host` | `normal` | Symmetric scheduling variance |
| `lan_switch` | `normal` | Cut-through latency symmetric |
| `lan_router` | `normal` | Software forwarding symmetric |
| `isp_backbone_switch` | `paretonormal` | Heavy-tail: rare large delays from OTN frame slips |
| `wan_router` | `paretonormal` | Heavy-tail: BGP reconvergence, MPLS reroute |
| `vpn_concentrator` | `normal` | Crypto is deterministic |
| `datacenter_server` | `normal` | Predictable NIC queuing |

`paretonormal` is a convolution of Pareto and Normal — it produces the
heavy right tail observed in measured Internet delay distributions (CAIDA,
RIPE Atlas) where most packets are fast but occasional packets are much
slower.

---

## 9. TBF (Token Bucket Filter) — Rate Limiting

TBF is a token bucket: tokens accumulate at rate R (the configured
bandwidth). A packet of size S consumes S tokens. If insufficient tokens
exist, the packet waits in the TBF queue.

### 9.1 Rate

```
rate = bw_mbps  [Mbit/s, sampled from link_capacity_mbps[area]]
```

**Bandwidth bounds by area:**

| Area | Min (Mbps) | Max (Mbps) |
|------|-----------|-----------|
| `pan` | 1 | 100 |
| `lan` | 100 | 10,000 |
| `can` | 1,000 | 10,000 |
| `man` | 1,000 | 100,000 |
| `wan` | 10 | 100,000 |
| `isp_access` | 10 | 100 |
| `isp_enterprise` | 100 | 1,000 |

### 9.2 Burst Size

The Linux TBF implementation requires a minimum burst equal to the
token accumulation between kernel timer ticks:

```
burst_bytes = max(MTU,  rate_bytes_per_second / kernel_hz)

rate_bytes_per_second = bw_mbps × 10⁶ / 8
kernel_hz = 250          (CONFIG_HZ=250, typical desktop/server)
```

**Why this floor?**  
At 250 Hz, the kernel services the TBF token bucket every 4 ms.
In 4 ms at rate R, the number of bytes that arrive is
`R_bytes × 0.004`. If burst < that, every tick would find the bucket
empty and artificially throttle below R. The burst floor ensures the
link actually delivers its configured rate.

**Example — 1,000 Mbps LAN:**
```
rate_bytes = 1000 × 10⁶ / 8 = 125,000,000 B/s
burst = max(1500, 125,000,000 / 250) = max(1500, 500,000) = 500,000 B
```

### 9.3 TBF Queue Depth (limit) — Bandwidth-Delay Product

The TBF queue must be deep enough for TCP to fill its congestion window
without tail-dropping. The theoretical minimum queue size is the
Bandwidth-Delay Product (BDP):

```
BDP (packets) = (rate_bytes_per_second × RTT_s) / MTU

RTT_s = (delay_ms × 2) / 1000     [one-way delay × 2 for round-trip]
```

The queue limit is the larger of BDP and an area-typical minimum:

```
ql = lerp(buffer_packets[area], U(0,1))
limit = max(20,  max(BDP, ql))
```

**Buffer packet bounds by area:**

| Area | Min | Max | Reasoning |
|------|-----|-----|-----------|
| `pan` | 10 | 50 | Low BDP |
| `lan` | 50 | 200 | Office RTT small |
| `can` | 100 | 500 | Campus RTT moderate |
| `man` | 200 | 1,000 | City RTT |
| `wan` | 500 | 2,000 | Long RTT, large BDP |
| `isp_access` | 200 | 1,000 | Bufferbloat-aware |
| `isp_enterprise` | 200 | 1,000 | Enterprise SLA |

**Example — WAN 100 Mbps, delay 50 ms:**
```
rate_bytes = 100 × 10⁶ / 8 = 12,500,000 B/s
RTT = 50 × 2 / 1000 = 0.1 s
BDP = 12,500,000 × 0.1 / 1500 = 833 packets
ql = U(500, 2000) ≈ 1,200 packets (sample)
limit = max(20, max(833, 1200)) = 1,200 packets
```

### 9.4 TBF Latency Parameter

TBF's `latency` parameter is NOT a delay — it is the maximum time a
packet may wait in the TBF queue before being tail-dropped. It defines
the effective buffer capacity in time units:

```
tbf_latency_ms = max(0.1 ms,  (limit × MTU × 8) / (rate_bps) × 1000)

                = max(0.1,  limit × MTU_bits / rate_bps × 1000)
```

This is: **how long it takes to drain `limit` MTU-sized packets at
full rate**. Fast links get short latency (tight buffer, quick drop).
Slow links get long latency (deep buffer, tolerates burst arrivals).

**Example — 100 Mbps WAN, limit = 1,200 packets:**
```
tbf_latency = (1200 × 1500 × 8) / (100 × 10⁶) × 1000
            = 14,400,000 / 100,000,000 × 1000
            = 144 ms
```

---

## 10. TBF + netem Chain — Packet Flow

```
Packet arrives at TBF
│
├─ Tokens available?
│    YES → consume tokens, enqueue to netem immediately
│    NO  → wait in TBF queue until tokens accumulate
│          if wait > tbf_latency → tail-drop
│
▼
Packet enters netem (after TBF dequeue)
│
└─ Add delay sample: D ~ Normal(delay_ms, jitter_ms²)
                     or Pareto-Normal for ISP/WAN
│
▼
Packet exits to wire after D milliseconds
```

**Result:**
- Under light load: packet waits only `D` ms (netem delay). TBF queue
  stays empty. Observed latency ≈ `L_prop + L_proc + L_infra`.
- Under heavy NPC load: TBF queue builds up. Each packet waits
  `T_queue` in TBF, then `D` in netem.
  Observed latency ≈ `T_queue + L_prop + L_proc + L_infra`.

`T_queue` is **not configured** — it is a consequence of the traffic load.

---

## 11. Queuing Delay — Emergence from NPC Traffic

The emulator does not configure `L_queue`. It emerges from NPC traffic:

```
T_queue ≈ Q_depth × MTU_bits / rate_bps
```

where `Q_depth` is the current TBF occupancy in packets.

With NPC intensity `ρ` (utilisation):

```
ρ = NPC_rate / rate_bps
```

At steady state (M/D/1 queue approximation):

```
T_queue ≈ (ρ² × MTU_bits) / (2 × (1 - ρ) × rate_bps)
```

| NPC Intensity | ρ range | T_queue behaviour |
|--------------|---------|-------------------|
| `low` | 0.20 – 0.30 | Negligible queuing delay |
| `medium` | 0.50 – 0.70 | Moderate queuing, visible jitter |
| `high` | 0.90 – 1.00+ | Queue saturates, packet loss begins |

This is why the emulator needs NPC traffic to produce realistic
jitter — a single TCP flow at low utilisation sees near-zero `T_queue`.
Only when multiple NPC flows simultaneously compete for the link does
the queue fill and queuing delay emerge.

---

## 12. Full Parameter Summary Per Interface

```
Input:   device_class, area, medium, seed
Output:  tc qdisc add dev {iface} root handle 1: tbf \
             rate {bw_mbps}mbit \
             burst {burst_bytes}b \
             latency {tbf_latency_ms}ms
         && \
         tc qdisc add dev {iface} parent 1:1 handle 10: netem \
             delay {delay_ms}ms {jitter_ms}ms \
             distribution {dist_type}
```

| Parameter | Formula | Physics |
|-----------|---------|---------|
| `bw_mbps` | `lerp(link_capacity_mbps[area], U)` | Physical link capacity |
| `delay_ms` | `L_prop + L_proc + L_infra` | Speed-of-light + hardware |
| `jitter_ms` | `max(0.01, L_infra × U(0.02, 0.10))` | Equipment variance |
| `dist_type` | `distribution[device_class]` | Measured traffic models |
| `burst_bytes` | `max(MTU, R_bytes / kernel_hz)` | Token accumulation per tick |
| `limit` | `max(20, max(BDP, ql))` | TCP flight window support |
| `tbf_latency_ms` | `(limit × MTU_bits) / R_bps × 1000` | Queue drain time |

---

## 13. Why Not Just Use netem Alone?

netem can set `rate`, `delay`, `loss`, `jitter` independently. But:

1. **netem rate limiting is inaccurate at high speeds** — it uses a
   simple token bucket without the burst accounting TBF provides.
   TBF's burst parameter correctly handles Linux timer granularity.

2. **TBF queue gives realistic back-pressure** — when the link fills,
   TCP senders receive reduced ACK rates and back off. netem's delay
   does not interact with TCP's congestion control the same way.

3. **Separation of concerns** — TBF owns bandwidth, netem owns delay.
   Changing one does not disturb the other. This matches real network
   equipment where the rate scheduler and the physical medium are
   independent components.

---

## 14. NPC Traffic Generation — Logic and Formulas

NPC (Non-Player Character) hosts generate synthetic background traffic that
fills the TBF queue, causing queuing delay and jitter to emerge organically.
This is what makes the timing watermark dataset realistic — the watermark
signal must survive real congestion, not simulated congestion.

---

### 14.1 Architecture

One thread per NPC host. Each thread runs an infinite selection loop:

```
start()
  │
  ├─ priming phase: fire each behavior once immediately
  │   (ensures capture window contains at least one of every type)
  │
  └─ main loop:
       behavior = random.choices(behavior_names, weights, k=1)
       execute behavior (inside Mininet namespace via node.cmd)
       wait = sample_inter_arrival(behavior)
       sleep(wait)   ← stop_event.wait(timeout=wait) for clean shutdown
```

Heavy behaviors (FTP, SMTP, bulk) are gated by a global semaphore:

```
_MAX_HEAVY = max(1, min(4, cpu_count - 2))
```

This prevents simultaneous iperf3/FTP/SMTP processes from saturating
the host OS when many NPC nodes run in parallel Mininet namespaces.

---

### 14.2 Behavior Mix — CAIDA-Derived Weights

The probability of selecting each behavior is drawn from CAIDA Internet
traffic measurements, scaled so idle weight controls the active fraction ρ:

```
P(behavior) = weight[behavior] / sum(all weights)
```

**Weight tables by intensity:**

| Behavior | low | medium | high | CAIDA share |
|----------|-----|--------|------|-------------|
| `http`   | 13  | 39     | 65   | 65% |
| `bulk`   | 3   | 9      | 15   | 15% |
| `dns`    | 2   | 5      | 8    | 8% |
| `ftp`    | 1   | 3      | 5    | 5% |
| `smtp`   | 1   | 3      | 5    | 5% |
| `db`     | 1   | 1      | 2    | 2% |
| `echo`   | 0   | 1      | 2    | — |
| `idle`   | 79  | 39     | 0    | — |

The ACTIVE behaviors (non-idle) maintain their CAIDA ratios at all
intensities. Only the idle fraction changes:

```
ρ_active = sum(non-idle weights) / sum(all weights)

low:    21  / 100 = 0.21  →  ρ ≈ 0.20–0.30
medium: 61  / 100 = 0.61  →  ρ ≈ 0.50–0.70
high:   102 / 102 = 1.00  →  ρ ≈ 0.90–1.00+
```

`high` allows weights to sum > 100 (idle=0) — the active fraction
reaches saturation, matching peak-hour ISP utilisation.

---

### 14.3 Inter-Arrival Times — Exponential and Uniform Sampling

The time between successive behavior rounds follows application-layer
arrival distributions from CAIDA field measurements, scaled to fit
emulation capture windows (15–25 s):

```
wait = sample_inter_arrival(behavior)
```

| Behavior | Distribution | Mean (s) | Physical basis |
|----------|-------------|---------|----------------|
| `http`   | Expovariate(1/5)  | 5  | HTTP pipelining, browser think time |
| `dns`    | Expovariate(1/4)  | 4  | DNS TTL expiry, resolver cache miss |
| `db`     | Expovariate(1/3)  | 3  | Application query intervals |
| `echo`   | Expovariate(1/8)  | 8  | Keep-alive / heartbeat |
| `idle`   | Expovariate(1/10) | 10 | User think time |
| `bulk`   | Expovariate(1/15) | 15 | Background transfer intervals |
| `ftp`    | Uniform(8, 20)    | 14 | File transfer periodicity |
| `smtp`   | Uniform(5, 15)    | 10 | Email send cadence |

Exponential inter-arrival (`Expovariate(λ)`) models a Poisson arrival
process — the standard model for independent user-initiated requests.
FTP and SMTP use Uniform because file transfers and email have more
regular scheduled intervals than random web requests.

---

### 14.4 Behavior Payload Sizes — Lognormal and Uniform

Each behavior generates a transfer of realistic size derived from
measured Internet traffic payload distributions:

**HTTP — Lognormal(μ=7, σ=2) bytes:**
```
size_bytes = max(512, exp(gauss(7, 2)))

E[size] = exp(μ + σ²/2) = exp(7 + 2) = exp(9) ≈ 8,100 bytes
```
Lognormal matches real HTTP object sizes (CAIDA): most responses are
small (HTML, JSON), occasional large (images, video segments).

**SMTP — Lognormal(μ=8, σ=3) bytes, capped at 65,536:**
```
body_size = min(65536, max(512, exp(gauss(8, 3))))

E[size] = exp(8 + 4.5) = exp(12.5) ≈ 268,000 bytes  (before cap)
```
The cap models typical SMTP server message size limits.

**FTP — Uniform(0.1, 5.0) MB:**
```
size_bytes = uniform(0.1, 5.0) × 1024²
```
File transfers vary uniformly — no strong distributional preference.

**Bulk (iperf3 UDP) — Uniform(2, 8) Mbps sustained for 5 s:**
```
bw_mbps = uniform(2.0, 8.0)
duration = 5 s
bytes_transferred = bw_mbps × 10⁶ / 8 × 5
```
Models background video streaming, large file sync, or VM migrations.

**Echo — Uniform(8, 512) bytes:**
```
size = randint(8, 512)
```
Heartbeat / keep-alive. Small, frequent.

---

### 14.5 How NPC Traffic Loads the TBF Queue

The NPC-generated load in bytes per second per host:

```
R_npc (B/s) ≈ ρ × R_link

ρ = active_fraction × mean_payload / mean_inter_arrival
```

For `medium` intensity on a 1 Gbps LAN link:

```
ρ ≈ 0.61
R_npc ≈ 0.61 × 1,000 Mbps = 610 Mbps
```

The TBF queue occupancy `Q` at steady state (M/D/1 approximation):

```
Q (packets) ≈ ρ² / (2 × (1 - ρ))

medium (ρ = 0.60): Q ≈ 0.36 / 0.80 = 0.45 packets  (nearly empty)
high   (ρ = 0.95): Q ≈ 0.90 / 0.10 = 9.0  packets  (significant queue)
```

Queuing delay contributed by NPC:

```
T_queue ≈ Q × MTU × 8 / R_link_bps

high, 1 Gbps: T_queue ≈ 9.0 × 1500 × 8 / 10⁹ = 0.108 ms
high, 10 Mbps: T_queue ≈ 9.0 × 1500 × 8 / 10⁷ = 10.8 ms
```

At `low` intensity, `T_queue` is negligible. At `high`, it can
exceed the configured propagation delay on slow links — which is
exactly the noisy-rhythm condition for the timing watermark.

---

### 14.6 NPC Effect on the Timing Watermark

The covert channel encodes bits in inter-packet delays (IPDs):

```
bit=0 → server delays next chunk by short_delay_ms  (e.g., 20 ms)
bit=1 → server delays next chunk by long_delay_ms   (e.g., 50 ms)

IPD_observed = IPD_encoded + T_queue + L_jitter
```

NPC traffic adds `T_queue` noise on top of the watermark signal.
For the watermark to be recoverable:

```
(long_delay_ms - short_delay_ms) >> max(T_queue) + max(L_jitter)

30 ms gap >> T_queue + jitter
```

| NPC intensity | max T_queue (LAN) | Recovery difficulty |
|--------------|------------------|---------------------|
| `low` | ~0 ms | Easy — clean IPDs |
| `medium` | ~0.5 ms | Moderate — small noise |
| `high` | ~5–15 ms | Hard — approaches gap |

This is why the three intensity levels map directly to dataset labels:
`low` → easy detection, `high` → noisy / adversarial condition.

---

### 14.7 Service IP Resolution — From Topology, Not Hardcoded

NPC service targets are resolved from `config.services` and
`config.databases` at manager initialisation:

```python
_web_ip  = first_ip_of_type("http")     # HTTP + SMTP target
_ftp_ip  = first_ip_of_type("ftp")
_dns_ip  = first_ip_of_type("dns")
_echo_ip = first_ip_of_type("echo")
_smtp_ip = first_ip_of_type("smtp")
_db_ip   = allocation.get_host_ip(databases[0].host)

dns_domains = [f"{node}.local" for node in sorted(all_node_names)]

smtp_from = f"npc@{smtp_node_name}.local"
smtp_to   = f"user@{smtp_node_name}.local"

db_endpoints = exfiltration.endpoints  or  [f"/api/{t.name}" for t in db.tables]
```

If a service type is absent from `services:` in the YAML, its target IP
is `None` and that behavior is silently skipped. The remaining behaviors
continue running with their correct CAIDA-derived weights.

---

### 14.8 NPC Lifecycle Summary

```
npc start [--intensity low|medium|high]
│
├─ iperf3 server started on each NPC host (for bulk behavior)
│
├─ per-host thread launched
│   │
│   ├─ priming: http → dns → db → echo → smtp → ftp (once each)
│   │
│   └─ main loop:
│        b = random.choices(behaviors, weights)
│        execute(b)
│        sleep(inter_arrival(b))
│        if stop_event: exit
│
npc stop
│
└─ stop_event.set() on all threads
   join(timeout=15s)
   iperf3 processes terminated via capture_manager.stop()
```

---

## 15. Timing Protocol — Covert Channel Mechanism

The timing protocol is a network steganography channel that encodes a
secret bit-stream into the inter-packet delays (IPDs) of an HTTP response.
The receiver can reconstruct the bit-stream from observed IPDs without
any modification to the HTTP payload.

---

### 15.1 System Overview

```
Attacker (h2)                        Victim DB server (db1)
─────────────                        ──────────────────────
socket.IP_TOS = attack_tos           Scapy sniffer watches port
                                     detects TOS-marked SYN
HTTP GET /api/employees ──────────►  new_session(src=172.16.0.2)
    [TOS=0x10 marked]
                                     build SQLite response body
                        ◄── chunk[0] (immediate, no delay)
                        ◄── delay(bit_1)
                        ◄── chunk[1]
                        ◄── delay(bit_2)
                        ◄── chunk[2]
                             ...
                        ◄── chunk[N]  ← finalize_session()

                                     persist timing metadata →
                                     /tmp/timing_db1_*.json
```

---

### 15.2 Bit Generation — SHA-512 Keystream

The server generates a deterministic bit-stream from a shared secret key
and a per-session nonce. The attacker and server share `secret_key`;
no other side-channel is needed.

**Keystream formula:**

```
digest_n = SHA-512( secret_key : t0 : nonce_n )

  secret_key  — shared secret from YAML timing_protocol.secret_key
  t0          — Unix timestamp of the FIRST TOS-marked packet (pkt.time),
                recorded by the Scapy sniffer when new_session() fires
  nonce_n     — integer counter, starts at 1, increments each digest

bits = [ (digest_n[byte] >> shift) & 1
         for byte in digest_n
         for shift in range(7, -1, -1) ]      # MSB first
```

One SHA-512 digest produces **512 bits**. The bits are consumed
sequentially from a pool. When the pool is exhausted, `nonce` increments
and a new digest is computed:

```
nonce_1 → SHA-512(key:t0:1) → 512 bits
nonce_2 → SHA-512(key:t0:2) → 512 bits
nonce_3 → SHA-512(key:t0:3) → 512 bits
...
```

Each nonce used is recorded in `nonces_used[]` in the session metadata.

**Why include `t0` (first TOS timestamp)?**

`t0` is the precise Unix timestamp (float) of the first TCP SYN or data
packet that carries `IP_TOS == attack_tos`, observed by the server's
Scapy sniffer. Including it in the digest input means:

- Two sessions from the same attacker with the same `secret_key` and
  nonce counter produce **different bit-streams** — session keystreams
  are independent even if replayed.
- An observer who intercepts the `secret_key` but does not know `t0`
  cannot reconstruct the keystream — `t0` acts as a session-unique salt.
- `t0` is not transmitted over the wire; it exists only in the server's
  memory and in the persisted `start_timestamp` field of `schema.json`.

**Why SHA-512?**
- Cryptographically unpredictable: no observer can predict the next bit
  without knowing both `secret_key` AND `t0`.
- Deterministic: given the same key, `t0`, and nonce, the server always
  produces the same bit sequence — the receiver can reproduce and verify
  using the recorded `start_timestamp` from `schema.json`.
- 512 bits per digest avoids frequent key-schedule overhead.

---

### 15.3 IPD Encoding — Binary Delay Modulation

Each response body is chunked into segments of `chunk_size = 1200` bytes
(slightly below MTU to avoid IP fragmentation):

```
chunks = [ body[i : i + 1200]  for i in range(0, len(body), 1200) ]
```

Encoding rule:

```
chunk[0]  → sent immediately, no delay
chunk[k]  → bit = next_bit_from_keystream()
             delay = short_delay_s  if bit == 0
                     long_delay_s   if bit == 1
             time.sleep(delay)
             send chunk[k]
```

The observable inter-packet delay between successive chunks encodes one bit:

```
IPD_k ≈ short_delay_ms    →  bit = 0
IPD_k ≈ long_delay_ms     →  bit = 1
```

**Example with short=20 ms, long=50 ms and 5 chunks:**

```
t=0.000 s  →  chunk[0]  (immediate)
t=0.050 s  →  chunk[1]  (bit=1, long delay)
t=0.070 s  →  chunk[2]  (bit=0, short delay)
t=0.090 s  →  chunk[3]  (bit=0, short delay)
t=0.140 s  →  chunk[4]  (bit=1, long delay)

rhythm = [1, 0, 0, 1]     ← bits encoded (chunk[0] carries no bit)
```

---

### 15.4 TOS Detection — Per-Connection Session Trigger

The server runs a Scapy BPF sniffer in a daemon thread:

```python
filter = f'tcp dst port {PORT} and ip[1] = {ATTACK_TOS}'
```

`ip[1]` is the TOS byte in the IPv4 header. `ATTACK_TOS` comes from
`exfiltration.attack_tos` in the YAML (default `0x10 = 16`).

**New session trigger:**

```python
if pkt[IP].tos == ATTACK_TOS and pkt[TCP].dport == PORT:
    sport = pkt[TCP].sport
    if sport != _active_sport:          ← new TCP connection (distinct sport)
        _active_sport = sport
        TIMING.new_session(
            timestamp = float(pkt.time),
            attacker_ip = pkt[IP].src,  ← real src IP from kernel packet
        )
```

One session = one distinct TCP connection (identified by source port).
Multiple connections from the same attacker host are separate sessions,
each with their own nonce sequence and rhythm.

**Why source-port tracking?**
TCP connections from the same IP reuse the IP but have distinct source
ports. Tracking sport prevents a retried connection from resetting an
in-progress session mid-encoding.

---

### 15.5 TCP_NODELAY — Packet Boundary Alignment

The HTTP response is written in chunks with `time.sleep()` between them.
Without `TCP_NODELAY`, the kernel's Nagle algorithm might coalesce two
consecutive small chunks into one TCP segment, collapsing an IPD to zero:

```python
self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
```

With `TCP_NODELAY`, each `wfile.write() + wfile.flush()` causes an
immediate TCP segment emission. The IPD between segments maps 1:1 to
the `time.sleep(delay)` call — no coalescing.

---

### 15.6 Session Lifecycle

```
new_session(timestamp, attacker_ip)        ← TOS sniffer triggers
│
├─ reset current state
├─ enabled = True
├─ start_timestamp = timestamp
├─ src = attacker_ip
│
HTTP GET arrives
│
├─ observe_first_request()                 ← HTTP handler
│   └─ records client_address[0] as src (confirms VPN IP)
│
├─ build body = SELECT * FROM table
│
├─ _write_body_with_ipd(body)
│   ├─ chunk[0] → immediate
│   ├─ for chunk[1..N]:
│   │   ├─ record_data_packet()
│   │   ├─ bit = next_delay_seconds()     ← consumes from keystream pool
│   │   ├─ time.sleep(delay)
│   │   └─ write + flush
│   └─ record_end()                        ← stamps end_timestamp
│
├─ finalize_session()                      ← archive snapshot to _sessions[]
│
└─ _persist_timing_metadata()              ← write JSON to /tmp/timing_*.json
```

---

### 15.7 Metadata Persisted to schema.json

After each response, the server writes a JSON snapshot:

```json
{
  "sessions": [
    {
      "enabled":                  true,
      "secret_key":               "enterprise-company-covert-key",
      "src":                      "172.16.0.2",
      "dest":                     "192.168.1.3:9090",
      "start_timestamp":          1784834305.863,
      "end_timestamp":            1784834308.893,
      "nonces_used":              [1],
      "exfiltrated_data_packets": 81,
      "rhythm":                   [1,1,0,0,1,0,1,1,...],
      "short_delay_ms":           20.0,
      "long_delay_ms":            50.0
    }
  ]
}
```

`capture_manager` reads this file at `capture stop` and folds the
session into `schema.json` alongside the PCAPNG metadata.

| Field | Synthetic source |
|-------|-----------------|
| `src` | Real packet `pkt[IP].src` from Scapy sniffer |
| `dest` | Real `client_address[0]` from HTTP handler |
| `vpn` | `ipaddress(src) in vpn_subnet` — packet evidence |
| `start_timestamp` | Real `pkt.time` from Scapy |
| `end_timestamp` | Real `time.time()` at last chunk sent |
| `rhythm` | Actual bits consumed from keystream |
| `exfiltrated_data_packets` | Actual chunk count sent |
| `nonces_used` | Actual nonces that generated the keystream |

---

### 15.8 Bit Capacity Per Request

The number of bits encoded per HTTP response depends on the response size:

```
N_chunks = ceil(body_bytes / chunk_size)
N_bits   = N_chunks - 1          ← first chunk carries no bit

body_bytes = row_count × avg_row_bytes

chunk_size = 1200 bytes
```

**Example — 50 employees table:**

```
avg_row ≈ 120 bytes  (id, name, email, department, salary)
body    = 50 × 120 = 6,000 bytes
chunks  = ceil(6000 / 1200) = 5
bits    = 4
```

For 81 data packets (as seen in the real schema.json above):

```
bits_encoded = 81 - 1 = 80 bits
nonces_used = ceil(80 / 512) = 1   (one SHA-512 digest sufficient)
```

---

### 15.9 Signal-to-Noise Ratio

The receiver measures IPDs from captured packets. The observable IPD is:

```
IPD_observed = IPD_encoded + T_queue + L_jitter + T_sys

where:
  IPD_encoded = short_delay_ms or long_delay_ms    (server-controlled)
  T_queue     = queuing delay from NPC traffic      (M/D/1, see §14.5)
  L_jitter    = netem jitter                        (see §7)
  T_sys       = OS scheduling jitter (~0–5 ms)      (time.sleep accuracy)
```

For reliable bit detection the gap must dominate noise:

```
gap = long_delay_ms - short_delay_ms

SNR condition:  gap >> 2 × (max T_queue + max L_jitter + max T_sys)
```

| Setup | gap | max noise | SNR |
|-------|-----|-----------|-----|
| LAN, NPC low | 30 ms | ~1 ms | 30× — trivial |
| LAN, NPC high | 30 ms | ~5 ms | 6× — detectable |
| WAN, NPC high | 30 ms | ~15 ms | 2× — marginal |
| WAN, NPC high, gap=10 ms | 10 ms | ~15 ms | <1× — undetectable |

This is the research-interesting regime: finding the minimum gap that
survives a given network path and NPC load level.

---

### 15.10 Runtime Control

Timing parameters can be modified mid-experiment without restarting
the server via `inject on/off` CLI or direct POST:

```
POST /timing/set
{"enabled": true, "short_delay_ms": 20, "long_delay_ms": 50}
```

`inject on` in the CLI sends this POST to every database API port,
enabling the covert channel for the next exfil request.
`inject off` sends `{"enabled": false}` which resets the timing state.

---

## 16. Reproducibility

The same `seed` always produces the same TC profile:

```python
rng = random.Random(seed)   # deterministic PRNG
bw_mbps  = lerp(bounds, rng.random())
dist_km  = lerp(bounds, rng.random())
proc_ms  = lerp(bounds, rng.random())
infra_ms = lerp(bounds, rng.random())
ql       = lerp(bounds, rng.random())
jitter_f = rng.uniform(0.02, 0.10)
```

Each call to `rng.random()` advances the PRNG state. Interfaces are
processed in config declaration order. Given the same YAML and the
same seed, the exact same `tc qdisc` commands are generated every run —
enabling reproducible dataset sessions.

Default seed used by `capture start` auto-apply: **42**.
