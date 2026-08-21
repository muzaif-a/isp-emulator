# Mechanism — TC, NPC, and Timing Watermark

This document explains how traffic shaping, background traffic generation, and the
covert timing-channel watermark work. TC parameters are set in YAML and applied by
Mininet's `TCLink`; the physics sections below are a reference for choosing realistic
values, not a description of automatic computation.

---

## 1. Architecture Overview

Every interface gets two chained qdiscs:

```
Packet in
    │
    ▼
┌─────────────────────────────────┐
│  TBF  (root qdisc, handle 1:)  │  ← rate limiter
│  rate, burst, max_queue_size    │
└────────────────┬────────────────┘
                 │ packets dequeued at rate R
                 ▼
┌─────────────────────────────────┐
│  netem  (child, parent 1:1)    │  ← propagation delay + jitter
│  delay, jitter, loss            │
└─────────────────────────────────┘
                 │
                 ▼
            Wire / NIC
```

**TBF controls WHEN packets leave** (bandwidth).
**netem controls HOW LONG they sit in the pipe** (propagation physics).

They are chained: a packet passes through TBF first, gets rate-limited,
then immediately enters netem which adds the physical transmission delay.

TC parameters (`bw`, `delay`, `jitter`, `loss`, `max_queue_size`) are declared
in the YAML `traffic_control` section, parsed into `TCParams` by `config_loader.py`,
and applied via `TCLink` during `addLink()`. No random sampling or external files.

---

## 2. Total Observed Latency

What a real receiver measures as RTT has four physical components:

```
L_total = L_prop + L_proc + L_infra + L_queue
```

| Term | Source | How emulated |
|------|--------|--------------|
| `L_prop` | Speed-of-light in medium over distance | netem `delay` |
| `L_proc` | Device forwarding/switching latency | netem `delay` |
| `L_infra` | Optical amplifiers, metro equipment | netem `delay` |
| `L_queue` | TBF queue fill under load | emerges from NPC traffic |

The emulator injects `L_prop + L_proc + L_infra` deterministically via netem.
`L_queue` is not configured — it **emerges naturally** when NPC traffic fills
the TBF token bucket. Queue delay is caused, not simulated.

---

## 3. Propagation Delay — Physics Reference

Electromagnetic signals travel at a fraction of the speed of light in vacuum
(`c = 300,000 km/s`), reduced by the refractive index of the medium.

```
L_prop (ms) = (d / v) × 1000
```

| Medium | Speed (km/s) | Refractive index vs vacuum |
|--------|-------------|---------------------------|
| `fiber` | 200,000 | ~1.5 (glass core) |
| `copper` | 200,000 | ~1.5 (coaxial dielectric) |
| `wireless` | 300,000 | ~1.0 (free space, near-c) |

**Typical distance ranges by area:**

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

Set this value (plus `L_proc` + `L_infra`) as the netem `delay` in YAML.

---

## 4. Processing Delay — Device Hardware Reference

Every network device takes finite time to process a packet:

| Device class | Typical range (ms) | Physical basis |
|-------------|-------------------|----------------|
| `lan_host` | 0.01 – 0.10 | NIC interrupt + kernel stack |
| `lan_switch` | 0.05 – 0.50 | Cut-through or store-and-forward |
| `lan_router` | 0.05 – 0.50 | Software forwarding, ACL lookup |
| `isp_backbone_switch` | 0.10 – 1.00 | Deep TCAM, OTN framing |
| `wan_router` | 0.02 – 0.50 | ASIC forwarding, MPLS pop/push |
| `vpn_concentrator` | 0.10 – 3.00 | Crypto engine (ChaCha20-Poly1305) |
| `datacenter_server` | 0.01 – 0.50 | DPDK or kernel TCP stack |

`vpn_concentrator` is highest because WireGuard's per-packet encryption
runs even on hardware with dedicated crypto engines.

---

## 5. Infrastructure Overhead — Optical/Metro Equipment Reference

Long-distance and metro links traverse optical amplifiers (EDFAs),
regenerators, and multiplexers:

| Area | Typical overhead (ms) | Source |
|------|----------------------|--------|
| `pan` | 0.0 – 0.1 | No infrastructure |
| `lan` | 0.0 – 0.5 | Patch panels, switch fabrics |
| `can` | 0.5 – 2.0 | Campus distribution layer |
| `man` | 1.0 – 10.0 | Metro OTN muxponders |
| `wan` | 2.0 – 20.0 | EDFA amplifiers, OEO regenerators |
| `isp_access` | 2.0 – 15.0 | DSLAM, CMTS, OLT processing |
| `isp_enterprise` | 1.0 – 8.0 | PE routers, MPLS label operations |

---

## 6. Base Delay (netem input)

Sum the three physical components and set as YAML `delay`:

```
delay_ms = L_prop + L_proc + L_infra
```

netem applies this delay to every packet, regardless of load.
This is the **propagation floor** — the minimum latency even with zero congestion.

---

## 7. Jitter — Physical Variance Reference

Jitter is proportional to infrastructure overhead, not propagation:

```
jitter_ms ≈ max(0.01,  L_infra × U(0.02, 0.10))
```

- Pure propagation delay (`L_prop`) does not vary packet-to-packet.
- Processing delay (`L_proc`) is nearly constant for ASIC forwarding.
- Infrastructure overhead (`L_infra`) varies: amplifier gain, mux scheduling, clock adjustments.
- Variance is 2–10% of `L_infra`.

**Example — MAN link with L_infra = 5 ms:**
```
jitter_ms ≈ 5 × 0.05 = 0.25 ms
```

---

## 8. Jitter Distribution

netem supports several statistical distributions. Select based on device class:

| Device class | Distribution | Reasoning |
|-------------|-------------|-----------|
| `lan_host` | `normal` | Symmetric scheduling variance |
| `lan_switch` | `normal` | Cut-through latency symmetric |
| `lan_router` | `normal` | Software forwarding symmetric |
| `isp_backbone_switch` | `paretonormal` | Heavy-tail: rare OTN frame slips |
| `wan_router` | `paretonormal` | Heavy-tail: BGP reconvergence |
| `vpn_concentrator` | `normal` | Crypto is deterministic |
| `datacenter_server` | `normal` | Predictable NIC queuing |

`paretonormal` is a convolution of Pareto and Normal — produces the heavy right tail
observed in measured Internet delay distributions (CAIDA, RIPE Atlas).

---

## 9. TBF (Token Bucket Filter) — Rate Limiting

TBF is a token bucket: tokens accumulate at rate R (the configured bandwidth).
A packet of size S consumes S tokens. If insufficient tokens exist, the packet
waits in the TBF queue.

### 9.1 Rate

```
bw: <Mbps>   # e.g. bw: 100
```

**Typical bandwidth by area:**

| Area | Min (Mbps) | Max (Mbps) |
|------|-----------|-----------|
| `pan` | 1 | 100 |
| `lan` | 100 | 10,000 |
| `can` | 1,000 | 10,000 |
| `man` | 1,000 | 100,000 |
| `wan` | 10 | 100,000 |
| `isp_access` | 10 | 100 |
| `isp_enterprise` | 100 | 1,000 |

### 9.2 Queue Depth (max_queue_size)

The TBF queue must be deep enough for TCP to fill its congestion window
without tail-dropping. The theoretical minimum is the Bandwidth-Delay Product:

```
BDP (packets) = (rate_B_per_s × RTT_s) / MTU

RTT_s = (delay_ms × 2) / 1000
```

Set `max_queue_size` to at least `max(20, BDP)`. Typical values by area:

| Area | Typical range (packets) |
|------|------------------------|
| `pan` | 10 – 50 |
| `lan` | 50 – 200 |
| `can` | 100 – 500 |
| `man` | 200 – 1,000 |
| `wan` | 500 – 2,000 |
| `isp_access` | 200 – 1,000 |

**Example — WAN 100 Mbps, delay 50 ms:**
```
rate_bytes = 100 × 10⁶ / 8 = 12,500,000 B/s
RTT = 50 × 2 / 1000 = 0.1 s
BDP = 12,500,000 × 0.1 / 1500 = 833 packets
max_queue_size: 1000   # comfortably above BDP
```

---

## 10. TBF + netem Chain — Packet Flow

```
Packet arrives at TBF
│
├─ Tokens available?
│    YES → consume tokens, enqueue to netem immediately
│    NO  → wait in TBF queue until tokens accumulate
│          if wait > drain time → tail-drop
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
- Under light load: packet waits only `D` ms. TBF queue stays empty.
  Observed latency ≈ `L_prop + L_proc + L_infra`.
- Under heavy NPC load: TBF queue builds. Each packet waits `T_queue` in TBF,
  then `D` in netem. Observed latency ≈ `T_queue + L_prop + L_proc + L_infra`.

`T_queue` is not configured — it is a consequence of traffic load.

---

## 11. Queuing Delay — Emergence from NPC Traffic

```
T_queue ≈ Q_depth × MTU_bits / rate_bps
```

With NPC utilisation `ρ`, at steady state (M/D/1 approximation):

```
T_queue ≈ (ρ² × MTU_bits) / (2 × (1 - ρ) × rate_bps)
```

| NPC Intensity | ρ range | T_queue behaviour |
|--------------|---------|-------------------|
| `low` | 0.20 – 0.30 | Negligible queuing delay |
| `medium` | 0.50 – 0.70 | Moderate queuing, visible jitter |
| `high` | 0.90 – 1.00+ | Queue saturates, packet loss begins |

Only when multiple NPC flows simultaneously compete for the link does
the queue fill and queuing delay emerge.

---

## 12. YAML TC Configuration Summary

```yaml
traffic_control:
  links:
    - nodes: [h1, s1]
      bw: 100          # Mbps
      delay: "10ms"    # netem propagation delay
      jitter: "1ms"    # netem jitter
      loss: 0.0        # packet loss %
      max_queue_size: 200   # TBF queue depth (packets)
```

```
tc qdisc add dev {iface} root handle 1: tbf \
    rate {bw}mbit burst {auto} latency {auto}ms

tc qdisc add dev {iface} parent 1:1 handle 10: netem \
    delay {delay} {jitter} distribution {normal|paretonormal}
```

Mininet's `TCLink` computes `burst` and `latency` from `bw` and
`max_queue_size` automatically using the Linux TBF kernel requirements.

---

## 13. Why Not Just Use netem Alone?

1. **netem rate limiting is inaccurate at high speeds** — it uses a simple token
   bucket without the burst accounting TBF provides. TBF's burst parameter correctly
   handles Linux timer granularity.

2. **TBF queue gives realistic back-pressure** — when the link fills, TCP senders
   receive reduced ACK rates and back off. netem delay does not interact with TCP's
   congestion control the same way.

3. **Separation of concerns** — TBF owns bandwidth, netem owns delay. Changing one
   does not disturb the other. This matches real network equipment where the rate
   scheduler and physical medium are independent components.

---

## 14. NPC Traffic Generation — Logic and Formulas

NPC hosts generate synthetic background traffic that fills the TBF queue, causing
queuing delay and jitter to emerge organically. The watermark signal must survive
real congestion, not simulated congestion.

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

---

### 14.2 Behavior Mix — CAIDA-Derived Weights

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

```
ρ_active = sum(non-idle weights) / sum(all weights)

low:    21  / 100 = 0.21  →  ρ ≈ 0.20–0.30
medium: 61  / 100 = 0.61  →  ρ ≈ 0.50–0.70
high:   102 / 102 = 1.00  →  ρ ≈ 0.90–1.00+
```

---

### 14.3 Inter-Arrival Times

| Behavior | Distribution | Mean (s) | Physical basis |
|----------|-------------|---------|----------------|
| `http`   | Expovariate(1/5)  | 5  | Browser think time |
| `dns`    | Expovariate(1/4)  | 4  | DNS TTL expiry |
| `db`     | Expovariate(1/3)  | 3  | Application query interval |
| `echo`   | Expovariate(1/8)  | 8  | Keep-alive / heartbeat |
| `idle`   | Expovariate(1/10) | 10 | User think time |
| `bulk`   | Expovariate(1/15) | 15 | Background transfer interval |
| `ftp`    | Uniform(8, 20)    | 14 | File transfer periodicity |
| `smtp`   | Uniform(5, 15)    | 10 | Email send cadence |

---

### 14.4 Behavior Payload Sizes

**HTTP — Lognormal(μ=7, σ=2) bytes:**
```
size = max(512, exp(gauss(7, 2)))
E[size] ≈ 8,100 bytes
```

**SMTP — Lognormal(μ=8, σ=3) bytes, capped at 65,536.**

**FTP — Uniform(0.1, 5.0) MB.**

**Bulk (iperf3 UDP) — Uniform(2, 8) Mbps sustained for 5 s.**

**Echo — Uniform(8, 512) bytes.**

---

### 14.5 How NPC Traffic Loads the TBF Queue

```
R_npc (B/s) ≈ ρ × R_link

medium, 1 Gbps LAN:  R_npc ≈ 0.61 × 1,000 Mbps = 610 Mbps
```

Queue occupancy at steady state (M/D/1):

```
Q (packets) ≈ ρ² / (2 × (1 - ρ))

medium (ρ = 0.60): Q ≈ 0.45 packets  (nearly empty)
high   (ρ = 0.95): Q ≈ 9.0  packets  (significant queue)
```

Queuing delay:

```
T_queue ≈ Q × MTU × 8 / R_link_bps

high, 1 Gbps:   T_queue ≈ 0.108 ms
high, 10 Mbps:  T_queue ≈ 10.8  ms
```

---

### 14.6 NPC Effect on the Timing Watermark

```
IPD_observed = IPD_encoded + T_queue + L_jitter + T_sys

IPD_encoded = short_delay_ms or long_delay_ms    (server-controlled)
T_queue     = queuing delay from NPC traffic      (M/D/1, see §14.5)
L_jitter    = netem jitter                        (see §7)
T_sys       = clock_nanosleep scheduling jitter   (±50–200 µs)
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

---

### 14.7 Service IP Resolution — From Topology, Not Hardcoded

NPC service targets are resolved from `config.services` and `config.databases`
at manager initialisation. If a service type is absent from `services:` in YAML,
its target IP is `None` and that behavior is silently skipped.

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
   iperf3 processes terminated
```

---

## 15. Timing Protocol — Covert Channel Mechanism

The timing protocol encodes a secret bit-stream into the inter-packet delays (IPDs)
of the DB `/backup` HTTP response. The receiver reconstructs the bit-stream from
observed IPDs without modifying the HTTP payload.

Two watermark modes, selected by `timing_protocol.type` in YAML:

- **`app-flow`** (`AppWatermark`) — delays injected in the Python HTTP handler via `clock_nanosleep` between 512B chunk writes. No kernel dependencies.
- **`net-flow`** (`NetWatermark`) — nftables NFQUEUE intercepts each outgoing TCP segment before the kernel sends it; Python callback applies the delay then calls `nfpkt.accept()`. Requires `python3-netfilterqueue`, nftables, and root.
- **`auto`** — tries net-flow first; falls back to app-flow silently if unavailable.

Both modes produce identical observable IPDs at the attacker; analysis in `analyze_watermark.py` is mode-agnostic.

---

### 15.1 System Overview

```
Attacker                             Victim DB server (inside namespace)
────────                             ───────────────────────────────────
socket.IP_TOS = 0x10                 Scapy sniffer: watches tcp dst port N

TCP SYN [TOS=0x10] ───────────────► ARM: new_session() → _WM_ARMED.set()

HTTP GET /backup ──────────────────► Handler: _WM_ARMED.wait(timeout=500ms)
                                     backup SQLite → read all bytes into buf
                                     set TCP_NODELAY on connection socket

                      ◄── chunk[0] (512B) → then _cns_hold(delay[bit_0])
                      ◄── chunk[1] (512B) → then _cns_hold(delay[bit_1])
                      ◄── ...
                      ◄── chunk[N-1] (512B)  ← no delay (last chunk)

TCP FIN ────────────────────────────► DISARM: finalize_session() → _WM_ARMED.clear()
                                      persist /tmp/timing_<host>_<db>.json
```

---

### 15.2 Bit Generation — SHA-512 Keystream

A deterministic 512-bit pool is precomputed from the secret key **once at server
startup** (`TimingProtocol.__init__`):

```python
digest = hashlib.sha512(secret_key.encode("utf-8")).digest()   # 64 bytes

_fixed_bits = [
    (byte >> shift) & 1
    for byte in digest
    for shift in range(7, -1, -1)    # MSB first
]
# len(_fixed_bits) == 512
```

The pool resets to `_fixed_bits` each time it is exhausted:

```python
def next_delay_seconds(self):
    if not self._bits_pool:
        self._bits_pool = list(self._fixed_bits)   # cycle same 512 bits
    bit = self._bits_pool.pop(0)
    self._rhythm.append(bit)
    return self.short_delay_s if bit == 0 else self.long_delay_s
```

**Why SHA-512 of the key only (no nonce, no timestamp)?**
- Both attacker and server share only `secret_key`. No side-channel needed.
- 512 bits from a single digest covers hundreds of chunk IPDs per session.
- Pool cycling means unlimited capacity with the same deterministic sequence.
- The analyzer reconstructs the expected bit-stream from `secret_key` alone
  and compares it against measured IPDs.

---

### 15.3 IPD Encoding — Delay-After-Write

Response data is split into 512-byte chunks (`_WM_CHUNK = 512`):

```python
chunk_offsets = list(range(0, len(data), 512))   # N offsets → N chunks

for idx, i in enumerate(chunk_offsets):
    chunk = data[i : i + 512]
    self.wfile.write(chunk)          # 1. send chunk
    self.wfile.flush()               # 2. flush → one TCP segment (TCP_NODELAY)
    TIMING.record_data_packet()      # 3. count this chunk
    is_last = (idx == len(chunk_offsets) - 1)
    if wm_active and not is_last:
        delay = TIMING.next_delay_seconds()   # 4. pop bit, get delay
        _cns_hold(delay)                       # 5. hold until next chunk
```

**Delay is applied AFTER each chunk write.** This maps each bit to the IPD that
follows the corresponding chunk:

```
t=0.000   chunk[0] sent  →  _cns_hold(delay[bit_0] = 50ms)
t=0.050   chunk[1] sent  →  _cns_hold(delay[bit_1] = 20ms)
t=0.070   chunk[2] sent  →  _cns_hold(delay[bit_2] = 50ms)
t=0.120   chunk[3] sent  →  no delay (last chunk)

IPD_0 = 50ms → bit_0 = 1
IPD_1 = 20ms → bit_1 = 0
IPD_2 = 50ms → bit_2 = 1

rhythm = [1, 0, 1]     ← TIMING._rhythm (N-1 bits for N chunks)
exfiltrated_data_packets = 4
```

**Critical:** Applying delay BEFORE write (delay-before-write) causes off-by-one
— the analyzer compares each IPD against the wrong expected bit, giving survival ≈ 50%
(equivalent to random chance) and false negatives on every session.

---

### 15.4 clock_nanosleep — Kernel-Clock Timing

`time.sleep()` is NOT used. Delays are applied via `clock_nanosleep(CLOCK_MONOTONIC,
TIMER_ABSTIME)` through ctypes, which holds the calling thread with ±50–200 µs
accuracy:

```python
def _cns_hold(delay_s):
    """Busy-wait free kernel hold. No Python GIL involvement during sleep."""
    now = time.monotonic_ns()
    target_ns = now + int(delay_s * 1_000_000_000)
    ts = _Ts(tv_sec=target_ns // 10**9, tv_nsec=target_ns % 10**9)
    while _librt.clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
                                  ctypes.byref(ts), None) == 4:
        pass   # EINTR — kernel woke early, retry to target
```

Python's `time.sleep()` has OS-scheduler granularity (typically 1–10 ms),
which would make short delays (e.g. 20 ms) unreliable. `clock_nanosleep` bypasses
the scheduler and sleeps directly to the MONOTONIC clock target.

---

### 15.5 TOS Detection — SYN-Only ARM

The server runs a Scapy BPF sniffer in a daemon thread inside the DB node's
network namespace:

```python
filter = f'tcp dst port {PORT}'
```

**ARM — SYN flag required:**

```python
if (ip_layer.tos == ATTACK_TOS
        and tcp_layer.dport == PORT
        and TIMING_GATE
        and not is_fin_or_rst
        and bool(int(flags) & 0x02)):   # SYN flag required
    sport = tcp_layer.sport
    if sport != _active_sport:
        _active_sport = sport
        TIMING.new_session(timestamp=float(pkt.time),
                           attacker_ip=src_ip,
                           dest=f'{ip_layer.dst}:{PORT}')
        _WM_ARMED.set()   # unblock /backup handler
```

Requiring SYN (`0x02`) prevents data ACKs and the final post-FIN ACK from
triggering `new_session()` a second time (which would create duplicate sessions
in schema.json).

**DISARM — FIN or RST:**

```python
if (tcp_layer.dport == PORT
        and _active_sport is not None
        and tcp_layer.sport == _active_sport
        and is_fin_or_rst):
    _active_sport = None
    TIMING.finalize_session()
    _WM_ARMED.clear()
```

---

### 15.6 _WM_ARMED Event — Application-Layer Gate

```python
_WM_ARMED = threading.Event()   # set by new_session(); /backup waits on this
```

The `/backup` handler waits up to 500 ms for the sniffer to detect the TOS SYN
before sending data:

```python
armed = _WM_ARMED.wait(timeout=0.5)
if not armed:
    # exfil=off or sniffer missed SYN — proceed without watermark
    pass
```

The sniffer runs in a separate thread. The SYN always precedes the GET (TCP
handshake completes before HTTP), so in practice the Event is set before the
handler calls `wait()`. The 500 ms timeout is a safety valve for exfil=off
captures (no TOS SYN ever arrives; handler proceeds as normal HTTP).

---

### 15.7 TCP_NODELAY — Packet Boundary Alignment

```python
self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
```

Without `TCP_NODELAY`, the kernel's Nagle algorithm might coalesce two consecutive
small chunks into one TCP segment, collapsing an IPD to zero. With `TCP_NODELAY`,
each `wfile.write() + wfile.flush()` causes an immediate TCP segment. The IPD
between segments maps 1:1 to the `_cns_hold(delay)` call.

---

### 15.8 Session Lifecycle

```
TCP SYN [TOS=0x10] detected
  │
  └─ new_session(timestamp=pkt.time, attacker_ip=src_ip)
       _reset_state()          ← clear previous session
       enabled = True
       start_timestamp = pkt.time
       src = attacker_ip
       _WM_ARMED.set()

HTTP GET /backup arrives
  │
  └─ _WM_ARMED.wait(timeout=0.5)
     backup SQLite to tmpfile
     read all bytes
     set TCP_NODELAY
     for each 512B chunk:
         write → flush → record_data_packet()
         if not last: next_delay_seconds() → _cns_hold()

TCP FIN/RST detected
  │
  └─ _active_sport = None
     TIMING.finalize_session()
         end_timestamp = time.time()
         _sessions.append(_snapshot())
         _reset_state()
         _WM_ARMED.clear()
     _persist_timing_metadata()    ← /tmp/timing_<host>_<db>.json
```

---

### 15.9 Metadata Written to /tmp/timing_*.json

```json
{
  "conf_atc_ip": "192.168.0.3",
  "victim_ip": "192.168.1.3:9090",
  "secret_key": "enterprise-company-covert-key",
  "short_delay_ms": 20.0,
  "long_delay_ms": 50.0,
  "sessions": [
    {
      "attacker_ip": "172.16.0.2",
      "start_timestamp": 1787263134.670,
      "end_timestamp": 1787263150.601,
      "exfiltrated_data_packets": 424,
      "rhythm": [1, 0, 1, 0, 0, 1, 1, 0, ...]
    }
  ]
}
```

`capture_manager` reads this file at `capture stop` and folds it into `schema.json`.

| Field | Source |
|-------|--------|
| `conf_atc_ip` | Attacker node IP from `ip_allocator` (ground truth) |
| `attacker_ip` | Real `pkt[IP].src` seen by Scapy sniffer (may be VPN tunnel IP) |
| `start_timestamp` | Real `pkt.time` from first TOS-marked SYN |
| `end_timestamp` | Real `time.time()` when FIN arrives and session finalizes |
| `exfiltrated_data_packets` | Actual count of 512B chunks sent |
| `rhythm` | Actual bits popped from SHA-512 pool during the transfer |

---

### 15.10 Bit Capacity Per Request

```
N_chunks = ceil(body_bytes / 512)
N_bits   = N_chunks - 1          ← last chunk has no delay; N-1 IPDs encoded
```

**Example — 213 KB SQLite database:**
```
body  = 218,112 bytes
chunks = ceil(218112 / 512) = 426
bits   = 425
```

425 bits < 512 (one SHA-512 digest). One pool cycle covers the full transfer.

---

### 15.11 Runtime Control

```
POST /timing/set
{"enabled": true, "short_delay_ms": 20, "long_delay_ms": 50}
```

`inject on` in the CLI sends this POST to every database API port.
`inject off` sends `{"enabled": false}` which resets the timing gate.
`TIMING_GATE` controls whether the `/backup` handler applies delays —
even if `_WM_ARMED` fires, a gate-off session sends chunks without delay
(exfil=off baseline capture).

---

## 16. Reproducibility

**TC:** Parameters are static YAML values. Same YAML → same TC profile on every run.

**Timing keystream:** SHA-512 of the same `secret_key` always produces the same
512-bit pool. Given `secret_key`, the analyzer reconstructs the exact expected
bit sequence and compares it against measured IPDs without any additional state.

**NPC:** Inter-arrival and payload sizes are sampled from pseudo-random distributions
seeded by Python's default PRNG (not fixed). NPC traffic intentionally varies between
runs to produce diverse queue load conditions. The watermark must survive varying noise,
not just a single fixed noise level.

**Capture:** Session IDs are timestamp-based (`YYYYMMDD_HHMMSS_µs`). PCAPNG files
record real packet timestamps from the Mininet namespace clocks.
