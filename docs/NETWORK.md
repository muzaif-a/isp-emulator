# Network Emulation & Data Collection

How the testbed is built, how it is made realistic, and how it turns into a
labeled capture dataset. Read top to bottom — each section builds on the last.

---

## 1. What this produces

A controlled network that carries a hidden timing signal through realistic path
conditions, captured at two points, and written out as per-packet CSV files ready
for analysis.

```
config → build network → add path realism → tunnel → run signal + load
       → capture at two points → parse to CSV → session registry
```

**Guiding rule.** This is a *data factory*, not a production network. Optimize for
**reproducible ground truth**, not scale or maintainability. A realism feature
earns its place only if it changes packet **timing** (the thing being measured) or
is needed to tell the story. Everything else is cosmetic and adds risk.

---

## 2. Build the network

| Tool | Role |
|---|---|
| Linux network namespaces | Each "host" is a namespace with its own TCP/IP stack, interfaces, routing table. Real processes run inside |
| veth pairs | Virtual cable: packet in one end comes out the other. Connects hosts to switches |
| Open vSwitch (OVS) | Layer-2 software switch. Forwards frames by MAC. Used for LAN segments |
| Mininet | Orchestrates the namespaces, veths, and switches from the topology file |

**LAN segments = OVS switches.** Real LANs are layer 2, so keep them as switches.

**The transit/ISP node = a host acting as a router, NOT a switch.** A switch only
forwards frames and is invisible to the path. A router is a real hop: it rewrites
MAC addresses per hop, decrements TTL, and queues packets on its outgoing
interface — which is exactly where a real ISP delays traffic. Make it a router:

```bash
sysctl -w net.ipv4.ip_forward=1      # turn the host into a router
ip route add <dest-subnet> via <next-hop>   # static routes
```

Put the path-impairment (Section 4) on this router's **egress interfaces** — that
is where a real hop queues.

### Addressing and routing: keep them static

Static, fixed addresses and static routes every run. This is a **feature**: it
makes every dataset reproducible and keeps host identity out of the captured
signal. Do **not** add dynamic routing protocols or dynamic address assignment to
the factory — they introduce run-to-run non-determinism for no measurable gain.
(A separate demo configuration may use them; see Section 9.)

---

## 3. Where realism actually lives

Split every property of the testbed into three honest buckets:

| Genuinely real | Modeled (must be calibrated) | Absent (only a real path covers it) |
|---|---|---|
| TCP stack behavior | Propagation delay | Middlebox reshaping |
| Application code | **Jitter distribution** | Internet-scale cross traffic |
| Timer slack | Queuing / bufferbloat | Vendor-specific queuing |
| Scheduler jitter | Bandwidth limit | Hardware timestamping |
| Encryption overhead | Loss, reordering | |
| L2 switching, capture | | |

The left column is real because real code runs on a real kernel. The middle column
all flows through **one subsystem — `tc`** — so that is the only place realism must
be engineered, and it must be *calibrated from measurements*, not invented. The
right column is why one real-path validation run exists (Section 8).

---

## 4. Path realism with `tc`

`tc` is the kernel traffic-control subsystem. Two jobs: impose delay/jitter/loss
(**netem**) and shape bandwidth/queue (a **shaper**).

### 4a. Parameters come from vendor datasheets, not guesses

| Parameter | Source |
|---|---|
| Bandwidth | Line-card / CPE datasheet |
| Buffer depth (drives bufferbloat) | Datasheet buffer size, or bandwidth-delay product. Source deliberately — often not on the glossy sheet |
| Serialization delay | packet_size ÷ bandwidth |

### 4b. Do not hardcode one shaper — sample a regime

Real timing distortion depends heavily on the queue discipline. Pick per-run from a
set of regimes:

| Regime | Queue discipline | Models | Effect on timing |
|---|---|---|---|
| Bufferbloat access | TBF + large pfifo | Old CPE, deep dumb buffer | Compresses gaps inside bursts (hardest) |
| Modern AQM | HTB + fq_codel | Current ISP/CPE | Reshapes bursts, controlled latency |
| Home router | CAKE | Shaper + AQM + fairness | Per-flow fairness + shaping |
| Path only | netem (calibrated) | Long-haul link | Additive delay smear |

Vary the regime *within* a session over a schedule with `tc change` to imitate
changing conditions.

### 4c. Jitter must be calibrated to real measurements

netem's built-in delay distribution is not internet-like — this is the single
biggest realism weakness. Fix it by feeding netem a distribution built from **real
measured delay samples**:

```bash
# 1. collect real one-way-delay / RTT samples (see sources below) into a file
# 2. build a netem distribution table from them:
#    (iproute2 ships maketable / stats tools for this)
# 3. load it:
tc qdisc add dev <egress-if> root netem \
   delay <mean>ms <sigma>ms distribution <realtable> \
   reorder <p>% <corr>% loss <l>% <lcorr>%
```

Sources for real samples: **RIPE Atlas** (API), **M-Lab** (public measurements),
**CAIDA** (traces), or **mahimahi** (records and replays a real path directly).

### 4d. Keep one realistic propagation baseline — do not remove delay entirely

Propagation delay is a constant offset, so it does not directly change the timing
*gaps*. But removing it makes every link behave like a sub-millisecond LAN, which
makes the TCP stack behave unrealistically and produces a signal that is too clean.
Keep a representative round-trip time; spend the realism budget on jitter, queuing,
and reordering (Section 4c), which are what actually distort the gaps.

### 4e. Measure the noise floor (do this once, early)

Run one session with **no `tc` and no background load**. The variation in packet
gaps you still see is the testbed's own noise floor (timer slack + scheduler
jitter), typically ~1–2 ms. Repeat under heavy load for the contended figure.
Record both — they define the measurement error budget.

---

## 5. Encrypted tunnel

Use **self-hosted WireGuard**, hub-and-spoke, with the client and server on
**distinct nodes with the path between them** (never collapsed onto one node).

Why self-hosted and why WireGuard:

- It encrypts and forwards each packet immediately — no buffering, no reordering,
  near-constant sub-millisecond overhead. A constant offset preserves the timing
  gaps; buffering would destroy them.
- Reproducible (you control it) and you can capture at both the encrypted and
  decrypted sides.

Frame WireGuard as the **timing-preserving baseline**. A padding/obfuscating tunnel
is a *defense* to be tested separately (it is expected to break the signal) — do
not claim the signal survives all tunnels.

---

## 6. Generate the signal and the load

**The hidden signal.** A service (Flask + SQLite) responds to requests with a
deliberately controlled delay between packets. Each response gap is either "short"
or "long" (e.g. 20 ms vs 50 ms), driven by a keyed pseudorandom bit sequence
(`SHA-512(key:t0:nonce)`). `time.sleep()` produces the gap — a real kernel timer,
so real timer slack is included. Marked packets carry a distinguishing IP TOS byte
(`0x10`) so ground truth can be labeled **offline** — this marker is metadata only
and never enters analysis features.

**Background load.** One daemon thread per host runs a mix of ordinary protocols
(http/dns/db/smtp/ftp/bulk). Load level (none/low/medium/high) controls congestion.
Queuing, jitter, and loss then *emerge* from real contention rather than being
faked — this is genuine realism, for free.

---

## 7. Capture at two points

| Tool | Role |
|---|---|
| tcpdump / libpcap | Taps at layer 2, captures whole frames, **per interface**. Software timestamps (this is the noise floor from 4e) |
| PCAPNG | On-disk capture format |
| mergecap | Merges per-interface captures by timestamp |
| scapy / pure-Python reader | Parse packets → per-packet fields |
| feature/CSV parser | PCAPNG → per-packet CSV |

**Two capture points, chosen by where you sniff:**

1. **Transit point** (the router) — sees only the **encrypted outer** packets:
   timing and sizes, no inner content. This is the network-operator view.
2. **Endpoint** (the service host) — sees the **decrypted inner** packets and the
   TOS label. This is the ground-truth view.

The two-point design costs nothing extra — it is just two sniffers at two places.

### Capture hygiene (important)

- **Extract timing from a single capture point, not the merged file.** The merged
  file contains the *same packet twice* (seen on two interfaces), which corrupts
  gap measurements and triggers false "retransmission" flags in analysis tools.
- **Drop retransmissions and duplicates** before using a flow — a retransmitted
  data packet is large enough to pass length filters and would add a false beat.

---

## 8. One real-path validation run

The "absent" column in Section 3 cannot be modeled. Cover it with a single external
run: two machines you own in different locations (a free academic testbed such as
**FABRIC** or **CloudLab**, or two cloud VMs), real WireGuard between them, and the
**same signal** sent across the real link. You still own both ends, so ground truth
stays exact. Hold this out entirely and use it to report how much the result changes
between the testbed and the real path. Reporting that gap honestly is a strength.

Optional deeper realism: **GNS3 / EVE-NG** run real vendor router images (Cisco
IOS-XR, Arista, Juniper), giving actual vendor queue behavior for a validation
variant. Heavy per-node cost; not for bulk generation.

---

## 9. Two configurations

| Configuration | Contents | Purpose |
|---|---|---|
| **Data factory** | Static routing + static addressing, calibrated `tc` | The reproducible captures |
| **Demo** | Dynamic routing (FRR) + dynamic addressing + a packet-flow visual

**Never generate the dataset with the demo configuration.** Dynamic routing and
addressing reintroduce non-determinism. The demo exists to *show the network works*;
the factory exists to *produce the data*. For a quick visual, open a capture in
Wireshark (Statistics → Flow Graph / IO Graph) — real data, no conversion.

---

## 10. Build order

1. Convert the transit node from a switch to a router-host (Section 2).
2. Replace hardcoded `tc` values with datasheet-derived params and the regime
   sampler (4a, 4b).
3. Calibrate the jitter distribution from real samples (4c); keep one RTT baseline
   (4d); measure the noise floor (4e).
4. Confirm the tunnel keeps client and server on separate nodes (Section 5).
5. Confirm capture runs at both points and timing is extracted from a single point
   with duplicates dropped (Section 7).
6. **Run the parse-to-CSV step over existing captures** — captures are not usable
   until parsed. This is a required manual step, not automatic.
7. Generate the full session set across load levels and conditions.
8. Do the real-path validation run (Section 8).
