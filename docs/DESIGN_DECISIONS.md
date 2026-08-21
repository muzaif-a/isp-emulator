# ISP Emulator — Research Design Decisions

**Status:** living document · **Last updated:** 2026-08-04

This file records the architecture and research-design decisions taken while
converting the emulator from a "CNN detects a covert timing channel" testbed
into a publishable study. Each entry states the **decision**, the **rationale**,
and any **guardrail** that keeps it valid. The governing principle throughout:

> A research **data factory** optimizes for reproducible ground truth. A
> production network optimizes for scalability/maintainability. These pull in
> opposite directions. Realism earns a place in the factory only if it (a)
> reaches the model — and the model reads **inter-packet delays (IPD) only**, so
> realism reaches it *exclusively through timing* — or (b) is needed for the
> threat-model narrative. Nothing else.

---

## Quick reference

| # | Area | Decision | Status |
|---|------|----------|--------|
| D1 | Research framing | Relocate novelty to encrypted-transit detection + cross-vantage attribution + cross-encoding generalization + public dataset | Adopted |
| D2 | Deployment | **Hybrid**: emulation = factory, cloud = proving ground. Not cloud-only, not emulation-only | Adopted |
| D3 | ISP node | L3 **router-host** (ip_forward), not L2 switch. LANs stay OVS switches | To implement |
| D4 | Capture | Per-interface tcpdump; compute IPDs from **single-vantage** file, not merged; dedup/drop retransmissions before windowing | To implement |
| D5 | Addressing | Static/deterministic in factory. DHCP allowed **only** with MAC-pinned reservations. IP never a model feature | Adopted |
| D6 | Routing | Static in factory. **FRR** only in optional demo/realism variant | Adopted |
| D7 | TC params | Calibrate to **vendor datasheets** (Cisco + Juniper/CPE mix); source buffer depth deliberately | To implement |
| D8 | TC qdisc | **Regime sampler** (TBF-bufferbloat / HTB+fq_codel / CAKE / netem), not lone TBF; time-varying | To implement |
| D9 | Propagation delay | Remove hardcoded **by-area constants**, keep one realistic RTT baseline. Realism budget → jitter/queuing/reordering | To implement |
| D10 | VPN | Keep self-hosted **WireGuard**; distinct client/server across path; framed as timing-preserving baseline | Adopted |
| D11 | Jitter model | **Trace-calibrated** (Pareto/Weibull from real data) + domain randomization + real-WAN anchor | To implement |
| D12 | Microservices | Containerize the **workload** only; emulator (Mininet+TC) stays host-native | To implement |
| D13 | Channel encodings | **Multi-encoding** (SHA-512-bimodal, Jitterbug, model-based, randomized) + cross-encoding test | To implement |
| D14 | Model | Benchmark family, do **not** assume CNN; keep frozen 1D-CNN, add MiniROCKET + hybrid + entropy baseline | To implement |
| D15 | Evaluation | LOCO primary (prereg); PR-AUC + detection@fixed-FPR primary; leakage audits | Partly (prereg) |
| D16 | Demo vs factory | Two configs: `realism-demo` (FRR+DHCP+NetAnim) vs `data-factory` (static). Never generate dataset with demo variant | Adopted |
| D17 | Visualization | Wireshark Flow/IO graph for quick real-data review; NetAnim only if required (reads ns-3 XML, not pcapng) | Adopted |
| D18 | ns-3 vs tc | **Keep tc/netem as the channel.** ns-3 is a companion (NetAnim, delay-model cross-check, caveated scale experiment), never the channel | Adopted |
| D18a | Jitter layering | Mininet's native jitter is real but **host-shaped**; channel is explicitly two-layer (real fine-grained + calibrated coarse-grained netem). Measure the noise floor | Adopted |
| D18b | Tool survey | **GNS3/EVE-NG** (real vendor images) for a realism-validation variant; **FABRIC/CloudLab** (free real-hardware testbed) as proving ground. Amends D7 and D2 | Adopted |
| D19 | Attribution | Correlation is the **easier** task; use **Hamming distance on decoded bits** for an exact binomial p-value, not a learned score. Clock sync solved by using IPDs. **Tunnel multiplexing is the real risk.** Cite DeepCorr | Adopted |

---

## Research framing (D1)

**Decision.** "A CNN detects a covert timing channel" is already published
(Al-Eidi 2020 CNN-on-IPD; Gianvecchio–Wang 2011 entropy). Relocate the novelty to:

1. **Encrypted-transit detection** — detect the covert rhythm on the *encrypted*
   WireGuard outer flow at a transit vantage, without decryption.
2. **Cross-vantage rhythm-correlation attribution** — link a VPN-masked outer
   flow to the decrypted inner flow to attribute exfil despite a masqueraded IP.
3. **Cross-encoding generalization benchmark** — the anti-tautology test (below).
4. **Public dual-vantage dataset** — first CTC dataset captured at transit
   (encrypted) and endpoint (decrypted) simultaneously.

**Rationale.** Detection-only is a solved, tautology-prone claim. The intersection
{encrypted transit + attribution + cross-encoding generalization} is empty in the
literature.

**Guardrail — the tautology risk.** The channel is a deterministic SHA-512
keystream mapped to fixed bimodal delays (20/50 ms). A model can learn *the
encoder's fingerprint* rather than "covert timing." Mitigation is D13 +
cross-encoding LOCO. **Week-8 go/no-go:** if a detector trained on SHA-512-bimodal
collapses toward chance on Jitterbug/model-based encodings, we were detecting our
own encoder — pivot the narrative to "why DL-CTC detectors don't generalize."

---

## Deployment architecture (D2)

**Decision.** Hybrid with a hard division of labor:

| | Emulation (Mininet) — **factory** | Cloud (owned VMs) — **proving ground** |
|---|---|---|
| Role | Bulk labeled training data + all controlled experiments | One held-out real-path validation set |
| Ground truth | Exact | Exact (own both ends) |
| Scale/cost | Cheap, thousands of sessions | Expensive, dozens of sessions |
| Proves | Internal validity + robustness envelope | External validity (sim-to-real gap) |

**Rationale.** Cloud-only loses cheap domain randomization, controlled
defense/encoding sweeps, and reproducibility, and still can't label wild
positives. Emulation-only has no real-path anchor. Hybrid: factory makes the data
and the envelope; proving ground makes the honesty.

**Validity ladder to report:** internal (testbed LOCO) → trace realism (emulator
calibrated to measured delay; KS-test emulated vs real IPD) → external (real-WAN
held-out; report sim-to-real Δ PR-AUC). Reporting the gap honestly is a strength.

---

## Network fidelity

### ISP node = L3 router-host (D3)
A switch forwards on MAC (L2), rewrites nothing, no TTL decrement, not a hop. A
real ISP transit point is an **L3 router**: rewrites src/dst MAC per hop,
decrements TTL, does per-hop queuing, appears in traceroute. Implement as a Linux
host with `net.ipv4.ip_forward=1` + static routes (standard Mininet `LinuxRouter`).
LAN segments stay OVS switches (real LANs are L2). **Caveat:** the model reads IPD
only, so this does not change model inputs — its value is vantage fidelity and
correct delay-injection placement. Cheap; do it; don't over-invest.

### Capture (D4)
- tcpdump/libpcap taps at **L2** and captures full frames up through payload,
  **per interface**. It does not see below L2 (irrelevant in emulation).
- At a transit point on an encrypted flow it sees only the **outer WireGuard UDP**
  (timing + sizes). At `db1` after decryption it sees the **inner TCP**. The
  dual-vantage split falls out of *where* you sniff — for free.
- **Measurement caveat:** software timestamps carry kernel/scheduler jitter = the
  IPD measurement noise floor. Report it. Hardware (PTP) timestamping is
  unavailable in emulation.
- **IPD extraction runs on a single-vantage file, NOT the merged pcapng.** Merged
  multi-interface captures duplicate packets (same frame on ingress + egress) and
  interleave order → Wireshark `tcp.analysis` flags fire (false
  retransmission/out-of-order/duplicate). That is a capture artifact, **not** a
  failure. Duplicates/retransmissions must be dropped before windowing or they add
  false beats to the rhythm (retransmitted data packets are >100 B and pass the
  length filter).

### Addressing (D5)
Factory uses **static deterministic** addressing (protect `ip_allocator.py`; it is
a reproducibility feature). DHCP is acceptable **only** with **MAC-pinned
reservations** so the same node gets the same IP every run (keeps `schema.json`
`src`/`dest` stable). The real leakage control is **feature hygiene** — IP must
never enter the detection model's input; enforce in the leakage audit. With those
two guardrails, addressing scheme is cosmetic for an IPD-only model.

### Routing (D6)
Factory uses **static routing** (deterministic, reproducible). The model never
reads a routing table; routing reaches the detector only as timing (a reroute = a
delay shift), modeled far more cleanly as a scheduled `tc change` than by running
OSPF/BGP. **FRR** (intra-AS OSPF/IS-IS, inter-AS BGP) belongs **only** in the
optional demo/realism variant (D16) for the multi-AS threat-model picture — never
in the bulk generator, where reconvergence hurts reproducibility.

### TC parameters (D7)
Replace seed-42 arbitrary values with **vendor-datasheet-derived** numbers:
bandwidth (line-card/CPE), buffer depth (drives bufferbloat — source it
deliberately; often not in the glossy datasheet), serialization delay
(packet_size ÷ bandwidth). Mix vendors/tiers to match the scenario (core vs
access). Datasheets give *numbers*; queue *behavior* still comes from the qdisc.

### TC qdisc regimes (D8)
Do not hardcode a single TBF. Sample a **qdisc regime** (domain randomization at
the device layer):

| Regime | Stack | Models | Effect on rhythm |
|---|---|---|---|
| Bufferbloat access | TBF + large pfifo | Old CPE, deep dumb buffer | Burst-compresses IPDs (hardest) |
| Modern AQM | HTB + fq_codel | Current ISP/CPE | Reshapes bursts, controlled latency |
| CPE combined | CAKE | Home-router shaper+AQM | Per-flow fairness + shaping |
| Path-only | netem (datasheet dist) | Long-haul propagation + jitter | Additive smear |

Time-vary within a session via scheduled `tc change`. The bufferbloat-vs-AQM
contrast directly feeds the H5 defense-robustness experiment.

### Propagation delay (D9)
**Remove the hardcoded by-area constants; do NOT remove path delay entirely.**
Propagation is a constant offset → invisible to an IPD-based detector directly.
But deleting it makes Mininet *more* artificial: (1) TCP RTT dynamics
(ACK-clocking, cwnd growth) shape the wire-level IPDs, and at sub-ms LAN latency
the channel looks unrealistically clean → sim-to-real failure on real high-RTT
paths; (2) Mininet's native link latency is microseconds, so netem delay is the
only thing making the path non-LAN. Keep **one realistic RTT baseline**; spend the
realism budget on **jitter / queuing / reordering** (the parts that reach the
model). Cloud supplies real propagation+jitter for the validation anchor; the
factory keeps *calibrated* (not hardcoded) delay for bulk data.

### VPN (D10)
Keep **self-hosted WireGuard**. Three disqualifying reasons against commercial
providers: (1) their buffering/obfuscation/multi-hop distorts or destroys timing;
(2) non-reproducible internal state; (3) no sniffer access at their server (the
dual-vantage capture is impossible). WireGuard applies a near-constant sub-ms
offset — rhythm-preserving. Keep **client and server on distinct nodes with the
path (and TC) between them** — do not collapse to one node. Frame WireGuard as the
**timing-preserving baseline (no defense)**; obfuscating/padding tunnels are the
**defense case** (H5, where the channel dies). Optionally add OpenVPN/IPsec as a
second timing-preserving tunnel for generality. Do not overclaim "survives all
VPNs" — claim "survives timing-preserving tunnels."

### Jitter model (D11)
Stop inventing jitter with netem defaults. **Measure and match:** fit
Pareto/Weibull (+ reordering rate, loss correlation, burst/slot behavior) to real
delay traces (own cloud VMs, RIPE Atlas, CAIDA, M-Lab); build a netem custom
distribution table; **domain-randomize** across the measured range so no single
testbed signature is learned. Real-WAN run is the external anchor.

---

## Software architecture

### Microservices (D12)
Containerize the **workload** so identical containers run in Mininet namespaces
*and* on cloud VMs (kills the sim-vs-real code mismatch, makes the sim-to-real
comparison apples-to-apples):

- `victim-db` — SQLite + REST + timing protocol
- `attacker-exfil` — covert encoder (pluggable) + TOS marking
- `channel-encoder` — encoding strategy interface (D13)
- `capture-agent` — sniffer → PCAPNG → feature/window → schema

The **emulator layer** (Mininet + OVS + TC) stays **host-native** — it needs host
namespaces and root; containerizing it fights the platform. TC/delay modeling is
environment-specific by design (cloud has no TC — the real path replaces it).

---

## Model and evaluation

### Channel encodings (D13)
Add a pluggable encoder strategy in `timing_protocol.py`; ship ≥4 encodings:
SHA-512-bimodal (current), Jitterbug-style, model-based (Cabuk-style IPCTC),
randomized-delay. **Cross-encoding LOCO** (train on one, test on another) is the
anti-tautology test and the novelty go/no-go (D1 guardrail).

### Model selection (D14)
This is a **1D sequence** problem, not an image problem. Benchmark a family; do
not assume CNN wins:

| Model | Role |
|---|---|
| Entropy + KS (Gianvecchio) | **Mandatory baseline** |
| RF / XGBoost on timing stats | Baseline + interpretability |
| **MiniROCKET** | Likely strong contender (SOTA TSC, small-data-robust) |
| 1D-CNN (frozen prereg) | Primary DL model (respect the freeze) |
| 1D-CNN + light self-attention | Proposed model (attention = periodicity head; ablation target) |
| LSTM/GRU | Baseline |
| Al-Eidi 2D-CNN | Prior-art baseline |

If MiniROCKET ties the deep nets, **say so** — "a simple kernel method matches deep
learning here" is a clean, honest result that defuses the "you just wanted a CNN"
critique.

### Evaluation (D15)
- **Primary:** LOCO (prereg: train {none,low,medium} NPC, test {high}); secondary
  LOCO_VPN, LOCO_Attacker, **LOCO_Encoding**. Random split is a **diagnostic only**
  (label it optimistic).
- **Metrics:** PR-AUC + detection@fixed-FPR **primary** (base-rate honesty), plus
  F1/Recall/FPR/FNR/ROC-AUC/MCC/κ, calibration (ECE/Brier). Test at realistic
  prevalence, not 50/50.
- **Stats:** bootstrap 95% CI; paired significance (Wilcoxon / corrected resampled
  t-test); Holm–Bonferroni across the model family; effect sizes.
- **Leakage audits (run + report):** shuffle-label must collapse to chance;
  confirm no TOS/port/size/IP feature enters the model; session-grouped splits
  (never split windows of one session across folds); inner/outer of the same
  session never straddle train/test.
- **Robustness:** jitter sweep (netem → Pareto → Weibull → real-WAN); defense
  sweep (bound where the channel dies — a feature, not a flaw).

---

## Demonstration vs data factory

### Two-config split (D16)
| Config | Contains | Purpose |
|---|---|---|
| `realism-demo` | FRR (BGP/OSPF) + DHCP + NetAnim/Wireshark visual | Faculty, defense, screenshots — "it works normally" |
| `data-factory` | Static routing + MAC-pinned addressing | The reproducible dataset that trains/tests the model |

Same codebase, two configs. **Hard guardrail: never generate the training/test
dataset with the demo variant.** Documenting both (and why they differ) is a
maturity signal to a committee — it shows the difference between a *demonstration*
and a *controlled experiment*.

### Visualization (D17)
- **NetAnim reads ns-3 XML, not pcapng.** So "NetAnim on the pcapng" needs a
  bridge.
- **Quick faculty review → Wireshark** (Statistics → Flow Graph / IO Graph) on the
  existing pcapng: real data, zero conversion, shows the network works and the
  timing rhythm.
- **NetAnim only if required by name:** either re-model the topology in ns-3 (an
  *illustrative reconstruction* — label it, it is not the captured data) or build a
  `pcapng → NetAnim-XML` translator on top of `network/pcapng_reader.py` (real
  data, ~100–150 lines: IP→node with fixed (x,y), packet→`<p>` tx/rx event).
- Visualization is a **figure, not evidence**. Use it to explain (satisfies
  faculty demonstrability), never to prove (peer-review validity rests on
  detection/attribution results).

---

### ns-3 vs TCLink/tc as the channel (D18)

**Decision.** Keep `TCLink` + tc/netem as the channel. Do **not** replace it with
ns-3. ns-3 is a *companion tool*, never the channel.

**Rationale — ns-3 would make a timing study *less* real, not more.**

1. **ns-3 timing is too perfect.** It is a discrete-event simulator with virtual
   time: a specified 20 ms delay departs at exactly 20.000000 ms. Of the six noise
   sources that shape our IPDs, five are real in Mininet and absent/modeled in ns-3:

   | Noise source | Mininet + tc | ns-3 |
   |---|---|---|
   | `time.sleep()` granularity / kernel timer slack | **Real** | Absent |
   | OS scheduler jitter under load | **Real** | Absent |
   | TCP stack (Nagle, delayed-ACK, cwnd, retransmit) | **Real Linux stack** | Reimplemented model |
   | WireGuard encryption overhead | **Real crypto** | **No WireGuard model exists** |
   | Capture timestamp jitter | **Real (libpcap)** | Absent (perfect timestamps) |
   | Queuing / AQM | Real fq_codel/cake/TBF | Modeled (better instrumented) |

   Training on ns-3 means training on a channel cleaner than any real one, which
   *widens* the sim-to-real gap (cf. D9, D11).

2. **Circularity — fatal.** The claim is "the rhythm survives *real* WireGuard
   encapsulation and *real* stack behavior." ns-3 has no WireGuard model, no
   Flask/SQLite service, no real socket; we would have to reimplement the channel,
   the encryption, and the service as ns-3 application models — i.e. measure our
   own assumptions. Mininet runs the actual encoder, actual WireGuard, actual
   kernel TCP. That is the basis of the claim, not a detail.

3. **ns-3 + TapBridge is the legitimate hybrid, and it is still disqualified.**
   `TapBridge`/`FdNetDevice` can attach real namespaces/containers to a simulated
   network (keeping real app + stack + WireGuard while ns-3 supplies the channel).
   But it requires `RealtimeSimulatorImpl`, and when the simulator cannot keep pace
   with wall clock — under heavy NPC load, exactly the `high` condition — it
   **slips**, and that slip lands in the IPD measurements indistinguishably from a
   real network delay. Unacceptable silent measurement corruption for a study whose
   entire signal is inter-packet timing. tc/netem runs **in the kernel** on real
   packets at real kernel time; there is no scheduler to fall behind.

4. **It does not solve the hardware-constraint complaint.** Discrete-event
   simulation is CPU-bound too and often runs *slower* than real time at high
   packet rates. For wired ISP transit we gain none of ns-3's real strengths
   (wireless/LTE/5G/satellite channels, thousand-node topologies).

**Where ns-3 *is* worth using (companion roles only):**

1. **NetAnim visualization** (D17) — cleanest fit; faculty-facing artifact.
2. **Delay-model cross-check** — validate calibrated netem distributions against
   ns-3's detailed queue/channel models; two independent models agreeing
   strengthens D11.
3. **Scale extrapolation** — "does detection hold with 1000 background flows?" is
   infeasible in Mininet, feasible in ns-3 — **only** with the simulated-channel
   caveat stated and **never** mixed into the training corpus.

**Concession.** ns-3's queue-disc models are better instrumented than tc
(per-packet queue-occupancy tracing vs parsing `tc -s qdisc show`). If we
specifically want to *study* bufferbloat mechanics, that is a genuine advantage.

**Principle.** For a timing channel, realism comes from **real code at real kernel
time**, not from model sophistication. External validity comes from the real-WAN
cloud anchor (D2), which beats any simulator.

**Decision rule for tool choice.** Is the object of study the *protocol/channel
model* (→ simulator) or the *emergent timing behavior of real code* (→ emulator)?
Ours is the latter.

**Two clarifications on the "lower-layer simulation" argument.**

1. **ns-3's L1/L2 advantage is a *wireless* advantage.** For wired Ethernet
   transit, the lower layers contribute serialization delay plus rare bit errors —
   both one-line models. Lower-layer detail creates real timing chaos in 802.11
   (MAC contention, backoff, MAC-layer retransmission, fading, interference).
   **Conditional:** if we add a **WiFi last-mile** (plausible for
   `topology_remote_worker.yaml` — attacker on home WiFi), ns-3's 802.11 models are
   a genuine advantage Mininet cannot match. Revisit D18 only in that case.
2. **"Simulate more realistically" converges back to netem.** A simulator
   reproduces only the noise modeled into it. Making ns-3 realistic means injecting
   *measured distributions* — which is what netem already does, to **real packets
   from a real stack**. A simulator wins only when it models something we cannot
   measure or reproduce; for wired timing, that is not the case.
3. **ns-3 DCE is the honest "yes you can" — and it still fails.** DCE runs real
   binaries + the real Linux stack inside ns-3. Practically it is unmaintained,
   hard to build against modern ns-3, pinned to old kernels, and lacks WireGuard.
   Fundamentally it **intercepts time calls**, so `time.sleep(20ms)` becomes
   *virtual* and exact — it virtualizes away the timer slack and scheduler jitter
   that constitute realism here.

### Mininet's native jitter is real but host-shaped (D18a)

**Mininet already produces genuine unmodeled jitter:** CFS scheduler contention
between namespaces, softirq/`ksoftirqd` delay, veth + OVS datapath processing, CPU
contention under NPC load, `time.sleep()` timer slack, libpcap timestamping. The
design already relies on this — `CLAUDE.md`: "queuing delay, jitter, loss are
**emergent** from NPC load." ns-3 has none of it.

**Catch:** it is **host-artifact jitter, not WAN jitter** — wrong magnitude (µs to
low ms vs tens of ms), wrong shape (spiky/bounded vs heavy-tailed), wrong
correlation structure (no route changes, no multi-second congestion episodes).

**Therefore the channel is explicitly two-layered:** Mininet supplies real
*fine-grained* noise (real OS + real stack); calibrated netem (D11) imposes the
measured *coarse-grained* WAN distribution on top. Neither layer alone is correct.
ns-3 supplies the second layer only, with the first replaced by nothing.

**Action — measure the noise floor.** One session with no TC and no NPC → IPD
variance = Mininet's native jitter floor. Repeat at `high` NPC load for the
contention figure. Both numbers go in the paper's measurement error budget (D4
timestamp caveat).

### Tool survey (D18b)

| Tool | Gives | Verdict |
|---|---|---|
| **GNS3 / EVE-NG** | Runs **actual vendor images** (Cisco IOSv/IOS-XRv, Arista vEOS, Juniper vMX) | **Adopt for a validation variant** — supersedes datasheet approximation |
| **FABRIC / CloudLab / Emulab** | Free academic testbeds; real hardware, real WAN links between sites | **Adopt as proving ground** — may replace paid cloud VMs |
| **mahimahi** | Purpose-built record/replay of real paths (`delayshell`, `linkshell`) | Useful — off-the-shelf D11 trace calibration |
| **Containernet** | Mininet fork with Docker container hosts | Useful — aligns with D12 workload containers |
| **Kathará** | Container emulator, native FRR support | Optional — fits D16 demo variant |
| **CORE** | Namespace-based real-time emulator | Redundant with Mininet |

**Two upgrades to earlier decisions:**

- **Amends D7 (datasheet TC).** GNS3/EVE-NG running a real **IOS-XR/vEOS/vMX**
  image gives *actual* vendor queuing, buffer, and QoS behavior — no approximation
  error. Cost: a core + ~1 GB RAM per vendor VM, image licensing, no scale. So use
  it as a **realism-validation variant** ("does tc-approximated queuing match real
  IOS-XR queuing?"), **not** the bulk factory. Datasheet-calibrated tc remains the
  factory mechanism.
- **Amends D2 (cloud proving ground).** **FABRIC/CloudLab** are free for academic
  research, provide real hardware across real geographic links, and we own both
  endpoints so ground truth stays exact — strictly better than renting VMs, and
  "validated on the NSF FABRIC testbed" is stronger in a paper than "two rented
  VMs." Evaluate access before committing to paid cloud.

---

## Attribution / correlation (D19)

**Framing correction (D19a).** The model **cannot and must not** be described as
"reading the SHA rhythm." SHA-512 output is cryptographically pseudorandom;
predicting it means breaking SHA-512. Three distinct tasks:

| Task | Mechanism | Difficulty |
|---|---|---|
| **Detect** channel exists | Model sees IPDs are artificially **bimodal** (20/50 ms) vs naturally continuous/heavy-tailed | The research |
| **Decode** bits | Threshold at 26.5 ms (prereg `bit_classification_ms`) | Trivial, no ML |
| **Predict** next bit | Would require breaking SHA-512 | Impossible |

Paper language: *the model detects a discretized timing structure; it never reads
the message.* The SHA-512 keystream matters only because it makes the bit sequence
unpredictable, so the detector cannot cheat on a fixed pattern.

**Correlation is the *easier* task (D19b).** Detection asks "is this anomalous?"
(needs a model of normal; jitter smearing the modes attacks it directly).
Correlation asks "do these two sequences match?" — both vantages observe the *same
event*, so only the path segment **between capture points** adds noise. The covert
channel is **self-incriminating**: normal flow correlation is hard because ordinary
timing is low-entropy, but the attacker stamps their own traffic with a
maximum-entropy SHA-512 sequence.

**Use Hamming distance on decoded bits, not a learned correlator (D19c).** Decode
both vantages to bits, compare. Gives an **exact closed-form binomial p-value**
instead of an empirical ROC — forensic-grade evidence ("probability these flows are
unrelated < 1e-16") vastly stronger than "CNN outputs 0.97." Observed sessions
carry **402–460 packets** = 400+ bits of matching material:

| Bits | Agreement threshold | P(random match) |
|---|---|---|
| 100 | 70% | ~1e-5 |
| 100 | 89% (pilot integrity) | ~1e-16 |
| 400 | 70% | ~1e-16 |
| 400 | 89% | ~1e-55 |

**Emulation vs real — what changes:**

- **Clock sync: solved by construction.** We correlate **IPDs, not absolute
  timestamps**, so constant offset cancels. Drift at NTP quality (1e-6–1e-5) over a
  30 s session = 30–300 µs stretch against 20–50 ms bits. Negligible. Fine in both
  environments.
- **Inter-vantage jitter is bounded by the *segment*, not the path.** Correlation
  quality depends on noise between the two capture points, not total path length.
  **Sweep vantage separation** as an experimental variable.
- **Candidate-set size: not the threat.** At 1e-16 per-pair false match, even 1e6
  candidate flows gives ~1e-10 expected false matches.

**THE real risk — tunnel multiplexing (D19d).** WireGuard multiplexes everything
into one tunnel. If the attacker's tunnel carries **only** exfil, outer IPD ≈ inner
IPD and correlation is trivial (and unrealistically clean — reviewers will find
this). If it also carries browsing/updates, the outer IPD is an **interleaving of
several flows** and the rhythm is buried.

- **Verify:** does NPC traffic traverse the same tunnel as the exfil, or separate
  paths? If separate, the current testbed does not exercise this at all.
- **Required experiment:** multiplexing robustness — how many concurrent flows in
  one tunnel before correlation fails?
- **Mitigations:** WireGuard preserves inner packet size + constant overhead
  (size-based demultiplexing); sliding-window and spectral matching recover a
  periodic signal from a merged stream.
- This is the one place a **learned** correlator may beat Hamming distance — the
  natural justification for a deep model in the attribution stage.

**Prior art that must be engaged (D19e).** **DeepCorr** (Nasr, Bahramali,
Houmansadr — CCS 2018): CNN for Tor flow correlation from timing + size, beating
prior statistical methods. Cuts both ways — strong evidence that timing correlation
**works on real internet traffic at scale**, *and* prior art constraining novelty on
the mechanism. Also: Zhang & Paxson stepping-stone detection (USENIX Sec 2000);
flow watermarking (RAINBOW NDSS 2009, SWIRL NDSS 2011).

**Defensible novelty is therefore NOT "we correlate flows"** — it is correlating a
**covert timing channel** across an encrypted-transit / decrypted-endpoint vantage
pair for **exfiltration attribution** (a different threat model from Tor
deanonymization), with an **exact statistical bound** rather than a learned score.

---

## Project status snapshot (2026-08-04)

`research_stats/` is **gitignored** — it lives outside this working copy (also at
`~/Documents/research_stats`, `~/Desktop/isp-emulator/`, `~/SDN_ENGINE/isp-emulator/`).

| Component | Size | Status |
|---|---|---|
| Network emulator | 12,420 LOC, 12 test files | **Mature, working** — 147 PCAPNGs / 288 MB prove it runs |
| ML / analysis code | 10,266 LOC, 11 modules | **Written, never successfully run** |

### What is already implemented (verified 2026-08-04)

**The CNN is NOT missing — it is complete and faithful to the preregistration.**
`cnn_detector.py` (296 lines): `Conv1D(32,k=3)`→BN→MaxPool→`Conv1D(64,k=5)`→BN→
GAP→`Dense(64)`→`Dropout(0.5)`→sigmoid, L2 1e-4, Adam 1e-3, batch 16,
EarlyStopping on `val_auc` (patience 20), ReduceLROnPlateau, seed 42. Preprocessing
= clip[0,100] / 100, left-pad to 64, **IPD-only, no metadata**.

| Component | Location | Status |
|---|---|---|
| 1D-CNN detector | `cnn_detector.py` | implemented |
| LRT detector | `evaluation.py:482` | implemented |
| Matched filter | `evaluation.py:523` | implemented |
| DTW detector | `evaluation.py:556` | implemented |
| Shannon entropy | `ml_pipeline.py:446` | implemented |
| Random Forest | `hybrid_model.py:554` | implemented |
| LOCO harness | `evaluation.py:763` | implemented |
| Noise sensitivity | `evaluation.py:833` | implemented |
| Multi-vantage per-device IPD + SI | `forensic_path.py:92` | implemented — **attribution scaffolding** |
| Augmentation (window slice, local permutation) | `ml_pipeline.py:334–377` | implemented |
| sim2real | `sim2real_dataset.py` (696) | implemented |
| Degradation / robustness | `degradation_analysis.py` (958), `robustness_tests.py` (912) | implemented |

`PREREGISTRATION.txt` is also stronger than assumed: it contains a real **power
analysis** (n=20/group, d=1.0, power 0.80) and **preregistered fallbacks** — if H2
fails, report the best classical detector; if H1 fails, report a negative result.

### THE blocker: one command was never run

`capture_manager.py:209,216` — *"User may later call 'capture merge' and 'capture
parsetocsv'."* **CSV generation is a MANUAL step.** The 147 PCAPNGs were captured
and never parsed. Everything downstream is starved by that single omission:

```
147 PCAPNG on disk
      │  ✗ `capture parsetocsv` never run
      ▼
dataset/csv/  →  0 files
      ▼
extract_real_ipds.py  (reads dataset/csv/*.csv)  →  nothing to read
      ▼
eda.py  →  no eda_results.json   ← the file preregistration.yaml cites
      ▼
cnn_detector.py / evaluation.py  →  empty models/, graphs/, reports/
```

**`CLAUDE.md` is wrong** where it describes `capture stop` → mergecap →
feature_selector → csv_parser → schema upsert as automatic. Fix that doc.

### Sample-size gap (the real work)

`PREREGISTRATION.txt` §2 requires **160 sessions minimum** (80 watermarked = 4
intensities × 20, plus 80 baseline), **252 preferred**. Currently **13 registered**,
all `npc: medium`. Arithmetic, not mystery.

### Design bug to fix before training

`preprocess_sequences` keeps only the **last 64 IPDs per session** = one sample per
session, discarding ~85% of a 400–460-IPD capture. Its own docstring notes ~35,000
parameters needing 350+ samples — unreachable at one-per-session even at 252
sessions. **Window instead:** ~6 non-overlapping windows per session → 252 sessions
≈ 1,500 samples. The prereg's `split_level: session` ("never split windows from the
same session across train/test") already anticipates windowing.

### Integrity item

**`eda_results.json` does not exist**, yet `configs/preregistration.yaml` cites it as
the source of `bit_classification_ms: 26.5` and "88.9% observed in pilot (n=15)".
Regenerate it. If the value moves, document that honestly — releasing a
preregistration invites reviewers to ask for the pilot EDA behind the frozen
threshold.

### Effort estimate (one person; generation wall-clock overlaps)

| Step | Effort |
|---|---|
| Run `capture parsetocsv` over the 147 existing PCAPNGs | hours–2 days |
| `extract_real_ipds.py` → `eda.py`, regenerate `eda_results.json`, verify 26.5 ms | 1–3 days |
| Fix windowing in `preprocess_sequences` | 1–2 days |
| Generate prereg-required sessions (4 intensities × 20 × 2 labels) | ~1 wk, mostly unattended |
| Run `evaluation.py` full LOCO, debug | 2–5 days |
| **First complete preregistered result** | **2–4 weeks** |
| + single-vantage IPD fix, dedup, leakage audit, jitter floor | 1 wk |
| + P0 cross-encoding gate (encoder interface, 3 encodings) | 1–2 wk |
| + dual-vantage capture, Hamming/binomial attribution, multiplexing | 2–3 wk |
| + netem calibration (RIPE Atlas / M-Lab) | 1 wk |
| + real-path run (FABRIC/CloudLab, containerize) | 2–3 wk |
| + robustness / defense sweeps | 1–2 wk |
| + paper writing, figures, red-team | 4–6 wk |

| Target | Calendar |
|---|---|
| First complete preregistered result | **2–4 weeks** |
| Workshop / short paper (detection, testbed only) | **8–12 weeks** |
| Solid journal (TIFS, Computers & Security) | **16–22 weeks** |
| Top-tier (USENIX/CCS/PETS) | **24–34 weeks** + likely one rejection cycle |

Add 3–6 months review for a journal, 2–4 for a conference (outside our control).
The model-benchmark phase largely collapses because CNN/LRT/matched-filter/DTW/RF
already exist, and attribution has a head start in `forensic_path.py`.

**Critical path:** `parsetocsv` → `eda` → generate 160–252 sessions → `evaluation`.
Then the P0 cross-encoding gate, which determines whether the detector generalizes
or memorized the SHA-512 encoder.

**Top schedule risks:** (1) 10K LOC never executed end to end will contain bugs —
trust nothing until one small case runs clean; (2) the cross-encoding gate may force
a narrative pivot; (3) FABRIC/CloudLab access has approval lead time — **apply now**.

---

## Appendix A — Tool inventory and data-collection flow

Scope: network stack and data collection only (no training/evaluation tooling).

```
CONFIG        configs/*.yaml
                │  config_loader.py  (sole YAML reader at runtime)
                ▼
ADDRESSING    ip_allocator.py   pure logic, no Mininet calls → AllocationResult
                ▼
BUILD         Mininet → Linux netns (hosts) + veth pairs + OVS (L2 LAN segments)
                ▼
L3            sysctl ip_forward=1  +  iproute2 static routes     [FRR: demo only]
                ▼
IMPAIRMENT    tc:  netem (delay/jitter/loss/reorder)                ◄── REALISM KNOB
                 +  shaper (TBF | HTB+fq_codel | CAKE | pfifo)
                ▼
TUNNEL        WireGuard (in-kernel) hub-and-spoke
                ▼
SERVICES      Flask + SQLite inside the victim namespace
                ▼
SIGNAL        rhythm_computer.py: SHA-512 → 512 bits (cycles mod 512)
              app_watermarking.py or net_watermarking.py: clock_nanosleep(20|50 ms)
              + TOS 0x10 marking  ← ground-truth label
                ▼
LOAD          npc_manager: one daemon thread per host (http/dns/db/smtp/ftp/bulk)
                ▼
CAPTURE       tcpdump/libpcap, per interface → PCAPNG
                 transit vantage  = encrypted WireGuard outer
                 endpoint vantage = decrypted inner TCP
                ▼
ASSEMBLE      mergecap → feature_selector.py → csv_parser.py
                 (scapy + featureapi.py compute per-packet columns)
                ▼
REGISTRY      dataset/schema.json  +  dataset/network_profile.json
```

Driver: `auto_gen.py` uses **pexpect** to type commands into `ISPCli`, with `mn -c`
before and after each experiment to clear stale namespaces, veths, and OVS bridges.

### Build layer
| Tool | Job |
|---|---|
| Linux network namespaces | Isolation primitive. Each "host" = own TCP/IP stack, interfaces, routing table, ARP cache. Processes run for real |
| veth pairs | Virtual ethernet cable; packet in one end exits the other. Attaches namespaces to switches |
| Open vSwitch | L2 software switch, forwards by MAC. LAN segments |
| Mininet | Orchestrates namespaces + veths + switches from the topology description |
| Containernet *(proposed)* | Mininet fork with Docker-container hosts — enables the D12 portable workload |

### L3 layer
| Tool | Job |
|---|---|
| `net.ipv4.ip_forward=1` | Turns a host into a router: TTL decrement, per-hop MAC rewrite, egress queuing. This sysctl is what makes the ISP node a real L3 device (D3) |
| iproute2 (`ip route`) | Static routes. Deterministic — the factory default |
| FRR *(demo only)* | Real OSPF/IS-IS/BGP daemons. Excluded from the factory: reconvergence is unreproducible (D6) |

### Impairment layer (where network realism lives)
| Tool | Job | Models |
|---|---|---|
| tc | Kernel QoS subsystem; umbrella for all below | — |
| netem | Delay, jitter, loss, reordering, duplication, corruption | The WAN path |
| TBF | Token-bucket rate limiter with burst | Simple bandwidth cap |
| HTB | Classful hierarchical shaper | Tiered/shared links |
| pfifo (large `limit`) | Dumb deep FIFO | **Bufferbloat** — old CPE, oversized buffer |
| fq_codel | Fair queuing + CoDel AQM | Modern ISP/CPE fighting bufferbloat |
| CAKE | Shaper + AQM + per-flow fairness | Contemporary home router |
| iproute2 `netem/maketable` | Converts **real measured delay samples** → netem distribution table | The measurement→emulation bridge (D11) |

### Tunnel, signal, load
| Tool | Job |
|---|---|
| WireGuard (in-kernel) | Encrypts + forwards immediately; no buffering/reordering; ~constant sub-ms overhead. Why the rhythm survives (D10) |
| Flask + SQLite | Victim service — real HTTP server, real socket, real queries |
| `rhythm_computer.py` | `WatermarkBitstream`: SHA-512(secret_key) → 512 bits, cycles mod 512 |
| `app_watermarking.py` | App-layer engine: `clock_nanosleep` between chunk writes in HTTP handler |
| `net_watermarking.py` | Net-layer engine: NFQUEUE delays outgoing TCP segment before kernel sends it |
| `timing_protocol.type` | YAML key: `net-flow` / `app-flow` / `auto` selects engine at DB startup |
| `clock_nanosleep` | Actual IPD mechanism. ±50–200 µs accuracy via librt ABSTIME |
| TOS byte 0x10 | Ground-truth label in the IP header. Offline labeling only; never a model input |
| `npc_manager` / `behaviors.py` | Background load, one daemon thread per host. Source of *emergent* queuing and contention |

### Capture layer
| Tool | Job |
|---|---|
| libpcap / tcpdump | Taps at L2, whole frames, **per interface**. Software timestamps = measurement noise floor |
| PCAPNG | Capture format (SHB/IDB/EPB); sniffers write EPBs straight to disk |
| mergecap | Merges per-interface captures by timestamp. **Duplicates packets seen at two interfaces** — hence single-vantage IPD extraction (D4) |
| scapy | Packet parsing in `featureapi.py` (TOS, ports, lengths, timestamps) |
| `pcapng_reader.py` | Dependency-light pure-Python parser |
| `feature_selector.py` → `csv_parser.py` | Subprocess chain: PCAPNG → JSON → CSV |
| `schema.json` | Session registry — one record per capture, ground-truth rhythm + conditions |

### External realism sources
| Source | Job |
|---|---|
| RIPE Atlas | Global measurement network + API — real RTT / delay-variation samples |
| M-Lab | Public NDT measurements at scale — real delay/throughput distributions |
| CAIDA | Traces and topology data |
| mahimahi | Purpose-built record/replay of real paths (`delayshell`, `linkshell`) |
| FABRIC / CloudLab | Free academic testbeds, real hardware + real inter-site links (proving ground, D18b) |
| GNS3 / EVE-NG | Actual vendor images (IOS-XRv, vEOS, vMX) for true vendor queuing (validation variant, D18b) |

### Realism ledger — what is actually real

| Property | Status | Source |
|---|---|---|
| TCP stack (cwnd, Nagle, delayed ACK, retransmit) | **Real** | Linux kernel, per namespace |
| Application code | **Real** | Python / Flask / SQLite |
| Timer slack on `sleep()` | **Real** | ~1–2 ms, measured |
| Scheduler / softirq jitter | **Real** | CFS contention, emergent under NPC load |
| Encryption overhead | **Real** | WireGuard kernel module |
| L2 switching | **Real** | OVS datapath |
| IP forwarding, TTL, MAC rewrite | **Real** (once ISP = router-host) | Kernel |
| Capture timestamping | **Real** (with software-timestamp jitter) | libpcap |
| Propagation delay | *Modeled* | netem |
| Jitter distribution | *Modeled* — **current weak spot** | netem; needs `maketable` calibration |
| Queuing / bufferbloat | *Modeled* | qdisc choice |
| Bandwidth limit | *Modeled* | TBF / HTB |
| Loss, reordering | *Modeled* | netem |
| Route changes | **Absent** | Schedule as `tc change` steps |
| Middlebox reshaping | **Absent** | Only the real-path run catches this |
| Vendor-specific queuing | **Absent** | GNS3/EVE-NG variant would supply |
| Internet-scale cross traffic | **Absent** | NPC load is local only |
| Hardware (PTP) timestamping | **Absent** | Needs real NIC support |

**Reading of the ledger.** Everything touching **code execution and packet
handling is genuinely real** — real stack, real crypto, real timers, real capture.
Everything describing the **path is modeled**. Hence: the path model must be
calibrated from measurements rather than invented (D11), and one real-path run is
required to cover the three "absent" rows no model reaches (D2/D18b).

---

## Open items / next steps

1. **Build order:** (a) ISP switch → router-host; (b) datasheet TC params +
   qdisc-regime sampler; (c) encoder-strategy interface + cross-encoding; (d)
   containerize the four workload services; (e) 2–3 cloud VMs for the held-out
   real-WAN set; (f) leakage audit in CI.
2. **Week-8 gate:** cross-encoding generalization = go/no-go on the novelty claim.
3. **Verify now:** does `capture_manager.py` extract IPDs from the merged file (risky)
   or per-vantage, and does it drop TCP retransmissions before windowing? (D4)
6. **Measure the Mininet jitter floor** (D18a): IPD variance with no TC / no NPC,
   and at `high` NPC load. Feeds the measurement error budget.
7. **Check FABRIC/CloudLab academic access** before committing to paid cloud (D18b).
8. **Revisit D18 only if** a WiFi last-mile enters the threat model — ns-3's 802.11
   MAC modeling would then be a genuine, hard-to-replace advantage.
9. **Verify tunnel multiplexing** (D19d): does NPC traffic share the attacker's
   WireGuard tunnel, or take separate paths? If separate, correlation results are
   unrealistically clean and the multiplexing-robustness experiment is mandatory.
10. **Dataset coverage gap (blocking):** all 13 recorded sessions are `npc: medium`,
    one topology, one nonce, `run: 1`. The **preregistered primary evaluation
    (LOCO_NPC: train {none,low,medium} / test {high}) is currently not runnable.**
    Batch the NPC-intensity sweep together with the P0 cross-encoding runs.
11. **Anomaly to confirm:** two VPN-off (20,50) sessions ran ~5 s vs 15–30 s for
    comparable sessions. Packet *rates* are normal, so it is early termination, not
    a timing fault — confirm it is intentional.
4. **Do not touch** `configs/preregistration.yaml` (frozen 2026-07-18).
5. **Venues:** first target PETS/PoPETs, ACSAC, IEEE TIFS, or Computers & Security;
   reach USENIX/CCS gated on attribution + real-WAN strength.
