"""
hardware/tc_generator.py

Generates per-interface TBF+netem tc commands from traffic_control config.

Architecture:
  TBF  → rate limit (bandwidth constraint)
  netem → physical propagation delay only

All queuing delay, jitter, and packet loss emerge naturally from NPC traffic
filling the TBF queue. No synthetic impairments are injected.

Command structure per interface:
  tc qdisc add dev {iface} root handle 1: tbf rate Xmbit burst Yb latency Zms
  tc qdisc add dev {iface} parent 1:1 handle 10: netem delay Ams Bms distribution D

Usage:
    profile = generate(tc_config, device_classes, alias_map, seed=42)
    profile.commands["r1-eth0"]  → "tbf_cmd && netem_cmd"
"""

import json
import os
import random
from dataclasses import dataclass
from typing import Dict, Optional

_THRESHOLDS_PATH = os.path.join(os.path.dirname(__file__), "tc_thresholds.json")

with open(_THRESHOLDS_PATH, "r", encoding="utf-8") as _fh:
    _T = json.load(_fh)


@dataclass
class GeneratedProfile:
    commands: Dict[str, str]  # iface → "tbf_cmd && netem_cmd"


def _lerp(bounds, fraction: float) -> float:
    return bounds[0] + fraction * (bounds[1] - bounds[0])


def _build_tc_command(
    iface: str,
    device_class: str,
    area: str,
    medium: str,
    rng: random.Random,
) -> str:
    mtu = _T["mtu_bytes"]

    # ── Bandwidth — random within physical bounds for this area ───────────
    bw_mbps = round(_lerp(_T["link_capacity_mbps"][area], rng.random()), 2)
    bw_mbps = max(1.0, bw_mbps)

    # ── Propagation delay — physics only ─────────────────────────────────
    dist_km = _lerp(_T["distance_km"][area], rng.random())
    prop_ms = round((dist_km / _T["medium_speed_km_per_s"][medium]) * 1000, 4)

    # ── Processing delay — device hardware ───────────────────────────────
    proc_ms = round(_lerp(_T["processing_ms"][device_class], rng.random()), 4)

    # ── Infrastructure overhead — optical/metro equipment ─────────────────
    infra_ms = round(_lerp(_T["infrastructure_overhead_ms"][area], rng.random()), 4)

    # ── Base delay — physical only, no queue contribution ─────────────────
    delay_ms = round(prop_ms + proc_ms + infra_ms, 4)

    # ── Jitter — small physical equipment variance (2–10% of infra_ms) ────
    # Infrastructure delay is near-constant hardware latency; only a small
    # fraction varies packet-to-packet (thermal, clock, buffering variance).
    jitter_ms = round(max(0.01, infra_ms * rng.uniform(0.02, 0.1)), 4)

    # ── Buffer depth — TBF queue capacity before tail-drop ───────────────
    # limit = max(BDP, area_sample): never undersize below the bandwidth-
    # delay product so TCP flows can fill their flight window. buffer_packets
    # acts as a floor for slow links where BDP is small; BDP dominates on
    # fast high-delay links. Both are physically meaningful bounds.
    rtt_ms = delay_ms * 2
    bdp = int((bw_mbps * 1e6 / 8) * (rtt_ms / 1000) / mtu)
    ql = int(_lerp(_T["buffer_packets"][area], rng.random()))
    limit = max(20, max(bdp, ql))

    dist_type = _T["distribution"][device_class]

    # ── TBF parameters ────────────────────────────────────────────────────
    # Burst: choose large enough for token accumulation on typical kernels
    # (kernel requires roughly rate_bytes_per_second / kernel_hz as minimum).
    kernel_hz = 250
    burst_bytes = max(mtu, int(bw_mbps * 1e6 / 8 / kernel_hz))
    # Latency: time to drain the queue at full rate — no global floor.
    # Fast LAN links get a short latency (tight buffer, quick drop).
    # Slow WAN links get a long latency (deep buffer, tolerates bursts).
    tbf_latency_ms = max(0.1, round((limit * mtu * 8) / (bw_mbps * 1e6) * 1000, 3))

    tbf_cmd = (
        f"tc qdisc add dev {iface} root handle 1: tbf "
        f"rate {bw_mbps}mbit burst {burst_bytes}b latency {tbf_latency_ms}ms"
    )

    # ── netem — physical delay only; queuing delay/jitter/loss emerge from
    #    NPC traffic filling the TBF queue (requires multiple concurrent
    #    NPC flows — single TCP stream produces minimal jitter) ───────────
    netem_cmd = (
        f"tc qdisc add dev {iface} parent 1:1 handle 10: netem "
        f"delay {delay_ms}ms {jitter_ms}ms distribution {dist_type}"
    )

    return f"{tbf_cmd} && {netem_cmd}"


def generate(
    tc_config,
    device_classes: Dict[str, str],
    alias_map: Optional[Dict[str, str]] = None,
    seed: Optional[int] = None,
) -> GeneratedProfile:
    alias_map = alias_map or {}
    rng = random.Random(seed)
    commands = {}
    for iface, iface_cfg in tc_config.interfaces.items():
        alias = iface.rsplit("-eth", 1)[0]
        node_name = alias_map.get(alias, alias)
        device_class = device_classes.get(node_name)
        if not device_class:
            continue
        medium = tc_config.get_medium_for_iface(iface)
        commands[iface] = _build_tc_command(
            iface, device_class, iface_cfg.area, medium, rng
        )
    return GeneratedProfile(commands=commands)
