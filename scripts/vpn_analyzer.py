#!/usr/bin/env python3
"""VPN routing analyzer — compare VPN vs direct path from captured PCAPNG.

Usage:
    python3 scripts/vpn_analyzer.py --all          # all sessions in schema.json
    python3 scripts/vpn_analyzer.py --session <id> # single session

What it shows per session:
    - Routing mode (VPN tunnel detected / direct path)
    - WireGuard tunnel endpoints (which IPs exchange UDP 51820)
    - Effective hop count (TTL-based estimate from attacker→DB response)
    - Packet overhead from encapsulation
    - Cross-session comparison: watermark survival vpn=on vs vpn=off

Log written every run (append):
    dataset/vpn_routing_log.txt   — human-readable
    dataset/vpn_routing_log.jsonl — raw data for re-analysis

How routing is inferred from PCAPNG (no traceroute needed):
    VPN detected:
        UDP dst/src port 51820 between any two IPs → WireGuard data tunnel active
        First 4 bytes of WireGuard payload: type=1 handshake, type=4 data
    Direct path:
        No UDP 51820 packets → traffic flows without WireGuard encapsulation
    Hop estimate:
        TTL of first DB→attacker TCP SYN-ACK packet
        Linux default TTL = 64; each router decrements by 1
        hops = 64 - observed_TTL   (or 128 - TTL for Windows, 255 - TTL for some UNIX)
"""

import argparse
import datetime
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from scapy.all import rdpcap, IP, TCP, UDP, Raw
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

_ROOT          = Path(__file__).resolve().parent.parent
_SCHEMA_PATH   = _ROOT / "dataset" / "schema.json"
_WM_JSONL      = _ROOT / "dataset" / "watermark_log.jsonl"
_LOG_TXT       = _ROOT / "dataset" / "vpn_routing_log.txt"
_LOG_JSONL     = _ROOT / "dataset" / "vpn_routing_log.jsonl"

_WG_PORT       = 51820   # WireGuard default UDP port
_WG_TYPE_INIT  = 1       # handshake initiator
_WG_TYPE_RESP  = 2       # handshake response
_WG_TYPE_DATA  = 4       # transport data


# ── WireGuard detection ───────────────────────────────────────────────────────

def _is_wireguard(pkt) -> bool:
    """True if packet looks like a WireGuard UDP message."""
    if not pkt.haslayer(UDP):
        return False
    if pkt[UDP].dport != _WG_PORT and pkt[UDP].sport != _WG_PORT:
        return False
    if not pkt.haslayer(Raw):
        return True   # correct port, no payload — still WireGuard keepalive
    payload = pkt[Raw].load
    if len(payload) < 4:
        return True
    msg_type = int.from_bytes(payload[:4], "little") & 0xFF
    return msg_type in (_WG_TYPE_INIT, _WG_TYPE_RESP, _WG_TYPE_DATA, 3)


def _wg_msg_type_name(pkt) -> str:
    if not pkt.haslayer(Raw) or len(pkt[Raw].load) < 4:
        return "keepalive"
    t = int.from_bytes(pkt[Raw].load[:4], "little") & 0xFF
    return {1: "handshake_init", 2: "handshake_resp",
            3: "cookie_reply",   4: "data"}.get(t, f"type_{t}")


# ── hop count estimate from TTL ───────────────────────────────────────────────

def _estimate_hops(observed_ttl: int) -> int:
    """Estimate hop count from observed TTL using common OS defaults."""
    for default in (64, 128, 255):
        if observed_ttl <= default:
            return default - observed_ttl
    return -1


# ── per-session routing analysis ──────────────────────────────────────────────

def analyze_routing(
    session_id:  str,
    pcap_path:   str,
    attacker_ip: str,
    victim_ip:   str,
    victim_port: int,
    vpn_mode:    str,    # "on" or "off" from experiment
) -> dict:
    """Extract routing evidence from pcapng for one session."""

    pkts = rdpcap(pcap_path)

    wg_pairs     = defaultdict(int)   # (src,dst) → packet count
    wg_types     = defaultdict(int)   # type_name → count
    direct_count = 0                  # TCP packets attacker→DB without WireGuard
    hop_ttls     = []                 # TTLs from DB→attacker SYN-ACK or responses
    overhead_bytes = []               # WireGuard payload sizes vs estimated inner

    for pkt in pkts:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]

        # ── WireGuard packets ─────────────────────────────────────────────────
        if _is_wireguard(pkt):
            pair = (ip.src, ip.dst)
            wg_pairs[pair] += 1
            wg_types[_wg_msg_type_name(pkt)] += 1
            if pkt.haslayer(Raw):
                overhead_bytes.append(len(pkt[Raw].load))
            continue

        # ── direct TCP attacker→DB ────────────────────────────────────────────
        if (pkt.haslayer(TCP) and ip.src == attacker_ip
                and ip.dst == victim_ip and pkt[TCP].dport == victim_port):
            direct_count += 1

        # ── TTL from DB responses to attacker ─────────────────────────────────
        if (pkt.haslayer(TCP) and ip.src == victim_ip
                and ip.dst == attacker_ip and pkt[TCP].sport == victim_port):
            hop_ttls.append(ip.ttl)

    # Tunnel endpoints — unique (src,dst) pairs on WireGuard port
    tunnel_endpoints = [
        {"src": s, "dst": d, "packets": c}
        for (s, d), c in sorted(wg_pairs.items(), key=lambda x: -x[1])
    ]
    wg_detected = len(wg_pairs) > 0

    # Hop estimate from median TTL
    hop_count = None
    if hop_ttls:
        median_ttl = sorted(hop_ttls)[len(hop_ttls) // 2]
        hop_count  = _estimate_hops(median_ttl)

    # Routing determination
    if wg_detected:
        if direct_count > 0:
            routing = "VPN_TUNNEL_WITH_DIRECT_LEAK"   # unexpected — flag it
        else:
            routing = "VPN_TUNNEL"
    else:
        routing = "DIRECT"

    expected_routing = "VPN_TUNNEL" if vpn_mode == "on" else "DIRECT"
    routing_ok = routing.startswith(expected_routing)

    avg_wg_payload = (sum(overhead_bytes) / len(overhead_bytes)
                      if overhead_bytes else None)

    return {
        "session_id":        session_id,
        "pcap_path":         pcap_path,
        "attacker_ip":       attacker_ip,
        "victim_ip":         victim_ip,
        "victim_port":       victim_port,
        "vpn_mode":          vpn_mode,
        "routing_detected":  routing,
        "routing_expected":  expected_routing,
        "routing_ok":        routing_ok,
        "wg_detected":       wg_detected,
        "tunnel_endpoints":  tunnel_endpoints,
        "wg_message_types":  dict(wg_types),
        "direct_tcp_count":  direct_count,
        "hop_count":         hop_count,
        "hop_ttls_sample":   sorted(set(hop_ttls))[:5],
        "wg_total_packets":  sum(wg_pairs.values()),
        "avg_wg_payload_b":  round(avg_wg_payload, 1) if avg_wg_payload else None,
    }


# ── load watermark survival for a session (from watermark_log.jsonl) ──────────

def _load_wm_survival() -> dict:
    """Return {session_id: survival_pct} from watermark_log.jsonl."""
    if not _WM_JSONL.exists():
        return {}
    result = {}
    with open(_WM_JSONL, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                sid = rec.get("session_id")
                if sid:
                    result[sid] = rec.get("survival_pct")
            except Exception:
                continue
    return result


# ── cross-session VPN comparison ──────────────────────────────────────────────

def _cross_compare(results: list, wm_survival: dict) -> dict:
    """Compare watermark survival vpn=on vs vpn=off."""
    groups = defaultdict(list)
    for r in results:
        groups[r["vpn_mode"]].append(r["session_id"])

    def avg_survival(sids):
        vals = [wm_survival[s] for s in sids if wm_survival.get(s) is not None]
        return round(sum(vals) / len(vals), 2) if vals else None

    return {
        "vpn_on_sessions":       groups.get("on",  []),
        "vpn_off_sessions":      groups.get("off", []),
        "avg_survival_vpn_on":   avg_survival(groups.get("on",  [])),
        "avg_survival_vpn_off":  avg_survival(groups.get("off", [])),
        "routing_mismatches":    [
            r["session_id"] for r in results if not r["routing_ok"]
        ],
    }


# ── logging ───────────────────────────────────────────────────────────────────

def _log_session(r: dict, wm_survival: dict, run_ts: str) -> None:
    sep = "─" * 70
    survival = wm_survival.get(r["session_id"])
    survival_str = f"{survival:.1f}%" if survival is not None else "not analyzed"

    routing_flag = ""
    if not r["routing_ok"]:
        routing_flag = (f"  [!!] MISMATCH — expected {r['routing_expected']} "
                        f"but detected {r['routing_detected']}")
    elif r["routing_detected"] == "VPN_TUNNEL_WITH_DIRECT_LEAK":
        routing_flag = "  [!!] DIRECT LEAK alongside VPN tunnel — traffic bypass detected"

    lines = [
        f"\n{sep}",
        f"  Run            : {run_ts}",
        f"  Session        : {r['session_id']}",
        f"  Attacker       : {r['attacker_ip']}  →  {r['victim_ip']}:{r['victim_port']}",
        f"  VPN config     : {r['vpn_mode']}",
        f"  Routing        : {r['routing_detected']}",
        f"  Routing OK     : {'yes' if r['routing_ok'] else 'NO — see flag below'}",
    ]
    if routing_flag:
        lines.append(routing_flag)

    if r["wg_detected"]:
        lines.append(f"  WireGuard      : {r['wg_total_packets']} packets")
        lines.append(f"  WG msg types   : {r['wg_message_types']}")
        lines.append(f"  Tunnel pairs   :")
        for ep in r["tunnel_endpoints"][:5]:
            lines.append(f"    {ep['src']:>18} → {ep['dst']:<18}  ({ep['packets']} pkts)")
        if r["avg_wg_payload_b"]:
            lines.append(f"  Avg WG payload : {r['avg_wg_payload_b']} bytes")
    else:
        lines.append(f"  WireGuard      : not detected — direct routing")
        lines.append(f"  Direct TCP     : {r['direct_tcp_count']} attacker→DB packets")

    if r["hop_count"] is not None:
        lines.append(f"  Est. hop count : {r['hop_count']}  (from TTL={r['hop_ttls_sample']})")
    lines.append(f"  Watermark surv : {survival_str}")
    lines.append(sep)

    block = "\n".join(lines) + "\n"
    print(block)
    with open(_LOG_TXT, "a", encoding="utf-8") as fh:
        fh.write(block)

    raw = dict(r)
    raw["run_timestamp"] = run_ts
    raw["watermark_survival_pct"] = survival
    with open(_LOG_JSONL, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(raw) + "\n")


def _log_comparison(cmp: dict, run_ts: str) -> None:
    lines = [
        f"\n{'═'*70}",
        f"  VPN ROUTING COMPARISON  — {run_ts}",
        f"{'═'*70}",
        f"  VPN on  sessions : {len(cmp['vpn_on_sessions'])}  "
        f"avg watermark survival: {cmp['avg_survival_vpn_on']}%",
        f"  VPN off sessions : {len(cmp['vpn_off_sessions'])}  "
        f"avg watermark survival: {cmp['avg_survival_vpn_off']}%",
    ]

    on_s  = cmp["avg_survival_vpn_on"]
    off_s = cmp["avg_survival_vpn_off"]
    if on_s is not None and off_s is not None:
        diff = round(on_s - off_s, 2)
        if abs(diff) < 3:
            lines.append(f"  Difference       : {diff:+.1f}%  → VPN has negligible effect on watermark")
        elif diff < 0:
            lines.append(f"  Difference       : {diff:+.1f}%  → VPN reduces survival "
                         f"(WireGuard jitter / extra hop)")
        else:
            lines.append(f"  Difference       : {diff:+.1f}%  → VPN improves survival "
                         f"(unusual — check capture setup)")

    if cmp["routing_mismatches"]:
        lines.append(f"  Routing mismatches: {cmp['routing_mismatches']}")
        lines.append("    → VPN configured but not detected, or vice versa")
        lines.append("    → Troubleshoot: 'vpn on' CLI command may have failed — check auto_gen log")
    else:
        lines.append("  Routing mismatches: none — VPN on/off correctly reflected in captures")

    lines.append(f"{'═'*70}\n")
    block = "\n".join(lines) + "\n"
    print(block)
    with open(_LOG_TXT, "a", encoding="utf-8") as fh:
        fh.write(block)


# ── schema helpers ────────────────────────────────────────────────────────────

def _load_schema() -> list:
    if not _SCHEMA_PATH.exists():
        print(f"[ERROR] schema.json not found: {_SCHEMA_PATH}")
        sys.exit(1)
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _params_from_record(rec: dict) -> dict:
    tp          = rec.get("timing_protocol") or {}
    experiment  = rec.get("experiment")      or {}
    pcap_path   = rec.get("pcapng")
    attacker_ip = tp.get("attacker_ip") or tp.get("src") or ""
    victim_ip   = tp.get("victim_ip")   or ""
    victim_port = int(tp.get("victim_port") or 9090)
    vpn_mode    = experiment.get("vpn", "off")
    return {
        "pcap_path":   pcap_path,
        "attacker_ip": attacker_ip,
        "victim_ip":   victim_ip,
        "victim_port": victim_port,
        "vpn_mode":    vpn_mode,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="VPN routing analyzer")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--all",     action="store_true",
                      help="Analyze all sessions in dataset/schema.json")
    mode.add_argument("--session", default=None,
                      help="Single session ID from schema.json")
    args = parser.parse_args()

    if not _SCAPY_OK:
        print("[ERROR] scapy not installed.  pip install scapy")
        sys.exit(1)

    run_ts      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    wm_survival = _load_wm_survival()
    _LOG_TXT.parent.mkdir(parents=True, exist_ok=True)

    if args.all:
        records = _load_schema()
    else:
        records = [next((r for r in _load_schema()
                         if r.get("session_id") == args.session), None)]
        if not records[0]:
            print(f"[ERROR] session {args.session!r} not in schema.json")
            sys.exit(1)

    results = []
    for rec in records:
        sid = rec.get("session_id", "unknown")
        p   = _params_from_record(rec)

        if not p["pcap_path"] or not Path(p["pcap_path"]).exists():
            print(f"\n  [SKIP] {sid} — pcapng not found: {p['pcap_path']}")
            continue
        if not p["attacker_ip"] or not p["victim_ip"]:
            print(f"\n  [SKIP] {sid} — missing attacker/victim IP in schema.json")
            continue

        result = analyze_routing(
            session_id  = sid,
            pcap_path   = p["pcap_path"],
            attacker_ip = p["attacker_ip"],
            victim_ip   = p["victim_ip"],
            victim_port = p["victim_port"],
            vpn_mode    = p["vpn_mode"],
        )
        _log_session(result, wm_survival, run_ts)
        results.append(result)

    if len(results) > 1:
        cmp = _cross_compare(results, wm_survival)
        _log_comparison(cmp, run_ts)

    if results:
        print(f"Logs written:")
        print(f"  {_LOG_TXT}")
        print(f"  {_LOG_JSONL}\n")


if __name__ == "__main__":
    main()
