#!/usr/bin/env python3
"""Watermark survival analysis — strict IPD vs timing-protocol rhythm.

Usage:
    # Analyze ALL sessions in schema.json (recommended):
    python3 scripts/analyze_watermark.py --all

    # Single session by ID:
    python3 scripts/analyze_watermark.py --session 20240820_143022_000000

    # Manual override (raw pcap):
    python3 scripts/analyze_watermark.py --pcap dataset/pcapng/<id>.pcapng \\
        --config configs/topology.yaml

Logs written every run:
    dataset/watermark_log.txt   — human-readable, append mode
    dataset/watermark_log.jsonl — raw IPDs + full data, append mode (re-analysis)

Re-analysis without re-running experiments:
    python3 -c "
    import json, scripts.analyze_watermark as a
    for line in open('dataset/watermark_log.jsonl'):
        rec = json.loads(line)
        ipds = rec['raw_ipds_ms']
        # apply new strategy to rec['raw_ipds_ms'] + rec['expected_bits']
    "

Evaluation methodology (strict):
    1. Extract TCP data segments: DB→attacker, src_port=DB_port, payload > 0 bytes.
    2. IPD_i = t_{i+1} - t_i between consecutive data packets (ms).
    3. Classify each IPD:
         SHORT     if |IPD - short_ms| ≤ tight_tol  AND  IPD < midpoint
         LONG      if |IPD - long_ms|  ≤ tight_tol  AND  IPD > midpoint
         AMBIGUOUS otherwise — erasure (excluded from verdict)
       tight_tol = (long_ms - short_ms) / 4  — no zone overlap by construction
    4. Expected bitstream: SHA-512(secret_key) cycled at 512 bits.
    5. Survival = correct / clear  (ambiguous excluded).
    6. Verdict thresholds:
         ≥ 75%  DETECTED      — 5-σ above random baseline (p<0.001 for ≥20 bits)
         50–74% UNCERTAIN     — above random but below significance threshold
         ≤ 50%  NOT_DETECTED  — at or below random
    7. Expected outcome by combo:
         exfil=on  → DETECTED      (True Positive)
         exfil=off → NOT_DETECTED  (True Negative)
       Mismatch → False Positive or False Negative — see log for root cause.
"""

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from scapy.all import rdpcap, IP, TCP, Raw
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

from config_loader import load_config

# ── paths ─────────────────────────────────────────────────────────────────────
_ROOT        = Path(__file__).resolve().parent.parent
_SCHEMA_PATH = _ROOT / "dataset" / "schema.json"
_LOG_TXT     = _ROOT / "dataset" / "watermark_log.txt"
_LOG_JSONL   = _ROOT / "dataset" / "watermark_log.jsonl"


# ── SHA-512 bitstream ─────────────────────────────────────────────────────────

def _derive_bits(secret_key: str) -> list:
    digest = hashlib.sha512(secret_key.encode()).digest()
    bits = []
    for byte in digest:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _expected_bit(bits: list, index: int) -> int:
    return bits[index % len(bits)]


# ── PCAPNG extraction ─────────────────────────────────────────────────────────

def _extract_timestamps(pcap_path: str, attacker_ip: str,
                        victim_ip: str, victim_port: int) -> list:
    """Sorted list of packet timestamps (s) for DB→attacker TCP response segments.

    Watermark delays are injected by the /backup HTTP handler between 512B chunk
    writes (application layer), so IPDs are measured on the response direction
    (victim_ip → attacker_ip).
    """
    pkts = rdpcap(pcap_path)
    result = []
    for pkt in pkts:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        ip_l, tcp_l = pkt[IP], pkt[TCP]
        if ip_l.src != victim_ip or ip_l.dst != attacker_ip:
            continue
        if tcp_l.sport != victim_port:
            continue
        if not pkt.haslayer(Raw) or len(pkt[Raw].load) == 0:
            continue
        result.append(float(pkt.time))
    result.sort()
    return result


# ── IPD classification ────────────────────────────────────────────────────────

SHORT     = "SHORT"
LONG      = "LONG"
AMBIGUOUS = "AMBIGUOUS"


def _classify(ipd_ms: float, short_ms: float, long_ms: float, tight_tol: float) -> str:
    mid = (short_ms + long_ms) / 2
    if abs(ipd_ms - short_ms) <= tight_tol and ipd_ms < mid:
        return SHORT
    if abs(ipd_ms - long_ms) <= tight_tol and ipd_ms > mid:
        return LONG
    return AMBIGUOUS


# ── core analysis ─────────────────────────────────────────────────────────────

def analyze(
    session_id:  str,
    pcap_path:   str,
    attacker_ip: str,
    victim_ip:   str,
    victim_port: int,
    secret_key:  str,
    short_ms:    float,
    long_ms:     float,
    expected_exfil: str = "on",   # "on" or "off" — expected outcome from combo
) -> dict:
    """Run strict watermark analysis. Returns full result dict including raw IPDs."""

    tight_tol = (long_ms - short_ms) / 4
    midpoint  = (short_ms + long_ms) / 2

    # ── extract IPDs ──────────────────────────────────────────────────────────
    timestamps = _extract_timestamps(pcap_path, attacker_ip, victim_ip, victim_port)
    if len(timestamps) < 2:
        return _result_insufficient(session_id, pcap_path, attacker_ip, victim_ip,
                                    victim_port, secret_key, short_ms, long_ms,
                                    tight_tol, expected_exfil, len(timestamps))

    ipds_ms       = [(timestamps[i+1] - timestamps[i]) * 1000
                     for i in range(len(timestamps) - 1)]
    bits          = _derive_bits(secret_key)
    expected_bits = [_expected_bit(bits, i) for i in range(len(ipds_ms))]

    # ── classify ──────────────────────────────────────────────────────────────
    rows = []
    correct = wrong = ambig = 0
    for i, ipd in enumerate(ipds_ms):
        cls     = _classify(ipd, short_ms, long_ms, tight_tol)
        exp_bit = expected_bits[i]
        exp_cls = SHORT if exp_bit == 0 else LONG

        if cls == AMBIGUOUS:
            ambig  += 1
            outcome = "ERASURE"
        elif cls == exp_cls:
            correct += 1
            outcome  = "OK"
        else:
            wrong  += 1
            outcome = "WRONG"

        rows.append({
            "index":   i,
            "ipd_ms":  round(ipd, 4),
            "class":   cls,
            "exp_bit": exp_bit,
            "outcome": outcome,
        })

    clear        = correct + wrong
    survival_pct = (correct / clear * 100) if clear > 0 else None
    ber          = (wrong   / clear)        if clear > 0 else None

    if survival_pct is None:
        verdict = "INDETERMINATE"
    elif survival_pct >= 75.0:
        verdict = "DETECTED"
    elif survival_pct > 50.0:
        verdict = "UNCERTAIN"
    else:
        verdict = "NOT_DETECTED"

    # ── outcome classification vs expected ────────────────────────────────────
    if expected_exfil == "on":
        if verdict == "DETECTED":
            classification = "TRUE_POSITIVE"
        elif verdict == "NOT_DETECTED":
            classification = "FALSE_NEGATIVE"
        else:
            classification = "UNCERTAIN_POSITIVE"
    else:
        if verdict == "NOT_DETECTED":
            classification = "TRUE_NEGATIVE"
        elif verdict == "DETECTED":
            classification = "FALSE_POSITIVE"
        else:
            classification = "UNCERTAIN_NEGATIVE"

    return {
        "session_id":      session_id,
        "pcap_path":       pcap_path,
        "attacker_ip":     attacker_ip,
        "victim_ip":       victim_ip,
        "victim_port":     victim_port,
        "secret_key":      secret_key,
        "short_ms":        short_ms,
        "long_ms":         long_ms,
        "tight_tol":       tight_tol,
        "midpoint":        midpoint,
        "expected_exfil":  expected_exfil,
        "total_ipds":      len(ipds_ms),
        "clear":           clear,
        "correct":         correct,
        "wrong":           wrong,
        "ambiguous":       ambig,
        "survival_pct":    round(survival_pct, 2) if survival_pct is not None else None,
        "ber":             round(ber, 4)          if ber          is not None else None,
        "verdict":         verdict,
        "classification":  classification,
        "raw_ipds_ms":     [round(x, 4) for x in ipds_ms],
        "expected_bits":   expected_bits,
        "rows":            rows,
    }


def _result_insufficient(session_id, pcap_path, attacker_ip, victim_ip,
                         victim_port, secret_key, short_ms, long_ms,
                         tight_tol, expected_exfil, pkt_count) -> dict:
    classification = "FALSE_NEGATIVE" if expected_exfil == "on" else "TRUE_NEGATIVE"
    return {
        "session_id": session_id, "pcap_path": pcap_path,
        "attacker_ip": attacker_ip, "victim_ip": victim_ip,
        "victim_port": victim_port, "secret_key": secret_key,
        "short_ms": short_ms, "long_ms": long_ms,
        "tight_tol": tight_tol, "midpoint": (short_ms + long_ms) / 2,
        "expected_exfil": expected_exfil,
        "total_ipds": pkt_count, "clear": 0, "correct": 0,
        "wrong": 0, "ambiguous": 0,
        "survival_pct": None, "ber": None,
        "verdict": "INDETERMINATE",
        "classification": classification,
        "error": f"only {pkt_count} data packet(s) found — need ≥2 for IPDs",
        "raw_ipds_ms": [], "expected_bits": [], "rows": [],
    }


# ── logging ───────────────────────────────────────────────────────────────────

def _log_result(result: dict, run_ts: str) -> None:
    """Append human-readable entry to watermark_log.txt and raw entry to .jsonl."""
    _LOG_TXT.parent.mkdir(parents=True, exist_ok=True)

    r = result
    sep = "─" * 70

    lines = [
        f"\n{sep}",
        f"  Run timestamp  : {run_ts}",
        f"  Session ID     : {r['session_id']}",
        f"  PCAP           : {r['pcap_path']}",
        f"  Attacker       : {r['attacker_ip']}",
        f"  Victim         : {r['victim_ip']}:{r['victim_port']}",
        f"  short/long ms  : {r['short_ms']} / {r['long_ms']}",
        f"  tight_tol      : ±{r['tight_tol']} ms",
        f"  Expected exfil : {r['expected_exfil']}",
        f"{sep}",
    ]

    if r.get("error"):
        lines += [
            f"  ERROR          : {r['error']}",
            f"  Verdict        : {r['verdict']}",
            f"  Classification : {r['classification']}",
        ]
    else:
        total = r['total_ipds']
        clear = r['clear']
        lines += [
            f"  Total IPDs     : {total}",
            f"  Clear bits     : {clear}  ({clear/total*100:.1f}% of IPDs)" if total else "  Clear bits: 0",
            f"  Ambiguous      : {r['ambiguous']}",
            f"  Correct        : {r['correct']}",
            f"  Wrong          : {r['wrong']}",
            f"  Survival       : {r['survival_pct']}%  (random baseline = 50.0%)" if r['survival_pct'] is not None else "  Survival: N/A",
            f"  BER            : {r['ber']}" if r['ber'] is not None else "  BER: N/A",
            f"  Verdict        : {r['verdict']}",
            f"  Classification : {r['classification']}",
        ]
        # Flag TP/FP/FN clearly
        flag = {
            "TRUE_POSITIVE":    "  [OK]  Watermark survived — correctly DETECTED",
            "TRUE_NEGATIVE":    "  [OK]  No watermark — correctly NOT DETECTED",
            "FALSE_POSITIVE":   "  [!!]  FALSE POSITIVE — no watermark but DETECTED (NPC jitter coincidence?)",
            "FALSE_NEGATIVE":   "  [!!]  FALSE NEGATIVE — watermark present but NOT DETECTED (jitter destroyed rhythm?)",
            "UNCERTAIN_POSITIVE":  "  [?]  UNCERTAIN — watermark run but inconclusive",
            "UNCERTAIN_NEGATIVE":  "  [?]  UNCERTAIN — baseline but inconclusive",
        }.get(r["classification"], "")
        if flag:
            lines.append(flag)

    lines.append(sep)
    txt_block = "\n".join(lines) + "\n"

    with open(_LOG_TXT, "a", encoding="utf-8") as fh:
        fh.write(txt_block)

    # raw JSONL — full data for re-analysis
    raw = {k: v for k, v in r.items() if k != "rows"}   # rows redundant (derivable)
    raw["run_timestamp"] = run_ts
    with open(_LOG_JSONL, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(raw) + "\n")


def _log_summary(results: list, run_ts: str) -> None:
    tp = sum(1 for r in results if r["classification"] == "TRUE_POSITIVE")
    tn = sum(1 for r in results if r["classification"] == "TRUE_NEGATIVE")
    fp = sum(1 for r in results if r["classification"] == "FALSE_POSITIVE")
    fn = sum(1 for r in results if r["classification"] == "FALSE_NEGATIVE")
    uc = sum(1 for r in results if "UNCERTAIN" in r["classification"])
    total = len(results)

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall    = tp / (tp + fn) if (tp + fn) > 0 else None

    lines = [
        f"\n{'═'*70}",
        f"  BATCH SUMMARY  — {run_ts}",
        f"{'═'*70}",
        f"  Sessions analyzed : {total}",
        f"  True  Positive    : {tp}   (watermark present, correctly DETECTED)",
        f"  True  Negative    : {tn}   (no watermark, correctly NOT DETECTED)",
        f"  False Positive    : {fp}   (no watermark, wrongly DETECTED — check NPC jitter)",
        f"  False Negative    : {fn}   (watermark present, not detected — check timing/chunk size)",
        f"  Uncertain         : {uc}",
        f"  Precision         : {precision*100:.1f}%" if precision is not None else "  Precision: N/A",
        f"  Recall            : {recall*100:.1f}%"    if recall    is not None else "  Recall: N/A",
        f"{'═'*70}",
    ]
    if fp > 0:
        lines.append("  TROUBLESHOOT FP: Run exfil=off baseline — confirm NPC never sends TOS=0x10")
    if fn > 0:
        lines.append("  TROUBLESHOOT FN: Check /tmp/timing_*.json rhythm non-empty; verify TOS SYN reached DB sniffer")
    lines.append("")

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


def _load_session(session_id: str) -> dict:
    for rec in _load_schema():
        if isinstance(rec, dict) and rec.get("session_id") == session_id:
            return rec
    print(f"[ERROR] session_id={session_id!r} not in schema.json")
    sys.exit(1)


def _params_from_record(rec: dict, args) -> dict:
    """Extract analysis params from schema.json record (new structure).

    New schema layout:
        timing_protocol.secret_key        — actual key string
        timing_protocol.attacker_ip       — from topology exfil config
        timing_protocol.victim_ip/port    — DB host IP + API port
        timing_protocol.short/long_delay_ms — from YAML
        timing_protocol.sessions[]        — runtime session list (exfil=on only)
          .src                            — IP seen by DB sniffer (may be VPN IP)
          .start_timestamp / end_timestamp
          .exfiltrated_data_packets / rhythm

    Falls back to YAML if schema fields missing (old records).
    """
    tp    = rec.get("timing_protocol") or {}
    topo  = rec.get("topology", "")

    pcap_path = args.pcap or rec.get("pcapng")

    # victim_ip: new schema stores "IP:port"; old schema has separate victim_ip + victim_port
    _raw_victim = tp.get("victim_ip", "")
    if args.victim:
        victim_ip   = args.victim
        victim_port = args.port or tp.get("victim_port")
    elif _raw_victim and ":" in str(_raw_victim):
        _parts      = str(_raw_victim).rsplit(":", 1)
        victim_ip   = _parts[0]
        victim_port = args.port or int(_parts[1])
    else:
        victim_ip   = _raw_victim or None
        victim_port = args.port or tp.get("victim_port")
    short_ms    = args.short_ms or tp.get("short_delay_ms")
    long_ms     = args.long_ms  or tp.get("long_delay_ms")

    # secret_key: new schema stores actual key; old schema had secret_key_present (bool)
    secret_key = args.secret or tp.get("secret_key") or ""
    if not secret_key or isinstance(secret_key, bool):
        # old record or empty — load from YAML
        config_path = args.config or (_ROOT / "configs" / topo if topo else None)
        if config_path and Path(str(config_path)).exists():
            cfg = load_config(str(config_path))
            dbs = getattr(cfg, "databases", [])
            if dbs:
                tp_cfg = getattr(dbs[0], "timing_protocol", None)
                secret_key = getattr(tp_cfg, "secret_key", "") if tp_cfg else ""
                if short_ms is None:
                    short_ms = float(getattr(tp_cfg, "short_delay_ms", 20.0)) if tp_cfg else 20.0
                if long_ms is None:
                    long_ms  = float(getattr(tp_cfg, "long_delay_ms",  50.0)) if tp_cfg else 50.0

    # attacker_ip: use first session's observed IP (what DB sniffer saw).
    # For VPN this is the tunnel IP. conf_atc_ip is the real configured LAN IP.
    sessions    = tp.get("sessions") or []
    attacker_ip = (args.attacker
                   or (sessions[0].get("attacker_ip") if sessions else None)
                   or tp.get("conf_atc_ip")    # new schema top-level
                   or tp.get("attacker_ip")    # old schema compat
                   or tp.get("src"))           # oldest schema compat

    # resolve victim_ip/attacker_ip from ip_allocator if still missing
    if not victim_ip or not attacker_ip:
        config_path = args.config or (_ROOT / "configs" / topo if topo else None)
        if config_path and Path(str(config_path)).exists():
            cfg = load_config(str(config_path))
            try:
                from network.ip_allocator import allocate
                alloc = allocate(cfg)
                if not attacker_ip:
                    exfil = getattr(cfg, "exfiltration", None)
                    aname = getattr(exfil, "attacker", None)
                    if aname:
                        attacker_ip = alloc.get_host_ip(aname)
                if not victim_ip:
                    dbs = getattr(cfg, "databases", [])
                    if dbs:
                        victim_ip = alloc.get_host_ip(dbs[0].host)
                        if not victim_port:
                            victim_port = dbs[0].api_port or 9090
            except Exception:
                pass

    expected_exfil = (rec.get("experiment") or {}).get("exfil", "on")

    return {
        "pcap_path":      pcap_path,
        "attacker_ip":    attacker_ip or "",
        "victim_ip":      victim_ip   or "",
        "victim_port":    int(victim_port or 9090),
        "secret_key":     secret_key  or "",
        "short_ms":       float(short_ms or 20.0),
        "long_ms":        float(long_ms  or 50.0),
        "expected_exfil": expected_exfil,
    }


def _print_result(r: dict) -> None:
    print(f"\n  Session : {r['session_id']}")
    if r.get("error"):
        print(f"  ERROR   : {r['error']}")
        print(f"  Verdict : {r['verdict']}  [{r['classification']}]")
        return
    total = r["total_ipds"]
    clear = r["clear"]
    print(f"  IPDs    : {total}  |  Clear: {clear}  |  Ambig: {r['ambiguous']}")
    if r["survival_pct"] is not None:
        print(f"  Survival: {r['survival_pct']:.1f}%  BER: {r['ber']:.4f}")
    print(f"  Verdict : {r['verdict']}  [{r['classification']}]")
    if clear < 10 and total > 0:
        print(f"  WARNING : only {clear} clear bits — insufficient for strong claim")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Watermark survival analysis")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--all",     action="store_true",
                      help="Analyze ALL sessions in dataset/schema.json")
    mode.add_argument("--session", default=None,
                      help="Single session ID from schema.json")
    mode.add_argument("--pcap",    default=None,
                      help="Raw pcapng path (requires --config)")
    parser.add_argument("--config",    default=None)
    parser.add_argument("--attacker",  default=None)
    parser.add_argument("--victim",    default=None)
    parser.add_argument("--port",      type=int, default=None)
    parser.add_argument("--secret",    default=None)
    parser.add_argument("--short-ms",  type=float, dest="short_ms", default=None)
    parser.add_argument("--long-ms",   type=float, dest="long_ms",  default=None)
    args = parser.parse_args()

    if not _SCAPY_OK:
        print("[ERROR] scapy not installed.  pip install scapy")
        sys.exit(1)

    run_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = []

    # ── collect sessions to analyze ───────────────────────────────────────────
    if args.all:
        records = _load_schema()
        print(f"\n[analyze_watermark] --all  {len(records)} sessions in schema.json")
    elif args.session:
        records = [_load_session(args.session)]
    else:
        # --pcap mode: build a synthetic record
        records = [{"session_id": Path(args.pcap).stem,
                    "pcapng":     args.pcap,
                    "topology":   Path(args.config).name if args.config else "",
                    "timing_protocol": {},
                    "experiment": {"exfil": "on"}}]

    # ── run analysis on each session ──────────────────────────────────────────
    for rec in records:
        sid = rec.get("session_id", "unknown")
        p   = _params_from_record(rec, args)

        if not p["pcap_path"] or not Path(p["pcap_path"]).exists():
            print(f"\n  [SKIP] {sid} — pcapng not found: {p['pcap_path']}")
            continue
        if not p["attacker_ip"] or not p["victim_ip"]:
            print(f"\n  [SKIP] {sid} — cannot resolve attacker/victim IP")
            continue
        if not p["secret_key"]:
            print(f"\n  [SKIP] {sid} — no secret_key (check YAML timing_protocol.secret_key)")
            continue

        # skip exfil=off sessions unless --all explicitly requested full analysis
        # (they SHOULD be NOT_DETECTED — still logged for FP check)
        result = analyze(
            session_id  = sid,
            pcap_path   = p["pcap_path"],
            attacker_ip = p["attacker_ip"],
            victim_ip   = p["victim_ip"],
            victim_port = p["victim_port"],
            secret_key  = p["secret_key"],
            short_ms    = p["short_ms"],
            long_ms     = p["long_ms"],
            expected_exfil = p["expected_exfil"],
        )

        _print_result(result)
        _log_result(result, run_ts)
        results.append(result)

    if results:
        _log_summary(results, run_ts)
        print(f"\nLogs written:")
        print(f"  {_LOG_TXT}")
        print(f"  {_LOG_JSONL}  (raw IPDs — re-analyze without re-running experiments)\n")
    else:
        print("\n[analyze_watermark] No sessions analyzed.")


if __name__ == "__main__":
    main()
