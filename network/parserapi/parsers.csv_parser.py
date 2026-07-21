"""Default CSV parser for the ISP packet capture framework.

Usage (called by CaptureManager):
    python3 parserapi/parsers.csv_parser.py <pcap_path> <session_id> <yaml_path>

Reads ParserToCsv from YAML, extracts the mapped fields from each packet
using PyShark, and writes <schema.update_folder>/<session_id>.csv.
Prints the generated CSV path to stdout so the framework can read it.

Parser rules:
- Never modifies schema.json.
- Preserves the session_id as the output filename stem.
- Only changes folder and extension.
"""

import csv
import os
import sys

import yaml


def _get_field(pkt, field_path: str) -> str:
    """Extract a Wireshark field value from a PyShark packet. Returns '' on miss."""
    parts = field_path.split(".")
    layer = parts[0]

    if layer == "_ws":
        # _ws.col.* are Wireshark summary columns
        col = parts[2] if len(parts) > 2 else ""
        if col == "Source":
            return _network_src(pkt)
        if col == "Destination":
            return _network_dst(pkt)
        if col == "Protocol":
            return pkt.highest_layer
        if col == "Info":
            return str(pkt)
        return ""

    if layer == "frame":
        attr = parts[1] if len(parts) > 1 else ""
        try:
            return str(getattr(pkt.frame_info, attr, ""))
        except Exception:
            return ""

    # Generic layer.field access
    try:
        l = pkt[layer]
        if len(parts) > 1:
            return str(getattr(l, parts[1].replace(".", "_"), ""))
        return str(l)
    except Exception:
        return ""


def _network_src(pkt) -> str:
    for layer in ("ip", "ipv6", "eth"):
        try:
            return str(pkt[layer].src)
        except Exception:
            pass
    return ""


def _network_dst(pkt) -> str:
    for layer in ("ip", "ipv6", "eth"):
        try:
            return str(pkt[layer].dst)
        except Exception:
            pass
    return ""


def main() -> None:
    if len(sys.argv) < 4:
        print("Usage: parsers.csv_parser.py <pcap_path> <session_id> <yaml_path>",
              file=sys.stderr)
        sys.exit(1)

    pcap_path, session_id, yaml_path = sys.argv[1], sys.argv[2], sys.argv[3]

    if not os.path.exists(pcap_path):
        print(f"Error: pcap not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    with open(yaml_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    field_map: dict = raw.get("ParserToCsv") or {
        "SI.NO":        "frame.number",
        "TIME":         "frame.time",
        "SOURCE":       "_ws.col.Source",
        "DESTINATION":  "_ws.col.Destination",
        "PROTOCOL":     "_ws.col.Protocol",
        "LENGTH":       "frame.len",
        "INFO":         "_ws.col.Info",
    }

    update_folder: str = (
        raw.get("capture", {}).get("schema", {}).get("update_folder", "csv")
    )

    # Resolve output path relative to project root (two levels up from parserapi/)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(root, update_folder)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{session_id}.csv")

    import pyshark

    columns = list(field_map.keys())
    fields = list(field_map.values())

    cap = pyshark.FileCapture(pcap_path, keep_packets=False)
    try:
        with open(out_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(columns)
            for pkt in cap:
                writer.writerow([_get_field(pkt, f) for f in fields])
    finally:
        cap.close()

    # Return output path to framework via stdout
    print(out_path)


if __name__ == "__main__":
    main()
