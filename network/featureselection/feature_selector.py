"""Feature Selection Engine.

Responsibility: feature extraction only.

Reads the merged PCAPNG file using the custom pcapng_reader (which preserves
interface metadata from IDB blocks), then executes configured feature functions
for each packet, producing a flat JSON dataset.

Pipeline:
  Validate dependencies
    → Read YAML feature_selection
    → for each COLUMN_NAME: module.py:function_name
    → dynamically import module (path relative to project root)
    → for each packet in merged PCAPNG:
        → reconstruct Scapy packet from raw bytes
        → inject _device, _interface, _frame_number onto packet
        → execute function(packet) → one value per column
    → write tmp/<session_id>_session_dataset.json (flat JSON array)
    → print dataset path to stdout

No CSV writing. No schema.json updates. No packet merging.

Usage (always invoked with sys.executable from the parent process):
    python3 featureselection/feature_selector.py <pcapng_path> <session_id> <yaml_path>
"""

import importlib.util
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------- dependency check

def _check_dependencies() -> bool:
    print("[FEATURE_SELECTOR] Checking Feature Selection dependencies...", flush=True)

    results = []
    ok = True

    try:
        import scapy  # noqa: F401
        results.append(("Scapy", True, ""))
    except ImportError:
        results.append(("Scapy", False, "pip install scapy"))
        ok = False

    try:
        import yaml  # noqa: F401
        results.append(("PyYAML", True, ""))
    except ImportError:
        results.append(("PyYAML", False, "pip install pyyaml"))
        ok = False

    # pcapng_reader is shipped with the framework — not a pip package
    reader_path = os.path.join(_ROOT, "network", "pcapng_reader.py")
    if os.path.exists(reader_path):
        results.append(("pcapng_reader", True, ""))
    else:
        results.append(("pcapng_reader", False, f"missing: {reader_path}"))
        ok = False

    for name, passed, install in results:
        mark = "✓" if passed else "✗"
        line = f"[FEATURE_SELECTOR]   {mark} {name}"
        if not passed:
            line += f"  ({install})"
        print(line, flush=True)

    if ok:
        print("[FEATURE_SELECTOR] Dependencies OK.", flush=True)
    else:
        print(
            "[FEATURE_SELECTOR] Feature Selection cannot continue — see missing dependencies above.",
            flush=True,
        )
    return ok


# ---------------------------------------------------------------- module loader

def _load_function(spec_str: str):
    """Parse 'path/to/module.py:function_name', import module, return callable."""
    if ":" not in spec_str:
        raise ValueError(
            f"Feature spec must be 'file.py:function_name', got {spec_str!r}"
        )
    file_part, func_name = spec_str.rsplit(":", 1)
    module_path = os.path.join(_ROOT, file_part)

    if not os.path.exists(module_path):
        raise FileNotFoundError(
            f"Feature module not found: {module_path}\n"
            f"  Check that {file_part!r} exists relative to the project root."
        )

    module_name = os.path.splitext(os.path.basename(file_part))[0]
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if not hasattr(module, func_name):
        raise AttributeError(
            f"Function {func_name!r} not found in {module_path}\n"
            f"  Available: {[n for n in dir(module) if not n.startswith('_')]}"
        )
    return getattr(module, func_name)


# ---------------------------------------------------------------- main

def main() -> None:
    if len(sys.argv) < 4:
        print(
            "[FEATURE_SELECTOR] Usage: feature_selector.py <pcapng_path> <session_id> <yaml_path>",
            file=sys.stderr,
        )
        sys.exit(1)

    pcapng_path, session_id, yaml_path = sys.argv[1], sys.argv[2], sys.argv[3]

    if not _check_dependencies():
        sys.exit(1)

    import yaml
    from scapy.all import Ether, Raw

    # Load pcapng_reader from project root
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("pcapng_reader", os.path.join(_ROOT, "network", "pcapng_reader.py"))
    _mod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    PcapNgFile = _mod.PcapNgFile

    if not os.path.exists(pcapng_path):
        print(f"[FEATURE_SELECTOR] PCAPNG not found: {pcapng_path}", flush=True)
        sys.exit(1)

    with open(yaml_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    # feature_selection: prefer capture.feature_selection; fall back to top-level (backward compat)
    features_cfg: dict = (
        (raw.get("capture") or {}).get("feature_selection")
        or raw.get("feature_selection")
        or {}
    )
    if not features_cfg:
        print(
            "[FEATURE_SELECTOR] WARNING: No feature_selection configured in YAML "
            "— dataset will have no columns.",
            flush=True,
        )

    columns = list(features_cfg.keys())
    functions: dict = {}
    load_errors = 0

    for col, spec_str in features_cfg.items():
        try:
            functions[col] = _load_function(spec_str)
            print(f"[FEATURE_SELECTOR]   Loaded  {col:<20}  ←  {spec_str}", flush=True)
        except Exception as exc:
            print(
                f"[FEATURE_SELECTOR]   ERROR loading feature {col} ({spec_str}): {exc}",
                flush=True,
            )
            load_errors += 1
            functions[col] = lambda pkt: ""

    if load_errors:
        print(
            f"[FEATURE_SELECTOR] {load_errors} feature(s) failed to load — those columns will be empty.",
            flush=True,
        )

    # Read merged PCAPNG and extract features per packet
    dataset = []
    frame_number = 1

    print(f"[FEATURE_SELECTOR] Reading PCAPNG: {pcapng_path}", flush=True)

    try:
        with PcapNgFile(pcapng_path) as f:
            for pcapng_pkt in f:
                # Reconstruct Scapy packet from raw bytes for feature functions
                try:
                    pkt = Ether(pcapng_pkt.data)
                except Exception:
                    pkt = Raw(pcapng_pkt.data)

                # Inject metadata that feature functions can read
                pkt._frame_number = frame_number
                pkt._device = pcapng_pkt.device          # derived from IDB if_name
                pkt._interface = pcapng_pkt.interface_name  # from IDB if_name
                pkt.time = pcapng_pkt.timestamp_decimal  # full-precision Decimal from PCAPNG EPB

                row: dict = {}
                for col in columns:
                    try:
                        val = functions[col](pkt)
                        row[col] = val if val is not None else ""
                    except Exception as exc:
                        logger_print(
                            f"WARNING: feature {col} failed on frame {frame_number}: {exc}"
                        )
                        row[col] = ""
                dataset.append(row)
                frame_number += 1

    except Exception as exc:
        print(f"[FEATURE_SELECTOR] ERROR reading PCAPNG: {exc}", flush=True)
        sys.exit(1)

    print(
        f"[FEATURE_SELECTOR] Extracted {len(dataset)} rows across {len(columns)} features.",
        flush=True,
    )

    # Write flat JSON array to tmp/
    tmp_dir = os.path.join(
        _ROOT,
        (raw.get("capture") or {}).get("sessiondir", "dataset/tmp").rstrip("/"),
    )
    os.makedirs(tmp_dir, exist_ok=True)
    dataset_path = os.path.join(tmp_dir, f"{session_id}_session_dataset.json")

    with open(dataset_path, "w", encoding="utf-8") as fh:
        json.dump(dataset, fh)

    print(f"[FEATURE_SELECTOR] Dataset written: {dataset_path}", flush=True)
    print(dataset_path)


def logger_print(msg: str) -> None:
    print(f"[FEATURE_SELECTOR]   {msg}", flush=True)


if __name__ == "__main__":
    main()
