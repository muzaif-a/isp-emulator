"""CSV Parser — serialization only.

Responsibility: receive generic dataset JSON, preserve YAML column order, write CSV.

No feature extraction. No packet parsing. No protocol decoding. No schema.json updates.

Input:
    tmp/<session_id>_session_dataset.json   — flat JSON array produced by Feature Selection Engine

Output:
    csv/<session_id>.csv

Usage:
    python3 parserapi/csv_parser.py <dataset_json_path> <session_id> <yaml_path>

Prints the generated CSV path to stdout so the Capture Engine can read it.
"""

import csv
import json
import os
import sys

import yaml


def main() -> None:
    if len(sys.argv) < 4:
        print(
            "Usage: csv_parser.py <dataset_json_path> <session_id> <yaml_path>",
            file=sys.stderr,
        )
        sys.exit(1)

    dataset_path, session_id, yaml_path = sys.argv[1], sys.argv[2], sys.argv[3]

    if not os.path.exists(dataset_path):
        print(f"Dataset not found: {dataset_path}", file=sys.stderr)
        sys.exit(1)

    with open(dataset_path, "r", encoding="utf-8") as fh:
        dataset = json.load(fh)

    # Dataset is a flat array of dicts — validate
    if not isinstance(dataset, list):
        print(f"Dataset must be a JSON array, got {type(dataset).__name__}", file=sys.stderr)
        sys.exit(1)

    with open(yaml_path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    # Column order: prefer capture.feature_selection; fall back to top-level (backward compat)
    features_cfg: dict = (
        (raw.get("capture") or {}).get("feature_selection")
        or raw.get("feature_selection")
        or {}
    )
    columns = list(features_cfg.keys())

    # Fall back to keys from first row if YAML has no feature_selection
    if not columns and dataset:
        columns = list(dataset[0].keys())

    if not columns:
        print("No columns found in dataset or YAML feature_selection.", file=sys.stderr)
        sys.exit(1)

    # Output directory: prefer capture.parser.dir[0]; fall back to dataset/csv
    parser_raw = (raw.get("capture") or {}).get("parser") or {}
    parser_dir_raw = parser_raw.get("dir", [])
    if isinstance(parser_dir_raw, list) and parser_dir_raw:
        csv_out_folder = str(parser_dir_raw[0]).strip()
    elif isinstance(parser_dir_raw, str) and parser_dir_raw.strip():
        csv_out_folder = parser_dir_raw.strip()
    else:
        csv_out_folder = "dataset/csv"

    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    out_dir = os.path.join(root, csv_out_folder)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{session_id}.csv")

    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(columns)
        for row in dataset:
            writer.writerow([row.get(col, "") for col in columns])

    # Return output path to Capture Engine via stdout
    print(out_path)


if __name__ == "__main__":
    main()
