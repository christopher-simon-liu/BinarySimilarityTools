#!/usr/bin/env python3
"""Convert a Ghidra flowchart CSV into model-compatible function metadata."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

METADATA_DEFAULTS = {
    "project": "binary",
    "library": "unknown",
    "arch": "unknown",
    "bit": "",
    "compiler": "unknown",
    "version": "unknown",
    "optimizations": "unknown",
}


def _address(value: str) -> int:
    return int(value.rstrip("L"), 16)


def create_metadata(flowchart_csv: Path, output_name: str, min_basic_blocks: int) -> None:
    output_dir = flowchart_csv.resolve().parent
    functions_csv = output_dir / f"{output_name}.csv"
    names_csv = output_dir / f"{output_name}_function_names.csv"
    selected_json = output_dir / f"selected_{output_name}.json"

    with flowchart_csv.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "ghidra_proj_path" not in reader.fieldnames:
            raise ValueError("flowchart CSV must contain a ghidra_proj_path column")
        rows = [row for row in reader if int(row.get("bb_num", 0)) >= min_basic_blocks]

    selected: dict[str, list[int]] = defaultdict(list)
    function_rows = []
    name_rows = []
    for row in rows:
        project_path = row.pop("ghidra_proj_path")
        row.pop("bb_list", None)
        row["idb_path"] = project_path  # Compatibility name expected by the bundled models.
        row.update(METADATA_DEFAULTS)
        selected[project_path].append(_address(row["fva"]))
        function_rows.append(row)
        name_rows.append(
            {
                "firmware": Path(project_path).name,
                "fva": _address(row["fva"]),
                "func_name": row["func_name"],
            }
        )

    fieldnames = [
        "idb_path",
        "fva",
        "func_name",
        "start_ea",
        "end_ea",
        "bb_num",
        "hashopcodes",
        *METADATA_DEFAULTS,
    ]
    with functions_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(function_rows)
    with names_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("firmware", "fva", "func_name"))
        writer.writeheader()
        writer.writerows(name_rows)
    selected_json.write_text(json.dumps(selected, indent=2), encoding="utf-8")

    print(f"Generated {functions_csv}")
    print(f"Generated {names_csv}")
    print(f"Generated {selected_json}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create model input CSV and selected-functions JSON from Ghidra output"
    )
    parser.add_argument("flowchart_csv", type=Path)
    parser.add_argument("output_name", help="Output basename without .csv")
    parser.add_argument("--min-basic-blocks", type=int, default=5)
    args = parser.parse_args()
    create_metadata(args.flowchart_csv, args.output_name, args.min_basic_blocks)


if __name__ == "__main__":
    main()
