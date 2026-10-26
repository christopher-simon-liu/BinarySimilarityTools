#!/usr/bin/env python3
"""Compute Catalog1 signatures from Ghidra ACFG-disassembly JSON files."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import time
from pathlib import Path

from src.models.Catalog1.Catalog1.catalog1.catalog_fast import sign

COLUMNS = ("path", "address", "size", "catalog_hash_list", "time")


def function_bytes(function: dict) -> bytes:
    blocks = function.get("basic_blocks", {})
    ordered = sorted(blocks.items(), key=lambda item: int(item[0], 0))
    return b"".join(base64.b64decode(block["b64_bytes"]) for _, block in ordered)


def generate(input_dir: Path, output_prefix: Path, signature_sizes: list[int]) -> None:
    outputs = {}
    try:
        for size in signature_sizes:
            path = output_prefix.with_name(f"{output_prefix.name}_{size}.csv")
            handle = path.open("w", encoding="utf-8", newline="")
            writer = csv.DictWriter(handle, fieldnames=COLUMNS)
            writer.writeheader()
            outputs[size] = (handle, writer)

        for json_path in sorted(input_dir.glob("*_acfg_disasm.json")):
            document = json.loads(json_path.read_text(encoding="utf-8"))
            for project_path, functions in document.items():
                for address, function in functions.items():
                    if address == "arch":
                        continue
                    data = function_bytes(function)
                    for size, (_, writer) in outputs.items():
                        started = time.perf_counter()
                        signature = (
                            ["min_function_size_error"]
                            if len(data) < 4
                            else sign(data, size)
                        )
                        writer.writerow(
                            {
                                "path": project_path,
                                "address": address,
                                "size": len(data),
                                "catalog_hash_list": ";".join(map(str, signature)),
                                "time": time.perf_counter() - started,
                            }
                        )
    finally:
        for handle, _ in outputs.values():
            handle.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-prefix", required=True, type=Path)
    parser.add_argument(
        "--signature-sizes", nargs="+", type=int, default=[16, 32, 64, 128]
    )
    args = parser.parse_args()
    args.output_prefix.parent.mkdir(parents=True, exist_ok=True)
    generate(args.input_dir, args.output_prefix, args.signature_sizes)


if __name__ == "__main__":
    main()
