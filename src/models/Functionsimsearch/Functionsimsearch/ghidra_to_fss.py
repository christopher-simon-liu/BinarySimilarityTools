#!/usr/bin/env python3
"""Convert Ghidra ACFG disassembly into FunctionSimSearch input JSON."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

IMMEDIATE = re.compile(r"^-?(?:0x[0-9a-f]+|\d+)$", re.IGNORECASE)


def operands(disassembly: str) -> list[str]:
    parts = disassembly.strip().split(None, 1)
    if len(parts) == 1:
        return []
    result = []
    for operand in parts[1].split(","):
        operand = operand.strip()
        result.append(f"#{operand}" if IMMEDIATE.fullmatch(operand) else operand)
    return result


def convert_function(function: dict) -> dict:
    instructions = {}
    for address, block in function.get("basic_blocks", {}).items():
        mnemonics = block.get("bb_mnems", [])
        disassembly = block.get("bb_disasm", [])
        instructions[address] = [
            [mnemonic, operands(text)] for mnemonic, text in zip(mnemonics, disassembly)
        ]
    return {
        "nodes": function.get("nodes", []),
        "edges": function.get("edges", []),
        "instructions": instructions,
    }


def convert(input_dir: Path, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for source in sorted(input_dir.glob("*_acfg_disasm.json")):
        document = json.loads(source.read_text(encoding="utf-8"))
        converted = {}
        for project_path, functions in document.items():
            converted[project_path] = {
                address: convert_function(function)
                for address, function in functions.items()
                if address != "arch"
            }
        destination = output_dir / source.name.replace("_acfg_disasm.json", "_fss.json")
        destination.write_text(json.dumps(converted), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    convert(args.input_dir, args.output_dir)


if __name__ == "__main__":
    main()
