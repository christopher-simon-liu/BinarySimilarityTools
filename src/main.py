#!/usr/bin/env python3
"""End-to-end two-binary similarity pipeline."""

from __future__ import annotations

import argparse
import csv
import math
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from tqdm import tqdm

REPO_ROOT = Path(__file__).resolve().parents[1]
MODELS = {
    "asm2vec": "models/Asm2vec/Asm2vec_wrapper.py",
    "catalog1": "models/Catalog1/Catalog1_wrapper.py",
    "functionsimsearch": "models/Functionsimsearch/functionsimsearch_wrapper.py",
    "gnn-s2v-gemini": "models/GNN-s2v-Gemini/GNN-s2v-Gemini_wrapper.py",
    "gnn-s2v-massarelli": "models/GNN-s2v-Massarelli/GNN-s2v-Massarelli_wrapper.py",
    "hermessim": "models/Hermessim/Hermessim_wrapper.py",
    "safe": "models/SAFE/SAFE_wrapper.py",
    "trex": "models/Trex/Trex_wrapper.py",
    "zeek": "models/Zeek/Zeek_wrapper.py",
}
PIPELINE_STAGES = 9


def _begin_stage(progress: tqdm | None, description: str) -> None:
    if progress is not None:
        progress.set_description_str(description, refresh=True)


def _complete_stage(progress: tqdm | None) -> None:
    if progress is not None:
        progress.update(1)


def _base_address(value: str) -> int:
    try:
        address = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer address: {value}") from exc
    if not 0 <= address <= 0xFFFFFFFFFFFFFFFF:
        raise argparse.ArgumentTypeError(
            "address must be between 0 and 0xffffffffffffffff"
        )
    return address


def _report_path(
    output_dir: Path, model: str, binary_a: Path, binary_b: Path
) -> Path:
    """Return the deterministic report path for one binary pair."""
    return output_dir / f"{model}_report_{binary_a.stem}_{binary_b.stem}.json"


def _run(command: list[str], *, environment: dict[str, str] | None = None) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, env=environment, check=True)


def _stage_binary(source: Path, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / source.name
    if target.exists() or target.is_symlink():
        if target.resolve() != source.resolve():
            raise RuntimeError(f"Staged binary already points elsewhere: {target}")
        return
    target.symlink_to(source.resolve())


def _project_selectors(inventory: Path, project_dir: Path) -> tuple[str, str]:
    with inventory.open("r", encoding="utf-8-sig", newline="") as handle:
        paths = sorted({row["idb_path"] for row in csv.DictReader(handle)})
    project_dir = project_dir.resolve()
    binary_a = [path for path in paths if Path(path).resolve().parent == project_dir / "a"]
    binary_b = [path for path in paths if Path(path).resolve().parent == project_dir / "b"]
    if len(binary_a) != 1 or len(binary_b) != 1:
        raise RuntimeError(
            "Could not resolve one Ghidra project for each input binary from the inventory"
        )
    return binary_a[0], binary_b[0]


def _replace_link(target: Path, link: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink():
        if link.resolve() == target.resolve():
            return
        link.unlink()
    elif link.exists():
        return
    link.symlink_to(target.resolve(), target_is_directory=target.is_dir())


def _write_pairs(functions_csv: Path, comparison_dir: Path, comparison: str) -> None:
    with functions_csv.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    binaries = sorted({row["idb_path"] for row in rows})
    if len(binaries) != 2:
        raise RuntimeError(f"Expected two binaries in {functions_csv}; found {len(binaries)}")
    left = [row for row in rows if row["idb_path"] == binaries[0]]
    right = [row for row in rows if row["idb_path"] == binaries[1]]
    pair_rows = [
        {
            "idb_path_1": function_a["idb_path"],
            "fva_1": function_a["fva"],
            "func_name_1": function_a.get("func_name", ""),
            "idb_path_2": function_b["idb_path"],
            "fva_2": function_b["fva"],
            "func_name_2": function_b.get("func_name", ""),
        }
        for function_a in left
        for function_b in right
    ]
    columns = (
        "idb_path_1", "fva_1", "func_name_1",
        "idb_path_2", "fva_2", "func_name_2",
    )
    for split, names in {
        "validation": (
            f"pos_validation_{comparison}.csv",
            f"neg_validation_{comparison}.csv",
        ),
        "testing": (
            f"neg_rank_testing_{comparison}.csv",
            f"neg_testing_{comparison}.csv",
            f"pos_rank_testing_{comparison}.csv",
            f"pos_testing_{comparison}.csv",
        ),
    }.items():
        pair_dir = comparison_dir / "pairs" / split
        pair_dir.mkdir(parents=True, exist_ok=True)
        for name in names:
            with (pair_dir / name).open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=columns)
                writer.writeheader()
                writer.writerows(pair_rows)
    shutil.copy2(
        functions_csv,
        comparison_dir / "pairs/validation/validation_functions.csv",
    )


def _create_model_layout(
    *,
    comparison_dir: Path,
    comparison: str,
    functions: Path,
    selection: Path,
    disassembly: Path,
    acfg: Path,
) -> None:
    """Expose combined extraction under paths retained model runners expect."""
    features = comparison_dir / "features"
    for split in ("training", "validation", "testing"):
        split_dir = features / split
        split_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(functions, comparison_dir / f"{split}_{comparison}.csv")
        shutil.copy2(selection, split_dir / f"selected_{split}_{comparison}.json")
        _replace_link(
            disassembly,
            split_dir / f"acfg_disasm_{comparison}_{split}",
        )
        _replace_link(
            acfg,
            split_dir / f"acfg_features_{comparison}_{split}",
        )
    _write_pairs(functions, comparison_dir, comparison)


def preprocess(
    *,
    binary_a: Path,
    binary_b: Path,
    comparison: str,
    workspace: Path,
    batch_size: int,
    min_basic_blocks: int,
    base_address_a: int | None = None,
    base_address_b: int | None = None,
    progress: tqdm | None = None,
) -> tuple[Path, Path, str, str]:
    ghidra_scripts = REPO_ROOT / "src/util/Ghidra_scripts"
    input_dir = workspace / "input" / comparison
    project_dir = workspace / "GhidraProjs" / comparison
    comparison_dir = workspace / "DBs" / comparison
    features_dir = comparison_dir / "features"
    inventory = features_dir / f"flowchart_{comparison}.csv"
    functions = features_dir / f"{comparison}.csv"
    selection = features_dir / f"selected_{comparison}.json"
    disassembly = features_dir / f"acfg_disasm_{comparison}"
    acfg = features_dir / f"acfg_features_{comparison}"

    _begin_stage(progress, "Staging binaries")
    _stage_binary(binary_a, input_dir / "a")
    _stage_binary(binary_b, input_dir / "b")
    features_dir.mkdir(parents=True, exist_ok=True)
    _complete_stage(progress)

    project_command = [
        sys.executable,
        str(ghidra_scripts / "generate_ghidra_projects.py"),
        "--input-dir",
        str(input_dir),
        "--output-dir",
        str(project_dir),
    ]
    if base_address_a is not None:
        project_command.extend(("--base-address-a", hex(base_address_a)))
    if base_address_b is not None:
        project_command.extend(("--base-address-b", hex(base_address_b)))
    _begin_stage(progress, "Creating Ghidra projects")
    _run(project_command)
    _complete_stage(progress)
    _begin_stage(progress, "Extracting flowcharts")
    _run(
        [
            sys.executable,
            str(ghidra_scripts / "ghidra_flowchart/cli_flowchart.py"),
            "--ghidra-proj-folder",
            str(project_dir),
            "--output-csv",
            str(inventory),
            "--batch-size",
            str(batch_size),
        ]
    )
    _complete_stage(progress)
    _begin_stage(progress, "Selecting functions")
    _run(
        [
            sys.executable,
            str(ghidra_scripts / "create_function_metadata.py"),
            str(inventory),
            comparison,
            "--min-basic-blocks",
            str(min_basic_blocks),
        ]
    )
    _complete_stage(progress)
    _begin_stage(progress, "Extracting disassembly")
    _run(
        [
            sys.executable,
            str(ghidra_scripts / "ghidra_acfg_disasm/cli_acfg_disasm.py"),
            "--json-path",
            str(selection),
            "--output-dir",
            str(disassembly),
        ]
    )
    _complete_stage(progress)
    _begin_stage(progress, "Extracting ACFG features")
    _run(
        [
            sys.executable,
            str(ghidra_scripts / "ghidra_acfg_features/cli_acfg_features.py"),
            "--json-path",
            str(selection),
            "--output-dir",
            str(acfg),
            "--batch-size",
            str(batch_size),
        ]
    )
    _complete_stage(progress)
    _begin_stage(progress, "Preparing model inputs")
    _create_model_layout(
        comparison_dir=comparison_dir,
        comparison=comparison,
        functions=functions,
        selection=selection,
        disassembly=disassembly,
        acfg=acfg,
    )
    selector_a, selector_b = _project_selectors(functions, project_dir)
    _complete_stage(progress)
    return comparison_dir, functions, selector_a, selector_b


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preprocess two binaries, run a model, and write a JSON report"
    )
    parser.add_argument("--binary-a", required=True, type=Path)
    parser.add_argument("--binary-b", required=True, type=Path)
    parser.add_argument("--model", required=True, choices=MODELS)
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output directory for <model>_report_<binary-a>_<binary-b>.json",
    )
    parser.add_argument("--comparison-name")
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path(os.environ.get("BINSIM_WORK_ROOT", REPO_ROOT / "output/runs")),
    )
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--min-basic-blocks", type=int, default=5)
    parser.add_argument(
        "--top-n",
        type=int,
        default=3,
        help="Number of highest-scoring Binary-B matches per Binary-A function",
    )
    parser.add_argument(
        "--min-similarity",
        type=float,
        default=0.0,
        help="Exclude similarities less than or equal to this value",
    )
    parser.add_argument(
        "--base-address-a",
        type=_base_address,
        help="Load address for binary A (decimal or 0x-prefixed); inferred if omitted",
    )
    parser.add_argument(
        "--base-address-b",
        type=_base_address,
        help="Load address for binary B (decimal or 0x-prefixed); inferred if omitted",
    )
    parser.add_argument("--variant")
    parser.add_argument(
        "--raw",
        action="append",
        default=[],
        help="Use existing native model output instead of executing the model",
    )
    parser.add_argument("--allow-unsafe-pickle", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    for binary in (args.binary_a, args.binary_b):
        if not binary.is_file():
            parser.error(f"Binary does not exist: {binary}")
    if args.binary_a.resolve() == args.binary_b.resolve():
        parser.error("Binary A and binary B must be different files")
    if args.batch_size < 1 or args.min_basic_blocks < 0 or args.top_n < 1:
        parser.error(
            "batch-size and top-n must be positive; min-basic-blocks must be nonnegative"
        )
    if not math.isfinite(args.min_similarity):
        parser.error("min-similarity must be finite")

    comparison = args.comparison_name or (
        f"{args.binary_a.stem}-vs-{args.binary_b.stem}-{args.model}"
    )
    if not re.fullmatch(r"[A-Za-z0-9._-]+", comparison):
        parser.error("comparison-name may contain only letters, numbers, '.', '_' and '-'")
    output_dir = args.output.resolve()
    if output_dir.exists() and not output_dir.is_dir():
        parser.error(f"Output path is not a directory: {output_dir}")
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        parser.error(f"Cannot create output directory {output_dir}: {exc}")
    report_path = _report_path(output_dir, args.model, args.binary_a, args.binary_b)
    workspace = args.workspace.resolve()

    try:
        with tqdm(
            total=PIPELINE_STAGES,
            desc="Starting pipeline",
            unit="stage",
            dynamic_ncols=True,
        ) as progress:
            comparison_dir, functions, selector_a, selector_b = preprocess(
                binary_a=args.binary_a.resolve(),
                binary_b=args.binary_b.resolve(),
                comparison=comparison,
                workspace=workspace,
                batch_size=args.batch_size,
                min_basic_blocks=args.min_basic_blocks,
                base_address_a=args.base_address_a,
                base_address_b=args.base_address_b,
                progress=progress,
            )
            run_dir = workspace / "results" / comparison / args.model
            scores = run_dir / "scores.csv"
            wrapper = REPO_ROOT / "src" / MODELS[args.model]
            wrapper_command = [
                sys.executable,
                str(wrapper),
                "--input",
                str(comparison_dir),
                "--functions",
                str(functions),
                "--output",
                str(scores),
            ]
            for raw in args.raw:
                wrapper_command.extend(("--raw", raw))
            if args.allow_unsafe_pickle:
                wrapper_command.append("--allow-unsafe-pickle")
            _begin_stage(progress, f"Running {args.model}")
            _run(wrapper_command)
            _complete_stage(progress)

            report_command = [
                sys.executable,
                str(REPO_ROOT / "src/generate_report.py"),
                "--scores",
                str(scores),
                "--binary-a",
                selector_a,
                "--binary-b",
                selector_b,
                "--model",
                args.model,
                "--top-n",
                str(args.top_n),
                "--min-similarity",
                str(args.min_similarity),
                "--output",
                str(report_path),
            ]
            if args.variant:
                report_command.extend(("--variant", args.variant))
            _begin_stage(progress, "Writing report")
            _run(report_command)
            _complete_stage(progress)
            progress.set_description_str("Pipeline complete", refresh=True)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
