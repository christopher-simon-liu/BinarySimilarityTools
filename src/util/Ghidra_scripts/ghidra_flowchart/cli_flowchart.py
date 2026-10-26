#!/usr/bin/env python3
"""Run the Ghidra flowchart post-script over a project tree."""

from __future__ import annotations

import csv
import multiprocessing
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import click
from tqdm import tqdm

SOURCE_ROOT = Path(__file__).resolve().parents[3]
REPO_ROOT = SOURCE_ROOT.parent
DEFAULT_GHIDRA = SOURCE_ROOT / "util" / "ghidra" / "support" / "analyzeHeadless"
GHIDRA_PATH = Path(os.environ.get("GHIDRA_PATH", DEFAULT_GHIDRA))
SCRIPT_DIR = Path(__file__).resolve().parent
GHIDRA_SCRIPT = "ghidra_flowchart.py"


@dataclass(frozen=True)
class Task:
    project_dir: Path
    project_name: str
    identity: str
    output_dir: Path


def _run(task: Task) -> tuple[str, int, str]:
    expected_output = task.output_dir / f"flowchart_{task.project_name}.csv"
    command = [
        str(GHIDRA_PATH),
        str(task.project_dir),
        task.project_name,
        "-scriptPath",
        str(SCRIPT_DIR),
        "-postScript",
        GHIDRA_SCRIPT,
        task.identity,
        task.project_name,
        f"{task.output_dir}{os.sep}",
        "-process",
        task.project_name,
        "-noanalysis",
        "-readonly",
    ]
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    returncode = result.returncode
    if returncode == 0 and not expected_output.is_file():
        returncode = 1
        result.stdout += f"\nExpected output was not created: {expected_output}\n"
    return task.project_name, returncode, result.stdout


def _tasks(project_root: Path, output_dir: Path) -> list[Task]:
    tasks = []
    for index, project_file in enumerate(sorted(project_root.rglob("*.gpr"))):
        project_dir = project_file.parent
        project_name = project_file.stem
        try:
            identity = project_dir.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            identity = project_dir.as_posix()
        # Each process writes into its own directory, so projects with the same
        # filename cannot overwrite one another's intermediate CSV.
        task_output_dir = output_dir / f"{index:06d}"
        task_output_dir.mkdir(parents=True)
        tasks.append(Task(project_dir, project_name, identity, task_output_dir))
    return tasks


def _combine_csvs(parts_dir: Path, output_csv: Path) -> int:
    """Combine per-project files while retaining exactly one header."""
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    row_count = 0
    fieldnames = None
    with output_csv.open("w", encoding="utf-8", newline="") as output:
        writer = None
        for part in sorted(parts_dir.rglob("flowchart_*.csv")):
            with part.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                if fieldnames is None:
                    fieldnames = reader.fieldnames
                    if not fieldnames:
                        continue
                    writer = csv.DictWriter(output, fieldnames=fieldnames)
                    writer.writeheader()
                elif reader.fieldnames != fieldnames:
                    raise click.ClickException(
                        f"incompatible flowchart columns in {part}"
                    )
                for row in reader:
                    writer.writerow(row)
                    row_count += 1
    return row_count


def _log_excerpt(log: str, line_count: int = 8) -> str:
    """Return the useful tail of Ghidra's verbose output."""
    lines = [line for line in log.splitlines() if line.strip()]
    return "\n".join(lines[-line_count:])


@click.command()
@click.option(
    "-p",
    "--ghidra-proj-folder",
    required=True,
    type=click.Path(path_type=Path, file_okay=False),
)
@click.option(
    "-o", "--output-csv", required=True, type=click.Path(path_type=Path, dir_okay=False)
)
@click.option(
    "-b", "--batch-size", default=8, show_default=True, type=click.IntRange(1)
)
def main(ghidra_proj_folder: Path, output_csv: Path, batch_size: int) -> None:
    """Extract and aggregate function summaries from Ghidra projects."""
    if not GHIDRA_PATH.is_file():
        raise click.ClickException(f"Ghidra headless analyzer not found: {GHIDRA_PATH}")
    if not ghidra_proj_folder.is_dir():
        raise click.ClickException(f"project directory does not exist: {ghidra_proj_folder}")

    with tempfile.TemporaryDirectory(prefix="binsim-flowchart-") as temp_dir:
        parts_dir = Path(temp_dir)
        tasks = _tasks(ghidra_proj_folder.resolve(), parts_dir)
        if not tasks:
            raise click.ClickException(
                f"no .gpr projects found in {ghidra_proj_folder}"
            )

        failures: list[tuple[str, str, Path]] = []
        worker_count = min(batch_size, len(tasks))
        with multiprocessing.Pool(processes=worker_count) as pool:
            for name, returncode, log in tqdm(
                pool.imap_unordered(_run, tasks), total=len(tasks)
            ):
                if returncode:
                    log_dir = output_csv.resolve().parent / f"{output_csv.stem}_logs"
                    log_dir.mkdir(parents=True, exist_ok=True)
                    log_path = log_dir / f"{len(failures) + 1:06d}_{name}.log"
                    log_path.write_text(log, encoding="utf-8")
                    failures.append((name, _log_excerpt(log), log_path))
        if failures:
            details = "\n\n".join(
                f"{name} ({log_path}):\n{excerpt}"
                for name, excerpt, log_path in failures
            )
            raise click.ClickException(
                f"flowchart extraction failed for {len(failures)} project(s): "
                + ", ".join(name for name, _, _ in failures)
                + f"\n\n{details}"
            )

        rows = _combine_csvs(parts_dir, output_csv.resolve())
        click.echo(f"Wrote {rows} functions to {output_csv}")


if __name__ == "__main__":
    main()
