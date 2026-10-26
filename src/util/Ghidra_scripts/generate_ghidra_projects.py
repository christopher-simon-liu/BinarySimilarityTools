#!/usr/bin/env python3
"""Create and validate one headless Ghidra project per input binary."""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

import click

SOURCE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GHIDRA = SOURCE_ROOT / "util" / "ghidra" / "support" / "analyzeHeadless"
GHIDRA_PATH = Path(os.environ.get("GHIDRA_PATH", DEFAULT_GHIDRA))

# Cortex-M firmware normally starts with an SRAM stack pointer and an odd
# reset-vector address. Raw .bin files have no format metadata, so Ghidra needs
# both the language and load address supplied explicitly.
CORTEX_M_LANGUAGE = "ARM:LE:32:Cortex"
IMPORT_SUCCEEDED = "Import succeeded"
PROCESS_SUCCEEDED = "Processing project file:"


@dataclass(frozen=True)
class ImportSettings:
    language: str
    base_address: int


def infer_raw_import_settings(binary: Path) -> ImportSettings | None:
    """Infer common Cortex-M raw-image settings from its vector table."""
    with binary.open("rb") as handle:
        vector_table = handle.read(8)
    if len(vector_table) != 8:
        return None

    initial_sp, reset_vector = struct.unpack("<II", vector_table)
    reset_address = reset_vector & ~1
    stack_is_sram = 0x20000000 <= initial_sp < 0x40000000
    reset_is_thumb = bool(reset_vector & 1)
    base_address = reset_address & 0xFFFF0000
    reset_is_in_image = base_address <= reset_address < base_address + binary.stat().st_size
    if stack_is_sram and reset_is_thumb and reset_is_in_image:
        return ImportSettings(CORTEX_M_LANGUAGE, base_address)
    return None


def resolve_import_settings(
    binary: Path, base_address: int | None
) -> ImportSettings | None:
    """Apply an explicit base address, falling back to vector-table inference."""
    inferred = infer_raw_import_settings(binary)
    if base_address is None:
        return inferred
    language = inferred.language if inferred else CORTEX_M_LANGUAGE
    return ImportSettings(language, base_address)


def _settings_payload(settings: ImportSettings | None) -> dict[str, object]:
    if settings is None:
        return {"mode": "auto"}
    return {
        "mode": "raw",
        "language": settings.language,
        "base_address": settings.base_address,
    }


def _cached_settings_match(config_file: Path, settings: ImportSettings | None) -> bool:
    try:
        cached = json.loads(config_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return False
    return cached == _settings_payload(settings)


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )


def _project_is_usable(project_dir: Path, project_name: str, program_name: str) -> bool:
    """Ask Ghidra to open the cached program instead of trusting an empty .gpr."""
    result = _run(
        [
            str(GHIDRA_PATH),
            str(project_dir),
            project_name,
            "-process",
            program_name,
            "-noanalysis",
            "-readonly",
        ]
    )
    return result.returncode == 0 and PROCESS_SUCCEEDED in result.stdout


def _remove_project(project_dir: Path, project_name: str) -> None:
    """Remove a broken generated project so Ghidra can recreate it."""
    project_file = project_dir / f"{project_name}.gpr"
    project_store = project_dir / f"{project_name}.rep"
    config_file = project_dir / f"{project_name}.import.json"
    project_file.unlink(missing_ok=True)
    config_file.unlink(missing_ok=True)
    if project_store.is_dir():
        shutil.rmtree(project_store)


def analyze_binary(
    project_dir: Path,
    project_name: str,
    binary: Path,
    base_address: int | None = None,
) -> bool:
    """Import ``binary``, repairing an incomplete cached project when needed."""
    project_file = project_dir / f"{project_name}.gpr"
    log_file = project_dir / f"{project_name}.import.log"
    config_file = project_dir / f"{project_name}.import.json"
    settings = resolve_import_settings(binary, base_address)
    if project_file.is_file():
        if (
            _cached_settings_match(config_file, settings)
            and _project_is_usable(project_dir, project_name, binary.name)
        ):
            click.echo(f"[skip] {project_file}")
            return True
        click.echo(f"[repair] rebuilding stale or incomplete project {project_file}")
        _remove_project(project_dir, project_name)

    project_dir.mkdir(parents=True, exist_ok=True)
    command = [
        str(GHIDRA_PATH),
        str(project_dir),
        project_name,
        "-import",
        str(binary),
    ]
    if settings:
        command.extend(
            (
                "-loader",
                "BinaryLoader",
                "-processor",
                settings.language,
                "-loader-baseAddr",
                f"0x{settings.base_address:08x}",
            )
        )
        click.echo(
            f"[analyze] {binary} ({settings.language} at "
            f"0x{settings.base_address:08x})"
        )
    else:
        click.echo(f"[analyze] {binary} (format auto-detection)")

    result = _run(command)
    log_file.write_text(result.stdout, encoding="utf-8")
    succeeded = (
        result.returncode == 0
        and IMPORT_SUCCEEDED in result.stdout
        and project_file.is_file()
    )
    if not succeeded:
        click.echo(f"[error] import failed; see {log_file}", err=True)
    else:
        config_file.write_text(
            json.dumps(_settings_payload(settings), indent=2) + "\n",
            encoding="utf-8",
        )
    return succeeded


def generate_projects(
    binary_root: Path,
    project_root: Path,
    base_addresses: dict[str, int] | None = None,
) -> tuple[int, int]:
    """Mirror the binary directory tree under ``project_root``."""
    successes = failures = 0
    binaries = sorted(path for path in binary_root.rglob("*") if path.is_file())
    for binary in binaries:
        relative_parent = binary.parent.relative_to(binary_root)
        input_name = relative_parent.parts[0] if relative_parent.parts else ""
        base_address = (base_addresses or {}).get(input_name)
        if analyze_binary(
            project_root / relative_parent,
            binary.name,
            binary,
            base_address,
        ):
            successes += 1
        else:
            failures += 1
    return successes, failures


@click.command()
@click.option(
    "--input-dir",
    required=True,
    type=click.Path(path_type=Path, file_okay=False, exists=True),
)
@click.option(
    "--output-dir", required=True, type=click.Path(path_type=Path, file_okay=False)
)
@click.option("--base-address-a", type=str, metavar="ADDRESS")
@click.option("--base-address-b", type=str, metavar="ADDRESS")
def main(
    input_dir: Path,
    output_dir: Path,
    base_address_a: str | None,
    base_address_b: str | None,
) -> None:
    """Create Ghidra projects for every binary below INPUT_DIR."""
    if not GHIDRA_PATH.is_file():
        raise click.ClickException(
            f"Ghidra headless analyzer not found: {GHIDRA_PATH}. "
            "Set GHIDRA_PATH to analyzeHeadless if using another installation."
        )

    base_addresses = {}
    for name, value in (("a", base_address_a), ("b", base_address_b)):
        if value is None:
            continue
        try:
            address = int(value, 0)
        except ValueError as exc:
            raise click.BadParameter(
                f"invalid integer address: {value}",
                param_hint=f"--base-address-{name}",
            ) from exc
        if not 0 <= address <= 0xFFFFFFFFFFFFFFFF:
            raise click.BadParameter(
                "address must be between 0 and 0xffffffffffffffff",
                param_hint=f"--base-address-{name}",
            )
        base_addresses[name] = address

    successes, failures = generate_projects(
        input_dir.resolve(), output_dir.resolve(), base_addresses
    )
    click.echo(f"Ghidra projects: {successes} succeeded, {failures} failed")
    if failures:
        raise click.ClickException(f"failed to create {failures} Ghidra project(s)")


if __name__ == "__main__":
    main()
