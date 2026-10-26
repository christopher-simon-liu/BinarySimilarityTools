"""Execution helpers used by concrete model wrappers."""

from __future__ import annotations

import glob
import os
import subprocess
from pathlib import Path
from collections.abc import Sequence

from src.models.api import ComparisonError


def run_scripts(
    *,
    model_dir: Path,
    scripts: Sequence[str],
    preprocessed_dir: Path,
) -> None:
    """Run retained model stages against one preprocessed comparison."""
    if not (preprocessed_dir / "features").is_dir():
        raise ComparisonError(
            f"Preprocessed input has no features directory: {preprocessed_dir}"
        )
    environment = {
        **os.environ,
        "BINSIM_DB_ROOT": str(preprocessed_dir.parent.resolve()),
    }
    repo_root = Path(__file__).resolve().parents[2]
    existing_pythonpath = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = (
        str(repo_root)
        if not existing_pythonpath
        else f"{repo_root}{os.pathsep}{existing_pythonpath}"
    )
    for script_name in scripts:
        script = model_dir / script_name
        if not script.is_file():
            raise ComparisonError(f"Model runner is missing: {script}")
        try:
            subprocess.run(
                ["bash", str(script), preprocessed_dir.name],
                cwd=model_dir,
                env=environment,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            raise ComparisonError(
                f"Model stage failed with exit code {exc.returncode}: {script}"
            ) from exc


def discover_outputs(patterns: Sequence[str], *, comparison: str) -> list[Path]:
    """Resolve model-native result patterns after execution."""
    paths: list[Path] = []
    for pattern in patterns:
        paths.extend(
            Path(match).resolve()
            for match in sorted(
                glob.glob(pattern.format(comparison=comparison), recursive=True)
            )
            if Path(match).is_file()
        )
    paths = list(dict.fromkeys(paths))
    if not paths:
        raise ComparisonError("Model completed but produced no discoverable output")
    return paths
