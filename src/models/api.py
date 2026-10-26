#!/usr/bin/env python3
"""Abstract interface shared by model-specific normalization wrappers."""

from __future__ import annotations

import argparse
import csv
import glob
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

RAW_SUFFIXES = {".csv", ".pkl", ".pickle"}
FunctionKey = tuple[str, str]


class ComparisonError(RuntimeError):
    """A comparison error suitable for display by a command-line client."""


@dataclass(frozen=True)
class Function:
    """Canonical identity and display metadata for one binary function."""

    path: str
    address: str
    name: str = ""

    @property
    def key(self) -> FunctionKey:
        return self.path, self.address

    def json(self) -> dict[str, str]:
        return {"address": self.address, "name": self.name}


@dataclass(frozen=True)
class FunctionScore:
    """One model-normalized function-pair score."""

    left: Function
    right: Function
    similarity: float


@dataclass(frozen=True)
class NormalizedModelOutput:
    """The only representation accepted by the shared report generator."""

    functions: Mapping[FunctionKey, Function]
    scores: Sequence[FunctionScore]


class ModelAdapter(ABC):
    """Interface implemented by every model-specific ``*_wrapper.py`` file."""

    name: str

    @abstractmethod
    def run(self, *, preprocessed_dir: Path) -> Sequence[Path]:
        """Run the model and return its native output files."""

    @abstractmethod
    def normalize(
        self,
        *,
        raw_paths: Sequence[Path],
        function_path: Path | None,
        allow_unsafe_pickle: bool,
    ) -> NormalizedModelOutput:
        """Convert native model output into functions and pair scores."""


def canonical_path(value: str) -> str:
    value = value.strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    while "//" in value:
        value = value.replace("//", "/")
    return value


def canonical_address(value: str) -> str:
    value = value.strip().rstrip("L")
    if value.lower().startswith("0x"):
        try:
            return hex(int(value, 16))
        except ValueError:
            pass
    return value


def expand_paths(values: Sequence[str]) -> list[Path]:
    """Expand files, recursive directories, and shell-style globs."""
    paths: list[Path] = []
    for value in values:
        matches = [Path(match) for match in glob.glob(value, recursive=True)]
        if not matches and Path(value).exists():
            matches = [Path(value)]
        for match in matches:
            if match.is_dir():
                paths.extend(
                    path
                    for path in sorted(match.rglob("*"))
                    if path.is_file() and path.suffix.lower() in RAW_SUFFIXES
                )
            elif match.is_file() and match.suffix.lower() in RAW_SUFFIXES:
                paths.append(match)
    return list(dict.fromkeys(path.resolve() for path in paths))


SCORE_COLUMNS = (
    "binary_a",
    "address_a",
    "name_a",
    "binary_b",
    "address_b",
    "name_b",
    "similarity",
)


def write_scores(output: NormalizedModelOutput, path: Path) -> int:
    """Write model-normalized function pairs to the canonical scores CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=SCORE_COLUMNS)
        writer.writeheader()
        for score in output.scores:
            writer.writerow(
                {
                    "binary_a": score.left.path,
                    "address_a": score.left.address,
                    "name_a": score.left.name,
                    "binary_b": score.right.path,
                    "address_b": score.right.address,
                    "name_b": score.right.name,
                    "similarity": format(score.similarity, ".17g"),
                }
            )
    return len(output.scores)


def build_wrapper_parser(adapter: ModelAdapter) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"Run {adapter.name} and normalize its output to scores.csv"
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Preprocessed comparison directory under the DB root",
    )
    parser.add_argument(
        "--raw",
        action="append",
        default=[],
        help="Use existing native model output instead of running; repeat as needed",
    )
    parser.add_argument("--output", required=True, type=Path, help="Canonical scores.csv")
    parser.add_argument(
        "--functions",
        type=Path,
        help="Function inventory CSV; defaults to <input>/features/<name>.csv",
    )
    parser.add_argument(
        "--allow-unsafe-pickle",
        action="store_true",
        help="Load trusted pickle output (pickle can execute arbitrary code)",
    )
    return parser


def wrapper_main(adapter: ModelAdapter, argv: Sequence[str] | None = None) -> int:
    parser = build_wrapper_parser(adapter)
    args = parser.parse_args(argv)
    try:
        preprocessed_dir = args.input.resolve()
        if not preprocessed_dir.is_dir():
            raise ComparisonError(
                f"Preprocessed comparison directory does not exist: {preprocessed_dir}"
            )
        raw_paths = expand_paths(args.raw) if args.raw else list(
            adapter.run(preprocessed_dir=preprocessed_dir)
        )
        function_path = args.functions
        if function_path is None:
            candidate = (
                preprocessed_dir
                / "features"
                / f"{preprocessed_dir.name}.csv"
            )
            function_path = candidate if candidate.is_file() else None
        normalized = adapter.normalize(
            raw_paths=raw_paths,
            function_path=function_path,
            # Output produced by adapter.run() is local and trusted. External
            # pickle input remains explicitly gated.
            allow_unsafe_pickle=args.allow_unsafe_pickle or not args.raw,
        )
        count = write_scores(normalized, args.output)
    except ComparisonError as exc:
        parser.error(str(exc))
    print(f"Wrote {count} normalized scores to {args.output}")
    return 0
