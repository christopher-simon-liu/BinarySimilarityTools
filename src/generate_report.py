#!/usr/bin/env python3
"""Generate report.json from the canonical model scores.csv."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.models.api import (
    ComparisonError,
    Function,
    FunctionScore,
    NormalizedModelOutput,
    SCORE_COLUMNS,
    FunctionKey,
    canonical_address,
    canonical_path,
)

SCHEMA_VERSION = "1.3"
DEFAULT_TOP_N = 3
DEFAULT_MIN_SIMILARITY = 0.0


def _address_sort_key(value: str) -> tuple[int, int | str]:
    try:
        return 0, int(value, 0)
    except ValueError:
        return 1, value


def _resolve_binary(selector: str, functions: Iterable[Function]) -> str:
    paths = sorted({function.path for function in functions if function.path})
    selector = canonical_path(selector)
    if selector in paths:
        return selector
    name = Path(selector).name
    stem = Path(name).stem
    matches = [
        path for path in paths if Path(path).name == name or Path(path).stem == stem
    ]
    if not matches:
        raise ComparisonError(f"Binary {selector!r} is not present in scores.csv")
    if len(matches) != 1:
        raise ComparisonError(
            f"Binary selector {selector!r} is ambiguous; matches: {', '.join(matches)}"
        )
    return matches[0]


def _resolve_binary_pair(
    normalized: NormalizedModelOutput,
    binary_a: str | None,
    binary_b: str | None,
    source_binary_a: str | None,
    source_binary_b: str | None,
) -> tuple[str, str]:
    """Resolve score identities from optional selectors or source paths."""
    functions = normalized.functions.values()
    paths = sorted({function.path for function in functions if function.path})
    selector_a = binary_a or source_binary_a
    selector_b = binary_b or source_binary_b
    resolved_a = _resolve_binary(selector_a, functions) if selector_a else None
    resolved_b = _resolve_binary(selector_b, functions) if selector_b else None

    if resolved_a is None and resolved_b is not None:
        remaining = [path for path in paths if path != resolved_b]
        if len(remaining) == 1:
            resolved_a = remaining[0]
    elif resolved_b is None and resolved_a is not None:
        remaining = [path for path in paths if path != resolved_a]
        if len(remaining) == 1:
            resolved_b = remaining[0]
    elif resolved_a is None and resolved_b is None:
        left_paths = {score.left.path for score in normalized.scores}
        right_paths = {score.right.path for score in normalized.scores}
        if len(left_paths) == 1 and len(right_paths) == 1:
            resolved_a = next(iter(left_paths))
            resolved_b = next(iter(right_paths))

    if resolved_a is None or resolved_b is None:
        raise ComparisonError(
            "Cannot infer Binary A and Binary B from scores.csv; provide source "
            "paths or the optional --binary-a/--binary-b selectors"
        )
    return resolved_a, resolved_b


def create_report(
    *,
    model_name: str,
    normalized: NormalizedModelOutput,
    output_path: Path,
    binary_a: str | None = None,
    binary_b: str | None = None,
    source_binary_a: str | None = None,
    source_binary_b: str | None = None,
    variant: str | None = None,
    top_n: int = DEFAULT_TOP_N,
    min_similarity: float = DEFAULT_MIN_SIMILARITY,
) -> dict[str, Any]:
    """Select the highest-scoring binary-B matches for every A function."""
    if top_n < 1:
        raise ComparisonError("top_n must be positive")
    if not math.isfinite(min_similarity):
        raise ComparisonError("min_similarity must be finite")
    functions = normalized.functions
    resolved_a, resolved_b = _resolve_binary_pair(
        normalized,
        binary_a,
        binary_b,
        source_binary_a,
        source_binary_b,
    )
    if resolved_a == resolved_b:
        raise ComparisonError("Binary A and binary B must be different")
    functions_a = sorted(
        (function for function in functions.values() if function.path == resolved_a),
        key=lambda function: (_address_sort_key(function.address), function.name),
    )
    functions_b = [function for function in functions.values() if function.path == resolved_b]
    if not functions_a or not functions_b:
        raise ComparisonError("Both binaries must contain at least one scored function")

    candidates: dict[
        FunctionKey, dict[FunctionKey, tuple[Function, float]]
    ] = {}
    for score in normalized.scores:
        left, right = score.left, score.right
        if left.path == resolved_b and right.path == resolved_a:
            left, right = right, left
        if left.path != resolved_a or right.path != resolved_b:
            continue
        if score.similarity <= min_similarity:
            continue
        matches = candidates.setdefault(left.key, {})
        previous = matches.get(right.key)
        candidate_key = (-score.similarity, _address_sort_key(right.address), right.name)
        previous_key = (
            (-previous[1], _address_sort_key(previous[0].address), previous[0].name)
            if previous
            else None
        )
        if previous_key is None or candidate_key < previous_key:
            matches[right.key] = right, score.similarity

    report_functions = []
    for function in functions_a:
        ranked = sorted(
            candidates.get(function.key, {}).values(),
            key=lambda match: (
                -match[1],
                _address_sort_key(match[0].address),
                match[0].name,
            ),
        )[:top_n]
        report_functions.append(
            {
                "function": function.json(),
                "top_matches": [
                    {**match.json(), "similarity": similarity}
                    for match, similarity in ranked
                ],
            }
        )
    matched = sum(bool(item["top_matches"]) for item in report_functions)
    report = {
        "schema_version": SCHEMA_VERSION,
        "model": {"name": model_name, "variant": variant or "default"},
        "binaries": {
            "a": {"path": canonical_path(source_binary_a or binary_a or resolved_a)},
            "b": {"path": canonical_path(source_binary_b or binary_b or resolved_b)},
        },
        "score_semantics": "higher_is_more_similar",
        "top_n": top_n,
        "min_similarity": min_similarity,
        "functions": report_functions,
        "summary": {
            "functions": len(report_functions),
            "matched": matched,
            "unmatched": len(report_functions) - matched,
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    return report


def read_scores(path: Path) -> NormalizedModelOutput:
    functions = {}
    scores = []
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            missing = [
                column
                for column in SCORE_COLUMNS
                if column not in (reader.fieldnames or ())
            ]
            if missing:
                raise ComparisonError(
                    f"Scores CSV is missing columns: {', '.join(missing)}"
                )
            for line, row in enumerate(reader, start=2):
                left = Function(
                    canonical_path(row["binary_a"]),
                    canonical_address(row["address_a"]),
                    row["name_a"].strip(),
                )
                right = Function(
                    canonical_path(row["binary_b"]),
                    canonical_address(row["address_b"]),
                    row["name_b"].strip(),
                )
                try:
                    similarity = float(row["similarity"])
                except (TypeError, ValueError) as exc:
                    raise ComparisonError(
                        f"Invalid similarity in {path}:{line}: {row['similarity']!r}"
                    ) from exc
                if not math.isfinite(similarity):
                    raise ComparisonError(f"Non-finite similarity in {path}:{line}")
                functions[left.key] = left
                functions[right.key] = right
                scores.append(FunctionScore(left, right, similarity))
    except OSError as exc:
        raise ComparisonError(f"Cannot read scores CSV {path}: {exc}") from exc
    if not scores:
        raise ComparisonError(f"Scores CSV contains no function scores: {path}")
    return NormalizedModelOutput(functions=functions, scores=scores)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a two-binary function match report from normalized scores"
    )
    parser.add_argument("--scores", required=True, type=Path)
    parser.add_argument(
        "--binary-a",
        help="Optional Binary-A selector for ambiguous scores",
    )
    parser.add_argument(
        "--binary-b",
        help="Optional Binary-B selector for ambiguous scores",
    )
    parser.add_argument(
        "--source-binary-a",
        help="Source Binary-A path used for orientation and report display",
    )
    parser.add_argument(
        "--source-binary-b",
        help="Source Binary-B path used for orientation and report display",
    )
    parser.add_argument("--model", required=True)
    parser.add_argument("--variant")
    parser.add_argument("--top-n", type=int, default=DEFAULT_TOP_N)
    parser.add_argument(
        "--min-similarity",
        type=float,
        default=DEFAULT_MIN_SIMILARITY,
        help="Exclude similarities less than or equal to this value (default: 0)",
    )
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.top_n < 1:
        parser.error("top-n must be positive")
    if not math.isfinite(args.min_similarity):
        parser.error("min-similarity must be finite")
    try:
        report = create_report(
            model_name=args.model,
            normalized=read_scores(args.scores),
            output_path=args.output,
            binary_a=args.binary_a,
            binary_b=args.binary_b,
            source_binary_a=args.source_binary_a,
            source_binary_b=args.source_binary_b,
            variant=args.variant,
            top_n=args.top_n,
            min_similarity=args.min_similarity,
        )
    except ComparisonError as exc:
        parser.error(str(exc))
    summary = report["summary"]
    print(
        f"Wrote report for {summary['functions']} functions "
        f"({summary['matched']} matched, {summary['unmatched']} unmatched) "
        f"to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
