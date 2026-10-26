"""Reusable primitives for model-specific wrapper normalization."""

from __future__ import annotations

import csv
import math
import pickle
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from src.models.api import (
    ComparisonError,
    Function,
    FunctionKey,
    FunctionScore,
    NormalizedModelOutput,
    canonical_address,
    canonical_path,
)

SCORE_FIELDS = ("similarity", "sim", "cs", "score", "cosine_similarity")
PATH_FIELDS = ("idb_path", "path", "binary_path", "file")
ADDRESS_FIELDS = ("fva", "address", "addr", "function_address")
NAME_FIELDS = ("func_name", "function_name", "name")


def _first(row: Mapping[str, Any], fields: Iterable[str]) -> str:
    for field in fields:
        value = row.get(field)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def function_from_row(row: Mapping[str, Any], side: int | None = None) -> Function:
    suffix = f"_{side}" if side else ""
    return Function(
        path=canonical_path(_first(row, (f"{field}{suffix}" for field in PATH_FIELDS))),
        address=canonical_address(
            _first(row, (f"{field}{suffix}" for field in ADDRESS_FIELDS))
        ),
        name=_first(row, (f"{field}{suffix}" for field in NAME_FIELDS)),
    )


def read_csv(path: Path) -> list[dict[str, str]]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                raise ComparisonError(f"CSV has no header: {path}")
            rows = [
                {
                    key.strip(): (value or "").strip()
                    for key, value in row.items()
                    if key and not key.startswith("Unnamed:")
                }
                for row in reader
            ]
            return [
                row
                for row in rows
                if row and not all(value == key for key, value in row.items())
            ]
    except (OSError, csv.Error) as exc:
        raise ComparisonError(f"Cannot read CSV {path}: {exc}") from exc


def _finite_float(value: Any, context: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ComparisonError(f"Expected a numeric value in {context}, got {value!r}") from exc
    if not math.isfinite(result):
        raise ComparisonError(f"Expected a finite value in {context}, got {value!r}")
    return result


def _vector(value: Any, context: str) -> list[float]:
    if hasattr(value, "tolist"):
        value = value.tolist()
    if isinstance(value, str):
        text = value.strip().strip("[]")
        parts = text.split(";") if ";" in text else text.split(",")
        return [_finite_float(part, context) for part in parts if part.strip()]
    if isinstance(value, Sequence):
        return [_finite_float(item, context) for item in value]
    raise ComparisonError(f"Unsupported embedding in {context}: {type(value).__name__}")


def cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or len(left) != len(right):
        raise ComparisonError(
            f"Cannot compare embeddings with dimensions {len(left)} and {len(right)}"
        )
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    return 0.0 if left_norm == 0 or right_norm == 0 else dot / (left_norm * right_norm)


def jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def simhash_similarity(left: tuple[int, int], right: tuple[int, int]) -> float:
    different = (left[0] ^ right[0]).bit_count() + (left[1] ^ right[1]).bit_count()
    return 1.0 - different / 128.0


def read_inventory(path: Path | None) -> dict[FunctionKey, Function]:
    if path is None:
        return {}
    functions: dict[FunctionKey, Function] = {}
    for row in read_csv(path):
        function = function_from_row(row)
        if not function.path or not function.address:
            raise ComparisonError(
                f"Function inventory must contain idb_path/path and fva/address: {path}"
            )
        functions[function.key] = function
    return functions


def _merge_functions(
    raw: Iterable[Function], inventory: Mapping[FunctionKey, Function]
) -> dict[FunctionKey, Function]:
    merged = dict(inventory)
    for function in raw:
        existing = merged.get(function.key)
        merged[function.key] = Function(
            function.path,
            function.address,
            function.name or (existing.name if existing else ""),
        )
    return merged


def _normalize_function_values(
    *,
    raw_paths: Sequence[Path],
    function_path: Path | None,
    required_columns: set[str],
    convert: Callable[[Mapping[str, Any], str], Any],
    similarity: Callable[[Any, Any], float],
) -> NormalizedModelOutput:
    rows: list[Mapping[str, Any]] = []
    seen: set[FunctionKey] = set()
    for path in raw_paths:
        source_rows = read_csv(path)
        if source_rows and not required_columns.issubset(source_rows[0]):
            raise ComparisonError(
                f"{path} lacks required columns: {', '.join(sorted(required_columns))}"
            )
        for row in source_rows:
            function = function_from_row(row)
            if not function.path or not function.address:
                raise ComparisonError(f"Function path or address missing in {path}")
            if function.key in seen:
                raise ComparisonError(
                    f"Model outputs overlap at {function.path}:{function.address}; "
                    "select one variant"
                )
            seen.add(function.key)
        rows.extend(source_rows)
    if not rows:
        raise ComparisonError("Model output contains no functions")

    raw_functions = [function_from_row(row) for row in rows]
    inventory = read_inventory(function_path)
    functions = _merge_functions(raw_functions, inventory)
    values = {
        function.key: convert(row, str(raw_paths[0]))
        for function, row in zip(raw_functions, rows)
    }
    scored_functions = [functions[function.key] for function in raw_functions]
    scores = [
        FunctionScore(left, right, similarity(values[left.key], values[right.key]))
        for left in scored_functions
        for right in scored_functions
        if left.path != right.path
    ]
    return NormalizedModelOutput(functions=functions, scores=scores)


def normalize_embedding_csv(
    raw_paths: Sequence[Path], function_path: Path | None
) -> NormalizedModelOutput:
    return _normalize_function_values(
        raw_paths=raw_paths,
        function_path=function_path,
        required_columns={"embeddings"},
        convert=lambda row, context: _vector(row["embeddings"], context),
        similarity=cosine,
    )


def normalize_catalog1_csv(
    raw_paths: Sequence[Path], function_path: Path | None
) -> NormalizedModelOutput:
    return _normalize_function_values(
        raw_paths=raw_paths,
        function_path=function_path,
        required_columns={"catalog_hash_list"},
        convert=lambda row, _context: {
            item for item in row["catalog_hash_list"].split(";") if item
        },
        similarity=jaccard,
    )


def normalize_simhash_csv(
    raw_paths: Sequence[Path], function_path: Path | None
) -> NormalizedModelOutput:
    return _normalize_function_values(
        raw_paths=raw_paths,
        function_path=function_path,
        required_columns={"hashes0", "hashes1"},
        convert=lambda row, _context: (int(row["hashes0"]), int(row["hashes1"])),
        similarity=simhash_similarity,
    )


def normalize_pair_score_csv(
    raw_paths: Sequence[Path], function_path: Path | None
) -> NormalizedModelOutput:
    inventory = read_inventory(function_path)
    raw_functions: dict[FunctionKey, Function] = {}
    raw_scores: list[tuple[Function, Function, float]] = []
    for path in raw_paths:
        for line, row in enumerate(read_csv(path), start=2):
            left, right = function_from_row(row, 1), function_from_row(row, 2)
            if not left.path or not left.address or not right.path or not right.address:
                raise ComparisonError(f"Pair identity missing in {path}:{line}")
            score_text = _first(row, SCORE_FIELDS)
            if not score_text:
                raise ComparisonError(f"Similarity score missing in {path}:{line}")
            raw_functions[left.key] = left
            raw_functions[right.key] = right
            raw_scores.append((left, right, _finite_float(score_text, f"{path}:{line}")))
    if not raw_scores:
        raise ComparisonError("Model output contains no pair scores")
    functions = _merge_functions(raw_functions.values(), inventory)
    scores = [
        FunctionScore(functions[left.key], functions[right.key], score)
        for left, right, score in raw_scores
    ]
    return NormalizedModelOutput(functions=functions, scores=scores)


def normalize_pickle_embeddings(
    raw_paths: Sequence[Path],
    function_path: Path | None,
    allow_unsafe_pickle: bool,
) -> NormalizedModelOutput:
    if not allow_unsafe_pickle:
        raise ComparisonError(
            "Refusing to load pickle data because it can execute code; "
            "use --allow-unsafe-pickle only for trusted local output"
        )
    if len(raw_paths) != 1:
        raise ComparisonError("Hermessim accepts exactly one pickle output")
    if function_path is None:
        raise ComparisonError("Hermessim pickle output requires --functions")
    functions = read_inventory(function_path)
    ordered_functions = list(functions.values())
    try:
        with raw_paths[0].open("rb") as handle:
            embeddings = pickle.load(handle)
    except OSError as exc:
        raise ComparisonError(f"Cannot read pickle {raw_paths[0]}: {exc}") from exc
    if hasattr(embeddings, "tolist"):
        embeddings = embeddings.tolist()
    if len(ordered_functions) != len(embeddings):
        raise ComparisonError(
            f"Function/embedding count mismatch: {len(ordered_functions)} functions, "
            f"{len(embeddings)} embeddings"
        )
    values = {
        function.key: _vector(embedding, str(raw_paths[0]))
        for function, embedding in zip(ordered_functions, embeddings)
    }
    scores = [
        FunctionScore(left, right, cosine(values[left.key], values[right.key]))
        for left in ordered_functions
        for right in ordered_functions
        if left.path != right.path
    ]
    return NormalizedModelOutput(functions=functions, scores=scores)
