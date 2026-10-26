import tempfile
import unittest
from pathlib import Path

from src.generate_report import create_report
from src.models.api import (
    ComparisonError,
    Function,
    FunctionScore,
    NormalizedModelOutput,
)


class GenerateReportTest(unittest.TestCase):
    def test_returns_top_three_distinct_matches_in_score_order(self) -> None:
        function_a = Function("a.bin", "0x10", "source")
        candidates = [
            Function("b.bin", "0x40", "fourth"),
            Function("b.bin", "0x20", "second"),
            Function("b.bin", "0x30", "third"),
            Function("b.bin", "0x11", "first"),
        ]
        scores = [
            FunctionScore(function_a, candidates[0], 0.1),
            FunctionScore(function_a, candidates[1], 0.8),
            FunctionScore(function_a, candidates[2], 0.8),
            FunctionScore(candidates[3], function_a, 0.9),
            # Duplicate A/B pair: only its highest score should remain.
            FunctionScore(function_a, candidates[1], 0.7),
        ]
        functions = {
            function.key: function
            for function in [function_a, *candidates]
        }
        normalized = NormalizedModelOutput(functions, scores)

        with tempfile.TemporaryDirectory() as temp_dir:
            report = create_report(
                model_name="test-model",
                normalized=normalized,
                output_path=Path(temp_dir) / "report.json",
                source_binary_a="input/a.bin",
                source_binary_b="input/b.bin",
            )

        self.assertEqual(report["schema_version"], "1.3")
        self.assertEqual(
            report["binaries"],
            {
                "a": {"path": "input/a.bin"},
                "b": {"path": "input/b.bin"},
            },
        )
        self.assertEqual(report["top_n"], 3)
        self.assertEqual(report["min_similarity"], 0.0)
        self.assertEqual(
            report["functions"][0]["top_matches"],
            [
                {"address": "0x11", "name": "first", "similarity": 0.9},
                {"address": "0x20", "name": "second", "similarity": 0.8},
                {"address": "0x30", "name": "third", "similarity": 0.8},
            ],
        )

    def test_top_n_is_configurable(self) -> None:
        function_a = Function("a.bin", "0x10", "source")
        function_b = Function("b.bin", "0x20", "target")
        normalized = NormalizedModelOutput(
            {function_a.key: function_a, function_b.key: function_b},
            [FunctionScore(function_a, function_b, 0.5)],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            report = create_report(
                model_name="test-model",
                normalized=normalized,
                output_path=Path(temp_dir) / "report.json",
                binary_a="a.bin",
                binary_b="b.bin",
                top_n=1,
            )

        self.assertEqual(report["top_n"], 1)
        self.assertEqual(len(report["functions"][0]["top_matches"]), 1)

    def test_infers_binary_order_from_one_way_scores(self) -> None:
        function_a = Function("a.bin", "0x10", "source")
        function_b = Function("b.bin", "0x20", "target")
        normalized = NormalizedModelOutput(
            {function_a.key: function_a, function_b.key: function_b},
            [FunctionScore(function_a, function_b, 0.5)],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            report = create_report(
                model_name="test-model",
                normalized=normalized,
                output_path=Path(temp_dir) / "report.json",
            )

        self.assertEqual(
            report["binaries"],
            {"a": {"path": "a.bin"}, "b": {"path": "b.bin"}},
        )

    def test_requires_orientation_for_symmetric_scores(self) -> None:
        function_a = Function("a.bin", "0x10", "source")
        function_b = Function("b.bin", "0x20", "target")
        normalized = NormalizedModelOutput(
            {function_a.key: function_a, function_b.key: function_b},
            [
                FunctionScore(function_a, function_b, 0.5),
                FunctionScore(function_b, function_a, 0.5),
            ],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(ComparisonError, "Cannot infer Binary A"):
                create_report(
                    model_name="test-model",
                    normalized=normalized,
                    output_path=Path(temp_dir) / "report.json",
                )

    def test_omits_scores_less_than_or_equal_to_minimum(self) -> None:
        function_a = Function("a.bin", "0x10", "source")
        candidates = [
            Function("b.bin", "0x20", "below"),
            Function("b.bin", "0x30", "equal"),
            Function("b.bin", "0x40", "above"),
        ]
        normalized = NormalizedModelOutput(
            {
                function.key: function
                for function in [function_a, *candidates]
            },
            [
                FunctionScore(function_a, candidates[0], 0.1),
                FunctionScore(function_a, candidates[1], 0.2),
                FunctionScore(function_a, candidates[2], 0.3),
            ],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            report = create_report(
                model_name="test-model",
                normalized=normalized,
                output_path=Path(temp_dir) / "report.json",
                binary_a="a.bin",
                binary_b="b.bin",
                min_similarity=0.2,
            )

        self.assertEqual(report["min_similarity"], 0.2)
        self.assertEqual(
            report["functions"][0]["top_matches"],
            [{"address": "0x40", "name": "above", "similarity": 0.3}],
        )

    def test_zero_similarity_is_unmatched_by_default(self) -> None:
        function_a = Function("a.bin", "0x10", "source")
        function_b = Function("b.bin", "0x20", "target")
        normalized = NormalizedModelOutput(
            {function_a.key: function_a, function_b.key: function_b},
            [FunctionScore(function_a, function_b, 0.0)],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            report = create_report(
                model_name="test-model",
                normalized=normalized,
                output_path=Path(temp_dir) / "report.json",
                binary_a="a.bin",
                binary_b="b.bin",
            )

        self.assertEqual(report["functions"][0]["top_matches"], [])
        self.assertEqual(report["summary"]["matched"], 0)
        self.assertEqual(report["summary"]["unmatched"], 1)


if __name__ == "__main__":
    unittest.main()
