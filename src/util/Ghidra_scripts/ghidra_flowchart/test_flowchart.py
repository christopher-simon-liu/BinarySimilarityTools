import csv
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from src.util.Ghidra_scripts.ghidra_flowchart.cli_flowchart import (
    Task,
    _combine_csvs,
    _log_excerpt,
    _run,
    _tasks,
)


class FlowchartHelpersTest(unittest.TestCase):
    def test_tasks_use_distinct_output_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            project_root = root / "projects"
            (project_root / "a").mkdir(parents=True)
            (project_root / "b").mkdir()
            (project_root / "a" / "firmware.gpr").touch()
            (project_root / "b" / "firmware.gpr").touch()

            tasks = _tasks(project_root, root / "parts")

            self.assertEqual([task.project_name for task in tasks], ["firmware"] * 2)
            self.assertEqual(len({task.output_dir for task in tasks}), 2)
            self.assertTrue(all(task.output_dir.is_dir() for task in tasks))

    def test_combine_csvs_writes_one_header_and_all_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parts = root / "parts"
            parts.mkdir()
            columns = ["ghidra_proj_path", "fva", "func_name"]
            for index in range(2):
                part_dir = parts / str(index)
                part_dir.mkdir()
                with (part_dir / f"flowchart_{index}.csv").open(
                    "w", newline=""
                ) as handle:
                    writer = csv.DictWriter(handle, fieldnames=columns)
                    writer.writeheader()
                    writer.writerow(
                        {
                            "ghidra_proj_path": f"project/{index}",
                            "fva": hex(index),
                            "func_name": f"function_{index}",
                        }
                    )

            output = root / "flowchart.csv"
            self.assertEqual(_combine_csvs(parts, output), 2)
            with output.open(newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(
                [row["func_name"] for row in rows],
                ["function_0", "function_1"],
            )

    def test_log_excerpt_keeps_nonempty_tail(self) -> None:
        log = "first\n\nsecond\nthird\n"
        self.assertEqual(_log_excerpt(log, line_count=2), "second\nthird")

    @patch("src.util.Ghidra_scripts.ghidra_flowchart.cli_flowchart.subprocess.run")
    def test_run_fails_when_ghidra_omits_expected_output(self, run_mock) -> None:
        run_mock.return_value = CompletedProcess([], 0, "post-script traceback")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            task = Task(root, "firmware", "project/firmware", root / "output")
            task.output_dir.mkdir()

            _, returncode, log = _run(task)

        self.assertEqual(returncode, 1)
        self.assertIn("Expected output was not created", log)


if __name__ == "__main__":
    unittest.main()
