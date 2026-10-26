import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.main import PIPELINE_STAGES, _report_path, build_parser, main, preprocess


class PipelineArgumentsTest(unittest.TestCase):
    def test_report_path_uses_binary_stems(self) -> None:
        path = _report_path(
            Path("reports"),
            "catalog1",
            Path("firmware-a.bin"),
            Path("firmware-b.elf"),
        )

        self.assertEqual(
            path,
            Path("reports/catalog1_report_firmware-a_firmware-b.json"),
        )

    def test_output_argument_is_a_directory_path(self) -> None:
        args = build_parser().parse_args(
            [
                "--binary-a",
                "a.bin",
                "--binary-b",
                "b.bin",
                "--model",
                "catalog1",
                "--output",
                "reports",
            ]
        )

        self.assertEqual(args.output, Path("reports"))

    @patch("src.main._project_selectors")
    @patch("src.main._create_model_layout")
    @patch("src.main._run")
    @patch("src.main._stage_binary")
    def test_preprocessing_advances_all_seven_stages(
        self,
        _stage_binary_mock,
        run_mock,
        _create_model_layout_mock,
        project_selectors_mock,
    ) -> None:
        project_selectors_mock.return_value = ("binary-a", "binary-b")
        progress = MagicMock()
        with tempfile.TemporaryDirectory() as temp_dir:
            preprocess(
                binary_a=Path("a.bin"),
                binary_b=Path("b.bin"),
                comparison="comparison",
                workspace=Path(temp_dir),
                batch_size=2,
                min_basic_blocks=5,
                progress=progress,
            )

        descriptions = [
            call.args[0]
            for call in progress.set_description_str.call_args_list
        ]
        self.assertEqual(
            descriptions,
            [
                "Staging binaries",
                "Creating Ghidra projects",
                "Extracting flowcharts",
                "Selecting functions",
                "Extracting disassembly",
                "Extracting ACFG features",
                "Preparing model inputs",
            ],
        )
        self.assertEqual(progress.update.call_count, 7)
        self.assertEqual(run_mock.call_count, 5)

    @patch("src.main.tqdm")
    @patch("src.main._run")
    @patch("src.main.preprocess")
    def test_main_passes_derived_report_path(
        self, preprocess_mock, run_mock, tqdm_mock
    ) -> None:
        preprocess_mock.return_value = (
            Path("comparison"),
            Path("functions.csv"),
            "binary-a-selector",
            "binary-b-selector",
        )
        progress = tqdm_mock.return_value.__enter__.return_value
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary_a = root / "firmware-a.bin"
            binary_b = root / "firmware-b.elf"
            binary_a.touch()
            binary_b.touch()
            output_dir = root / "reports"
            argv = [
                "main.py",
                "--binary-a",
                str(binary_a),
                "--binary-b",
                str(binary_b),
                "--model",
                "catalog1",
                "--output",
                str(output_dir),
            ]

            with patch("sys.argv", argv):
                result = main()

            report_command = run_mock.call_args_list[-1].args[0]

        self.assertEqual(result, 0)
        tqdm_mock.assert_called_once_with(
            total=PIPELINE_STAGES,
            desc="Starting pipeline",
            unit="stage",
            dynamic_ncols=True,
        )
        self.assertIs(preprocess_mock.call_args.kwargs["progress"], progress)
        self.assertEqual(progress.update.call_count, 2)
        self.assertEqual(
            report_command[report_command.index("--top-n") + 1],
            "3",
        )
        self.assertEqual(
            report_command[report_command.index("--min-similarity") + 1],
            "0.0",
        )
        self.assertEqual(
            Path(report_command[report_command.index("--output") + 1]),
            output_dir / "catalog1_report_firmware-a_firmware-b.json",
        )


if __name__ == "__main__":
    unittest.main()
