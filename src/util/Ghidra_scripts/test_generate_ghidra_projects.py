import json
import struct
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from src.util.Ghidra_scripts.generate_ghidra_projects import (
    CORTEX_M_LANGUAGE,
    analyze_binary,
    generate_projects,
    infer_raw_import_settings,
    resolve_import_settings,
)


class RawImportInferenceTest(unittest.TestCase):
    def test_infers_cortex_m_language_and_flash_base(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "firmware.bin"
            binary.write_bytes(
                struct.pack("<II", 0x20010000, 0x08020305) + bytes(0x400)
            )

            settings = infer_raw_import_settings(binary)

            self.assertIsNotNone(settings)
            assert settings is not None
            self.assertEqual(settings.language, CORTEX_M_LANGUAGE)
            self.assertEqual(settings.base_address, 0x08020000)

    def test_does_not_guess_unknown_raw_format(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "unknown.bin"
            binary.write_bytes(b"not a vector table")

            self.assertIsNone(infer_raw_import_settings(binary))

    def test_explicit_base_address_overrides_inference(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "firmware.bin"
            binary.write_bytes(
                struct.pack("<II", 0x20010000, 0x08020305) + bytes(0x400)
            )

            settings = resolve_import_settings(binary, 0x08100000)

            self.assertIsNotNone(settings)
            assert settings is not None
            self.assertEqual(settings.language, CORTEX_M_LANGUAGE)
            self.assertEqual(settings.base_address, 0x08100000)

    @patch("src.util.Ghidra_scripts.generate_ghidra_projects.analyze_binary")
    def test_routes_each_base_address_to_its_binary(self, analyze_mock) -> None:
        analyze_mock.return_value = True
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary_root = root / "input"
            (binary_root / "a").mkdir(parents=True)
            (binary_root / "b").mkdir()
            binary_a = binary_root / "a" / "a.bin"
            binary_b = binary_root / "b" / "b.bin"
            binary_a.touch()
            binary_b.touch()

            result = generate_projects(
                binary_root,
                root / "projects",
                {"a": 0x08020000, "b": 0x00080000},
            )

        self.assertEqual(result, (2, 0))
        self.assertEqual(analyze_mock.call_args_list[0].args[-1], 0x08020000)
        self.assertEqual(analyze_mock.call_args_list[1].args[-1], 0x00080000)

    @patch("src.util.Ghidra_scripts.generate_ghidra_projects._run")
    def test_changed_base_address_rebuilds_cached_project(self, run_mock) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary = root / "firmware.bin"
            binary.write_bytes(
                struct.pack("<II", 0x20010000, 0x08020305) + bytes(0x400)
            )
            project_dir = root / "projects"
            project_dir.mkdir()
            project_file = project_dir / "firmware.gpr"
            project_file.touch()
            (project_dir / "firmware.rep").mkdir()
            (project_dir / "firmware.import.json").write_text(
                json.dumps(
                    {
                        "mode": "raw",
                        "language": CORTEX_M_LANGUAGE,
                        "base_address": 0x08020000,
                    }
                )
            )

            def import_binary(_command):
                project_file.touch()
                return CompletedProcess([], 0, "REPORT: Import succeeded")

            run_mock.side_effect = import_binary
            succeeded = analyze_binary(
                project_dir,
                "firmware",
                binary,
                0x08100000,
            )

            config = json.loads(
                (project_dir / "firmware.import.json").read_text()
            )

        self.assertTrue(succeeded)
        self.assertEqual(config["base_address"], 0x08100000)

    @patch("src.util.Ghidra_scripts.generate_ghidra_projects._run")
    def test_rejects_ghidra_zero_exit_without_import_success(self, run_mock) -> None:
        run_mock.return_value = CompletedProcess([], 0, "REPORT: Import failed")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            binary = root / "unknown.bin"
            binary.write_bytes(b"not a recognized executable format")

            succeeded = analyze_binary(root / "projects", "unknown", binary)

        self.assertFalse(succeeded)


if __name__ == "__main__":
    unittest.main()
