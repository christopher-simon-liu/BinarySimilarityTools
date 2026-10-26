#!/usr/bin/env python3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from src.models.api import ModelAdapter, wrapper_main
from src.models.normalization import normalize_simhash_csv
from src.models.runner import discover_outputs, run_scripts

WRAPPER_DIR = Path(__file__).resolve().parent
MODEL_DIR = WRAPPER_DIR / "Functionsimsearch"
SOURCE_ROOT = WRAPPER_DIR.parents[1]


class FunctionSimSearchAdapter(ModelAdapter):
    name = "functionsimsearch"

    def run(self, *, preprocessed_dir):
        run_scripts(
            model_dir=MODEL_DIR,
            scripts=("runpart1.sh", "runpart2.sh"),
            preprocessed_dir=preprocessed_dir,
        )
        return discover_outputs(
            (
                str(
                    SOURCE_ROOT
                    / "Results/data/raw_results/FunctionSimSearch/{comparison}/IMM:1.00_MNEM:1.00_GRAPH:1.00.csv"
                ),
            ),
            comparison=preprocessed_dir.name,
        )

    def normalize(self, *, raw_paths, function_path, allow_unsafe_pickle):
        return normalize_simhash_csv(raw_paths, function_path)


MODEL = FunctionSimSearchAdapter()

if __name__ == "__main__":
    raise SystemExit(wrapper_main(MODEL))
