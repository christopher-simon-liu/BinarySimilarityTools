#!/usr/bin/env python3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from src.models.api import ModelAdapter, wrapper_main
from src.models.normalization import normalize_embedding_csv
from src.models.runner import discover_outputs, run_scripts

MODEL_DIR = Path(__file__).resolve().parent / "Asm2vec"


class Asm2vecAdapter(ModelAdapter):
    name = "asm2vec"

    def run(self, *, preprocessed_dir):
        run_scripts(
            model_dir=MODEL_DIR,
            scripts=("runPart1.sh", "runPart2.sh"),
            preprocessed_dir=preprocessed_dir,
        )
        return discover_outputs(
            (str(MODEL_DIR / "asm2vec_inference_{comparison}-testing/embeddings.csv"),),
            comparison=preprocessed_dir.name,
        )

    def normalize(self, *, raw_paths, function_path, allow_unsafe_pickle):
        return normalize_embedding_csv(raw_paths, function_path)


MODEL = Asm2vecAdapter()

if __name__ == "__main__":
    raise SystemExit(wrapper_main(MODEL))
