#!/usr/bin/env python3
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from src.models.api import ModelAdapter, wrapper_main
from src.models.normalization import normalize_pickle_embeddings
from src.models.runner import discover_outputs, run_scripts

MODEL_DIR = Path(__file__).resolve().parent / "Hermessim"


def _replace_dataset(value, dataset):
    if isinstance(value, dict):
        return {key: _replace_dataset(item, dataset) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_dataset(item, dataset) for item in value]
    return value.replace("Dataset-1", dataset) if isinstance(value, str) else value


class HermessimAdapter(ModelAdapter):
    name = "hermessim"

    def run(self, *, preprocessed_dir):
        configs = MODEL_DIR / "NeuralNetwork/model/configures"
        template = configs / "e00_major_Dataset-1.json"
        generated = configs / f"e00_major_{preprocessed_dir.name}.json"
        with template.open("r", encoding="utf-8") as handle:
            config = _replace_dataset(json.load(handle), preprocessed_dir.name)
        with generated.open("w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)
        run_scripts(
            model_dir=MODEL_DIR,
            scripts=("runhermessim1.sh", "runhermessim2.sh"),
            preprocessed_dir=preprocessed_dir,
        )
        return discover_outputs(
            (str(MODEL_DIR / "outputs/**/testing_{comparison}.pkl"),),
            comparison=preprocessed_dir.name,
        )

    def normalize(self, *, raw_paths, function_path, allow_unsafe_pickle):
        return normalize_pickle_embeddings(
            raw_paths, function_path, allow_unsafe_pickle
        )


MODEL = HermessimAdapter()

if __name__ == "__main__":
    raise SystemExit(wrapper_main(MODEL))
