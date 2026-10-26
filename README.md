# Binary Similarity Tools

Binary Similarity Tools compares two binaries with a selectable function
similarity model. One command performs the complete workflow:

1. Import and analyze both binaries with headless Ghidra.
2. Extract function inventories, disassembly, and ACFG features.
3. Run the selected model through its model-specific wrapper.
4. Normalize native model output into `scores.csv`.
5. Rank the scores and retain the three highest-scoring binary-B matches per
   binary-A function in `<model>_report_<binary-a>_<binary-b>.json`.

## Run a comparison

```bash
scripts/entrypoint.sh \
  --binary-a /path/to/firmware-v1 \
  --binary-b /path/to/firmware-v2 \
  --base-address-a 0x08000000 \
  --base-address-b 0x08040000 \
  --model catalog1 \
  --output output/reports
```

For `firmware-v1` and `firmware-v2`, this writes
`output/reports/catalog1_report_firmware-v1_firmware-v2.json`.

Supported model names are:

```text
asm2vec
catalog1
functionsimsearch
gnn-s2v-gemini
gnn-s2v-massarelli
hermessim
safe
trex
zeek
```

### Examples for every model

Asm2Vec:

```bash
./scripts/entrypoint.sh --binary-a ./input/px4_fmu-v6x.bin --base-address-a 0x08020000 --binary-b ./input/Basic.bin --base-address-b 0x00080000 --model asm2vec --output ./output
```

Catalog1:

```bash
./scripts/entrypoint.sh --binary-a ./input/px4_fmu-v6x.bin --base-address-a 0x08020000 --binary-b ./input/Basic.bin --base-address-b 0x00080000 --model catalog1 --output ./output
```

FunctionSimSearch:

```bash
./scripts/entrypoint.sh --binary-a ./input/px4_fmu-v6x.bin --base-address-a 0x08020000 --binary-b ./input/Basic.bin --base-address-b 0x00080000 --model functionsimsearch --output ./output
```

GNN-s2v Gemini:

```bash
./scripts/entrypoint.sh --binary-a ./input/px4_fmu-v6x.bin --base-address-a 0x08020000 --binary-b ./input/Basic.bin --base-address-b 0x00080000 --model gnn-s2v-gemini --output ./output
```

GNN-s2v Massarelli:

```bash
./scripts/entrypoint.sh --binary-a ./input/px4_fmu-v6x.bin --base-address-a 0x08020000 --binary-b ./input/Basic.bin --base-address-b 0x00080000 --model gnn-s2v-massarelli --output ./output
```

HermesSim:

```bash
./scripts/entrypoint.sh --binary-a ./input/px4_fmu-v6x.bin --base-address-a 0x08020000 --binary-b ./input/Basic.bin --base-address-b 0x00080000 --model hermessim --output ./output
```

SAFE:

```bash
./scripts/entrypoint.sh --binary-a ./input/px4_fmu-v6x.bin --base-address-a 0x08020000 --binary-b ./input/Basic.bin --base-address-b 0x00080000 --model safe --output ./output
```

Trex:

```bash
./scripts/entrypoint.sh --binary-a ./input/px4_fmu-v6x.bin --base-address-a 0x08020000 --binary-b ./input/Basic.bin --base-address-b 0x00080000 --model trex --output ./output
```

Zeek:

```bash
./scripts/entrypoint.sh --binary-a ./input/px4_fmu-v6x.bin --base-address-a 0x08020000 --binary-b ./input/Basic.bin --base-address-b 0x00080000 --model zeek --output ./output
```

Intermediate Ghidra data and normalized scores are retained under
`output/runs/`. Use `--comparison-name` to choose their comparison identifier,
`--workspace` to choose another root, `--batch-size` to control Ghidra
parallelism, and `--min-basic-blocks` to change function filtering.
`--output` selects the report directory, which is created when necessary.
The command displays a stage-level progress bar throughout preprocessing,
model execution, and report generation.
Use `--top-n` to change the number of matches retained per Binary-A function;
the default is `3`.
Use `--min-similarity` to omit scores less than or equal to a threshold. Its
default is `0`, so zero and negative similarities are reported as unmatched.
Use `--base-address-a` and `--base-address-b` for raw firmware load addresses;
each accepts decimal or `0x`-prefixed notation. When an address is omitted,
the pipeline falls back to Cortex-M vector-table inference.

Each retained model has its own Docker/runtime requirements. When native model
output already exists, repeat `--raw PATH` to bypass model execution while
still using the selected model wrapper's normalization.

## Pipeline boundaries

[`src/main.py`](src/main.py) is the orchestration pipeline. It stages the two
binaries, runs Ghidra preprocessing, invokes the selected wrapper, and then
invokes the report generator. [`scripts/entrypoint.sh`](scripts/entrypoint.sh)
only forwards its arguments to `main.py`.

Every `src/models/**/_wrapper.py` has the same standalone interface:

```bash
python3 src/models/Catalog1/Catalog1_wrapper.py \
  --input output/runs/DBs/example \
  --output output/runs/results/example/catalog1/scores.csv
```

A wrapper receives a preprocessed comparison, runs its model, and writes the
canonical score schema:

```text
binary_a,address_a,name_a,binary_b,address_b,name_b,similarity
```

[`src/models/api.py`](src/models/api.py) contains only the abstract
`ModelAdapter` contract, normalized function/score types, and model-independent
score serialization. Shared parsing and similarity helpers live in
[`src/models/normalization.py`](src/models/normalization.py).

[`src/generate_report.py`](src/generate_report.py) consumes only `scores.csv`:

The main pipeline automatically records its original binary paths in the
report. For standalone report generation, `--source-binary-a` and
`--source-binary-b` both establish the A/B orientation and set the displayed
paths. The separate `--binary-a` and `--binary-b` selectors are optional and
are needed only when source basenames are ambiguous in `scores.csv`.

```bash
python3 src/generate_report.py \
  --scores output/scores.csv \
  --source-binary-a input/firmware-v1 \
  --source-binary-b input/firmware-v2 \
  --model catalog1 \
  --top-n 3 \
  --min-similarity 0 \
  --output output/reports/catalog1_report_firmware-v1_firmware-v2.json
```

## Report format

```json
{
  "schema_version": "1.3",
  "model": {"name": "catalog1", "variant": "default"},
  "binaries": {
    "a": {"path": "input/firmware-v1"},
    "b": {"path": "input/firmware-v2"}
  },
  "score_semantics": "higher_is_more_similar",
  "top_n": 3,
  "min_similarity": 0.0,
  "functions": [
    {
      "function": {"address": "0x1010", "name": "parse_packet"},
      "top_matches": [
        {"address": "0x2050", "name": "FUN_2050", "similarity": 0.923},
        {"address": "0x2060", "name": "FUN_2060", "similarity": 0.901},
        {"address": "0x2070", "name": "FUN_2070", "similarity": 0.887}
      ]
    }
  ],
  "summary": {"functions": 1, "matched": 1, "unmatched": 0}
}
```

Scores remain in the selected model's native range; larger values always mean
more similar.

## Requirements and tests

### Ghidra

The preprocessing pipeline is tested with **Ghidra 11.0.3 PUBLIC** and a
64-bit JDK 17 or newer. Download the prebuilt archive from the official
[Ghidra 11.0.3 release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_11.0.3_build).
The release archive is named `ghidra_11.0.3_PUBLIC_20240410.zip`; its published
SHA-256 checksum is
`2462a2d0ab11e30f9e907cd3b4aa6b48dd2642f325617e3d922c28e752be6761`.

Extract and rename the release directory so the headless analyzer is located
at `src/util/ghidra/support/analyzeHeadless`:

```bash
mkdir -p src/util
unzip ~/Downloads/ghidra_11.0.3_PUBLIC_20240410.zip -d src/util
mv src/util/ghidra_11.0.3_PUBLIC src/util/ghidra
```

Verify the installed version:

```bash
grep '^application.version=' src/util/ghidra/Ghidra/application.properties
# application.version=11.0.3
```

If Ghidra is installed elsewhere, set `GHIDRA_PATH` to its `analyzeHeadless`
executable instead of placing it under `src/util`.

### Python dependencies

Install the launcher dependencies with:

```bash
python3 -m venv env
source env/bin/activate
pip install -r src/util/Ghidra_scripts/requirements.txt
```

Run the lightweight API tests with:

```bash
python3 -m unittest src.models.test_api -v
```
