# Model adapters

Each model owns an executable `_wrapper.py` that implements the abstract
`ModelAdapter` interface from [`api.py`](api.py).

A wrapper has two responsibilities:

1. Run its model against a preprocessed Ghidra comparison directory.
2. Normalize the native results into the canonical `scores.csv` schema.

All wrappers accept:

```text
--input PATH       preprocessed `DBs/<comparison>` directory
--output PATH      destination scores.csv
--raw PATH         optional existing native output; repeatable and skips execution
--functions PATH   optional function inventory override
```

Wrappers use [`runner.py`](runner.py) to execute retained model stages and
[`normalization.py`](normalization.py) for common parsing and similarity
operations. Format choice remains explicit in each wrapper.

To add a model:

1. Implement `ModelAdapter.run()` to return its native output files.
2. Implement `ModelAdapter.normalize()` to return `NormalizedModelOutput`.
3. Export the adapter as `MODEL` and call `wrapper_main(MODEL)`.
4. Register its wrapper path in `src/main.py`.

Do not add model-format branching to `api.py`; it is intentionally abstract.
