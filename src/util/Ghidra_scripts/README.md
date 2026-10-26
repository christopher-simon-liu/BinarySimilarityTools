# Ghidra extraction support

These Python launchers implement the preprocessing stage of the main command:

```bash
scripts/entrypoint.sh --binary-a A --binary-b B --model MODEL --output reports/
```

The command imports exactly two binaries with the bundled headless Ghidra,
then extracts a function inventory, selected-function metadata, ACFG
disassembly, and numerical ACFG features. The resulting compatibility fields
include `idb_path` and `fva` because the retained models consume those names.

Raw Cortex-M firmware is recognized from its vector table and imported with
Ghidra's raw binary loader at the inferred 64-KiB-aligned flash address. Other
formats continue to use Ghidra's normal loader auto-detection. Generated
projects are validated before reuse, so an interrupted or loader-less import
is repaired instead of being mistaken for a valid cached project. Import logs
are written beside each `.gpr`; failed extraction logs are written beside the
requested flowchart CSV.

The pipeline accepts `--base-address-a` and `--base-address-b` in decimal or
`0x`-prefixed notation. An explicit value overrides the inferred address for
that binary; inference remains the fallback when the option is omitted.

Each extraction launcher verifies that its expected artifact was actually
created because Ghidra may return status 0 after a post-script exception. The
ACFG feature script indexes string references once per program, avoiding a
full-program string scan for every basic block.

Requirements are a 64-bit JDK 17 or newer and the launcher dependencies:

```bash
python3 -m venv env
source env/bin/activate
pip install -r src/util/Ghidra_scripts/requirements.txt
```

Set `GHIDRA_PATH` only when using a different `analyzeHeadless` executable.
