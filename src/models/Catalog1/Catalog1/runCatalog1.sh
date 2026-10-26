#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <dataset-name>"
  exit 1
fi

DATASET_NAME="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
DBS_DIR="${BINSIM_DB_ROOT:-$PROJECT_ROOT/DBs}"
FEATURES_DIR="$DBS_DIR/$DATASET_NAME/features"
INPUT_DIR="$FEATURES_DIR/testing/acfg_disasm_${DATASET_NAME}_testing"

if [ ! -d "$INPUT_DIR" ]; then
  INPUT_DIR="$FEATURES_DIR/acfg_disasm_${DATASET_NAME}"
fi
if [ ! -d "$INPUT_DIR" ]; then
  echo "Missing Ghidra ACFG disassembly directory for $DATASET_NAME" >&2
  exit 1
fi

python3 "$SCRIPT_DIR/ghidra_catalog1.py" \
  --input-dir "$INPUT_DIR" \
  --output-prefix "$SCRIPT_DIR/${DATASET_NAME}_catalog1"
