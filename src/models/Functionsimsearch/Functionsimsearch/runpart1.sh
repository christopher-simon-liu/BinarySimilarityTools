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
FSS_DIR="$SCRIPT_DIR/IDA_fss"

convert_split() {
  local split="$1"
  local input_dir="$FEATURES_DIR/$split/acfg_disasm_${DATASET_NAME}_${split}"
  local output_dir="$FSS_DIR/fss_${DATASET_NAME}_${split}"
  if [ -d "$input_dir" ]; then
    python3 "$SCRIPT_DIR/ghidra_to_fss.py" \
      --input-dir "$input_dir" \
      --output-dir "$output_dir"
  fi
}

found_split=false
for split in testing training validation; do
  if [ -d "$FEATURES_DIR/$split/acfg_disasm_${DATASET_NAME}_${split}" ]; then
    found_split=true
    convert_split "$split"
  fi
done

if [ "$found_split" = false ]; then
  input_dir="$FEATURES_DIR/acfg_disasm_${DATASET_NAME}"
  output_dir="$FSS_DIR/fss_${DATASET_NAME}_testing"
  if [ ! -d "$input_dir" ]; then
    echo "Missing Ghidra ACFG disassembly directory for $DATASET_NAME" >&2
    exit 1
  fi
  python3 "$SCRIPT_DIR/ghidra_to_fss.py" \
    --input-dir "$input_dir" \
    --output-dir "$output_dir"
fi
