#!/bin/bash
# Usage (from apps/gasolina, inside sandbox-exec offline.sb): boundary/run-emitter.sh <dir> <script.ts> <output.json>
set -u
source /tmp/gasolina-run/env.sh
OUT=$1 SCRIPT=$2 RESULT=$3
rm -rf "$OUT/boundary-gen" "$OUT/boundary-report.json" "$OUT/$RESULT" "$OUT/emitter.stderr"
export BOUNDARY_REPORT=$PWD/$OUT/boundary-report.json BOUNDARY_GEN_DIR=$PWD/$OUT/boundary-gen
node --import tsx --import ./boundary/excluded-chain-boundary.mjs "$OUT/$SCRIPT" > "$OUT/$RESULT" 2> "$OUT/emitter.stderr"
echo "exit=$?"
