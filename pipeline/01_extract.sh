#!/usr/bin/env bash
# Extract the strings of the binary (and decompile the two signing functions)
# with the REA CLI + Ghidra. pipeline/03_detect_redact.py reads the strings.
#
# Requires: Node (REA runs via `npx -y rea-agents@6.8.0`; set REA=rea to use a
# global install instead), Ghidra 12.1.x, a full JDK 21+, python3.
# Config via env:
#   GHIDRA_INSTALL_DIR, JAVA_HOME  -> Ghidra provider (required by REA)
#   TARGET      -> path to the stripped binary (default: target/syncd)
#   OUT         -> output dir (default: out)
#   REA         -> REA command (default: npx -y rea-agents@6.8.0)
# Example: GHIDRA_INSTALL_DIR=/path/to/ghidra JAVA_HOME=/path/to/jdk bash pipeline/01_extract.sh
set -euo pipefail

REA="${REA:-npx -y rea-agents@6.8.0}"

TARGET="${TARGET:-target/syncd}"
OUT="${OUT:-out}"
SNAP="$OUT/syncd.snapshot"
mkdir -p "$OUT/raw"

echo "[1/3] string inventory"
$REA search "$TARGET" "." --mode regex --snapshot "$SNAP" --format json > "$OUT/raw/strings.json"

echo "[2/3] find the signing function via xrefs to the key-like string"
# In this demo the signing key lives at a known rodata address; in general, let
# the agent follow xrefs. Here we decompile the two signer functions directly.
# (Addresses are for the shipped target/syncd; adjust them for your own build.)
for addr in "${SIGN_FN_ADDR:-0x1013fa}" "${HASH_FN_ADDR:-0x101300}"; do
  echo "    decompiling function containing $addr"
  $REA decompile "$TARGET" "$addr" --snapshot "$SNAP" --format json \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["normalized_result"])' \
    > "$OUT/raw/decompile_$addr.txt"
done

echo "[3/3] done -> $OUT/raw/"
