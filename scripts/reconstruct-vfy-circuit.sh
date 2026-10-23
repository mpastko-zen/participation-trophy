#!/usr/bin/env bash
# Compile the RECONSTRUCTED Steal the VFY policy circuit (circuits/vfy-policy.circom) so it can be
# compared with the official witness calculator (scripts/compare-vfy-circuit.mjs).
# Proofs for the platform must use the official artifacts in build/circuits/vfy-policy-official/;
# this build is a readable model only, so there is no trusted setup here.
# Requires: circom 2.x on PATH, node_modules installed (snarkjs, circomlib).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=build/circuits/vfy-policy-reconstructed
mkdir -p "$OUT"
echo "[1/2] compiling circuits/vfy-policy.circom"
circom circuits/vfy-policy.circom --r1cs --wasm --sym -o "$OUT" -l node_modules
echo "[2/2] comparing with the official witness calculator"
node scripts/compare-vfy-circuit.mjs "$OUT/vfy-policy_js/vfy-policy.wasm"
