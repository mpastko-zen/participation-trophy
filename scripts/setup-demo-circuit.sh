#!/usr/bin/env bash
# Compile the local stand-in policy circuit and run a small local trusted setup.
# Produces build/circuits/vfy-policy/{vfy-policy.wasm, vfy-policy_final.zkey, verification_key.json}.
# Requires: circom 2.x on PATH, node_modules installed (snarkjs, circomlib).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=build/circuits/vfy-policy
mkdir -p "$OUT"

echo "[1/6] compiling circuit"
circom circuits/vfy-policy.circom --r1cs --wasm --sym -o "$OUT" -l node_modules
cp "$OUT/vfy-policy_js/vfy-policy.wasm" "$OUT/vfy-policy.wasm"

PTAU="$OUT/pot12_final.ptau"
if [ ! -f "$PTAU" ]; then
  echo "[2/6] powers of tau (2^12, local, not a production ceremony)"
  npx snarkjs powersoftau new bn128 12 "$OUT/pot12_0000.ptau" -v >/dev/null
  npx snarkjs powersoftau contribute "$OUT/pot12_0000.ptau" "$OUT/pot12_0001.ptau" --name="local" -e="$(head -c 32 /dev/urandom | base64)" >/dev/null
  npx snarkjs powersoftau prepare phase2 "$OUT/pot12_0001.ptau" "$PTAU" -v >/dev/null
else
  echo "[2/6] reusing $PTAU"
fi

echo "[3/6] groth16 setup"
npx snarkjs groth16 setup "$OUT/vfy-policy.r1cs" "$PTAU" "$OUT/vfy-policy_0000.zkey" >/dev/null
echo "[4/6] zkey contribution"
npx snarkjs zkey contribute "$OUT/vfy-policy_0000.zkey" "$OUT/vfy-policy_final.zkey" --name="local" -e="$(head -c 32 /dev/urandom | base64)" >/dev/null
echo "[5/6] export verification key"
npx snarkjs zkey export verificationkey "$OUT/vfy-policy_final.zkey" "$OUT/verification_key.json"
echo "[6/6] r1cs info"
npx snarkjs r1cs info "$OUT/vfy-policy.r1cs"

cat <<MSG

Done. To enable proof generation, set in .env:
  VFY_WASM=$OUT/vfy-policy.wasm
  VFY_ZKEY=$OUT/vfy-policy_final.zkey
Then (optional) register the verification key with Kurier and set VFY_VK_HASH:
  npm run kurier:register-vk -- $OUT/verification_key.json
MSG
