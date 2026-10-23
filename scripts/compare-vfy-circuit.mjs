// Compares the reconstructed circuit (circuits/vfy-policy.circom, compiled by `npm run circuit:reconstruct`)
// with the official witness calculator: same accept/reject outcome and identical public signals on a
// grid of strategies, states and declared actions.
// Usage: node scripts/compare-vfy-circuit.mjs [reconstructed.wasm]
import { buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';

const OFFICIAL = 'build/circuits/vfy-policy-official/vfy-policy.wasm';
const RECON = process.argv[2] ?? 'build/circuits/vfy-policy-reconstructed/vfy-policy_js/vfy-policy.wasm';
const poseidon = await buildPoseidon();
const P = (xs) => poseidon.F.toObject(poseidon(xs.map(BigInt)));
const FP = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function publicSignals(wasm, input) {
  try {
    const wtns = { type: 'mem' };
    await snarkjs.wtns.calculate(input, wasm, wtns);
    const w = await snarkjs.wtns.exportJson(wtns);
    return w.slice(1, 10).map(String).join(',');
  } catch {
    return 'REJECT';
  }
}

const strategies = [[10, 0, 0, 0], [7, 50, 20, 0], [1, 0, 0, 1], [10, 150, 0, 0], [10, 0, 100, 0], [0, 0, 0, 0], [11, 0, 0, 0], [10, 0, 0, 2], [10, 0, 0, 0, 1], [16, 0, 0, 0], [20, 0, 0, 0]];
const states = [[100, 100, 1, 1], [100, 0, 20, 1], [0, 100, 1, 1], [49, 100, 5, 1], [50, 100, 5, 1], [100, 20, 5, 1], [100, 21, 5, 1], [65535, 65535, 3, 1], [65536, 100, 3, 1], [100, 100, 7, 2], [1, 1, 1, 0]];
const actions = [[0, 0], [1, 0], [2, 10], [2, 7], [2, 1], [0, 5], [1, 2], [2, 0], [3, 0]];
let n = 0, mismatches = 0, accepted = 0;
for (const s of strategies) {
  const params = Array.from({ length: 8 }, (_, i) => String(s[i] ?? 0));
  const salt = '7';
  const commitment = P([...params, salt]).toString();
  for (const [self, opp, turn, version] of states) {
    for (const [action, amount] of actions) {
      const input = { commitment, matchId: '12345', turnNumber: String(turn), selfBalance: String(self), opponentBalance: String(opp), action: String(action), amount: String(amount), circuitVersion: String(version), strategyParams: params, salt };
      const [a, b] = await Promise.all([publicSignals(OFFICIAL, input), publicSignals(RECON, input)]);
      n++;
      if (a !== 'REJECT') accepted++;
      if (a !== b) { mismatches++; console.log('MISMATCH', JSON.stringify({ s, self, opp, turn, version, action, amount }), '\n  official:', a, '\n  recon:   ', b); }
    }
  }
}
// Wrong commitment must be rejected by both.
const bad = { commitment: '1', matchId: '1', turnNumber: '1', selfBalance: '100', opponentBalance: '100', action: '2', amount: '10', circuitVersion: '1', strategyParams: ['10', '0', '0', '0', '0', '0', '0', '0'], salt: '7' };
n++; if ((await publicSignals(OFFICIAL, bad)) !== (await publicSignals(RECON, bad))) mismatches++;
console.log(`${n} inputs compared, ${accepted} accepted by the official circuit, ${mismatches} mismatches`);
process.exit(mismatches ? 1 : 0);
