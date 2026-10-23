import { test } from 'node:test';
import assert from 'node:assert/strict';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { publicInputsHash, circuitVersionInt, matchIdToBigInt, type VfyAction } from '../src/vfy/hash.js';
import { DRAFT_RESOLVER, DEFAULT_STRATEGY, decide, differential, inferOpponentAction, normalizeStrategyParams, resolveTurn, strategyParamsToSignals } from '../src/vfy/strategy.js';
import { deriveSalt, strategyCommitment } from '../src/vfy/commitment.js';

const matchId = '9f4e1b2a-1234-4abc-8def-0123456789ab';
const commitment = '0x' + '7d'.repeat(32);

function refHash(fields: bigint[]): string {
  const packed = Buffer.concat(fields.map((f) => Buffer.from(f.toString(16).padStart(64, '0'), 'hex')));
  return '0x' + Buffer.from(keccak_256(packed)).toString('hex');
}

test('publicInputsHash matches an independent keccak256 over ABI-packed 32-byte fields', () => {
  const h = publicInputsHash({ commitment, matchId, turn: 3, selfBalance: '95', opponentBalance: '105', action: { type: 'EXTRACT', amount: 5 }, circuitVersion: 'v1' });
  const expected = refHash([BigInt(commitment), BigInt('0x' + matchId.replace(/-/g, '')), 3n, 95n, 105n, 2n, 5n, 1n]);
  assert.equal(h, expected);
  const hold = publicInputsHash({ commitment, matchId, turn: 3, selfBalance: '95', opponentBalance: '105', action: { type: 'HOLD' }, circuitVersion: 'v1' });
  assert.equal(hold, refHash([BigInt(commitment), BigInt('0x' + matchId.replace(/-/g, '')), 3n, 95n, 105n, 0n, 0n, 1n]));
  const fort = publicInputsHash({ commitment, matchId, turn: 3, selfBalance: '95', opponentBalance: '105', action: { type: 'FORTIFY' }, circuitVersion: 'v1' });
  assert.equal(fort, refHash([BigInt(commitment), BigInt('0x' + matchId.replace(/-/g, '')), 3n, 95n, 105n, 1n, 0n, 1n]));
});

test('circuit version and matchId encodings', () => {
  assert.equal(circuitVersionInt('v1-draft'), 1n);
  assert.equal(circuitVersionInt('v1'), 1n);
  assert.equal(circuitVersionInt('v2-final'), 2n);
  assert.equal(matchIdToBigInt(matchId), BigInt('0x9f4e1b2a12344abc8def0123456789ab'));
  assert.throws(() => matchIdToBigInt('not-a-uuid'));
});

test('EXTRACT at the cap weakly dominates every alternative under the draft resolver', () => {
  const me: VfyAction[] = [{ type: 'HOLD' }, { type: 'FORTIFY' }, { type: 'EXTRACT', amount: 10 }, { type: 'EXTRACT', amount: 5 }];
  const opp: VfyAction[] = [{ type: 'HOLD' }, { type: 'FORTIFY' }, { type: 'EXTRACT', amount: 10 }];
  for (const o of opp) {
    const best = differential({ type: 'EXTRACT', amount: 10 }, o, DRAFT_RESOLVER);
    for (const m of me) assert.ok(best >= differential(m, o, DRAFT_RESOLVER), `EXTRACT10 vs ${o.type} should beat ${JSON.stringify(m)}`);
  }
  // Spot-check the payoff table from the strategy comments.
  assert.equal(differential({ type: 'EXTRACT', amount: 10 }, { type: 'HOLD' }, DRAFT_RESOLVER), 20);
  assert.equal(differential({ type: 'EXTRACT', amount: 10 }, { type: 'FORTIFY' }, DRAFT_RESOLVER), 10);
  assert.equal(differential({ type: 'EXTRACT', amount: 10 }, { type: 'EXTRACT', amount: 10 }, DRAFT_RESOLVER), 0);
  assert.equal(differential({ type: 'FORTIFY' }, { type: 'EXTRACT', amount: 10 }, DRAFT_RESOLVER), -10);
});

test('decide: mirrors the official circuit (FORTIFY below threshold, else HOLD at/below opponent floor or always-hold, else EXTRACT)', () => {
  const p = DEFAULT_STRATEGY; // [10, 0, 0, 0]
  assert.deepEqual(decide(p, { turn: 1, selfBalance: 100n, opponentBalance: 100n }), { type: 'EXTRACT', amount: 10 });
  assert.deepEqual(decide(p, { turn: 20, selfBalance: 1n, opponentBalance: 3n }), { type: 'EXTRACT', amount: 10 });
  assert.deepEqual(decide(p, { turn: 7, selfBalance: 150n, opponentBalance: 0n }), { type: 'HOLD' });
  const c = { extractAmount: 7, fortifyBelow: 50, holdWhenOpponentAtMost: 20, alwaysHold: 0 as const };
  assert.deepEqual(decide(c, { turn: 1, selfBalance: 49n, opponentBalance: 100n }), { type: 'FORTIFY' });
  assert.deepEqual(decide(c, { turn: 1, selfBalance: 50n, opponentBalance: 100n }), { type: 'EXTRACT', amount: 7 });
  assert.deepEqual(decide(c, { turn: 1, selfBalance: 100n, opponentBalance: 20n }), { type: 'HOLD' });
  assert.deepEqual(decide(c, { turn: 1, selfBalance: 100n, opponentBalance: 21n }), { type: 'EXTRACT', amount: 7 });
  assert.deepEqual(decide(c, { turn: 1, selfBalance: 10n, opponentBalance: 0n }), { type: 'FORTIFY' });
  assert.deepEqual(decide({ ...c, alwaysHold: 1 }, { turn: 1, selfBalance: 100n, opponentBalance: 100n }), { type: 'HOLD' });
  assert.deepEqual(decide({ ...c, alwaysHold: 1 }, { turn: 1, selfBalance: 10n, opponentBalance: 100n }), { type: 'FORTIFY' });
});

test('strategy params: clamped into the circuit domain and laid out as strategyParams[8]', () => {
  assert.deepEqual(normalizeStrategyParams({ extractAmount: 99, fortifyBelow: -5, holdWhenOpponentAtMost: 1e9, alwaysHold: 1 }), { extractAmount: 10, fortifyBelow: 0, holdWhenOpponentAtMost: 65535, alwaysHold: 1 });
  assert.deepEqual(normalizeStrategyParams({ extractAmount: 0 }), { extractAmount: 1, fortifyBelow: 0, holdWhenOpponentAtMost: 0, alwaysHold: 0 });
  assert.deepEqual(normalizeStrategyParams({}), DEFAULT_STRATEGY);
  assert.deepEqual(strategyParamsToSignals({ extractAmount: 7, fortifyBelow: 50, holdWhenOpponentAtMost: 20, alwaysHold: 1 }), [7n, 50n, 20n, 1n, 0n, 0n, 0n, 0n]);
});

test('resolver model: extraction is bounded by the opponent spendable balance and fortify block', () => {
  assert.deepEqual(resolveTurn(100, 3, { type: 'EXTRACT', amount: 10 }, { type: 'HOLD' }), { deltaA: 3, deltaB: -3 });
  assert.deepEqual(resolveTurn(100, 100, { type: 'EXTRACT', amount: 10 }, { type: 'FORTIFY' }), { deltaA: 4, deltaB: -6 });
  assert.deepEqual(inferOpponentAction({ selfBalance: 100, opponentBalance: 100, myAction: { type: 'EXTRACT', amount: 10 } }, { selfBalance: 104, opponentBalance: 94 }), { type: 'FORTIFY' });
  assert.deepEqual(inferOpponentAction({ selfBalance: 100, opponentBalance: 100, myAction: { type: 'EXTRACT', amount: 10 } }, { selfBalance: 100, opponentBalance: 100 }), { type: 'EXTRACT', amount: 10 });
});

test('strategy commitment is a stable 32-byte Poseidon(strategyParams[8], salt) hash', async () => {
  const salt = deriveSalt('seed');
  const a = await strategyCommitment(DEFAULT_STRATEGY, salt);
  const b = await strategyCommitment({ ...DEFAULT_STRATEGY }, salt);
  const c = await strategyCommitment({ ...DEFAULT_STRATEGY, extractAmount: 9 }, salt);
  assert.match(a, /^0x[0-9a-f]{64}$/);
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.notEqual(a, await strategyCommitment(DEFAULT_STRATEGY, deriveSalt('other')));
  // Independent reference: circomlibjs Poseidon over the 9 field elements the circuit hashes.
  const { buildPoseidon } = await import('circomlibjs');
  const poseidon = await buildPoseidon();
  const ref = poseidon.F.toObject(poseidon([10n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, salt]));
  assert.equal(BigInt(a), ref);
});
