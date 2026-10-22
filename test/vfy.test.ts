import { test } from 'node:test';
import assert from 'node:assert/strict';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { publicInputsHash, circuitVersionInt, matchIdToBigInt, type VfyAction } from '../src/vfy/hash.js';
import { DRAFT_RESOLVER, decide, differential, inferOpponentAction, resolveTurn } from '../src/vfy/strategy.js';
import { deriveSalt, strategyCommitment } from '../src/vfy/commitment.js';

const matchId = '9f4e1b2a-1234-4abc-8def-0123456789ab';
const commitment = '0x' + '7d'.repeat(32);

function refHash(fields: bigint[]): string {
  const packed = Buffer.concat(fields.map((f) => Buffer.from(f.toString(16).padStart(64, '0'), 'hex')));
  return '0x' + Buffer.from(keccak_256(packed)).toString('hex');
}

test('publicInputsHash matches an independent keccak256 over ABI-packed 32-byte fields', () => {
  const h = publicInputsHash({ commitment, matchId, turn: 3, selfBalance: '95', opponentBalance: '105', action: { type: 'EXTRACT', amount: 5 }, circuitVersion: 'v1-draft' });
  const expected = refHash([BigInt(commitment), BigInt('0x' + matchId.replace(/-/g, '')), 3n, 95n, 105n, 2n, 5n, 1n]);
  assert.equal(h, expected);
  const hold = publicInputsHash({ commitment, matchId, turn: 3, selfBalance: '95', opponentBalance: '105', action: { type: 'HOLD' }, circuitVersion: 'v1-draft' });
  assert.equal(hold, refHash([BigInt(commitment), BigInt('0x' + matchId.replace(/-/g, '')), 3n, 95n, 105n, 0n, 0n, 1n]));
  const fort = publicInputsHash({ commitment, matchId, turn: 3, selfBalance: '95', opponentBalance: '105', action: { type: 'FORTIFY' }, circuitVersion: 'v1-draft' });
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

test('decide: EXTRACT cap normally, HOLD when the opponent is empty', () => {
  const p = { extractAmount: 10, holdWhenOpponentEmpty: 1 as const };
  assert.deepEqual(decide(p, { turn: 1, selfBalance: 100n, opponentBalance: 100n }), { type: 'EXTRACT', amount: 10 });
  assert.deepEqual(decide(p, { turn: 20, selfBalance: 1n, opponentBalance: 3n }), { type: 'EXTRACT', amount: 10 });
  assert.deepEqual(decide(p, { turn: 7, selfBalance: 150n, opponentBalance: 0n }), { type: 'HOLD' });
});

test('resolver model: extraction is bounded by the opponent spendable balance and fortify block', () => {
  assert.deepEqual(resolveTurn(100, 3, { type: 'EXTRACT', amount: 10 }, { type: 'HOLD' }), { deltaA: 3, deltaB: -3 });
  assert.deepEqual(resolveTurn(100, 100, { type: 'EXTRACT', amount: 10 }, { type: 'FORTIFY' }), { deltaA: 4, deltaB: -6 });
  assert.deepEqual(inferOpponentAction({ selfBalance: 100, opponentBalance: 100, myAction: { type: 'EXTRACT', amount: 10 } }, { selfBalance: 104, opponentBalance: 94 }), { type: 'FORTIFY' });
  assert.deepEqual(inferOpponentAction({ selfBalance: 100, opponentBalance: 100, myAction: { type: 'EXTRACT', amount: 10 } }, { selfBalance: 100, opponentBalance: 100 }), { type: 'EXTRACT', amount: 10 });
});

test('strategy commitment is a stable 32-byte Poseidon hash', async () => {
  const salt = deriveSalt('seed');
  const a = await strategyCommitment({ extractAmount: 10, holdWhenOpponentEmpty: 1 }, salt);
  const b = await strategyCommitment({ extractAmount: 10, holdWhenOpponentEmpty: 1 }, salt);
  const c = await strategyCommitment({ extractAmount: 9, holdWhenOpponentEmpty: 1 }, salt);
  assert.match(a, /^0x[0-9a-f]{64}$/);
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.notEqual(a, await strategyCommitment({ extractAmount: 10, holdWhenOpponentEmpty: 1 }, deriveSalt('other')));
});
