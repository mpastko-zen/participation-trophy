import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Agent } from '../src/agent.js';
import { loadConfig } from '../src/config.js';
import { Store } from '../src/store.js';
import { SIGNATURE_HEADER, sign } from '../src/signature.js';
import { deriveSalt, strategyCommitment } from '../src/vfy/commitment.js';
import { publicInputsHash, type VfyAction } from '../src/vfy/hash.js';
import { buildVfyCircuitInputs, expectedPublicSignals, expectedTurnNullifier, VFY_PUBLIC_SIGNAL_NAMES } from '../src/vfy/policy-proof.js';
import { decide, strategyParamsFromConfig, type StrategyParams } from '../src/vfy/strategy.js';

// Real proofs against the official Steal the VFY artifacts (~1.8k wires: a few hundred ms per proof).
const WASM = 'build/circuits/vfy-policy-official/vfy-policy.wasm';
const ZKEY = 'build/circuits/vfy-policy-official/vfy-policy_final.zkey';
const VK = 'build/circuits/vfy-policy-official/verification_key.json';
const SECRET = 'b'.repeat(64);
process.env.AGENT_GAMES_HMAC_SECRET = SECRET;
process.env.VFY_WASM = WASM;
process.env.VFY_ZKEY = ZKEY;
process.env.VFY_STRATEGY_SALT = 'vfy-proof-test-salt';
process.env.RESPONSE_SAFETY_MARGIN_MS = '1000';

let store: Store;
let agent: Agent; // default strategy [10, 0, 0, 0]
let cautious: Agent; // FORTIFY below 50, HOLD while the opponent has <= 20
let vk: unknown;
let snarkjs: typeof import('snarkjs');
let params: StrategyParams;
let cautiousParams: StrategyParams;
let salt: bigint;

before(async () => {
  store = new Store(':memory:');
  const config = loadConfig();
  agent = new Agent(config, store);
  params = strategyParamsFromConfig(config.vfy);
  salt = deriveSalt(config.vfy.strategySalt);
  process.env.VFY_FORTIFY_BELOW = '50';
  process.env.VFY_HOLD_WHEN_OPPONENT_AT_MOST = '20';
  const cautiousConfig = loadConfig();
  delete process.env.VFY_FORTIFY_BELOW;
  delete process.env.VFY_HOLD_WHEN_OPPONENT_AT_MOST;
  cautious = new Agent(cautiousConfig, new Store(':memory:'));
  cautiousParams = strategyParamsFromConfig(cautiousConfig.vfy);
  vk = JSON.parse(await readFile(VK, 'utf8'));
  snarkjs = await import('snarkjs');
});
after(async () => {
  store.close();
  await (globalThis as any).curve_bn128?.terminate?.();
});

function envelope(matchId: string, turn: number, self: string, opp: string, commitment: string) {
  const now = Date.now();
  return {
    protocolVersion: 'v1',
    eventId: 'steal-the-vfy',
    mode: 'competition',
    matchId,
    turn,
    issuedAt: new Date(now).toISOString(),
    deadlineAt: new Date(now + 60_000).toISOString(),
    state: { selfBalance: self, opponentBalance: opp, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: commitment },
    resolverVersion: 'v1',
    nonce: randomUUID(),
  };
}

async function post(a: Agent, payload: unknown) {
  const body = Buffer.from(JSON.stringify(payload));
  const res = await a.handle(body, { [SIGNATURE_HEADER]: sign(body, SECRET) });
  return { ...res, json: JSON.parse(res.body) as Record<string, any> };
}

test('official circuit: witness layout is [nullifier, commitment, matchId, turnNumber, selfBalance, opponentBalance, action, amount, circuitVersion]', async () => {
  const commitment = await strategyCommitment(params, salt);
  const facts = { commitment, matchId: '9f4e1b2a-1234-4abc-8def-0123456789ab', turn: 3, selfBalance: 95n, opponentBalance: 105n, action: { type: 'EXTRACT', amount: 10 } as VfyAction, circuitVersion: 'v1' };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(buildVfyCircuitInputs(facts, { params, salt }), WASM, ZKEY);
  assert.equal(publicSignals.length, VFY_PUBLIC_SIGNAL_NAMES.length);
  assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true);
  assert.deepEqual(publicSignals.slice(1), expectedPublicSignals(facts));
  assert.deepEqual(publicSignals.slice(1), [BigInt(commitment).toString(), BigInt('0x9f4e1b2a12344abc8def0123456789ab').toString(), '3', '95', '105', '2', '10', '1']);
  assert.equal(publicSignals[0], await expectedTurnNullifier(facts));

  // The nullifier binds (matchId, turnNumber, circuitVersion) and nothing else: same for another strategy...
  const otherSalt = deriveSalt('another');
  const other = await snarkjs.groth16.fullProve(buildVfyCircuitInputs({ ...facts, commitment: await strategyCommitment(cautiousParams, otherSalt) }, { params: cautiousParams, salt: otherSalt }), WASM, ZKEY);
  assert.equal(other.publicSignals[0], publicSignals[0]);
  // ...different for the next turn.
  const next = await snarkjs.groth16.fullProve(buildVfyCircuitInputs({ ...facts, turn: 4 }, { params, salt }), WASM, ZKEY);
  assert.notEqual(next.publicSignals[0], publicSignals[0]);
});

test('official circuit: permits exactly the action decide() picks, for every branch of the policy', async () => {
  const cases: { p: StrategyParams; self: bigint; opp: bigint; want: VfyAction }[] = [
    { p: params, self: 100n, opp: 100n, want: { type: 'EXTRACT', amount: 10 } },
    { p: params, self: 1n, opp: 1n, want: { type: 'EXTRACT', amount: 10 } },
    { p: params, self: 150n, opp: 0n, want: { type: 'HOLD' } },
    { p: cautiousParams, self: 49n, opp: 100n, want: { type: 'FORTIFY' } },
    { p: cautiousParams, self: 50n, opp: 100n, want: { type: 'EXTRACT', amount: 10 } },
    { p: cautiousParams, self: 100n, opp: 20n, want: { type: 'HOLD' } },
    { p: cautiousParams, self: 100n, opp: 21n, want: { type: 'EXTRACT', amount: 10 } },
    { p: cautiousParams, self: 40n, opp: 0n, want: { type: 'FORTIFY' } }, // FORTIFY takes precedence over HOLD
    { p: { ...params, alwaysHold: 1 }, self: 100n, opp: 100n, want: { type: 'HOLD' } },
    { p: { ...params, extractAmount: 3 }, self: 100n, opp: 100n, want: { type: 'EXTRACT', amount: 3 } },
  ];
  const all: VfyAction[] = [{ type: 'HOLD' }, { type: 'FORTIFY' }, ...Array.from({ length: 11 }, (_, n) => ({ type: 'EXTRACT', amount: n }) as VfyAction)];
  const label = (c: (typeof cases)[number]) => `${JSON.stringify(c.p)} self=${c.self} opp=${c.opp}`;
  for (const c of cases) {
    const got = decide(c.p, { turn: 5, selfBalance: c.self, opponentBalance: c.opp });
    assert.deepEqual(got, c.want, label(c));
    const commitment = await strategyCommitment(c.p, salt);
    const facts = (action: VfyAction) => ({ commitment, matchId: randomUUID(), turn: 5, selfBalance: c.self, opponentBalance: c.opp, action, circuitVersion: 'v1' });
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(buildVfyCircuitInputs(facts(got), { params: c.p, salt }), WASM, ZKEY);
    assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true, label(c));
    // Every other action in the domain is refused by the witness generator (no valid witness exists).
    for (const alt of all) {
      if (JSON.stringify(alt) === JSON.stringify(got)) continue;
      await assert.rejects(snarkjs.wtns.calculate(buildVfyCircuitInputs(facts(alt), { params: c.p, salt }), WASM, { type: 'mem' }), /Assert Failed/, `${label(c)} should refuse ${JSON.stringify(alt)}`);
    }
  }
});

test('official circuit: refuses a wrong commitment, out-of-range params and oversized balances', async () => {
  const base = { commitment: await strategyCommitment(params, salt), matchId: randomUUID(), turn: 1, selfBalance: 100n, opponentBalance: 100n, action: { type: 'EXTRACT', amount: 10 } as VfyAction, circuitVersion: 'v1' };
  const calc = (facts: typeof base, secret: { params: StrategyParams; salt: bigint }) => snarkjs.wtns.calculate(buildVfyCircuitInputs(facts, secret), WASM, { type: 'mem' });
  await assert.rejects(calc(base, { params, salt: salt + 1n }), /Assert Failed/); // commitment mismatch
  await assert.rejects(calc({ ...base, action: { type: 'EXTRACT', amount: 11 } }, { params: { ...params, extractAmount: 11 }, salt }), /Assert Failed/);
  await assert.rejects(calc({ ...base, action: { type: 'EXTRACT', amount: 0 } }, { params: { ...params, extractAmount: 0 }, salt }), /Assert Failed/);
  await assert.rejects(calc({ ...base, selfBalance: 65536n }, { params, salt }), /Assert Failed/); // 16-bit comparator
  await calc({ ...base, selfBalance: 65535n, opponentBalance: 65535n }, { params, salt });
});

test('agent: a competition turn carries a verifying proof whose public signals are the publicInputsHash fields', async () => {
  const commitment = await strategyCommitment(params, salt);
  const matchId = randomUUID();
  for (const [turn, self, opp, want] of [[1, '100', '100', { type: 'EXTRACT', amount: 10 }], [12, '190', '0', { type: 'HOLD' }]] as const) {
    const r = await post(agent, envelope(matchId, turn, self, opp, commitment));
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.action, want);
    const pp = r.json.policyProof;
    assert.deepEqual(Object.keys(pp).sort(), ['circuitVersion', 'proof', 'publicInputsHash', 'public_signals']);
    assert.equal(pp.circuitVersion, 'v1');
    assert.equal(await snarkjs.groth16.verify(vk, pp.public_signals, pp.proof), true);
    assert.deepEqual(pp.public_signals.slice(1), expectedPublicSignals({ commitment, matchId, turn, selfBalance: BigInt(self), opponentBalance: BigInt(opp), action: want, circuitVersion: 'v1' }));
    assert.equal(pp.public_signals[0], await expectedTurnNullifier({ matchId, turn, circuitVersion: 'v1' }));
    assert.equal(pp.publicInputsHash, publicInputsHash({ commitment, matchId, turn, selfBalance: self, opponentBalance: opp, action: want, circuitVersion: 'v1' }));
  }
  // The cautious agent fortifies when low, and proves it.
  const cc = await strategyCommitment(cautiousParams, salt);
  const r = await post(cautious, envelope(randomUUID(), 7, '30', '100', cc));
  assert.deepEqual(r.json.action, { type: 'FORTIFY' });
  assert.equal(await snarkjs.groth16.verify(vk, r.json.policyProof.public_signals, r.json.policyProof.proof), true);
  assert.equal(r.json.policyProof.public_signals[6], '1');
});

test('agent: a frozen commitment that is not ours gets the hash but no proof', async () => {
  const r = await post(agent, envelope(randomUUID(), 2, '100', '100', '0x' + '7d'.repeat(32)));
  assert.equal(r.status, 200);
  assert.deepEqual(r.json.action, { type: 'EXTRACT', amount: 10 });
  assert.deepEqual(Object.keys(r.json.policyProof).sort(), ['circuitVersion', 'publicInputsHash']);
});
