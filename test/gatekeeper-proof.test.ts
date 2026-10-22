import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Agent } from '../src/agent.js';
import { loadConfig } from '../src/config.js';
import { Store } from '../src/store.js';
import { SIGNATURE_HEADER, sign } from '../src/signature.js';
import { buildGatekeeperCircuitInputs, expectedPublicSignals, taskIdToField, toField, FIELD_P } from '../src/zk/gatekeeper-proof.js';
import { gatekeeperInputSchema } from '../src/protocol.js';
import { generateRoundTasks, gatekeeperEnvelope } from './fixtures/traps.js';

// Real proofs against the official Proof Gatekeeper artifacts (small circuit: ~60 ms per proof).
const WASM = 'build/circuits/gatekeeper/gatekeeper.wasm';
const ZKEY = 'build/circuits/gatekeeper/gatekeeper_final.zkey';
const VK = 'build/circuits/gatekeeper/verification_key.json';
const SECRET = 'a'.repeat(64);
process.env.AGENT_GAMES_HMAC_SECRET = SECRET;
process.env.GATEKEEPER_WASM = WASM;
process.env.GATEKEEPER_ZKEY = ZKEY;
process.env.RESPONSE_SAFETY_MARGIN_MS = '1000';

let agent: Agent;
let store: Store;
let vk: unknown;
let snarkjs: typeof import('snarkjs');

before(async () => {
  store = new Store(':memory:');
  agent = new Agent(loadConfig(), store);
  vk = JSON.parse(await readFile(VK, 'utf8'));
  snarkjs = await import('snarkjs');
});
after(async () => {
  store.close();
  // snarkjs keeps worker threads alive on the global curve; release them so the test process can exit.
  await (globalThis as any).curve_bn128?.terminate?.();
});

async function post(payload: unknown) {
  const body = Buffer.from(JSON.stringify(payload));
  const res = await agent.handle(body, { [SIGNATURE_HEADER]: sign(body, SECRET) });
  return { ...res, json: JSON.parse(res.body) as Record<string, any> };
}

test('field mapping: hex and decimal inputs reduce into the BN128 scalar field', () => {
  assert.equal(toField('1000'), '1000');
  assert.equal(toField('0x0f'), '15');
  assert.equal(toField(8430000), '8430000');
  assert.equal(toField('0x' + 'ff'.repeat(32)), (BigInt('0x' + 'ff'.repeat(32)) % FIELD_P).toString());
  assert.equal(taskIdToField('gk_24_9d1'), taskIdToField('gk_24_9d1', 'sha256'));
  assert.notEqual(taskIdToField('gk_24_9d1', 'keccak256'), taskIdToField('gk_24_9d1', 'sha256'));
  assert.equal(taskIdToField('gk_x_123e4567-e89b-12d3-a456-426614174000', 'uuid'), toField('0x123e4567e89b12d3a456426614174000'));
});

test('official circuit: provable verdicts produce a verifying Groth16 proof with the documented public signals', async () => {
  const tasks = generateRoundTasks('proof-test', 'R01');
  for (const trap of ['VALID_CONDITION', 'VK_SUBSTITUTION', 'THRESHOLD_MISMATCH', 'EXPIRED_CONDITION', 'RECIPIENT_MISMATCH', 'AMOUNT_OVERFLOW'] as const) {
    const t = tasks.find((x) => x.trapCode === trap)!;
    const r = await post(gatekeeperEnvelope(`gk_proof_${trap}`, t.input));
    assert.equal(r.status, 200);
    assert.equal(r.json.decision, t.expected, trap);
    assert.ok(r.json.proof && Array.isArray(r.json.public_signals), `${trap}: proof missing -> ${r.body}`);
    assert.equal(r.json.public_signals.length, 13);
    assert.equal(await snarkjs.groth16.verify(vk, r.json.public_signals, r.json.proof), true, `${trap}: proof did not verify`);
    const input = gatekeeperInputSchema.parse(t.input);
    assert.deepEqual(r.json.public_signals.slice(1), expectedPublicSignals(input, `gk_proof_${trap}`, r.json.decision), `${trap}: public signals`);
    assert.equal(r.json.public_signals[11], t.expected === 'APPROVE' ? '1' : '0');
    assert.deepEqual(Object.keys(r.json).sort(), ['decision', 'proof', 'proof_tx', 'public_signals', 'reason_code']);
  }
});

test('official circuit: a replayed proof reference is rejected without a proof (not provable by the circuit)', async () => {
  const valid = generateRoundTasks('proof-replay', 'R01').find((x) => x.trapCode === 'VALID_CONDITION')!;
  const first = await post(gatekeeperEnvelope('gk_replay_1', valid.input));
  assert.equal(first.json.decision, 'APPROVE');
  assert.ok(first.json.proof);
  const second = await post(gatekeeperEnvelope('gk_replay_2', valid.input));
  assert.equal(second.json.decision, 'REJECT');
  assert.equal(second.json.reason_code, 'PROOF_REUSED');
  assert.equal(second.json.proof, undefined);
  assert.deepEqual(Object.keys(second.json).sort(), ['decision', 'proof_tx', 'reason_code']);
});

test('official circuit: the circuit refuses a decision that contradicts the field checks', async () => {
  const valid = generateRoundTasks('proof-contra', 'R01').find((x) => x.trapCode === 'VALID_CONDITION')!;
  const input = gatekeeperInputSchema.parse(valid.input);
  const wrong = buildGatekeeperCircuitInputs(input, 'gk_contra', 'REJECT', { salt: '7' });
  await assert.rejects(snarkjs.groth16.fullProve(wrong, WASM, ZKEY), /Assert Failed/);
  // Boundaries the circuit enforces, matching src/gatekeeper.ts: expiry inclusive, cap inclusive.
  const atExpiry = buildGatekeeperCircuitInputs({ ...input, current_block: input.expiry_block }, 'gk_b1', 'APPROVE', { salt: '7' });
  await assert.rejects(snarkjs.groth16.fullProve(atExpiry, WASM, ZKEY), /Assert Failed/);
  const atCap = buildGatekeeperCircuitInputs({ ...input, amount: input.max_transfer }, 'gk_b2', 'APPROVE', { salt: '7' });
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(atCap, WASM, ZKEY);
  assert.equal(await snarkjs.groth16.verify(vk, publicSignals, proof), true);
});
