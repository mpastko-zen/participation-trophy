import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Agent } from '../src/agent.js';
import { loadConfig } from '../src/config.js';
import { Store } from '../src/store.js';
import { SIGNATURE_HEADER, sign, verify } from '../src/signature.js';
import { generateRoundTasks, gatekeeperEnvelope } from './fixtures/traps.js';
import { publicInputsHash } from '../src/vfy/hash.js';

const SECRET = 'f'.repeat(64);
process.env.AGENT_GAMES_HMAC_SECRET = SECRET;
process.env.RESPONSE_SAFETY_MARGIN_MS = '1000';
let agent: Agent;
let store: Store;

before(() => {
  store = new Store(':memory:');
  agent = new Agent(loadConfig(), store);
});
after(() => store.close());

async function post(payload: unknown, opts: { sig?: string | null } = {}) {
  const body = Buffer.from(JSON.stringify(payload));
  const headers: Record<string, string> = {};
  if (opts.sig !== null) headers[SIGNATURE_HEADER] = opts.sig ?? sign(body, SECRET);
  const res = await agent.handle(body, headers);
  return { ...res, json: JSON.parse(res.body) as Record<string, any> };
}

test('preflight answers ok with a valid response signature', async () => {
  const r = await post({ type: 'agent-games.preflight.v1', agent_id: randomUUID(), issued_at: new Date().toISOString(), nonce: randomUUID() });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { ok: true, protocolVersion: 'v1' });
  assert.equal(verify(r.body, r.headers[SIGNATURE_HEADER], SECRET), true);
  assert.equal(r.headers['content-type'], 'application/json');
});

test('unsigned and badly signed requests are refused before parsing', async () => {
  assert.equal((await post({ type: 'agent-games.preflight.v1' }, { sig: null })).status, 401);
  assert.equal((await post({ type: 'agent-games.preflight.v1' }, { sig: 'ab'.repeat(32) })).status, 401);
  const r = await agent.handle(Buffer.from('not json'), { [SIGNATURE_HEADER]: sign('not json', SECRET) });
  assert.equal(r.status, 400);
});

test('gatekeeper: full rounds through the agent, with the replay trap crossing rounds', async () => {
  let n = 0;
  for (const round of ['R01', 'R02', 'R03']) {
    for (const t of generateRoundTasks('agent-a', round)) {
      const r = await post(gatekeeperEnvelope(`gk_${round}_${n++}`, t.input));
      assert.equal(r.status, 200);
      assert.equal(r.json.decision, t.expected, `${round} ${t.trapCode} -> ${r.body}`);
      assert.equal(r.json.proof_tx, t.input.proof_tx);
      assert.match(r.json.reason_code, /^[A-Z0-9_:-]{2,80}$/);
      assert.deepEqual(Object.keys(r.json).sort(), ['decision', 'proof_tx', 'reason_code']);
    }
  }
});

test('gatekeeper: retries return the identical cached body, and are not counted as replays', async () => {
  const valid = generateRoundTasks('agent-b', 'R01').find((t) => t.trapCode === 'VALID_CONDITION')!;
  const env = gatekeeperEnvelope('gk_retry_1', valid.input);
  const a = await post(env);
  const b = await post({ ...env, issued_at: new Date().toISOString() });
  assert.equal(a.body, b.body);
  assert.equal(a.json.decision, 'APPROVE');
  const replay = await post(gatekeeperEnvelope('gk_retry_2', valid.input));
  assert.equal(replay.json.decision, 'REJECT');
  assert.equal(replay.json.reason_code, 'PROOF_REUSED');
});

test('gatekeeper: practice approvals do not poison the competition seen-set', async () => {
  const valid = generateRoundTasks('agent-c', 'R01').find((t) => t.trapCode === 'VALID_CONDITION')!;
  assert.equal((await post(gatekeeperEnvelope('gk_p1', valid.input, 'practice'))).json.decision, 'APPROVE');
  assert.equal((await post(gatekeeperEnvelope('gk_c1', valid.input, 'competition'))).json.decision, 'APPROVE');
  assert.equal((await post(gatekeeperEnvelope('gk_c2', valid.input, 'competition'))).json.reason_code, 'PROOF_REUSED');
});

test('gatekeeper: garbage input still gets a signed REJECT, never a 500', async () => {
  const r = await post({ type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_bad', deadline_at: 'soon', input: { registered_vk: 1 } });
  assert.equal(r.status, 200);
  assert.equal(r.json.decision, 'REJECT');
  assert.equal(verify(r.body, r.headers[SIGNATURE_HEADER], SECRET), true);
});

function vfyEnvelope(mode: 'practice' | 'competition', matchId: string, turn: number, self: string, opp: string) {
  const now = Date.now();
  return {
    protocolVersion: 'v1',
    eventId: 'steal-the-vfy',
    mode,
    matchId,
    turn,
    issuedAt: new Date(now).toISOString(),
    deadlineAt: new Date(now + 60_000).toISOString(),
    state: { selfBalance: self, opponentBalance: opp, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null, ...(mode === 'practice' ? { priorTurnHash: '0x' + '0'.repeat(64) } : {}) },
    ...(mode === 'competition' ? { strategyCommitment: { hash: '0x' + '7d'.repeat(32) } } : {}),
    resolverVersion: 'v1-draft',
    nonce: randomUUID(),
  };
}

test('vfy competition turn: exact echo, EXTRACT 10, correct hash, timestamp and idempotency key', async () => {
  const matchId = randomUUID();
  const r = await post(vfyEnvelope('competition', matchId, 3, '95', '105'));
  assert.equal(r.status, 200);
  assert.equal(r.json.matchId, matchId);
  assert.equal(r.json.turn, 3);
  assert.deepEqual(r.json.action, { type: 'EXTRACT', amount: 10 });
  assert.equal(r.json.policyProof.circuitVersion, 'v1-draft');
  assert.equal(r.json.policyProof.publicInputsHash, publicInputsHash({ commitment: '0x' + '7d'.repeat(32), matchId, turn: 3, selfBalance: '95', opponentBalance: '105', action: { type: 'EXTRACT', amount: 10 }, circuitVersion: 'v1-draft' }));
  assert.match(r.json.agentTimestamp, /^\d{4}-\d{2}-\d{2}T.*Z$/);
  assert.match(r.json.idempotencyKey, /^[0-9a-f-]{36}$/);
  assert.deepEqual(Object.keys(r.json).sort(), ['action', 'agentTimestamp', 'idempotencyKey', 'matchId', 'policyProof', 'turn']);
  assert.deepEqual(Object.keys(r.json.policyProof).sort(), ['circuitVersion', 'publicInputsHash']);

  // Retry of the same turn: same body, same idempotency key. New turn: new key.
  const again = await post(vfyEnvelope('competition', matchId, 3, '95', '105'));
  assert.equal(again.body, r.body);
  const next = await post(vfyEnvelope('competition', matchId, 4, '95', '105'));
  assert.notEqual(next.json.idempotencyKey, r.json.idempotencyKey);
});

test('vfy practice turn: minimal strict shape, no competition-only fields', async () => {
  const r = await post(vfyEnvelope('practice', randomUUID(), 1, '100', '100'));
  assert.equal(r.status, 200);
  assert.deepEqual(Object.keys(r.json).sort(), ['action', 'matchId', 'policyProof', 'turn']);
  assert.deepEqual(Object.keys(r.json.policyProof).sort(), ['circuitVersion', 'publicInputsHash']);
  assert.match(r.json.policyProof.publicInputsHash, /^0x[0-9a-f]{64}$/);
});

test('vfy: HOLD when the opponent has nothing left, and amount is omitted for HOLD', async () => {
  const r = await post(vfyEnvelope('competition', randomUUID(), 12, '190', '0'));
  assert.deepEqual(r.json.action, { type: 'HOLD' });
});

test('unknown envelopes get a signed 400', async () => {
  const r = await post({ hello: 'world' });
  assert.equal(r.status, 400);
  assert.equal(verify(r.body, r.headers[SIGNATURE_HEADER], SECRET), true);
});
