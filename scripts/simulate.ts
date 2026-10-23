// Plays the platform against a running agent: preflight, Gatekeeper rounds, VFY turns, retries.
// Usage: AGENT_GAMES_HMAC_SECRET=... npm run simulate -- [http://localhost:3000/agent]
import { randomUUID } from 'node:crypto';
import { SIGNATURE_HEADER, sign, verify } from '../src/signature.js';
import { generateRoundTasks, gatekeeperEnvelope } from '../test/fixtures/traps.js';
import { publicInputsHash } from '../src/vfy/hash.js';
import { resolveTurn } from '../src/vfy/strategy.js';
import { deriveSalt, strategyCommitment } from '../src/vfy/commitment.js';
import { loadConfig } from '../src/config.js';
import { strategyParamsFromConfig } from '../src/vfy/strategy.js';
import { readFile } from 'node:fs/promises';

const url = process.argv[2] ?? `http://localhost:${process.env.PORT ?? 3000}${process.env.AGENT_PATH ?? '/agent'}`;
const secret = process.env.AGENT_GAMES_HMAC_SECRET ?? '';
if (!secret) {
  console.error('AGENT_GAMES_HMAC_SECRET must be set (same value the agent runs with)');
  process.exit(2);
}
let failures = 0;
const ok = (cond: boolean, msg: string) => {
  console.log(`${cond ? '  ok ' : '  FAIL'} ${msg}`);
  if (!cond) failures++;
};

async function post(payload: unknown): Promise<{ status: number; json: any; ms: number }> {
  const body = JSON.stringify(payload);
  const t0 = Date.now();
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', [SIGNATURE_HEADER]: sign(body, secret) }, body });
  const text = await res.text();
  const ms = Date.now() - t0;
  if (!verify(text, res.headers.get(SIGNATURE_HEADER), secret)) {
    ok(false, `response signature invalid (${res.status})`);
  }
  return { status: res.status, json: text ? JSON.parse(text) : null, ms };
}

console.log(`\n== preflight -> ${url}`);
{
  const r = await post({ type: 'agent-games.preflight.v1', agent_id: randomUUID(), issued_at: new Date().toISOString(), nonce: randomUUID() });
  ok(r.status === 200 && r.json?.ok === true && r.json?.protocolVersion === 'v1', `preflight ${JSON.stringify(r.json)} in ${r.ms}ms`);
}

const agentId = process.env.SIM_AGENT_ID ?? randomUUID();
console.log(`\n== Proof Gatekeeper: 4 simulated daily rounds (agent ${agentId})`);
let score = 0;
let n = 0;
for (const round of ['R01', 'R02', 'R03', 'R04']) {
  for (const t of generateRoundTasks(agentId, round)) {
    const r = await post(gatekeeperEnvelope(`gk_${agentId.slice(0, 8)}_${round}_${n++}`, t.input, 'competition'));
    const correct = r.json?.decision === t.expected;
    score += correct ? 12 : t.expected === 'APPROVE' ? -3 : -6;
    ok(correct, `${round} ${t.trapCode.padEnd(19)} -> ${r.json?.decision} ${r.json?.reason_code} (${r.ms}ms)`);
  }
}
console.log(`  gatekeeper score over 4 rounds: ${score} (max ${n * 12})`);

console.log('\n== Gatekeeper retry: same task id twice must return the same body');
{
  // A fresh proof_tx (different generator seed) so the first delivery is a genuine APPROVE.
  const t = generateRoundTasks(`${agentId}-retry`, 'R01').find((x) => x.trapCode === 'VALID_CONDITION')!;
  const env = gatekeeperEnvelope(`gk_${agentId.slice(0, 8)}_retry`, t.input);
  const a = await post(env);
  const b = await post(env);
  ok(JSON.stringify(a.json) === JSON.stringify(b.json) && a.json.decision === 'APPROVE', `retry identical: ${JSON.stringify(a.json)}`);
}

console.log('\n== Steal the VFY: practice turn');
{
  const matchId = randomUUID();
  const r = await post({ protocolVersion: 'v1', eventId: 'steal-the-vfy', mode: 'practice', matchId, turn: 1, issuedAt: new Date().toISOString(), deadlineAt: new Date(Date.now() + 60_000).toISOString(), state: { selfBalance: '100', opponentBalance: '100', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null, priorTurnHash: '0x' + '0'.repeat(64) }, resolverVersion: 'v1', nonce: randomUUID() });
  ok(r.status === 200 && r.json?.matchId === matchId && r.json?.turn === 1 && r.json?.action?.type, `practice ${JSON.stringify(r.json)} (${r.ms}ms)`);
}

console.log('\n== Steal the VFY: 20-turn competition match vs an always-EXTRACT opponent (local resolver model)');
{
  const matchId = randomUUID();
  // The platform echoes back the commitment we registered; reproduce it from the same env.
  const commitment = await strategyCommitment(strategyParamsFromConfig(loadConfig().vfy), deriveSalt(process.env.VFY_STRATEGY_SALT || secret));
  const vkPath = process.env.SIM_VFY_VK; // optional: verify returned proofs against this verification key
  const vk = vkPath ? JSON.parse(await readFile(vkPath, 'utf8')) : null;
  const snarkjs = vk ? await import('snarkjs') : null;
  let proofsVerified = 0;
  let self = 100;
  let opp = 100;
  let maxMs = 0;
  for (let turn = 1; turn <= 20; turn++) {
    const r = await post({ protocolVersion: 'v1', eventId: 'steal-the-vfy', mode: 'competition', matchId, turn, issuedAt: new Date().toISOString(), deadlineAt: new Date(Date.now() + 60_000).toISOString(), state: { selfBalance: String(self), opponentBalance: String(opp), selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null }, strategyCommitment: { hash: commitment }, resolverVersion: 'v1', nonce: randomUUID() });
    maxMs = Math.max(maxMs, r.ms);
    const j = r.json;
    const expectedHash = publicInputsHash({ commitment, matchId, turn, selfBalance: self, opponentBalance: opp, action: j.action, circuitVersion: j.policyProof.circuitVersion });
    const good = r.status === 200 && j.matchId === matchId && j.turn === turn && j.policyProof.publicInputsHash === expectedHash && typeof j.idempotencyKey === 'string';
    if (!good) ok(false, `turn ${turn}: ${JSON.stringify(j)}`);
    if (vk && snarkjs) {
      const p = j.policyProof;
      const verified = p.proof && p.public_signals ? await snarkjs.groth16.verify(vk, p.public_signals, p.proof) : false;
      if (!verified) ok(false, `turn ${turn}: proof missing or did not verify`);
      else proofsVerified++;
    }
    const res = resolveTurn(self, opp, j.action, { type: 'EXTRACT', amount: 10 });
    self += res.deltaA;
    opp += res.deltaB;
  }
  ok(true, `20 turns played, final self=${self} opp=${opp}, slowest turn ${maxMs}ms${vk ? `, proofs verified ${proofsVerified}/20` : ''}`);
}

console.log(failures ? `\n${failures} check(s) FAILED` : '\nall checks passed');
process.exit(failures ? 1 : 0);
