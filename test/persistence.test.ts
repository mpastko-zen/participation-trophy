import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Agent } from '../src/agent.js';
import { loadConfig } from '../src/config.js';
import { Store } from '../src/store.js';
import { SIGNATURE_HEADER, sign } from '../src/signature.js';
import { generateRoundTasks, gatekeeperEnvelope } from './fixtures/traps.js';

const SECRET = 'c'.repeat(64);
process.env.AGENT_GAMES_HMAC_SECRET = SECRET;

test('the approved proof_tx seen-set and idempotency cache survive a process restart', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pt-'));
  try {
    const config = loadConfig();
    const post = async (agent: Agent, payload: unknown) => {
      const body = Buffer.from(JSON.stringify(payload));
      const r = await agent.handle(body, { [SIGNATURE_HEADER]: sign(body, SECRET) });
      return { ...r, json: JSON.parse(r.body) as Record<string, any> };
    };
    const day1 = generateRoundTasks('persist', 'R01');
    const valid = day1.find((t) => t.trapCode === 'VALID_CONDITION')!;

    // Day 1: process A approves a valid task.
    const storeA = Store.open(dir);
    const agentA = new Agent(config, storeA);
    const a = await post(agentA, gatekeeperEnvelope('gk_day1', valid.input));
    assert.equal(a.json.decision, 'APPROVE');
    storeA.close();

    // Day 2: process B (fresh memory, same disk) must still remember it.
    const storeB = Store.open(dir);
    const agentB = new Agent(config, storeB);
    const replay = await post(agentB, gatekeeperEnvelope('gk_day2', valid.input));
    assert.equal(replay.json.decision, 'REJECT');
    assert.equal(replay.json.reason_code, 'PROOF_REUSED');
    // ...and a platform retry of the day-1 task id still gets the identical day-1 body.
    const retry = await post(agentB, gatekeeperEnvelope('gk_day1', valid.input));
    assert.equal(retry.body, a.body);
    storeB.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
