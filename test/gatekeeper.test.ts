import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateGatekeeper, normHex, reasonCodeFor, type SeenSet } from '../src/gatekeeper.js';
import { generateRoundTasks } from './fixtures/traps.js';

class MemSeen implements SeenSet {
  map = new Map<string, string>();
  previouslyApprovedBy(tx: string) { return this.map.get(tx); }
  approve(tx: string, taskId: string) { this.map.set(normHex(tx), taskId); }
}

test('all seven trap categories across four rounds are decided correctly (seen-set persists across rounds)', () => {
  const seen = new MemSeen();
  let n = 0;
  const byTrap = new Map<string, number>();
  for (const round of ['R01', 'R02', 'R03', 'R04']) {
    for (const t of generateRoundTasks('agent-under-test', round)) {
      const id = `${round}-${n++}`;
      const v = evaluateGatekeeper(t.input, id, seen);
      assert.equal(v.decision, t.expected, `${round} ${t.trapCode}: ${JSON.stringify(v)}`);
      assert.equal(v.trap, t.trapCode, `${round} wrong trap classification: ${JSON.stringify(v)}`);
      if (v.decision === 'APPROVE') seen.approve(t.input.proof_tx as string, id);
      byTrap.set(t.trapCode, (byTrap.get(t.trapCode) ?? 0) + 1);
    }
  }
  assert.equal(byTrap.size, 7);
  assert.ok(byTrap.get('PROOF_REUSED')! >= 3);
});

test('a retry of the same task id is not a replay', () => {
  const seen = new MemSeen();
  const [valid] = generateRoundTasks('x', 'R01').filter((t) => t.trapCode === 'VALID_CONDITION');
  const first = evaluateGatekeeper(valid!.input, 'task-1', seen);
  assert.equal(first.decision, 'APPROVE');
  seen.approve(valid!.input.proof_tx as string, 'task-1');
  const retry = evaluateGatekeeper(valid!.input, 'task-1', seen);
  assert.equal(retry.decision, 'APPROVE');
  const replay = evaluateGatekeeper(valid!.input, 'task-2', seen);
  assert.equal(replay.trap, 'PROOF_REUSED');
});

test('replay is checked before every other validation', () => {
  const seen = new MemSeen();
  const [bad] = generateRoundTasks('x', 'R01').filter((t) => t.trapCode === 'VK_SUBSTITUTION');
  seen.approve(bad!.input.proof_tx as string, 'earlier');
  assert.equal(evaluateGatekeeper(bad!.input, 'now', seen).trap, 'PROOF_REUSED');
});

test('boundary conditions: expiry at equality rejects, balance at minimum and amount at cap approve', () => {
  const seen = new MemSeen();
  const base = generateRoundTasks('x', 'R01').find((t) => t.trapCode === 'VALID_CONDITION')!.input;
  assert.equal(evaluateGatekeeper({ ...base, expiry_block: base.current_block }, 't', seen).trap, 'EXPIRED_CONDITION');
  assert.equal(evaluateGatekeeper({ ...base, public_balance: base.minimum }, 't', seen).decision, 'APPROVE');
  assert.equal(evaluateGatekeeper({ ...base, amount: base.max_transfer }, 't', seen).decision, 'APPROVE');
  assert.equal(evaluateGatekeeper({ ...base, amount: String(BigInt(base.max_transfer as string) + 1n) }, 't', seen).trap, 'AMOUNT_OVERFLOW');
});

test('hex comparisons are case-insensitive but never partial', () => {
  const seen = new MemSeen();
  const base = generateRoundTasks('x', 'R01').find((t) => t.trapCode === 'VALID_CONDITION')!.input;
  assert.equal(evaluateGatekeeper({ ...base, proof_vk: (base.proof_vk as string).toUpperCase() }, 't', seen).decision, 'APPROVE');
  assert.equal(evaluateGatekeeper({ ...base, recipient: (base.recipient as string).slice(0, -2) }, 't', seen).trap, 'RECIPIENT_MISMATCH');
  assert.equal(evaluateGatekeeper({ ...base, proof_vk: (base.proof_vk as string) + '00' }, 't', seen).trap, 'VK_SUBSTITUTION');
});

test('malformed or missing input fails closed with a schema-valid reason code', () => {
  const seen = new MemSeen();
  for (const input of [undefined, null, {}, { registered_vk: '0x1' }, 'nope']) {
    const v = evaluateGatekeeper(input, 't', seen);
    assert.equal(v.decision, 'REJECT');
    assert.match(v.reason_code, /^[A-Z0-9_:-]{2,80}$/);
  }
});

test('reason code styles', () => {
  assert.equal(reasonCodeFor('PROOF_REUSED', 'trap'), 'PROOF_REUSED');
  assert.equal(reasonCodeFor('PROOF_REUSED', 'canonical'), 'PROOF_REPLAY');
  assert.equal(reasonCodeFor('VALID_CONDITION', 'trap'), 'VALID_PROOF');
});
