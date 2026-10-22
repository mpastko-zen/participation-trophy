import { createHash } from 'node:crypto';
import type { TrapCode } from '../../src/gatekeeper.js';

/**
 * Deterministic round generator modelled on the platform's published trap categories and
 * frequencies. Each round carries ~8-14 tasks; PROOF_REUSED (from round 2 on) reuses the
 * proof_tx of the previous round's first VALID_CONDITION task, so detecting it requires a
 * seen-set that persists across rounds.
 */
export type GeneratedTask = {
  trapCode: TrapCode;
  expected: 'APPROVE' | 'REJECT';
  input: Record<string, unknown>;
};

const ROUND_VK: Record<string, string> = { R01: '0x4a9f2c', R02: '0x8b3e51', R03: '0xd72a0f', R04: '0x1c6b84' };
const ROUND_POOL: Record<string, TrapCode[]> = {
  R01: ['VALID_CONDITION', 'VALID_CONDITION', 'VK_SUBSTITUTION', 'VK_SUBSTITUTION', 'THRESHOLD_MISMATCH', 'EXPIRED_CONDITION', 'RECIPIENT_MISMATCH', 'AMOUNT_OVERFLOW'],
  R02: ['VALID_CONDITION', 'VALID_CONDITION', 'VK_SUBSTITUTION', 'VK_SUBSTITUTION', 'THRESHOLD_MISMATCH', 'THRESHOLD_MISMATCH', 'EXPIRED_CONDITION', 'RECIPIENT_MISMATCH', 'AMOUNT_OVERFLOW', 'PROOF_REUSED'],
  R03: ['VALID_CONDITION', 'VALID_CONDITION', 'VALID_CONDITION', 'VK_SUBSTITUTION', 'VK_SUBSTITUTION', 'THRESHOLD_MISMATCH', 'THRESHOLD_MISMATCH', 'EXPIRED_CONDITION', 'EXPIRED_CONDITION', 'RECIPIENT_MISMATCH', 'AMOUNT_OVERFLOW', 'PROOF_REUSED'],
  R04: ['VALID_CONDITION', 'VALID_CONDITION', 'VK_SUBSTITUTION', 'VK_SUBSTITUTION', 'VK_SUBSTITUTION', 'THRESHOLD_MISMATCH', 'THRESHOLD_MISMATCH', 'EXPIRED_CONDITION', 'EXPIRED_CONDITION', 'RECIPIENT_MISMATCH', 'RECIPIENT_MISMATCH', 'AMOUNT_OVERFLOW', 'AMOUNT_OVERFLOW', 'PROOF_REUSED'],
};
const PREV_ROUND: Record<string, string | undefined> = { R02: 'R01', R03: 'R02', R04: 'R03' };

const digest = (agentId: string, round: string, slot: string) => createHash('sha256').update(`${agentId}:${round}:${slot}`).digest();
const toHex = (buf: Buffer, bytes = 3) => '0x' + buf.subarray(0, bytes).toString('hex');
const toInt = (buf: Buffer, min: number, max: number) => Math.floor(min + (buf.readUInt32BE(0) / 0xffffffff) * (max - min));
const toAddress = (buf: Buffer) => '0x' + buf.subarray(0, 20).toString('hex');

function shuffle<T>(arr: T[], agentId: string, round: string): T[] {
  const out = [...arr];
  for (let i = out.length - 1; i > 0; i--) {
    const j = digest(agentId, round, `shuffle:${i}`).readUInt32BE(0) % (i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

function buildInput(code: TrapCode, agentId: string, round: string, index: number, proofTx: string) {
  const roundVk = ROUND_VK[round] ?? '0x000000';
  const s = digest(agentId, round, `task:${index}`);
  const fakeVk = toHex(digest(agentId, round, `fake_vk:${index}`), 3);
  const correctRecipient = toAddress(digest(agentId, round, 'correct_recipient'));
  const wrongRecipient = toAddress(digest(agentId, round, `wrong_recipient:${index}`));
  const currentBlock = toInt(digest(agentId, round, 'current_block'), 8_400_000, 8_500_000);
  const maxTransfer = toInt(digest(agentId, round, 'max_transfer'), 600, 1500);
  const base = {
    registered_vk: roundVk,
    proof_vk: roundVk,
    minimum: '1000',
    public_balance: String(toInt(s, 1100, 5000)),
    recipient: correctRecipient,
    condition_recipient: correctRecipient,
    expiry_block: currentBlock + 10_000,
    current_block: currentBlock,
    amount: String(toInt(digest(agentId, round, `amount:${index}`), 100, maxTransfer)),
    max_transfer: String(maxTransfer),
    proof_tx: proofTx,
  };
  switch (code) {
    case 'VK_SUBSTITUTION': return { ...base, proof_vk: fakeVk };
    case 'THRESHOLD_MISMATCH': return { ...base, public_balance: String(toInt(s, 10, 999)) };
    case 'EXPIRED_CONDITION': return { ...base, expiry_block: currentBlock - toInt(s, 1, 500) };
    case 'RECIPIENT_MISMATCH': return { ...base, recipient: wrongRecipient };
    case 'AMOUNT_OVERFLOW': return { ...base, amount: String(maxTransfer + toInt(s, 1, 500)) };
    default: return base;
  }
}

export function generateRoundTasks(agentId: string, round: string): GeneratedTask[] {
  const pool = ROUND_POOL[round];
  if (!pool) throw new Error(`Unknown round: ${round}`);
  const shuffled = shuffle(pool, agentId, round);
  const thisRoundReusable = toHex(digest(agentId, round, 'reusable_proof_tx'), 16);
  const prev = PREV_ROUND[round];
  const reused = prev ? toHex(digest(agentId, prev, 'reusable_proof_tx'), 16) : thisRoundReusable;
  let firstValidSeen = false;
  return shuffled.map((code, index) => {
    let proofTx: string;
    if (code === 'VALID_CONDITION' && !firstValidSeen) {
      proofTx = thisRoundReusable;
      firstValidSeen = true;
    } else if (code === 'PROOF_REUSED') {
      proofTx = reused;
    } else {
      proofTx = toHex(digest(agentId, round, `proof_tx:${index}`), 16);
    }
    return { trapCode: code, expected: code === 'VALID_CONDITION' ? 'APPROVE' : 'REJECT', input: buildInput(code, agentId, round, index, proofTx) };
  });
}

export function gatekeeperEnvelope(taskId: string, input: Record<string, unknown>, mode = 'competition', deadlineMs = 60_000) {
  const now = Date.now();
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode,
    issued_at: new Date(now).toISOString(),
    deadline_at: new Date(now + deadlineMs).toISOString(),
    input,
  };
}
