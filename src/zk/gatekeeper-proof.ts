import { createHash } from 'node:crypto';
import { keccak256, toBytes } from 'viem';
import type { GatekeeperInput } from '../protocol.js';

/**
 * Proof Gatekeeper circuit (official artifacts, published at /build on 2026-10-22):
 *   build/circuits/gatekeeper/gatekeeper.wasm, gatekeeper_final.zkey  (Groth16 / BN128, circom 2.2.3)
 *   vk_hash on zkVerify mainnet: 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
 *
 * Everything below was established empirically against those artifacts (see test/gatekeeper-proof.test.ts):
 *
 * Input signals (13):
 *   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
 *   recipient, conditionRecipient, amount, maxTransfer, decision, taskId   (public)
 *   salt                                                                   (private)
 *
 * Public signals (13), in order:
 *   [0]  Poseidon(salt, taskId)        nullifier binding the proof to this task
 *   [1]  registeredVkHash  [2] proofVkHash  [3] minimum  [4] publicBalance  [5] expiryBlock
 *   [6]  currentBlock  [7] recipient  [8] conditionRecipient  [9] amount  [10] maxTransfer
 *   [11] decision (1 = APPROVE, 0 = REJECT)  [12] taskId
 *
 * Constraint: decision == (proofVkHash == registeredVkHash && publicBalance >= minimum &&
 *             currentBlock < expiryBlock && recipient == conditionRecipient && amount <= maxTransfer).
 * So expiry is inclusive (current == expiry is expired) and amount == cap is allowed, exactly as
 * src/gatekeeper.ts decides. The circuit has no notion of proof reuse: a PROOF_REUSED task
 * (all fields valid, decision REJECT) is NOT provable and must be answered without a proof.
 */

/** BN128 scalar field modulus (circom's default prime). */
export const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export type TaskIdMapping = 'sha256' | 'keccak256' | 'uuid';

/** Hex (0x...) or decimal string -> field element as a decimal string. */
export function toField(v: string | number | bigint): string {
  let n: bigint;
  if (typeof v === 'bigint') n = v;
  else if (typeof v === 'number') n = BigInt(Math.trunc(v));
  else {
    const t = v.trim();
    if (/^0x[0-9a-f]*$/i.test(t)) n = t.length > 2 ? BigInt(t) : 0n;
    else if (/^-?\d+$/.test(t)) n = BigInt(t);
    else throw new Error(`not a hex or integer string: ${t.slice(0, 40)}`);
  }
  n %= FIELD_P;
  if (n < 0n) n += FIELD_P;
  return n.toString();
}

/**
 * task_id -> field element. The platform's task ids look like "gk_8d31_..." (not numeric), so some
 * hash-to-field is required; which one the platform uses is not documented. 'sha256' is the default,
 * GATEKEEPER_TASKID_MAP switches it once practice-mode records show what the platform expects.
 */
export function taskIdToField(taskId: string, mapping: TaskIdMapping = 'sha256'): string {
  if (mapping === 'uuid') {
    const uuidHex = taskId.slice(-36).replace(/-/g, '');
    if (/^[0-9a-f]{32}$/i.test(uuidHex)) return toField('0x' + uuidHex);
    return taskIdToField(taskId, 'sha256');
  }
  if (mapping === 'keccak256') return toField(keccak256(toBytes(taskId)));
  return toField('0x' + createHash('sha256').update(taskId, 'utf8').digest('hex'));
}

/** Derive a stable private salt from an operator secret when GATEKEEPER_SALT is not set explicitly. */
export function deriveGatekeeperSalt(seed: string): string {
  return toField('0x' + createHash('sha256').update('agent-games:gatekeeper-salt:' + seed, 'utf8').digest('hex'));
}

export function buildGatekeeperCircuitInputs(
  input: GatekeeperInput,
  taskId: string,
  decision: 'APPROVE' | 'REJECT',
  opts: { salt: string; taskIdMapping?: TaskIdMapping },
): Record<string, string> {
  return {
    registeredVkHash: toField(input.registered_vk),
    proofVkHash: toField(input.proof_vk),
    minimum: toField(input.minimum),
    publicBalance: toField(input.public_balance),
    expiryBlock: toField(input.expiry_block),
    currentBlock: toField(input.current_block),
    recipient: toField(input.recipient),
    conditionRecipient: toField(input.condition_recipient),
    amount: toField(input.amount),
    maxTransfer: toField(input.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(taskId, opts.taskIdMapping),
    salt: toField(opts.salt),
  };
}

/** Public signals [1..12] the platform can recompute from the task; [0] is the salted nullifier. */
export function expectedPublicSignals(
  input: GatekeeperInput,
  taskId: string,
  decision: 'APPROVE' | 'REJECT',
  taskIdMapping?: TaskIdMapping,
): string[] {
  const i = buildGatekeeperCircuitInputs(input, taskId, decision, { salt: '0', taskIdMapping });
  return [i.registeredVkHash!, i.proofVkHash!, i.minimum!, i.publicBalance!, i.expiryBlock!, i.currentBlock!, i.recipient!, i.conditionRecipient!, i.amount!, i.maxTransfer!, i.decision!, i.taskId!];
}
