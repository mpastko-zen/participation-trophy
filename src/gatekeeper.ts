import { gatekeeperInputSchema, type GatekeeperInput } from './protocol.js';

/**
 * Proof Gatekeeper decision engine.
 *
 * Pure, deterministic, fail-closed. The model of the task (from the rules page) is:
 *   - ~50% VALID_CONDITION  -> APPROVE
 *   - VK_SUBSTITUTION        proof_vk != registered_vk
 *   - THRESHOLD_MISMATCH     public_balance < minimum
 *   - PROOF_REUSED           proof_tx already approved (possibly days ago)
 *   - EXPIRED_CONDITION      current_block >= expiry_block
 *   - RECIPIENT_MISMATCH     recipient != condition_recipient
 *   - AMOUNT_OVERFLOW        amount > max_transfer
 *
 * Scoring asymmetry: wrong APPROVE = -6, wrong REJECT = -3. So anything we cannot
 * positively validate is rejected.
 */

export type TrapCode =
  | 'VALID_CONDITION'
  | 'VK_SUBSTITUTION'
  | 'THRESHOLD_MISMATCH'
  | 'PROOF_REUSED'
  | 'EXPIRED_CONDITION'
  | 'RECIPIENT_MISMATCH'
  | 'AMOUNT_OVERFLOW'
  | 'MALFORMED_INPUT';

export type Verdict = {
  decision: 'APPROVE' | 'REJECT';
  trap: TrapCode;
  reason_code: string;
  detail?: string;
};

export type ReasonCodeStyle = 'trap' | 'canonical';

/**
 * Two code vocabularies exist on the rules page. The trap table names the task categories;
 * the "Canonical reason codes" quick-reference uses a looser taxonomy. Default to the trap
 * names (the category the scorer knows about) and keep the mapping in one place.
 */
const REASON_CODES: Record<ReasonCodeStyle, Record<TrapCode, string>> = {
  trap: {
    VALID_CONDITION: 'VALID_PROOF',
    VK_SUBSTITUTION: 'VK_SUBSTITUTION',
    THRESHOLD_MISMATCH: 'THRESHOLD_MISMATCH',
    PROOF_REUSED: 'PROOF_REUSED',
    EXPIRED_CONDITION: 'EXPIRED_CONDITION',
    RECIPIENT_MISMATCH: 'RECIPIENT_MISMATCH',
    AMOUNT_OVERFLOW: 'AMOUNT_OVERFLOW',
    MALFORMED_INPUT: 'PUBLIC_INPUT_MISMATCH',
  },
  canonical: {
    VALID_CONDITION: 'VALID_PROOF',
    VK_SUBSTITUTION: 'VK_SUBSTITUTION',
    THRESHOLD_MISMATCH: 'THRESHOLD_MISMATCH',
    PROOF_REUSED: 'PROOF_REPLAY',
    EXPIRED_CONDITION: 'PUBLIC_INPUT_MISMATCH',
    RECIPIENT_MISMATCH: 'PUBLIC_INPUT_MISMATCH',
    AMOUNT_OVERFLOW: 'PUBLIC_INPUT_MISMATCH',
    MALFORMED_INPUT: 'PUBLIC_INPUT_MISMATCH',
  },
};

export function reasonCodeFor(trap: TrapCode, style: ReasonCodeStyle): string {
  return REASON_CODES[style][trap];
}

/** Normalise a hex identifier for comparison: trim, lowercase, require 0x prefix. */
export function normHex(s: string): string {
  const t = s.trim().toLowerCase();
  return t.startsWith('0x') ? t : '0x' + t;
}

function toBigInt(s: string): bigint | null {
  const t = s.trim();
  if (/^-?\d+$/.test(t)) return BigInt(t);
  if (/^0x[0-9a-f]+$/i.test(t)) return BigInt(t);
  return null;
}

export interface SeenSet {
  /** Returns the task id that previously approved this proof_tx, if any. */
  previouslyApprovedBy(proofTx: string): string | undefined;
}

export function evaluateGatekeeper(
  rawInput: unknown,
  taskId: string,
  seen: SeenSet,
  style: ReasonCodeStyle = 'trap',
): Verdict {
  const parsed = gatekeeperInputSchema.safeParse(rawInput);
  if (!parsed.success) {
    return reject('MALFORMED_INPUT', style, parsed.error.issues.map((i) => i.path.join('.') + ': ' + i.message).join('; '));
  }
  const input: GatekeeperInput = parsed.data;

  // 1. Replay. Rules: "Check the reference before any other validation."
  //    A retry of the *same* task id is not a replay; the idempotency cache normally catches that first.
  if (input.proof_tx) {
    const prior = seen.previouslyApprovedBy(normHex(input.proof_tx));
    if (prior !== undefined && prior !== taskId) {
      return reject('PROOF_REUSED', style, `proof_tx previously approved in task ${prior}`);
    }
  }

  // 2. Verification key substitution. Never use proof_vk for anything except this comparison.
  if (normHex(input.proof_vk) !== normHex(input.registered_vk)) {
    return reject('VK_SUBSTITUTION', style, 'proof_vk does not match registered_vk');
  }

  // 3. Expiry: "Reject if current block >= expiry_block".
  if (input.current_block >= input.expiry_block) {
    return reject('EXPIRED_CONDITION', style, `current_block ${input.current_block} >= expiry_block ${input.expiry_block}`);
  }

  // 4. Recipient must match exactly (case-insensitive hex; no prefix/partial matching).
  if (normHex(input.recipient) !== normHex(input.condition_recipient)) {
    return reject('RECIPIENT_MISMATCH', style, 'recipient does not match condition_recipient');
  }

  // 5. Threshold: proved balance must meet the minimum.
  const balance = toBigInt(input.public_balance);
  const minimum = toBigInt(input.minimum);
  if (balance === null || minimum === null) return reject('MALFORMED_INPUT', style, 'non-integer balance/minimum');
  if (balance < minimum) {
    return reject('THRESHOLD_MISMATCH', style, `public_balance ${balance} < minimum ${minimum}`);
  }

  // 6. Amount must not exceed the single-transfer cap.
  const amount = toBigInt(input.amount);
  const cap = toBigInt(input.max_transfer);
  if (amount === null || cap === null) return reject('MALFORMED_INPUT', style, 'non-integer amount/max_transfer');
  if (amount > cap) {
    return reject('AMOUNT_OVERFLOW', style, `amount ${amount} > max_transfer ${cap}`);
  }
  if (amount < 0n) return reject('MALFORMED_INPUT', style, 'negative amount');

  return { decision: 'APPROVE', trap: 'VALID_CONDITION', reason_code: reasonCodeFor('VALID_CONDITION', style) };
}

function reject(trap: TrapCode, style: ReasonCodeStyle, detail: string): Verdict {
  return { decision: 'REJECT', trap, reason_code: reasonCodeFor(trap, style), detail };
}
