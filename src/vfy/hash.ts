import { concat, keccak256, numberToHex } from 'viem';

export type VfyActionType = 'HOLD' | 'FORTIFY' | 'EXTRACT';
export type VfyAction = { type: 'HOLD' } | { type: 'FORTIFY' } | { type: 'EXTRACT'; amount: number };

export const ACTION_CODE: Record<VfyActionType, bigint> = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };

/** Circuit version string -> integer public input. "v1-draft" -> 1 per the build guide. */
export function circuitVersionInt(version: string): bigint {
  const m = /^v(\d+)/i.exec(version.trim());
  return m ? BigInt(m[1]!) : 1n;
}

export function matchIdToBigInt(matchId: string): bigint {
  const hex = matchId.replace(/-/g, '');
  if (!/^[0-9a-f]+$/i.test(hex)) throw new Error(`matchId is not hex/uuid: ${matchId}`);
  return BigInt('0x' + hex);
}

export function amountOf(action: VfyAction): bigint {
  return action.type === 'EXTRACT' ? BigInt(action.amount) : 0n;
}

/**
 * keccak256 of ABI-packed public inputs, each left-padded to 32 bytes, in the order the
 * build guide specifies. The platform recomputes this from its own view of the match
 * state and rejects the turn (scored as HOLD) if it differs.
 */
export function publicInputsHash(p: {
  commitment: string;
  matchId: string;
  turn: number;
  selfBalance: string | number | bigint;
  opponentBalance: string | number | bigint;
  action: VfyAction;
  circuitVersion: string;
}): `0x${string}` {
  return keccak256(
    concat([
      numberToHex(BigInt(p.commitment), { size: 32 }),
      numberToHex(matchIdToBigInt(p.matchId), { size: 32 }),
      numberToHex(BigInt(p.turn), { size: 32 }),
      numberToHex(BigInt(p.selfBalance), { size: 32 }),
      numberToHex(BigInt(p.opponentBalance), { size: 32 }),
      numberToHex(ACTION_CODE[p.action.type], { size: 32 }),
      numberToHex(amountOf(p.action), { size: 32 }),
      numberToHex(circuitVersionInt(p.circuitVersion), { size: 32 }),
    ]),
  );
}
