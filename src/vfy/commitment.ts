import { createHash } from 'node:crypto';
import { strategyParamsToSignals, type StrategyParams } from './strategy.js';

/**
 * Strategy commitment C = Poseidon(params..., salt), rendered as 0x + 64 hex chars.
 * This is what gets registered under Dashboard -> My Agents -> Edit agent before Swiss Round 1.
 * The salt is private; derive it from VFY_STRATEGY_SALT (or, failing that, the HMAC secret)
 * so it is reproducible across restarts without storing it.
 */
export function deriveSalt(seed: string): bigint {
  const h = createHash('sha256').update('participation-trophy/vfy-salt/v1:' + seed).digest('hex');
  // Keep it below the BN128 scalar field modulus by truncating to 248 bits.
  return BigInt('0x' + h) & ((1n << 248n) - 1n);
}

let poseidonPromise: ReturnType<typeof loadPoseidon> | undefined;
async function loadPoseidon() {
  const { buildPoseidon } = await import('circomlibjs');
  return buildPoseidon();
}

export async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  poseidonPromise ??= loadPoseidon();
  const poseidon = await poseidonPromise;
  return poseidon.F.toObject(poseidon(inputs));
}

export async function strategyCommitment(params: StrategyParams, salt: bigint): Promise<`0x${string}`> {
  const h = await poseidonHash([...strategyParamsToSignals(params), salt]);
  return ('0x' + h.toString(16).padStart(64, '0')) as `0x${string}`;
}
