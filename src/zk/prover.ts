import { access } from 'node:fs/promises';
import { log } from '../log.js';

export type Groth16Proof = { proof: Record<string, unknown>; publicSignals: string[] };

export type CircuitArtifacts = { wasm: string; zkey: string };

export async function artifactsAvailable(a: CircuitArtifacts): Promise<boolean> {
  if (!a.wasm || !a.zkey) return false;
  try {
    await Promise.all([access(a.wasm), access(a.zkey)]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Generate a Groth16 proof with snarkjs, bounded by a time budget. snarkjs cannot be
 * cancelled, so on timeout we return null and let the caller respond without a proof
 * (losing the proof points but keeping the decision points).
 */
export async function groth16Prove(
  artifacts: CircuitArtifacts,
  inputs: Record<string, unknown>,
  budgetMs: number,
): Promise<Groth16Proof | null> {
  if (budgetMs < 500) {
    log('warn', 'skipping proof generation: budget too small', { budgetMs });
    return null;
  }
  const snarkjs = await import('snarkjs');
  const started = Date.now();
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), budgetMs);
  });
  try {
    const result = await Promise.race([snarkjs.groth16.fullProve(inputs, artifacts.wasm, artifacts.zkey), timeout]);
    if (result === null) {
      log('warn', 'proof generation timed out', { budgetMs });
      return null;
    }
    log('info', 'proof generated', { ms: Date.now() - started, publicSignals: result.publicSignals.length });
    return result;
  } catch (err) {
    log('error', 'proof generation failed', { error: String(err) });
    return null;
  } finally {
    if (timer) clearTimeout(timer);
  }
}
