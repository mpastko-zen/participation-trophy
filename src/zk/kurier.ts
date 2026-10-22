import { log } from '../log.js';
import type { Groth16Proof } from './prover.js';

/**
 * Kurier: zkVerify's REST relay. https://docs.zkverify.io/overview/getting-started/kurier
 *   POST /register-vk/{API_KEY}      -> { vkHash | meta.vkHash }
 *   POST /submit-proof/{API_KEY}     -> { jobId, optimisticVerify }
 *   GET  /job-status/{API_KEY}/{jobId} -> { status, txHash, blockHash, ... }
 * Status progression: Queued -> Valid -> Submitted -> IncludedInBlock -> Finalized (or Failed).
 */

export type KurierConfig = { apiUrl: string; apiKey: string; pollIntervalMs: number };

export type KurierJob = {
  jobId: string;
  optimisticVerify?: string;
  status?: string;
  txHash?: string;
  blockHash?: string;
};

const TERMINAL = new Set(['Finalized', 'Failed', 'Aggregated', 'AggregationPublished']);

export function kurierConfigured(c: KurierConfig): boolean {
  return Boolean(c.apiKey && c.apiUrl);
}

export async function submitGroth16(c: KurierConfig, p: Groth16Proof, vkHash: string, timeoutMs = 15_000): Promise<KurierJob | null> {
  try {
    const res = await fetch(`${c.apiUrl}/submit-proof/${c.apiKey}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        proofType: 'groth16',
        vkRegistered: true,
        proofOptions: { library: 'snarkjs', curve: 'bn128' },
        proofData: { proof: p.proof, publicSignals: p.publicSignals, vk: vkHash },
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      log('warn', 'kurier submit rejected', { status: res.status, body: data });
      return null;
    }
    const jobId = (data.jobId ?? data.job_id) as string | undefined;
    if (!jobId) {
      log('warn', 'kurier submit returned no job id', { body: data });
      return null;
    }
    const job: KurierJob = { jobId, optimisticVerify: data.optimisticVerify as string | undefined };
    log('info', 'kurier job submitted', job);
    return job;
  } catch (err) {
    log('warn', 'kurier submit failed', { error: String(err) });
    return null;
  }
}

export async function jobStatus(c: KurierConfig, jobId: string, timeoutMs = 10_000): Promise<KurierJob | null> {
  try {
    const res = await fetch(`${c.apiUrl}/job-status/${c.apiKey}/${jobId}`, { signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return null;
    const data = (await res.json()) as Record<string, unknown>;
    return {
      jobId,
      status: data.status as string | undefined,
      txHash: data.txHash as string | undefined,
      blockHash: data.blockHash as string | undefined,
    };
  } catch {
    return null;
  }
}

/** Poll until the job is terminal or the budget is spent. Returns the last status seen. */
export async function waitForJob(c: KurierConfig, jobId: string, budgetMs: number): Promise<KurierJob> {
  const until = Date.now() + budgetMs;
  let last: KurierJob = { jobId };
  while (Date.now() < until) {
    const s = await jobStatus(c, jobId, Math.max(1000, Math.min(10_000, until - Date.now())));
    if (s) last = s;
    if (s?.status && TERMINAL.has(s.status)) break;
    const wait = Math.min(c.pollIntervalMs, until - Date.now());
    if (wait <= 0) break;
    await new Promise((r) => setTimeout(r, wait));
  }
  log('info', 'kurier job status', last);
  return last;
}

/** Submit then wait. Returns the best available on-chain reference (txHash, else jobId). */
export async function submitAndWait(
  c: KurierConfig,
  p: Groth16Proof,
  vkHash: string,
  budgetMs: number,
): Promise<{ reference: string; finalized: boolean; job: KurierJob } | null> {
  const started = Date.now();
  const job = await submitGroth16(c, p, vkHash, Math.min(15_000, Math.max(2000, budgetMs)));
  if (!job) return null;
  const remaining = budgetMs - (Date.now() - started);
  const final = remaining > 1000 ? await waitForJob(c, job.jobId, remaining) : job;
  return {
    reference: final.txHash ?? job.jobId,
    finalized: final.status === 'Finalized',
    job: { ...job, ...final },
  };
}

export async function registerVk(c: KurierConfig, vk: unknown): Promise<string> {
  const res = await fetch(`${c.apiUrl}/register-vk/${c.apiKey}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ proofType: 'groth16', proofOptions: { library: 'snarkjs', curve: 'bn128' }, vk }),
  });
  const data = (await res.json()) as { vkHash?: string; meta?: { vkHash?: string } };
  if (!res.ok) throw new Error(`register-vk failed: ${res.status} ${JSON.stringify(data)}`);
  const hash = data.vkHash ?? data.meta?.vkHash;
  if (!hash) throw new Error(`register-vk returned no vkHash: ${JSON.stringify(data)}`);
  return hash;
}
