import { randomUUID } from 'node:crypto';
import type { Config } from './config.js';
import { evaluateGatekeeper, normHex } from './gatekeeper.js';
import { log } from './log.js';
import { gatekeeperInputSchema, workBudgetMs, type GatekeeperTask, type Preflight, type VfyTurn } from './protocol.js';
import type { Store } from './store.js';
import { deriveSalt, strategyCommitment } from './vfy/commitment.js';
import { publicInputsHash, type VfyAction } from './vfy/hash.js';
import { buildVfyCircuitInputs } from './vfy/policy-proof.js';
import { decide, strategyParamsFromConfig, type StrategyParams } from './vfy/strategy.js';
import { normHex as normHexCommitment } from './gatekeeper.js';
import { buildGatekeeperCircuitInputs, deriveGatekeeperSalt } from './zk/gatekeeper-proof.js';
import { kurierConfigured, submitAndWait } from './zk/kurier.js';
import { artifactsAvailable, groth16Prove } from './zk/prover.js';

export type Handled = { status: number; body: Record<string, unknown>; cacheKey?: string };

export class Handlers {
  private readonly params: StrategyParams;
  private readonly salt: bigint;
  private commitmentPromise: Promise<`0x${string}`> | undefined;

  constructor(
    private readonly config: Config,
    private readonly store: Store,
  ) {
    this.params = strategyParamsFromConfig(config.vfy);
    this.salt = deriveSalt(config.vfy.strategySalt || config.hmacSecret || 'dev');
    this.gatekeeperSalt = config.gatekeeper.salt || deriveGatekeeperSalt(config.vfy.strategySalt || config.hmacSecret || 'dev');
  }
  private readonly gatekeeperSalt: string;

  /** Our own strategy commitment (what to register on the dashboard). */
  commitment(): Promise<`0x${string}`> {
    this.commitmentPromise ??= strategyCommitment(this.params, this.salt);
    return this.commitmentPromise;
  }

  preflight(_task: Preflight): Handled {
    return { status: 200, body: { ok: true, protocolVersion: 'v1' } };
  }

  async gatekeeper(task: GatekeeperTask): Promise<Handled> {
    const started = Date.now();
    const cacheKey = `gk:${task.task_id}`;
    const scope = this.config.gatekeeper.scopeSeenSetByMode ? (task.mode ?? 'competition') : 'all';
    const budget = workBudgetMs(task.deadline_at, this.config.safetyMarginMs, this.config.maxWorkMs);

    const verdict = evaluateGatekeeper(
      task.input,
      task.task_id,
      { previouslyApprovedBy: (tx) => this.store.seenProof(scope, tx)?.task_id },
      this.config.gatekeeper.reasonCodeStyle,
    );

    const parsed = gatekeeperInputSchema.safeParse(task.input);
    const inputProofTx = parsed.success ? parsed.data.proof_tx : undefined;

    // Rules: on APPROVE, record the reference immediately.
    if (verdict.decision === 'APPROVE' && inputProofTx) {
      this.store.markProofSeen(scope, normHex(inputProofTx), task.task_id);
    }

    const body: Record<string, unknown> = { decision: verdict.decision, reason_code: verdict.reason_code };
    if (inputProofTx) body.proof_tx = inputProofTx;

    // Generate the official circuit proof on every provable task (a missing proof costs -2).
    // The circuit constrains decision == field checks, so it cannot prove a REJECT of a task whose
    // fields are all valid: PROOF_REUSED (and malformed input) are answered without a proof.
    const gk = this.config.gatekeeper;
    const provable = parsed.success && verdict.trap !== 'PROOF_REUSED' && verdict.trap !== 'MALFORMED_INPUT';
    if (provable && (await artifactsAvailable({ wasm: gk.wasm, zkey: gk.zkey }))) {
      const remaining = () => budget - (Date.now() - started);
      const proof = await groth16Prove(
        { wasm: gk.wasm, zkey: gk.zkey },
        buildGatekeeperCircuitInputs(parsed.data, task.task_id, verdict.decision, { salt: this.gatekeeperSalt, taskIdMapping: gk.taskIdMapping }),
        remaining(),
      );
      if (proof) {
        if (gk.includeProofInResponse) {
          body.proof = proof.proof;
          body.public_signals = proof.publicSignals;
        }
        if (kurierConfigured(this.config.kurier) && gk.vkHash && remaining() > 3000) {
          const r = await submitAndWait(this.config.kurier, proof, gk.vkHash, remaining());
          if (r) body.proof_tx = r.reference;
        }
      }
    }

    log('info', 'gatekeeper decided', {
      task_id: task.task_id,
      mode: task.mode,
      decision: verdict.decision,
      trap: verdict.trap,
      reason_code: verdict.reason_code,
      detail: verdict.detail,
      provable,
      proof: Boolean(body.proof),
      ms: Date.now() - started,
    });
    return { status: 200, body, cacheKey };
  }

  async vfy(task: VfyTurn): Promise<Handled> {
    const started = Date.now();
    const mode = task.mode === 'practice' ? 'practice' : 'competition';
    const cacheKey = `vfy:${mode}:${task.matchId}:${task.turn}`;
    const budget = workBudgetMs(task.deadlineAt, this.config.safetyMarginMs, this.config.maxWorkMs);

    const selfBalance = toBig(task.state.selfBalance);
    const opponentBalance = toBig(task.state.opponentBalance);
    const action: VfyAction = decide(this.params, { turn: task.turn, selfBalance, opponentBalance });

    // The platform freezes our registered commitment and sends it back each turn; prefer that.
    const commitment = task.strategyCommitment?.hash ?? (await this.commitment());
    const circuitVersion = this.config.vfy.circuitVersion;
    const hash = publicInputsHash({
      commitment,
      matchId: task.matchId,
      turn: task.turn,
      selfBalance,
      opponentBalance,
      action,
      circuitVersion,
    });

    const policyProof: Record<string, unknown> = { circuitVersion, publicInputsHash: hash };
    const body: Record<string, unknown> = { matchId: task.matchId, turn: task.turn, action, policyProof };
    if (mode === 'competition') {
      body.agentTimestamp = new Date().toISOString();
      body.idempotencyKey = randomUUID();
    }

    const v = this.config.vfy;
    // The circuit can only prove a turn against *our* committed strategy. If the platform froze a
    // different commitment (stale registration), proving would just fail: answer without a proof.
    const ours = await this.commitment();
    const provable = normHexCommitment(commitment) === normHexCommitment(ours);
    if (!provable) log('warn', 'vfy: frozen commitment differs from ours; re-register `npm run commitment`', { matchId: task.matchId, turn: task.turn });
    if (provable && (await artifactsAvailable({ wasm: v.wasm, zkey: v.zkey }))) {
      const remaining = () => budget - (Date.now() - started);
      const inputs = buildVfyCircuitInputs(
        { commitment, matchId: task.matchId, turn: task.turn, selfBalance, opponentBalance, action, circuitVersion },
        { params: this.params, salt: this.salt },
      );
      const proof = await groth16Prove({ wasm: v.wasm, zkey: v.zkey }, inputs, remaining());
      if (proof) {
        if (v.includeProofInResponse) {
          policyProof.proof = proof.proof;
          policyProof.public_signals = proof.publicSignals;
        }
        if (mode === 'competition' && kurierConfigured(this.config.kurier) && v.vkHash && remaining() > 3000) {
          const r = await submitAndWait(this.config.kurier, proof, v.vkHash, remaining());
          if (r) policyProof.proofReference = r.reference;
        }
      }
    }

    this.store.putTurn(task.matchId, mode, task.turn, { state: task.state, action, hash, issuedAt: task.issuedAt });
    log('info', 'vfy turn decided', {
      matchId: task.matchId,
      mode,
      turn: task.turn,
      self: selfBalance.toString(),
      opp: opponentBalance.toString(),
      action,
      ms: Date.now() - started,
    });
    return { status: 200, body, cacheKey };
  }

  /** Fail-closed bodies used when a handler throws. */
  static fallback(family: 'gatekeeper' | 'vfy', payload: Record<string, unknown>): Record<string, unknown> {
    if (family === 'gatekeeper') {
      const out: Record<string, unknown> = { decision: 'REJECT', reason_code: 'PUBLIC_INPUT_MISMATCH' };
      const tx = (payload.input as Record<string, unknown> | undefined)?.proof_tx;
      if (typeof tx === 'string') out.proof_tx = tx;
      return out;
    }
    return {
      matchId: payload.matchId,
      turn: payload.turn,
      action: { type: 'HOLD' },
      policyProof: { circuitVersion: 'v1', publicInputsHash: '0x' + '0'.repeat(64) },
      ...(payload.mode === 'practice' ? {} : { agentTimestamp: new Date().toISOString(), idempotencyKey: randomUUID() }),
    };
  }
}

function toBig(s: string): bigint {
  const t = s.trim();
  if (/^\d+$/.test(t)) return BigInt(t);
  if (/^\d+\.\d+$/.test(t)) return BigInt(t.split('.')[0]!); // balances are integers; tolerate "95.0"
  throw new Error(`non-numeric balance: ${s}`);
}
