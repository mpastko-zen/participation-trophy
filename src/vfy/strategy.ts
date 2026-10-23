import type { VfyAction } from './hash.js';

/**
 * Steal the VFY strategy, in the shape the official policy circuit understands.
 *
 * The official circuit (build/circuits/vfy-policy-official, see src/vfy/policy-proof.ts) fixes the
 * *family* of strategies: eight committed field elements `strategyParams[0..7]` evaluated as
 *
 *   if (selfBalance < params[1])                       -> FORTIFY
 *   else if (params[3] == 1 || opponentBalance <= params[2]) -> HOLD
 *   else                                               -> EXTRACT params[0]
 *
 * with params[0] in 1..10, params[3] in {0,1}, params[4..7] == 0 (reserved) and 16-bit balance
 * comparisons. The circuit permits exactly one action per state, so `decide` below must mirror it
 * precisely: a different move would not be provable and the turn would be scored as HOLD with a
 * POLICY_VIOLATION penalty.
 *
 * Why the defaults are [10, 0, 0, 0]: under the draft resolver (start 100 each, 20 simultaneous
 * turns, EXTRACT n <= 10 takes up to n from the opponent's spendable balance, FORTIFY costs 2 and
 * blocks 6 of incoming extraction that turn, HOLD does nothing) the per-turn differential
 * (mine - theirs) is
 *
 *                 opp HOLD   opp FORTIFY   opp EXTRACT
 *   me EXTRACT      +20        +10            0
 *   me FORTIFY       -2          0          -10
 *   me HOLD           0         +2          -20
 *
 * so EXTRACT at the cap weakly dominates every alternative against every opponent action. Hence
 * fortifyBelow = 0 (never fortify) and holdWhenOpponentAtMost = 0 (HOLD only once the opponent is
 * empty, where EXTRACT gains nothing and HOLD may earn resolver v1's reserve bonus).
 * Resolver v1's exact numbers are frozen before scored play; if FORTIFY becomes multi-turn or cheap
 * enough to matter, raise VFY_FORTIFY_BELOW and re-register the commitment between rounds.
 */

export type ResolverConfig = { extractCap: number; fortifyCost: number; fortifyBlock: number };
export const DRAFT_RESOLVER: ResolverConfig = { extractCap: 10, fortifyCost: 2, fortifyBlock: 6 };

/** Committed strategy parameters = the circuit's strategyParams[0..3]; [4..7] are reserved zeros. */
export type StrategyParams = {
  /** params[0]: EXTRACT amount, 1..10. The circuit requires action.amount to equal it exactly. */
  extractAmount: number;
  /** params[1]: FORTIFY while selfBalance < fortifyBelow. 0 = never fortify. */
  fortifyBelow: number;
  /** params[2]: HOLD while opponentBalance <= holdWhenOpponentAtMost. 0 = only when the opponent is empty. */
  holdWhenOpponentAtMost: number;
  /** params[3]: 1 = always HOLD (unless fortifying). */
  alwaysHold: 0 | 1;
};

export const STRATEGY_PARAM_COUNT = 8;
/** Balance comparisons in the circuit are 16-bit; thresholds above this overflow the comparator. */
export const MAX_THRESHOLD = 0xffff;

export const DEFAULT_STRATEGY: StrategyParams = { extractAmount: 10, fortifyBelow: 0, holdWhenOpponentAtMost: 0, alwaysHold: 0 };

/** Clamp arbitrary (env-sourced) numbers into the domain the circuit accepts. */
export function normalizeStrategyParams(p: Partial<StrategyParams>): StrategyParams {
  const clamp = (v: number | undefined, lo: number, hi: number, dflt: number) =>
    Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.trunc(v as number))) : dflt;
  return {
    extractAmount: clamp(p.extractAmount, 1, DRAFT_RESOLVER.extractCap, DEFAULT_STRATEGY.extractAmount),
    fortifyBelow: clamp(p.fortifyBelow, 0, MAX_THRESHOLD, 0),
    holdWhenOpponentAtMost: clamp(p.holdWhenOpponentAtMost, 0, MAX_THRESHOLD, 0),
    alwaysHold: p.alwaysHold ? 1 : 0,
  };
}

export function strategyParamsFromConfig(c: { extractAmount: number; fortifyBelow: number; holdWhenOpponentAtMost: number; alwaysHold: boolean }): StrategyParams {
  return normalizeStrategyParams({ ...c, alwaysHold: c.alwaysHold ? 1 : 0 });
}

/** The circuit's strategyParams[8], in order. Hashed with the salt into the commitment. */
export function strategyParamsToSignals(p: StrategyParams): bigint[] {
  return [BigInt(p.extractAmount), BigInt(p.fortifyBelow), BigInt(p.holdWhenOpponentAtMost), BigInt(p.alwaysHold), 0n, 0n, 0n, 0n];
}

export type TurnView = {
  turn: number;
  selfBalance: bigint;
  opponentBalance: bigint;
};

/** The one action the committed strategy permits in this state (mirrors the circuit exactly). */
export function decide(params: StrategyParams, view: TurnView): VfyAction {
  if (view.selfBalance < BigInt(params.fortifyBelow)) return { type: 'FORTIFY' };
  if (params.alwaysHold === 1 || view.opponentBalance <= BigInt(params.holdWhenOpponentAtMost)) return { type: 'HOLD' };
  return { type: 'EXTRACT', amount: params.extractAmount };
}

/** Differential payoff (mine - theirs) of a single turn under a resolver config. Used by tests. */
export function differential(me: VfyAction, opp: VfyAction, cfg: ResolverConfig, myBal = 100, oppBal = 100): number {
  const r = resolveTurn(myBal, oppBal, me, opp, cfg);
  return r.deltaA - r.deltaB;
}

/** Local model of the draft resolver. Mirrors the published semantics; used for tests and replays. */
export function resolveTurn(
  balanceA: number,
  balanceB: number,
  a: VfyAction,
  b: VfyAction,
  cfg: ResolverConfig = DRAFT_RESOLVER,
): { deltaA: number; deltaB: number } {
  const costA = a.type === 'FORTIFY' ? Math.min(cfg.fortifyCost, balanceA) : 0;
  const costB = b.type === 'FORTIFY' ? Math.min(cfg.fortifyCost, balanceB) : 0;
  const spendA = balanceA - costA;
  const spendB = balanceB - costB;
  const take = (act: VfyAction, oppAct: VfyAction, oppSpendable: number) => {
    if (act.type !== 'EXTRACT') return 0;
    const defence = oppAct.type === 'FORTIFY' ? cfg.fortifyBlock : 0;
    return Math.max(0, Math.min(act.amount, cfg.extractCap, oppSpendable) - defence);
  };
  const extractA = take(a, b, spendB);
  const extractB = take(b, a, spendA);
  return { deltaA: -costA + extractA - extractB, deltaB: -costB + extractB - extractA };
}

/**
 * Infer what the opponent did last turn from the balance change, given our own action.
 * Only for logging/replay; the decision above does not depend on it.
 */
export function inferOpponentAction(
  prev: { selfBalance: number; opponentBalance: number; myAction: VfyAction },
  cur: { selfBalance: number; opponentBalance: number },
  cfg: ResolverConfig = DRAFT_RESOLVER,
): VfyAction | null {
  const candidates: VfyAction[] = [{ type: 'HOLD' }, { type: 'FORTIFY' }];
  for (let n = 1; n <= cfg.extractCap; n++) candidates.push({ type: 'EXTRACT', amount: n });
  for (const c of candidates) {
    const r = resolveTurn(prev.selfBalance, prev.opponentBalance, prev.myAction, c, cfg);
    if (prev.selfBalance + r.deltaA === cur.selfBalance && prev.opponentBalance + r.deltaB === cur.opponentBalance) return c;
  }
  return null;
}
