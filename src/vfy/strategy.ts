import type { VfyAction } from './hash.js';

/**
 * Steal the VFY strategy.
 *
 * Draft resolver (from the build guide): start 100 each, 20 simultaneous turns,
 *   EXTRACT n (n <= 10) takes up to n from the opponent's spendable balance,
 *   FORTIFY costs 2 and blocks 6 of incoming extraction that turn,
 *   HOLD does nothing.
 * Highest balance wins, so what matters is the *differential* (mine - theirs) per turn:
 *
 *                 opp HOLD   opp FORTIFY   opp EXTRACT
 *   me EXTRACT      +20        +10            0
 *   me FORTIFY       -2          0          -10
 *   me HOLD           0         +2          -20
 *
 * EXTRACT at the cap weakly dominates every alternative against every opponent action,
 * so the committed policy is: EXTRACT cap, except HOLD when the opponent has nothing left.
 * (If resolver v1 adds multi-turn fortification or a HOLD reserve bonus, revisit this and
 * the policy circuit together: the circuit must prove whatever this function decides.)
 *
 * The strategy is a pure function of (params, state) so that it can be expressed as a
 * circuit and the commitment can be Poseidon(params, salt).
 */

export type ResolverConfig = { extractCap: number; fortifyCost: number; fortifyBlock: number };
export const DRAFT_RESOLVER: ResolverConfig = { extractCap: 10, fortifyCost: 2, fortifyBlock: 6 };

/** Committed strategy parameters. Field order matters: it is hashed into the commitment. */
export type StrategyParams = {
  extractAmount: number; // 1..extractCap
  holdWhenOpponentEmpty: 0 | 1;
};

export function strategyParamsToSignals(p: StrategyParams): bigint[] {
  return [BigInt(p.extractAmount), BigInt(p.holdWhenOpponentEmpty), 0n, 0n];
}

export type TurnView = {
  turn: number;
  selfBalance: bigint;
  opponentBalance: bigint;
};

export function decide(params: StrategyParams, view: TurnView): VfyAction {
  if (params.holdWhenOpponentEmpty === 1 && view.opponentBalance <= 0n) return { type: 'HOLD' };
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
