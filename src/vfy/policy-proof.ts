import { toField } from '../zk/gatekeeper-proof.js';
import { poseidonHash } from './commitment.js';
import { ACTION_CODE, amountOf, circuitVersionInt, matchIdToBigInt, type VfyAction } from './hash.js';
import { strategyParamsToSignals, type StrategyParams } from './strategy.js';

/**
 * Steal the VFY policy circuit (official artifacts, published at /build on 2026-10-22):
 *   build/circuits/vfy-policy-official/vfy-policy.wasm, vfy-policy_final.zkey  (Groth16 / BN128, circom 2.2.3)
 *   vk_hash on zkVerify mainnet: 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
 *
 * Everything below was established empirically against those artifacts (template VfyPolicyProof;
 * see test/vfy-proof.test.ts and circuits/vfy-policy.circom for a behaviourally equivalent reconstruction):
 *
 * Input signals (10 names, 17 values):
 *   commitment, matchId, turnNumber, selfBalance, opponentBalance, action, amount, circuitVersion   (public)
 *   strategyParams[8], salt                                                                         (private)
 *
 * Public signals (9), in order:
 *   [0]  turnNullifier = Poseidon(matchId, turnNumber, circuitVersion)   (binds the proof to one turn;
 *        independent of the strategy, salt, balances and action)
 *   [1]  commitment  [2] matchId  [3] turnNumber  [4] selfBalance  [5] opponentBalance
 *   [6]  action (HOLD=0, FORTIFY=1, EXTRACT=2)  [7] amount (0 unless EXTRACT)  [8] circuitVersion
 * Signals [1..8] are, in the same order, the eight fields of policyProof.publicInputsHash from /build.
 *
 * Constraints:
 *   Poseidon(strategyParams[0..7], salt) == commitment
 *   1 <= strategyParams[0] <= 10;  strategyParams[3] in {0,1};  strategyParams[4..7] == 0
 *   fortify = selfBalance < strategyParams[1]                       (16-bit comparison)
 *   hold    = !fortify && (strategyParams[3] == 1 || opponentBalance <= strategyParams[2])
 *   action  == fortify ? 1 : hold ? 0 : 2
 *   amount  == (action == 2 ? strategyParams[0] : 0)
 *   circuitVersion, matchId and turnNumber are only bound through the nullifier (no range checks).
 * Balances and thresholds must be < 2^16 or the comparators' Num2Bits range check fails.
 */

export type VfyCircuitInputs = {
  commitment: string;
  matchId: string;
  turnNumber: string;
  selfBalance: string;
  opponentBalance: string;
  action: string;
  amount: string;
  circuitVersion: string;
  strategyParams: string[];
  salt: string;
};

export type VfyTurnFacts = {
  commitment: string; // 0x... (the platform-frozen strategyCommitment.hash)
  matchId: string; // uuid or hex
  turn: number;
  selfBalance: bigint;
  opponentBalance: bigint;
  action: VfyAction;
  circuitVersion: string; // "v1" -> 1
};

export const VFY_PUBLIC_SIGNAL_NAMES = ['turnNullifier', 'commitment', 'matchId', 'turnNumber', 'selfBalance', 'opponentBalance', 'action', 'amount', 'circuitVersion'] as const;

/** Public signals [1..8] the platform can recompute from the turn; [0] is the circuit's nullifier. */
export function expectedPublicSignals(f: VfyTurnFacts): string[] {
  return [
    toField(f.commitment),
    matchIdToBigInt(f.matchId).toString(),
    String(f.turn),
    f.selfBalance.toString(),
    f.opponentBalance.toString(),
    ACTION_CODE[f.action.type].toString(),
    amountOf(f.action).toString(),
    circuitVersionInt(f.circuitVersion).toString(),
  ];
}

/** Public signal [0]: Poseidon(matchId, turnNumber, circuitVersion), as the circuit computes it. */
export async function expectedTurnNullifier(f: Pick<VfyTurnFacts, 'matchId' | 'turn' | 'circuitVersion'>): Promise<string> {
  return (await poseidonHash([matchIdToBigInt(f.matchId), BigInt(f.turn), circuitVersionInt(f.circuitVersion)])).toString();
}

export function buildVfyCircuitInputs(f: VfyTurnFacts, secret: { params: StrategyParams; salt: bigint }): VfyCircuitInputs {
  const [commitment, matchId, turnNumber, selfBalance, opponentBalance, action, amount, circuitVersion] = expectedPublicSignals(f) as [string, string, string, string, string, string, string, string];
  return {
    commitment,
    matchId,
    turnNumber,
    selfBalance,
    opponentBalance,
    action,
    amount,
    circuitVersion,
    strategyParams: strategyParamsToSignals(secret.params).map(String),
    salt: secret.salt.toString(),
  };
}
