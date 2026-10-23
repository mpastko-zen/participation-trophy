pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

/*
 * Steal the VFY policy circuit: a RECONSTRUCTION of the official `VfyPolicyProof` template whose
 * compiled artifacts live in build/circuits/vfy-policy-official/ (vk_hash
 * 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047). The platform only accepts
 * proofs made with those artifacts; this source exists so the policy family is readable and so the
 * agent's decision logic (src/vfy/strategy.ts) can be checked against a compiled model.
 *
 * It was derived by probing the official witness calculator (signal table, assert line numbers,
 * template instantiation order, witness differentials) and is behaviourally equivalent on every
 * probed input: same accept/reject outcome and the same public signals, including the nullifier.
 * It is not guaranteed to be byte-identical to the original source (the official build also contains
 * IsZero/IsEqual instances, i.e. it derives the action flags slightly differently).
 * Compile with `npm run circuit:reconstruct` and compare with scripts/compare-vfy-circuit.mjs.
 *
 * Public signals, in order:
 *   [0] turnNullifier = Poseidon(matchId, turnNumber, circuitVersion)
 *   [1..8] commitment, matchId, turnNumber, selfBalance, opponentBalance, action, amount, circuitVersion
 *   (= the eight fields of policyProof.publicInputsHash from /build, in the same order)
 */
template VfyPolicyProof() {
    signal input commitment;        // public: Poseidon(strategyParams[0..7], salt)
    signal input matchId;           // public: uuid as a 128-bit integer
    signal input turnNumber;        // public
    signal input selfBalance;       // public, < 2^16
    signal input opponentBalance;   // public, < 2^16
    signal input action;            // public: HOLD=0, FORTIFY=1, EXTRACT=2
    signal input amount;            // public: strategyParams[0] for EXTRACT, else 0
    signal input circuitVersion;    // public: "v1" -> 1
    signal input strategyParams[8]; // private: [extractAmount, fortifyBelow, holdWhenOpponentAtMost, alwaysHold, 0, 0, 0, 0]
    signal input salt;              // private
    signal output turnNullifier;

    // 1. The private strategy is the committed one.
    component h = Poseidon(9);
    for (var i = 0; i < 8; i++) h.inputs[i] <== strategyParams[i];
    h.inputs[8] <== salt;
    h.out === commitment;

    // 2. Reserved parameters.
    strategyParams[4] === 0;
    strategyParams[5] === 0;
    strategyParams[6] === 0;
    strategyParams[7] === 0;

    // 3. Parameter domain: 1 <= extractAmount <= 10, alwaysHold is a bit.
    component ge1 = GreaterEqThan(4);
    ge1.in[0] <== strategyParams[0];
    ge1.in[1] <== 1;
    ge1.out === 1;
    component le10 = LessEqThan(4);
    le10.in[0] <== strategyParams[0];
    le10.in[1] <== 10;
    le10.out === 1;
    strategyParams[3] * (strategyParams[3] - 1) === 0;

    // 4. Policy evaluation on the public state (16-bit comparisons).
    component low = LessThan(16);          // selfBalance < fortifyBelow  -> FORTIFY
    low.in[0] <== selfBalance;
    low.in[1] <== strategyParams[1];
    component oppAbove = GreaterThan(16);  // opponentBalance > holdWhenOpponentAtMost, else HOLD
    oppAbove.in[0] <== opponentBalance;
    oppAbove.in[1] <== strategyParams[2];

    component notLow = NOT();
    notLow.in <== low.out;
    component canExtract = AND();
    canExtract.a <== notLow.out;
    canExtract.b <== oppAbove.out;
    signal extract;
    extract <== canExtract.out * (1 - strategyParams[3]);
    signal expectedAction;
    expectedAction <== low.out + 2 * extract;   // FORTIFY=1 wins, then EXTRACT=2, else HOLD=0

    // 5. Bind the proof to this turn of this match and to the circuit version.
    component nul = Poseidon(3);
    nul.inputs[0] <== matchId;
    nul.inputs[1] <== turnNumber;
    nul.inputs[2] <== circuitVersion;
    turnNullifier <== nul.out;

    // 6. The declared move is the permitted one.
    action === expectedAction;
    extract * (amount - strategyParams[0]) === 0;
    (1 - extract) * amount === 0;
}

component main {public [commitment, matchId, turnNumber, selfBalance, opponentBalance, action, amount, circuitVersion]} = VfyPolicyProof();
