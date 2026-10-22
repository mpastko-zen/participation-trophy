pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
 * Steal the VFY policy circuit (local stand-in until the official event circuit ships).
 *
 * Proves, for a turn:
 *   1. Poseidon(params[0..3], salt) == commitment           (the committed strategy)
 *   2. circuitVersion == 1                                  (v1-draft)
 *   3. action is in the permitted domain and, for EXTRACT, 1 <= amount <= 10
 *   4. policy(params, state) == (action, amount)            (the move is what the policy dictates)
 *
 * Public inputs, in the order the platform's publicInputsHash packs them:
 *   commitment, matchId, turn, selfBalance, opponentBalance, action, amount, circuitVersion
 * matchId and turn are bound into the proof so it cannot be replayed on another turn.
 *
 * Policy: EXTRACT params[0], except HOLD when opponentBalance == 0 and params[1] == 1.
 * This mirrors src/vfy/strategy.ts; the two must change together.
 */
template VfyPolicy() {
    signal input params[4];       // private: [extractAmount, holdWhenOpponentEmpty, 0, 0]
    signal input salt;            // private

    signal input commitment;      // public
    signal input matchId;         // public
    signal input turn;            // public
    signal input selfBalance;     // public
    signal input opponentBalance; // public
    signal input action;          // public: HOLD=0, FORTIFY=1, EXTRACT=2
    signal input amount;          // public: 0 unless EXTRACT
    signal input circuitVersion;  // public: 1

    // 1. Commitment binds the private strategy.
    component h = Poseidon(5);
    for (var i = 0; i < 4; i++) h.inputs[i] <== params[i];
    h.inputs[4] <== salt;
    h.out === commitment;

    // 2. Version pin.
    circuitVersion === 1;

    // Sanity bounds on the private parameters.
    component amtLe10 = LessEqThan(8);
    amtLe10.in[0] <== params[0];
    amtLe10.in[1] <== 10;
    amtLe10.out === 1;
    component amtGe1 = GreaterEqThan(8);
    amtGe1.in[0] <== params[0];
    amtGe1.in[1] <== 1;
    amtGe1.out === 1;
    params[1] * (params[1] - 1) === 0;

    // 4. Policy evaluation.
    component oppZero = IsZero();
    oppZero.in <== opponentBalance;
    signal hold;
    hold <== oppZero.out * params[1];           // 1 iff we must HOLD

    signal expectedAction;
    expectedAction <== 2 - 2 * hold;            // HOLD(0) or EXTRACT(2)
    signal expectedAmount;
    expectedAmount <== (1 - hold) * params[0];

    action === expectedAction;
    amount === expectedAmount;

    // 3. Domain check follows from the above (action in {0,2}, amount in {0, 1..10}).

    // Bind the remaining public inputs so the compiler keeps them (they are already
    // part of the public signal list; this just makes their use explicit).
    signal bind;
    bind <== matchId * 0 + turn * 0 + selfBalance * 0;
    bind === 0;
}

component main {public [commitment, matchId, turn, selfBalance, opponentBalance, action, amount, circuitVersion]} = VfyPolicy();
