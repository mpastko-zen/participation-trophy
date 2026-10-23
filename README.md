# participation-trophy

An agent for [Agent Games](https://agentgames.zkverify.io) (zkVerify Foundation, 21 Oct – 19 Nov 2026).
One HTTPS endpoint serves both automated tracks:

- **Proof Gatekeeper** (8 daily rounds × 8 tasks, dates on the site's timeline): approve or reject proof-backed
  payment requests. Deterministic rule engine, fail-closed, durable replay seen-set, and a Groth16 proof from the
  **official gatekeeper circuit** on every provable task.
- **Steal the VFY** (Swiss, 5 rounds × 20 turns, then top-16 knockout): head-to-head balance game.
  Strategy committed in the **official policy circuit's** parameter space, a Groth16 proof from that circuit on
  every turn, correct public-inputs hash.

No LLM in the loop: every decision is a pure function of the task, which is what the scoring rewards.

## How it works

```
platform ──signed POST──▶ /agent ──▶ verify HMAC on raw body ──▶ classify envelope
                                        │
            ┌───────────────────────────┼─────────────────────────────┐
         preflight                 proof-gatekeeper                steal-the-vfy
      {ok, protocolVersion}     replay? vk? expiry? recipient?    decide(params, state)
                                threshold? amount? → APPROVE/REJECT  → publicInputsHash
                                + optional circuit proof + Kurier   + policy proof + Kurier
                                        │
                              idempotency cache (SQLite) ──▶ sign response ──▶ 200
```

| Module | Role |
|---|---|
| `src/server.ts` / `src/agent.ts` | HTTP transport, raw-body HMAC verification, idempotency, in-flight de-duplication, signed replies |
| `src/gatekeeper.ts` | The seven trap checks in the order the rules prescribe; reason-code vocabularies |
| `src/vfy/strategy.ts` | The committed strategy as the official circuit's `strategyParams[0..3]`, `decide()` mirroring the circuit, a local model of the draft resolver |
| `src/vfy/hash.ts` | `policyProof.publicInputsHash` exactly as the build guide packs it |
| `src/vfy/commitment.ts` | `Poseidon(strategyParams[0..7], salt)` strategy commitment to register on the dashboard |
| `src/vfy/policy-proof.ts` | Maps a turn onto the official policy circuit's 17 input signals; documents its public signals and constraints |
| `src/zk/gatekeeper-proof.ts` | Maps a task onto the official gatekeeper circuit's 13 input signals (names, field reduction, nullifier salt) |
| `src/zk/prover.ts`, `src/zk/kurier.ts` | Time-boxed Groth16 proving; zkVerify submission + polling to `Finalized` |
| `build/circuits/gatekeeper/` | Official `gatekeeper.wasm` + `gatekeeper_final.zkey` from `/build` (checksums in `SHA256SUMS`) |
| `build/circuits/vfy-policy-official/` | Official `vfy-policy.wasm` + `vfy-policy_final.zkey` from `/build` (checksums in `SHA256SUMS`) |
| `src/store.ts` | SQLite (`node:sqlite`): response cache, approved `proof_tx` seen-set, match memory, task log |
| `circuits/vfy-policy.circom` | Readable **reconstruction** of the official policy circuit (behaviourally equivalent, see `npm run circuit:reconstruct`) |

## Quick start

```bash
npm install
cp .env.example .env            # set AGENT_GAMES_HMAC_SECRET (any 64-hex value for local runs)
npm test                        # 40 tests: signatures, all traps across rounds, real proofs on both official circuits, HTTP, persistence
npm run dev                     # http://localhost:3000/agent
npm run simulate                # plays preflight, 4 Gatekeeper rounds, VFY practice + a 20-turn match against it
npm run circuit:reconstruct     # optional: compiles circuits/vfy-policy.circom and diffs it against the official wasm (needs circom 2.x)
```

With `VFY_WASM`/`VFY_ZKEY` pointing at `build/circuits/vfy-policy-official/` (the `.env.example` defaults) every VFY turn
carries a proof; add `SIM_VFY_VK=build/circuits/vfy-policy-official/verification_key.json` to `npm run simulate` to verify them.

## Deploy

The platform needs a public HTTPS URL on port 443 that never sleeps, and state that survives restarts.

**Fly.io** (config included): `fly launch --no-deploy --copy-config`, `fly volumes create agent_data --size 1`,
`fly secrets set AGENT_GAMES_HMAC_SECRET=… VFY_STRATEGY_SALT=…`, `fly deploy`.
Any Docker host works the same way: build the image, mount a volume at `/data`, set the secrets.
Both official circuits' artifacts are checked in under `build/circuits/` and ship in the image.

## Registering (dashboard)

1. Create your account, connect **GitHub and a wallet** (both required for prizes).
2. Add the agent with the **full path**: `https://<host>/agent`.
3. **Rotate Secret**, copy the one-time value into `AGENT_GAMES_HMAC_SECRET`, redeploy, then run **preflight**.
4. Enter Proof Gatekeeper and Steal the VFY; for VFY register the **strategy commitment** printed by
   `npm run commitment` (Dashboard → My Agents → Edit agent) before Swiss Round 1. Re-run and re-register it
   whenever a `VFY_*` strategy variable or `VFY_STRATEGY_SALT` changes (allowed between rounds, never mid-match).
5. Use **practice mode** (10 dispatches/hour) and read the task records in your debugging history.

## Proof Gatekeeper circuit (official artifacts, verified 2026-10-22)

`build/circuits/gatekeeper/` holds the artifacts published on `/build` (vk_hash on zkVerify mainnet
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`, also served at `/api/circuit-info`).
Established by generating proofs against them (`test/gatekeeper-proof.test.ts`):

- **Inputs**: `registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock, currentBlock, recipient,
  conditionRecipient, amount, maxTransfer, decision, taskId` (public) and `salt` (private). Hex values are reduced
  into the BN128 scalar field.
- **Public signals**: `[Poseidon(salt, taskId), registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
  currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision, taskId]`.
- **Constraint**: `decision == (vk match && balance >= minimum && current < expiry && recipient match && amount <= cap)`.
  Expiry is inclusive and the cap is inclusive, exactly as `src/gatekeeper.ts` decides.
- **Not provable**: `PROOF_REUSED` (all fields valid, decision REJECT) and malformed input. These are answered
  without `proof`/`public_signals`; the rules only penalise a missing proof on *provable* tasks.
- Proving takes ~60 ms, so the 60 s deadline is never at risk.

## Steal the VFY circuit (official artifacts, verified 2026-10-22)

`build/circuits/vfy-policy-official/` holds the artifacts published on `/build` (vk_hash on zkVerify mainnet
`0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`, also served at `/api/circuit-info`).
Recovered by reading the wasm's signal table and probing it with witnesses (`test/vfy-proof.test.ts`,
`src/vfy/policy-proof.ts`); `circuits/vfy-policy.circom` is a reconstruction that agrees with it on every probed input.

- **Inputs** (17 values): `commitment, matchId, turnNumber, selfBalance, opponentBalance, action, amount, circuitVersion`
  (public) and `strategyParams[8], salt` (private).
- **Public signals** (9): `[Poseidon(matchId, turnNumber, circuitVersion), commitment, matchId, turnNumber, selfBalance,
  opponentBalance, action, amount, circuitVersion]`. Signals 1–8 are the eight `publicInputsHash` fields in the same order.
- **Commitment**: `Poseidon(strategyParams[0..7], salt)`, which is what `npm run commitment` prints.
- **Policy family** (the circuit permits exactly one action per state):
  `FORTIFY` if `selfBalance < params[1]`; else `HOLD` if `params[3] == 1` or `opponentBalance <= params[2]`;
  else `EXTRACT params[0]`. Constraints: `1 <= params[0] <= 10`, `params[3] ∈ {0,1}`, `params[4..7] == 0`,
  balances and thresholds below 2^16, `amount == params[0]` for EXTRACT and `0` otherwise.
- **Our strategy** (`VFY_EXTRACT_AMOUNT=10`, `VFY_FORTIFY_BELOW=0`, `VFY_HOLD_WHEN_OPPONENT_AT_MOST=0`,
  `VFY_ALWAYS_HOLD=false` → `[10, 0, 0, 0]`): EXTRACT 10 every turn, HOLD once the opponent is empty. Under the draft
  resolver EXTRACT 10 weakly dominates everything (payoff table in `strategy.ts`); if resolver v1 makes FORTIFY worth it,
  raise `VFY_FORTIFY_BELOW` and re-register the commitment between rounds.
- If the platform's frozen `strategyCommitment.hash` is not ours (stale registration) the agent still answers with the
  correct action and hash but skips the proof, and logs a warning.
- Proving takes a few hundred ms (1.9k wires).

## What practice mode must confirm

Protocol details below are documented on `/build` and `/rules`; the open items are what those pages leave unsaid:

- **task_id → field element**: task ids are strings (`gk_8d31_...`), so the circuit's `taskId` needs a hash-to-field.
  Default `GATEKEEPER_TASKID_MAP=sha256`; `keccak256` and `uuid` are available if a practice record shows the proof
  "did not verify" while the inline proof is sound.
- **Nullifier salt**: public signal 0 is `Poseidon(salt, taskId)` with a salt only we know (`GATEKEEPER_SALT`,
  derived from `VFY_STRATEGY_SALT` when unset). The platform cannot recompute it, so it should be accepted as-is.

- **Response signature encoding**: HMAC-SHA256 over the raw body, bare hex. Incoming hex/`sha256=`/base64
  are all accepted; outgoing is bare hex. If preflight fails with a signature error, this is the first suspect.
- **Reason codes**: the event page and the build guide's sample use the trap names (`VK_SUBSTITUTION`,
  `PROOF_REUSED`, `EXPIRED_CONDITION`, …); the rules' quick reference lists "canonical" codes (`VALID_PROOF`,
  `PROOF_REPLAY`, `PUBLIC_INPUT_MISMATCH`, …). `GATEKEEPER_REASON_CODE_STYLE=trap` (default) or `canonical`;
  check which one the practice record marks as correctly identified.
- **Response fields**: `/build` asks for `decision`, `reason_code`, `proof`, `public_signals` and an optional
  `proof_tx`. `GATEKEEPER_INCLUDE_PROOF=false` drops the proof fields if a practice record rejects the schema.
- **Steal the VFY public signals**: the platform says it recomputes `publicInputsHash` from its own state; whether it
  also checks `public_signals[0]` (the circuit's nullifier) or `circuitVersion` strings other than `"v1"` is not
  documented. Keep `VFY_CIRCUIT_VERSION=v1`.
- **Resolver v1**: the draft (`EXTRACT ≤ 10`, `FORTIFY` costs 2 and blocks 6) makes `EXTRACT 10` weakly dominant.
  The event page says v1 freezes exact amounts, caps and protection duration before scored play and adds a HOLD
  reserve bonus; the circuit's policy family cannot express those, so only the thresholds (`VFY_FORTIFY_BELOW`,
  `VFY_HOLD_WHEN_OPPONENT_AT_MOST`) are tunable, and each change needs a re-registered commitment.

## Scoring notes that shaped the design

- Gatekeeper: +12 correct, −6 wrong APPROVE, −3 wrong REJECT, −2 timeout, −2 missing proof. Hence fail-closed,
  always answer, replay check first, and a seen-set that persists across days (the replay trap references the
  previous day's approved `proof_tx`).
- VFY: win +18 / draw +9 / loss +3, −1 timeout, −2 policy violation, +0..2 reliability. Against another optimal
  agent every match is a draw, so proof reliability and uptime decide the standings.
- Retries are expected: task ids / (matchId, turn) are idempotency keys and the cached body is returned verbatim.
