import 'dotenv/config';

function int(name: string, dflt: number): number {
  const v = process.env[name];
  if (v === undefined || v === '') return dflt;
  const n = Number(v);
  if (!Number.isFinite(n)) throw new Error(`${name} must be a number, got ${JSON.stringify(v)}`);
  return n;
}
function bool(name: string, dflt: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === '') return dflt;
  return ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
}
function str(name: string, dflt = ''): string {
  return process.env[name] ?? dflt;
}

export type Config = ReturnType<typeof loadConfig>;

export function loadConfig() {
  const secret = str('AGENT_GAMES_HMAC_SECRET');
  const allowUnsigned = bool('ALLOW_UNSIGNED', false);
  if (!secret && !allowUnsigned) {
    throw new Error(
      'AGENT_GAMES_HMAC_SECRET is not set. Rotate the secret on the Agent Games dashboard and set it, ' +
        'or set ALLOW_UNSIGNED=true for local development only.',
    );
  }
  return {
    port: int('PORT', 3000),
    host: str('HOST', '0.0.0.0'),
    agentPath: str('AGENT_PATH', '/agent'),
    hmacSecret: secret,
    allowUnsigned,
    dataDir: str('DATA_DIR', './data'),
    // How much of the task deadline we keep in reserve for network latency when doing proof work.
    safetyMarginMs: int('RESPONSE_SAFETY_MARGIN_MS', 8000),
    // Hard ceiling on our own processing time regardless of what the deadline says.
    maxWorkMs: int('MAX_WORK_MS', 50000),
    maxBodyBytes: int('MAX_BODY_BYTES', 1_000_000),

    gatekeeper: {
      // 'trap' = reason codes named after the trap categories (VK_SUBSTITUTION, PROOF_REUSED, ...)
      // 'canonical' = the "Canonical reason codes" table from the rules page (PROOF_REPLAY, PUBLIC_INPUT_MISMATCH, ...)
      reasonCodeStyle: (str('GATEKEEPER_REASON_CODE_STYLE', 'trap') as 'trap' | 'canonical'),
      // Partition the replay seen-set by task mode so practice approvals never poison competition.
      scopeSeenSetByMode: bool('GATEKEEPER_SCOPE_SEEN_BY_MODE', true),
      wasm: str('GATEKEEPER_WASM'),
      zkey: str('GATEKEEPER_ZKEY'),
      vkHash: str('GATEKEEPER_VK_HASH'),
      includeProofInResponse: bool('GATEKEEPER_INCLUDE_PROOF', true),
      // Private salt for the circuit's nullifier output (Poseidon(salt, taskId)). Any field element;
      // derived from VFY_STRATEGY_SALT / the HMAC secret when unset so it stays stable across restarts.
      salt: str('GATEKEEPER_SALT'),
      // How task_id is mapped to the circuit's taskId field element: sha256 | keccak256 | uuid.
      taskIdMapping: (str('GATEKEEPER_TASKID_MAP', 'sha256') as 'sha256' | 'keccak256' | 'uuid'),
    },

    vfy: {
      circuitVersion: str('VFY_CIRCUIT_VERSION', 'v1-draft'),
      wasm: str('VFY_WASM'),
      zkey: str('VFY_ZKEY'),
      vkHash: str('VFY_VK_HASH'),
      includeProofInResponse: bool('VFY_INCLUDE_PROOF', true),
      // Private salt for the strategy commitment. Keep it stable across deploys.
      strategySalt: str('VFY_STRATEGY_SALT'),
      extractAmount: int('VFY_EXTRACT_AMOUNT', 10),
      holdWhenOpponentEmpty: bool('VFY_HOLD_WHEN_OPPONENT_EMPTY', true),
    },

    kurier: {
      apiUrl: str('KURIER_API_URL', 'https://api.kurier.xyz/api/v1'),
      apiKey: str('KURIER_API_KEY'),
      pollIntervalMs: int('KURIER_POLL_INTERVAL_MS', 2500),
    },
  };
}
