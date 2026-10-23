import type { Config } from './config.js';
import { Handlers, type Handled } from './handlers.js';
import { log } from './log.js';
import { classify } from './protocol.js';
import { SIGNATURE_HEADER, sign, verify } from './signature.js';
import type { Store } from './store.js';

export type AgentResponse = { status: number; body: string; headers: Record<string, string> };

/** Classify a signature header's encoding without revealing it. */
export function describeSignature(sig: string | undefined): string {
  if (!sig) return 'missing';
  const s = sig.trim();
  if (/^[0-9a-f]{64}$/.test(s)) return 'hex64';
  if (/^[0-9A-F]{64}$/.test(s)) return 'HEX64';
  if (/^sha256=[0-9a-fA-F]{64}$/.test(s)) return 'sha256=hex64';
  if (/^(t=\d+,)?v1=[0-9a-fA-F]{64}$/.test(s)) return 'stripe-style';
  if (/^[A-Za-z0-9+/_-]{43}=?$/.test(s)) return 'base64-32';
  return `other(len=${s.length},prefix=${s.slice(0, 6).replace(/[0-9a-zA-Z]/g, 'x')})`;
}

/**
 * Transport-agnostic request handler: raw body in, signed JSON out.
 * Order of operations is the one the rules require:
 *   verify signature on the raw body -> parse -> idempotency -> decide -> sign response.
 */
export class Agent {
  readonly handlers: Handlers;
  private inflight = new Map<string, Promise<Handled>>();

  constructor(
    private readonly config: Config,
    private readonly store: Store,
  ) {
    this.handlers = new Handlers(config, store);
  }

  async handle(raw: Buffer, headers: Record<string, string | string[] | undefined>): Promise<AgentResponse> {
    const sigHeader = headers[SIGNATURE_HEADER];
    const sig = Array.isArray(sigHeader) ? sigHeader[0] : sigHeader;

    if (this.config.hmacSecret) {
      if (!verify(raw, sig, this.config.hmacSecret)) {
        // Shape only (never the value): enough to tell a wrong secret from a different wire encoding.
        log('warn', 'rejected request with bad signature', { hasSignature: Boolean(sig), sigShape: describeSignature(sig), bytes: raw.length });
        return this.reply(401, { error: 'invalid signature' });
      }
    } else if (!this.config.allowUnsigned) {
      return this.reply(500, { error: 'agent misconfigured: no HMAC secret' });
    }

    let payload: unknown;
    try {
      payload = JSON.parse(raw.toString('utf8'));
    } catch {
      return this.reply(400, { error: 'body is not valid JSON' });
    }

    const c = classify(payload);
    if (c.family === 'unknown') {
      log('warn', 'unrecognised envelope', { reason: c.reason });
      return this.reply(400, { error: 'unrecognised task envelope', detail: c.reason });
    }
    if (c.family === 'preflight') {
      log('info', 'preflight', { agent_id: c.task.agent_id });
      return this.reply(200, this.handlers.preflight(c.task).body);
    }

    const cacheKey = c.family === 'gatekeeper'
      ? `gk:${c.task.task_id}`
      : `vfy:${c.task.mode === 'practice' ? 'practice' : 'competition'}:${c.task.matchId}:${c.task.turn}`;

    // Idempotency: the platform may retry after a network failure. Return exactly what we sent before.
    const cached = this.store.getResponse(cacheKey);
    if (cached !== undefined) {
      log('info', 'replaying cached response', { cacheKey });
      return this.replyRaw(200, cached);
    }

    // Coalesce concurrent retries of the same task while the first is still computing.
    let p = this.inflight.get(cacheKey);
    if (!p) {
      p = (c.family === 'gatekeeper' ? this.handlers.gatekeeper(c.task) : this.handlers.vfy(c.task)).catch((err) => {
        log('error', 'handler failed, responding fail-closed', { cacheKey, error: String(err?.stack ?? err) });
        return { status: 200, body: Handlers.fallback(c.family, payload as Record<string, unknown>), cacheKey } as Handled;
      });
      this.inflight.set(cacheKey, p);
    }
    try {
      const result = await p;
      const body = JSON.stringify(result.body);
      this.store.putResponse(cacheKey, body);
      this.store.logTask(c.family, cacheKey, payload, result.body);
      return this.replyRaw(result.status, body);
    } finally {
      this.inflight.delete(cacheKey);
    }
  }

  private reply(status: number, body: Record<string, unknown>): AgentResponse {
    return this.replyRaw(status, JSON.stringify(body));
  }

  private replyRaw(status: number, body: string): AgentResponse {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (this.config.hmacSecret) headers[SIGNATURE_HEADER] = sign(body, this.config.hmacSecret);
    return { status, body, headers };
  }
}
