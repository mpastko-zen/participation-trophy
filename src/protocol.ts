import { z } from 'zod';

/**
 * Envelope schemas. Deliberately tolerant of extra fields (the platform may add some)
 * but strict about the fields we rely on. Anything that fails to parse is handled
 * fail-closed by the server.
 */

const integerString = z.union([z.string(), z.number()]).transform((v) => String(v).trim());

export const preflightSchema = z.object({
  type: z.literal('agent-games.preflight.v1'),
  agent_id: z.string().optional(),
  issued_at: z.string().optional(),
  nonce: z.string().optional(),
});
export type Preflight = z.infer<typeof preflightSchema>;

export const gatekeeperInputSchema = z.object({
  registered_vk: z.string().min(1),
  proof_vk: z.string().min(1),
  minimum: integerString,
  public_balance: integerString,
  expiry_block: z.coerce.number().int().nonnegative(),
  current_block: z.coerce.number().int().nonnegative(),
  recipient: z.string().min(1),
  condition_recipient: z.string().min(1),
  amount: integerString,
  max_transfer: integerString,
  proof_tx: z.string().min(1).optional(),
});
export type GatekeeperInput = z.infer<typeof gatekeeperInputSchema>;

export const gatekeeperSchema = z.object({
  type: z.literal('agent-games.proof-gatekeeper.v1'),
  task_id: z.string().min(1),
  mode: z.string().optional(),
  issued_at: z.string().optional(),
  deadline_at: z.string().optional(),
  // Parsed separately so a malformed input still yields a signed REJECT rather than a 400.
  input: z.unknown(),
});
export type GatekeeperTask = z.infer<typeof gatekeeperSchema>;

export const vfyStateSchema = z.object({
  selfBalance: integerString,
  opponentBalance: integerString,
  selfFortifiedUntilTurn: z.coerce.number().int().nullable().optional(),
  opponentFortifiedUntilTurn: z.coerce.number().int().nullable().optional(),
  priorTurnHash: z.string().optional(),
});
export type VfyState = z.infer<typeof vfyStateSchema>;

export const vfySchema = z.object({
  protocolVersion: z.string().optional(),
  eventId: z.literal('steal-the-vfy'),
  mode: z.string().default('competition'),
  matchId: z.string().min(1),
  turn: z.coerce.number().int().min(1),
  issuedAt: z.string().optional(),
  deadlineAt: z.string().optional(),
  state: vfyStateSchema,
  strategyCommitment: z.object({ hash: z.string() }).optional(),
  resolverVersion: z.string().optional(),
  nonce: z.string().optional(),
});
export type VfyTurn = z.infer<typeof vfySchema>;

export type Classified =
  | { family: 'preflight'; task: Preflight }
  | { family: 'gatekeeper'; task: GatekeeperTask }
  | { family: 'vfy'; task: VfyTurn }
  | { family: 'unknown'; reason: string };

export function classify(payload: unknown): Classified {
  if (typeof payload !== 'object' || payload === null) return { family: 'unknown', reason: 'body is not an object' };
  const p = payload as Record<string, unknown>;
  if (p.type === 'agent-games.preflight.v1') {
    const r = preflightSchema.safeParse(p);
    return r.success ? { family: 'preflight', task: r.data } : { family: 'unknown', reason: r.error.message };
  }
  if (p.type === 'agent-games.proof-gatekeeper.v1') {
    const r = gatekeeperSchema.safeParse(p);
    return r.success ? { family: 'gatekeeper', task: r.data } : { family: 'unknown', reason: r.error.message };
  }
  if (p.eventId === 'steal-the-vfy' || (typeof p.matchId === 'string' && p.turn !== undefined)) {
    const r = vfySchema.safeParse({ eventId: 'steal-the-vfy', ...p });
    return r.success ? { family: 'vfy', task: r.data } : { family: 'unknown', reason: r.error.message };
  }
  return { family: 'unknown', reason: `unrecognised envelope (type=${String(p.type)}, eventId=${String(p.eventId)})` };
}

/** Milliseconds we may spend before the platform's deadline, net of a safety margin. */
export function workBudgetMs(deadlineIso: string | undefined, safetyMarginMs: number, maxWorkMs: number): number {
  const fallback = Math.min(maxWorkMs, 60_000 - safetyMarginMs);
  if (!deadlineIso) return fallback;
  const deadline = Date.parse(deadlineIso);
  if (!Number.isFinite(deadline)) return fallback;
  const remaining = deadline - Date.now() - safetyMarginMs;
  return Math.max(0, Math.min(maxWorkMs, remaining));
}
