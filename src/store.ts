import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { log } from './log.js';

/**
 * Durable state. Everything that must survive a restart lives here:
 *  - idempotency cache (task id -> exact response body we already sent)
 *  - Proof Gatekeeper seen-set of approved proof_tx references (replay traps span days)
 *  - Steal the VFY per-match memory (for logs/replays and future adaptive play)
 */
export class Store {
  private db: DatabaseSync;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      CREATE TABLE IF NOT EXISTS responses (
        key TEXT PRIMARY KEY,
        body TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS seen_proofs (
        scope TEXT NOT NULL,
        proof_tx TEXT NOT NULL,
        task_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (scope, proof_tx)
      );
      CREATE TABLE IF NOT EXISTS match_turns (
        match_id TEXT NOT NULL,
        mode TEXT NOT NULL,
        turn INTEGER NOT NULL,
        data TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (match_id, mode, turn)
      );
      CREATE TABLE IF NOT EXISTS task_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        family TEXT NOT NULL,
        key TEXT NOT NULL,
        request TEXT NOT NULL,
        response TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `);
  }

  static open(dataDir: string): Store {
    try {
      mkdirSync(dataDir, { recursive: true });
      const s = new Store(join(dataDir, 'agent.db'));
      log('info', 'store opened', { path: join(dataDir, 'agent.db') });
      return s;
    } catch (err) {
      log('error', 'could not open durable store, falling back to in-memory (state will NOT survive restart)', {
        error: String(err),
      });
      return new Store(':memory:');
    }
  }

  getResponse(key: string): string | undefined {
    const row = this.db.prepare('SELECT body FROM responses WHERE key = ?').get(key) as { body: string } | undefined;
    return row?.body;
  }
  putResponse(key: string, body: string): void {
    this.db
      .prepare('INSERT OR REPLACE INTO responses (key, body, created_at) VALUES (?, ?, ?)')
      .run(key, body, Date.now());
  }

  seenProof(scope: string, proofTx: string): { task_id: string } | undefined {
    return this.db
      .prepare('SELECT task_id FROM seen_proofs WHERE scope = ? AND proof_tx = ?')
      .get(scope, proofTx) as { task_id: string } | undefined;
  }
  markProofSeen(scope: string, proofTx: string, taskId: string): void {
    this.db
      .prepare('INSERT OR IGNORE INTO seen_proofs (scope, proof_tx, task_id, created_at) VALUES (?, ?, ?, ?)')
      .run(scope, proofTx, taskId, Date.now());
  }

  putTurn(matchId: string, mode: string, turn: number, data: unknown): void {
    this.db
      .prepare('INSERT OR REPLACE INTO match_turns (match_id, mode, turn, data, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(matchId, mode, turn, JSON.stringify(data), Date.now());
  }
  getTurns(matchId: string, mode: string): { turn: number; data: unknown }[] {
    const rows = this.db
      .prepare('SELECT turn, data FROM match_turns WHERE match_id = ? AND mode = ? ORDER BY turn ASC')
      .all(matchId, mode) as { turn: number; data: string }[];
    return rows.map((r) => ({ turn: r.turn, data: JSON.parse(r.data) }));
  }

  logTask(family: string, key: string, request: unknown, response: unknown): void {
    this.db
      .prepare('INSERT INTO task_log (family, key, request, response, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(family, key, JSON.stringify(request), JSON.stringify(response), Date.now());
  }

  close(): void {
    this.db.close();
  }
}
