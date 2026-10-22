import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { Agent } from './agent.js';
import { loadConfig, type Config } from './config.js';
import { log } from './log.js';
import { Store } from './store.js';

export function buildServer(config: Config, store: Store): { server: Server; agent: Agent } {
  const agent = new Agent(config, store);
  const agentPath = config.agentPath.replace(/\/+$/, '') || '/';

  const server = createServer(async (req, res) => {
    const url = (req.url ?? '/').split('?')[0]!.replace(/\/+$/, '') || '/';
    try {
      if (req.method === 'GET' && (url === '/' || url === '/health' || url === agentPath)) {
        return sendJson(res, 200, { ok: true, service: 'participation-trophy', agentPath, time: new Date().toISOString() });
      }
      if (req.method !== 'POST' || url !== agentPath) {
        return sendJson(res, 404, { error: 'not found' });
      }
      const raw = await readBody(req, config.maxBodyBytes);
      if (raw === null) return sendJson(res, 413, { error: 'body too large' });
      const out = await agent.handle(raw, req.headers);
      res.writeHead(out.status, { ...out.headers, 'content-length': Buffer.byteLength(out.body) });
      res.end(out.body);
    } catch (err) {
      log('error', 'unhandled server error', { error: String((err as Error)?.stack ?? err) });
      if (!res.headersSent) sendJson(res, 500, { error: 'internal error' });
      else res.end();
    }
  });
  // Keep sockets open well past the 60s task deadline so slow proof work is never cut off by us.
  server.requestTimeout = 120_000;
  server.headersTimeout = 125_000;
  server.keepAliveTimeout = 65_000;
  return { server, agent };
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const s = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(s) });
  res.end(s);
}

function readBody(req: IncomingMessage, limit: number): Promise<Buffer | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > limit) {
        req.destroy();
        resolve(null);
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function main(): Promise<void> {
  const config = loadConfig();
  const store = Store.open(config.dataDir);
  const { server, agent } = buildServer(config, store);
  const commitment = await agent.handlers.commitment();
  server.listen(config.port, config.host, () => {
    log('info', 'agent listening', {
      port: config.port,
      agentPath: config.agentPath,
      signed: Boolean(config.hmacSecret),
      strategyCommitment: commitment,
      vfyCircuit: Boolean(config.vfy.wasm && config.vfy.zkey),
      gatekeeperCircuit: Boolean(config.gatekeeper.wasm && config.gatekeeper.zkey),
      kurier: Boolean(config.kurier.apiKey),
    });
  });
  const shutdown = () => {
    log('info', 'shutting down');
    server.close(() => {
      store.close();
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  main().catch((err) => {
    log('error', 'fatal', { error: String(err?.stack ?? err) });
    process.exit(1);
  });
}
