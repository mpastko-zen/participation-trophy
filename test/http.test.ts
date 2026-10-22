import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { buildServer } from '../src/server.js';
import { loadConfig } from '../src/config.js';
import { Store } from '../src/store.js';
import { SIGNATURE_HEADER, sign, verify } from '../src/signature.js';
import { generateRoundTasks, gatekeeperEnvelope } from './fixtures/traps.js';

const SECRET = 'd'.repeat(64);
process.env.AGENT_GAMES_HMAC_SECRET = SECRET;
process.env.AGENT_PATH = '/agent';
let base = '';
let store: Store;
let close: () => void;

before(async () => {
  store = new Store(':memory:');
  const { server } = buildServer(loadConfig(), store);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  close = () => server.close();
});
after(() => {
  close();
  store.close();
});

test('GET / and /health answer 200; other paths 404', async () => {
  assert.equal((await fetch(`${base}/`)).status, 200);
  assert.equal((await fetch(`${base}/health`)).status, 200);
  assert.equal((await fetch(`${base}/nope`)).status, 404);
  assert.equal((await fetch(`${base}/`, { method: 'POST', body: '{}' })).status, 404);
});

test('POST /agent over real HTTP: signature verified on the raw bytes, response signed', async () => {
  const task = generateRoundTasks('http', 'R01').find((t) => t.trapCode === 'VK_SUBSTITUTION')!;
  const body = JSON.stringify(gatekeeperEnvelope('gk_http_1', task.input));
  const res = await fetch(`${base}/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', [SIGNATURE_HEADER]: sign(body, SECRET) },
    body,
  });
  const text = await res.text();
  assert.equal(res.status, 200, text);
  assert.equal(res.headers.get('content-type'), 'application/json');
  assert.equal(verify(text, res.headers.get(SIGNATURE_HEADER), SECRET), true);
  assert.equal(JSON.parse(text).reason_code, 'VK_SUBSTITUTION');

  // Trailing slash on the registered path still works; a byte-different body with the old signature does not.
  const res2 = await fetch(`${base}/agent/`, { method: 'POST', headers: { [SIGNATURE_HEADER]: sign(body, SECRET) }, body });
  assert.equal(res2.status, 200);
  const res3 = await fetch(`${base}/agent`, { method: 'POST', headers: { [SIGNATURE_HEADER]: sign(body, SECRET) }, body: body + ' ' });
  assert.equal(res3.status, 401);
});

test('concurrent duplicate deliveries of one task produce one decision and identical bodies', async () => {
  const task = generateRoundTasks('http', 'R01').find((t) => t.trapCode === 'VALID_CONDITION')!;
  const body = JSON.stringify(gatekeeperEnvelope('gk_http_dup', task.input));
  const send = () => fetch(`${base}/agent`, { method: 'POST', headers: { [SIGNATURE_HEADER]: sign(body, SECRET) }, body }).then((r) => r.text());
  const bodies = await Promise.all([send(), send(), send(), send()]);
  assert.equal(new Set(bodies).size, 1);
  assert.equal(JSON.parse(bodies[0]!).decision, 'APPROVE');
});
