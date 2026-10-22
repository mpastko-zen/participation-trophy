import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { sign, verify } from '../src/signature.js';

const secret = 'a'.repeat(64);
const body = Buffer.from('{"type":"agent-games.preflight.v1","nonce":"abc"}');

test('sign produces bare lowercase hex of HMAC-SHA256', () => {
  const s = sign(body, secret);
  assert.match(s, /^[0-9a-f]{64}$/);
  assert.equal(s, createHmac('sha256', secret).update(body).digest('hex'));
});

test('verify accepts hex, sha256= prefix and base64 encodings', () => {
  const hex = sign(body, secret);
  const b64 = createHmac('sha256', secret).update(body).digest('base64');
  assert.equal(verify(body, hex, secret), true);
  assert.equal(verify(body, hex.toUpperCase(), secret), true);
  assert.equal(verify(body, `sha256=${hex}`, secret), true);
  assert.equal(verify(body, b64, secret), true);
});

test('verify rejects tampered body, wrong secret, and junk', () => {
  const hex = sign(body, secret);
  assert.equal(verify(Buffer.from(body.toString() + ' '), hex, secret), false);
  assert.equal(verify(body, hex, 'b'.repeat(64)), false);
  assert.equal(verify(body, undefined, secret), false);
  assert.equal(verify(body, '', secret), false);
  assert.equal(verify(body, 'zz'.repeat(32), secret), false);
  assert.equal(verify(body, hex.slice(1), secret), false);
});
