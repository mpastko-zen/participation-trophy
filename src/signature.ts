import { createHmac, timingSafeEqual } from 'node:crypto';

export const SIGNATURE_HEADER = 'x-agent-games-signature';

/** HMAC-SHA256 over the exact raw body, bare lowercase hex (64 chars). */
export function sign(body: Buffer | string, secret: string): string {
  return createHmac('sha256', secret).update(body).digest('hex');
}

/**
 * Verify an incoming signature against the raw body.
 * Accepts bare hex, "sha256=<hex>", or base64 of the same 32-byte digest,
 * so a change in the platform's wire encoding does not take us offline.
 */
export function verify(body: Buffer | string, header: unknown, secret: string): boolean {
  if (typeof header !== 'string' || header.length === 0 || header.length > 128) return false;
  const expected = createHmac('sha256', secret).update(body).digest();
  const provided = decodeDigest(header.trim());
  if (!provided || provided.length !== expected.length) return false;
  return timingSafeEqual(expected, provided);
}

function decodeDigest(s: string): Buffer | null {
  const hex = s.startsWith('sha256=') ? s.slice(7) : s;
  if (/^[0-9a-f]{64}$/i.test(hex)) return Buffer.from(hex, 'hex');
  if (/^[A-Za-z0-9+/]{43}=?$/.test(s) || /^[A-Za-z0-9_-]{43}=?$/.test(s)) {
    try {
      const b = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      return b.length === 32 ? b : null;
    } catch {
      return null;
    }
  }
  return null;
}
