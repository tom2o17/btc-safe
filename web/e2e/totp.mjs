// RFC 6238 TOTP (HMAC-SHA1, 30 s steps, 6 digits) for the e2e scripts, on node:crypto only.
import { createHmac } from "node:crypto";

export function base32Decode(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = s.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let val = 0;
  const out = [];
  for (const c of clean) {
    const i = A.indexOf(c);
    if (i < 0) throw new Error(`bad base32 character ${c}`);
    val = (val << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((val >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function hotp(key, counter, digits = 6) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", key).update(msg).digest();
  const o = h[h.length - 1] & 0x0f;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}

export const step = (t = Date.now()) => Math.floor(t / 1000 / 30);

export function totp(secretB32, t = Date.now()) {
  return hotp(base32Decode(secretB32), step(t));
}

/**
 * A code from a time step not used before (servers reject a replayed step), waiting for the
 * next step if needed. `used` is a Set of steps, shared per secret.
 */
export async function freshTotp(secretB32, used) {
  for (;;) {
    const s = step();
    // Don't hand out a code with < 3 s left: it may expire on the way to the server.
    const left = 30_000 - (Date.now() % 30_000);
    if (!used.has(s) && left > 3_000) {
      used.add(s);
      return totp(secretB32);
    }
    await new Promise((r) => setTimeout(r, left + 250));
  }
}

// RFC 6238 appendix B vector (SHA-1, 8 digits at T=59) as a self-check on import.
if (hotp(Buffer.from("12345678901234567890"), Math.floor(59 / 30), 8) !== "94287082") throw new Error("totp self-check failed");
