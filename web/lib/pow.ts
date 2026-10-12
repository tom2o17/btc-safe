// Signup proof of work: find the smallest decimal nonce n such that
// SHA-256(utf8(challenge + ":" + n)) starts with at least `bits` zero bits (big-endian, the first
// byte's MSB first). ~2^bits hashes on average: about a second at 20 bits.
//
// Self-contained SHA-256 (no imports, so node:test loads it directly and it stays fast: buffers are
// reused across nonces). test/pow.test.mjs checks it against node:crypto.

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const W = new Uint32Array(64);
const H = new Uint32Array(8);

function compress(buf: Uint8Array, off: number) {
  for (let i = 0; i < 16; i++) {
    const j = off + i * 4;
    W[i] = (buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3];
  }
  for (let i = 16; i < 64; i++) {
    const a = W[i - 15];
    const b = W[i - 2];
    const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
    const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
  }
  let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
    h = g;
    g = f;
    f = e;
    e = (d + t1) | 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) | 0;
  }
  H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

let scratch = new Uint8Array(128);

/** SHA-256 of `msg`. Returns the 8 big-endian state words (shared buffer: copy if you keep it). */
function sha256Words(msg: Uint8Array, len = msg.length): Uint32Array {
  const padded = (Math.floor((len + 8) / 64) + 1) * 64;
  if (scratch.length < padded) scratch = new Uint8Array(padded);
  const buf = scratch;
  buf.set(msg.subarray(0, len));
  buf[len] = 0x80;
  buf.fill(0, len + 1, padded);
  const bitsHi = Math.floor(len / 0x20000000);
  const bitsLo = (len << 3) >>> 0;
  buf[padded - 8] = bitsHi >>> 24; buf[padded - 7] = bitsHi >>> 16; buf[padded - 6] = bitsHi >>> 8; buf[padded - 5] = bitsHi;
  buf[padded - 4] = bitsLo >>> 24; buf[padded - 3] = bitsLo >>> 16; buf[padded - 2] = bitsLo >>> 8; buf[padded - 1] = bitsLo;
  H.set(H0);
  for (let off = 0; off < padded; off += 64) compress(buf, off);
  return H;
}

export function sha256(msg: Uint8Array): Uint8Array {
  const h = sha256Words(msg);
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4] = h[i] >>> 24;
    out[i * 4 + 1] = h[i] >>> 16;
    out[i * 4 + 2] = h[i] >>> 8;
    out[i * 4 + 3] = h[i];
  }
  return out;
}

/** Leading zero bits of a 256-bit big-endian value given as 8 words. */
export function leadingZeroBits(words: ArrayLike<number>): number {
  let n = 0;
  for (let i = 0; i < words.length; i++) {
    const w = words[i] >>> 0;
    if (w === 0) {
      n += 32;
      continue;
    }
    return n + Math.clz32(w);
  }
  return n;
}

/** Does `nonce` satisfy the challenge? */
export function checkPow(challenge: string, nonce: string, bits: number): boolean {
  return leadingZeroBits(sha256Words(new TextEncoder().encode(`${challenge}:${nonce}`))) >= bits;
}

export type SolveOptions = {
  /** Hashes per slice between yields to the event loop (keeps the UI responsive). */
  batch?: number;
  /** Called between slices; return a promise to yield (e.g. a setTimeout(0)). */
  yieldFn?: () => Promise<void>;
  signal?: AbortSignal;
  onProgress?: (tried: number) => void;
};

const defaultYield = () => new Promise<void>((r) => setTimeout(r, 0));

/** The smallest nonce (as a decimal string) meeting `bits`; tries 0, 1, 2, … in order. */
export async function solvePow(challenge: string, bits: number, opts: SolveOptions = {}): Promise<string> {
  if (!Number.isInteger(bits) || bits < 0 || bits > 64) throw new Error(`unsupported difficulty: ${bits} bits`);
  const batch = opts.batch ?? 20_000;
  const yieldFn = opts.yieldFn ?? defaultYield;
  const prefix = new TextEncoder().encode(`${challenge}:`);
  const msg = new Uint8Array(prefix.length + 20); // up to 20 decimal digits
  msg.set(prefix);
  const digits = msg.subarray(prefix.length);
  for (let n = 0, slice = 0; n < Number.MAX_SAFE_INTEGER; n++, slice++) {
    if (slice === batch) {
      slice = 0;
      opts.onProgress?.(n);
      await yieldFn();
      if (opts.signal?.aborted) throw new DOMException("aborted", "AbortError");
    }
    const s = String(n);
    for (let i = 0; i < s.length; i++) digits[i] = s.charCodeAt(i);
    if (leadingZeroBits(sha256Words(msg, prefix.length + s.length)) >= bits) return s;
  }
  throw new Error("proof of work: no nonce found");
}
