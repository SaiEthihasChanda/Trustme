import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const MAGIC = Buffer.from("TMKF", "ascii");
const VERSION = 2;

export class TrustMeError extends Error {
  constructor(message) {
    super(message);
    this.name = "TrustMeError";
  }
}

class Cursor {
  constructor(data) {
    this.data = data;
    this.pos = 0;
  }
  take(count) {
    if (this.pos + count > this.data.length) {
      throw new TrustMeError("Key file ended unexpectedly.");
    }
    const chunk = this.data.subarray(this.pos, this.pos + count);
    this.pos += count;
    return chunk;
  }
  u8() {
    return this.take(1)[0];
  }
  u16() {
    return this.take(2).readUInt16BE(0);
  }
  u32() {
    return this.take(4).readUInt32BE(0);
  }
  str8() {
    return this.take(this.u8()).toString("utf8");
  }
  str16() {
    return this.take(this.u16()).toString("utf8");
  }
  blob16() {
    return Buffer.from(this.take(this.u16()));
  }
}

// Reader for the .TM container (format version 2). The layout is public by
// design; the only secret is the password that unlocks the key inside it.
export async function loadTmFile(path) {
  let raw;
  try {
    raw = await readFile(path);
  } catch (err) {
    throw new TrustMeError(`Could not read key file ${path}: ${err.message}`);
  }

  if (raw.length < 100) {
    throw new TrustMeError(`File is too small to be a key file: ${path}`);
  }

  const body = raw.subarray(0, raw.length - 32);
  const stated = raw.subarray(raw.length - 32);
  if (!createHash("sha256").update(body).digest().equals(stated)) {
    throw new TrustMeError("Key file is corrupt: checksum does not match.");
  }

  const cursor = new Cursor(raw);
  if (!cursor.take(4).equals(MAGIC)) {
    throw new TrustMeError(`Not a TrustMe key file: ${path}`);
  }

  const version = cursor.u8();
  if (version !== VERSION) {
    throw new TrustMeError(
      `Unsupported key file version ${version}. Regenerate this file from the TrustMe console.`
    );
  }
  cursor.u8(); // flags

  return {
    appId: cursor.str8(),
    keyId: cursor.str8(),
    apiUrl: cursor.str16(),
    publicKey: cursor.blob16(),
    salt: cursor.take(16),
    memoryCostKib: cursor.u32(),
    timeCost: cursor.u32(),
    parallelism: cursor.u8(),
    nonce: Buffer.from(cursor.take(12)),
    ciphertext: cursor.blob16(),
    tag: Buffer.from(cursor.take(16)),
  };
}
