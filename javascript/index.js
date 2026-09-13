import { createDecipheriv, createHash, createPrivateKey, randomBytes, sign } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { createInterface } from "node:readline";
import { argon2id } from "hash-wasm";
import { loadTmFile, TrustMeError } from "./tmfile.js";
import * as keycache from "./keycache.js";

export { TrustMeError };

const SECRET_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const ASSERTION_LIFETIME = 60;
const cache = new Map();

const b64url = (buf) => Buffer.from(buf).toString("base64url");

function stripTrailingSlash(url) {
  return url.endsWith("/") ? url.slice(0, -1) : url;
}

class TrustMe {
  constructor(file, privateKey) {
    this.file = file;
    this.privateKey = privateKey;
  }

  get appId() {
    return this.file.appId;
  }

  async fetch(secretName) {
    if (!SECRET_NAME.test(secretName ?? "")) {
      throw new TrustMeError("Invalid secret name: " + secretName);
    }

    let response;
    try {
      response = await globalThis.fetch(stripTrailingSlash(this.file.apiUrl) + "/secret", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + this.buildAssertion(),
        },
        body: JSON.stringify({ secretName }),
        signal: AbortSignal.timeout(20000),
      });
    } catch (err) {
      throw new TrustMeError("Could not reach TrustMe: " + err.message);
    }

    const body = await response.text();
    if (!response.ok) {
      let reason = body;
      try {
        reason = JSON.parse(body).error ?? body;
      } catch {
        // leave the raw body as the reason
      }
      throw new TrustMeError(this.describe(String(reason), secretName));
    }

    const payload = JSON.parse(body);
    if (typeof payload.value !== "string") {
      throw new TrustMeError("Malformed response from TrustMe.");
    }
    return payload.value;
  }

  // Turns a server error code into something a person can act on. The secret
  // name is always included: a bare "not found" is useless when a config file
  // references a dozen of them.
  describe(code, secretName) {
    const app = this.file.appId;
    const q = JSON.stringify(secretName);
    const a = JSON.stringify(app);
    switch (code) {
      case "secret_not_found":
        return "Secret " + q + " does not exist in application " + a + ". Add it in the TrustMe console.";
      case "key_revoked":
        return "The key file for application " + a + " has been revoked (while fetching " + q
          + "). Generate a new one in the TrustMe console.";
      case "unknown_key":
        return "The key file for application " + a + " is not registered with TrustMe (while fetching "
          + q + "). Generate a new one in the TrustMe console.";
      case "bad_signature":
        return "TrustMe rejected the request for " + q + ": the signature did not verify."
          + " The key file may not match what the console holds for " + a + ".";
      case "replay_detected":
      case "bad_lifetime":
        return "TrustMe rejected the request for " + q + " (" + code + "). Check that this machine's clock is correct.";
      case "decrypt_failed":
        return "TrustMe could not decrypt " + q + " on the server. This is a server-side problem, not something in your application.";
      default:
        return "TrustMe refused the request for " + q + " in application " + a + ": " + code;
    }
  }

  buildAssertion() {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: "ES256", typ: "JWT", kid: this.file.keyId };
    const claims = {
      iss: this.file.appId,
      aud: "trustme",
      iat: now,
      exp: now + ASSERTION_LIFETIME,
      jti: randomBytes(16).toString("hex"),
    };
    const signingInput =
      b64url(JSON.stringify(header)) + "." + b64url(JSON.stringify(claims));

    // ieee-p1363 gives the raw r||s layout JOSE expects; the default DER
    // encoding would be rejected by the server.
    const signature = sign("sha256", Buffer.from(signingInput, "utf8"), {
      key: this.privateKey,
      dsaEncoding: "ieee-p1363",
    });
    return signingInput + "." + b64url(signature);
  }
}

function argOption(name) {
  const flag = "--" + name + "=";
  for (const arg of process.argv.slice(2)) {
    if (arg.startsWith(flag)) return arg.slice(flag.length);
  }
  return undefined;
}

async function keyFilesHere() {
  try {
    const entries = await readdir(process.cwd());
    return entries.filter((name) => name.toLowerCase().endsWith(".tm"));
  } catch {
    return [];
  }
}

function ask(prompt, hidden) {
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  if (hidden) {
    // Suppress echo so the password is not painted onto the terminal.
    rl._writeToOutput = (chunk) => {
      if (chunk.includes(prompt)) rl.output.write(prompt);
    };
  }
  return new Promise((done) =>
    rl.question(prompt, (answer) => {
      rl.close();
      if (hidden) process.stdout.write("\n");
      done(answer.trim());
    })
  );
}

function readLineFromStdin() {
  // No tty: a pipeline, or an IDE that redirected the streams. The prompt has
  // to be printed explicitly or an IDE run just hangs with no hint.
  process.stderr.write("TrustMe key file password: ");
  return new Promise((done) => {
    const rl = createInterface({ input: process.stdin, terminal: false });
    let settled = false;
    rl.once("line", (line) => {
      settled = true;
      rl.close();
      process.stderr.write("\n");
      done(line);
    });
    rl.once("close", () => {
      if (!settled) done("");
    });
  });
}

async function resolveKeyFile() {
  const configured = argOption("trustme-key-file");
  if (configured) return configured.trim();

  const found = await keyFilesHere();
  if (found.length === 1) return found[0];

  if (process.stdin.isTTY) {
    const typed = await ask(
      found.length === 0
        ? "Path to your .TM key file: "
        : "Several .TM files are here. Path to the one to use: ",
      false
    );
    if (typed) return typed;
  }

  throw new TrustMeError(
    found.length === 0
      ? "No .TM key file found. Pass --trustme-key-file=<path>, or run where one is present."
      : "Several .TM files found. Pass --trustme-key-file=<path> to choose one."
  );
}

async function resolvePassword() {
  const inline = argOption("trustme-password");
  if (inline) return inline;

  const file = argOption("trustme-password-file");
  if (file) {
    try {
      return (await readFile(file.trim(), "utf8")).trim();
    } catch (err) {
      throw new TrustMeError("Could not read --trustme-password-file: " + err.message);
    }
  }

  if (process.stdin.isTTY) {
    const typed = await ask("TrustMe key file password: ", true);
    if (typed) return typed;
    throw new TrustMeError("No password entered.");
  }

  // No terminal, so this is a pipeline: take the password from stdin, which
  // unlike a command-line flag does not show up in the process list.
  const line = await readLineFromStdin();
  if (line) return line;

  throw new TrustMeError(
    "No password available. Pipe it on stdin, or pass --trustme-password-file=<path>, " +
      "or --trustme-password=<value>."
  );
}

function fromPkcs8(file, pkcs8) {
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  pkcs8.fill(0);
  return new TrustMe(file, privateKey);
}

async function decrypt(file, path, password) {
  const derived = await argon2id({
    password,
    salt: file.salt,
    parallelism: file.parallelism,
    iterations: file.timeCost,
    memorySize: file.memoryCostKib,
    hashLength: 32,
    outputType: "binary",
  });
  try {
    // The GCM tag doubles as the password check: a wrong password fails here
    // rather than producing plausible-looking rubbish.
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(derived), file.nonce);
    decipher.setAuthTag(file.tag);
    return Buffer.concat([decipher.update(file.ciphertext), decipher.final()]);
  } catch {
    throw new TrustMeError("Incorrect password for " + basename(path) + ".");
  }
}

async function unlock(path, password) {
  const file = await loadTmFile(path);
  const pkcs8 = await decrypt(file, path, password);
  keycache.store(file.keyId, pkcs8);   // remember for next run
  return fromPkcs8(file, pkcs8);
}

/**
 * Opens a key file. Without a password, a key this machine already remembers is
 * used directly; otherwise the password is asked for, read from stdin, or taken
 * from the command line. With an explicit password the file is always unlocked
 * with it, so a wrong one fails rather than reusing an earlier success.
 */
export async function using(keyFile, password) {
  const path = keyFile ?? (await resolveKeyFile());

  if (password === undefined) {
    const slot = resolve(path);
    if (!cache.has(slot)) {
      // The header is plaintext, so the key id is readable without unlocking
      // anything - that is what makes a cache lookup possible before prompting.
      const file = await loadTmFile(path);
      const remembered = keycache.load(file.keyId);
      cache.set(slot, remembered
        ? fromPkcs8(file, remembered)
        : await unlock(path, await resolvePassword()));
    }
    return cache.get(slot);
  }

  const cacheKey = resolve(path) + " " + createHash("sha256").update(password).digest("hex");
  if (!cache.has(cacheKey)) cache.set(cacheKey, await unlock(path, password));
  return cache.get(cacheKey);
}

/** Forgets a key this machine has remembered, so the next run asks again. */
export async function forget(keyFile) {
  const file = await loadTmFile(keyFile);
  cache.delete(resolve(keyFile));
  return keycache.forget(file.keyId);
}

// Resolved once per process. Standard input in particular can only be read once,
// so a second get() must not go looking for the password again.
let defaults;

/** Fetches a secret using the default key file and password. */
export async function get(secretName) {
  if (!defaults) defaults = { keyFile: await resolveKeyFile() };
  return (await using(defaults.keyFile)).fetch(secretName);
}

export default { get, using, forget, TrustMeError };
