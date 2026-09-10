import { createDecipheriv, createHash, createPrivateKey, randomBytes, sign } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { createInterface } from "node:readline";
import { argon2id } from "hash-wasm";
import { loadTmFile, TrustMeError } from "./tmfile.js";

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
      throw new TrustMeError("TrustMe refused the request: " + reason);
    }

    const payload = JSON.parse(body);
    if (typeof payload.value !== "string") {
      throw new TrustMeError("Malformed response from TrustMe.");
    }
    return payload.value;
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
  return new Promise((done) => {
    const rl = createInterface({ input: process.stdin, terminal: false });
    let settled = false;
    rl.once("line", (line) => {
      settled = true;
      rl.close();
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

async function unlock(path, password) {
  const file = await loadTmFile(path);

  const derived = await argon2id({
    password,
    salt: file.salt,
    parallelism: file.parallelism,
    iterations: file.timeCost,
    memorySize: file.memoryCostKib,
    hashLength: 32,
    outputType: "binary",
  });

  let pkcs8;
  try {
    // The GCM tag doubles as the password check: a wrong password fails here
    // rather than producing plausible-looking rubbish.
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(derived), file.nonce);
    decipher.setAuthTag(file.tag);
    pkcs8 = Buffer.concat([decipher.update(file.ciphertext), decipher.final()]);
  } catch {
    throw new TrustMeError("Incorrect password for " + basename(path) + ".");
  }

  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  pkcs8.fill(0);
  return new TrustMe(file, privateKey);
}

/** Opens a key file, reusing an already-unlocked one where possible. */
export async function using(keyFile, password) {
  const path = keyFile ?? (await resolveKeyFile());
  const secret = password ?? (await resolvePassword());

  // The password forms part of the cache key so presenting a different one
  // re-runs the unlock and fails, rather than reusing an earlier success.
  const cacheKey = resolve(path) + " " + createHash("sha256").update(secret).digest("hex");

  if (!cache.has(cacheKey)) cache.set(cacheKey, await unlock(path, secret));
  return cache.get(cacheKey);
}

// Resolved once per process. Standard input in particular can only be read once,
// so a second get() must not go looking for the password again.
let defaults;

/** Fetches a secret using the default key file and password. */
export async function get(secretName) {
  if (!defaults) {
    defaults = { keyFile: await resolveKeyFile(), password: await resolvePassword() };
  }
  const tm = await using(defaults.keyFile, defaults.password);
  return tm.fetch(secretName);
}

export default { get, using, TrustMeError };
