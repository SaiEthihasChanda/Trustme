import { spawnSync } from "node:child_process";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// Remembers an unlocked private key for this account, so a key file is
// unlocked once per machine rather than once per run.
//
// On Windows the key is sealed with DPAPI under CurrentUser scope. Node has no
// DPAPI binding, so the call goes through PowerShell's ProtectedData, which
// every Windows install has. Key material is passed over stdin and never
// appears on a command line.
//
// On Linux there is no OS-backed secret store guaranteed to be present - no
// desktop session, no keyring daemon, especially headless or in a container -
// so the key is instead sealed with AES-256-GCM under a key derived from
// /etc/machine-id, and the file is restricted to this user with 0600
// permissions. That reproduces "copying the file elsewhere yields nothing",
// but the boundary against another account on the same machine is the
// filesystem permission, not an OS secret store.
//
// On anything else (macOS) the cache is disabled and every run asks.

const WINDOWS = process.platform === "win32";
const LINUX = process.platform === "linux";

function argOption(name) {
  const flag = "--" + name + "=";
  const hit = process.argv.slice(2).find((a) => a.startsWith(flag));
  return hit ? hit.slice(flag.length) : undefined;
}

const DEBUG = argOption("trustme-debug") !== undefined;
const debug = (m) => { if (DEBUG) process.stderr.write("TrustMe: " + m + "\n"); };

export function enabled() {
  if (!WINDOWS && !LINUX) return false;
  return (argOption("trustme-cache") ?? "true").toLowerCase() !== "false";
}

function directory() {
  if (WINDOWS) return join(process.env.LOCALAPPDATA || homedir(), "TrustMe", "keys");
  return join(process.env.XDG_CACHE_HOME || join(homedir(), ".cache"), "trustme", "keys");
}

const fileFor = (keyId) => join(directory(), keyId + ".bin");

function dpapi(method, data) {
  const script = [
    "Add-Type -AssemblyName System.Security",
    "$in = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())",
    "$out = [System.Security.Cryptography.ProtectedData]::" + method + "($in, $null, 'CurrentUser')",
    "[Console]::Out.Write([Convert]::ToBase64String($out))",
  ].join("; ");
  const r = spawnSync("powershell.exe",
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    { input: data.toString("base64"), encoding: "utf8", timeout: 20000, windowsHide: true });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error((r.stderr || "").trim().split("\n")[0] || "powershell exited " + r.status);
  return Buffer.from(r.stdout.trim(), "base64");
}

// Binds the Linux cache to this machine, standing in for the OS secret store
// DPAPI gives Windows. Tries systemd's machine-id, then the older D-Bus one.
function linuxMachineKey() {
  for (const candidate of ["/etc/machine-id", "/var/lib/dbus/machine-id"]) {
    try {
      const id = readFileSync(candidate, "utf8").trim();
      if (id) return createHash("sha256").update("trustme-linux-cache:" + id).digest();
    } catch {
      // try the next candidate
    }
  }
  throw new Error("no /etc/machine-id or /var/lib/dbus/machine-id");
}

function linuxSeal(data) {
  const key = linuxMachineKey();
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const sealed = Buffer.concat([cipher.update(data), cipher.final()]);
  return Buffer.concat([nonce, sealed, cipher.getAuthTag()]);
}

function linuxUnseal(data) {
  const key = linuxMachineKey();
  const nonce = data.subarray(0, 12);
  const tag = data.subarray(data.length - 16);
  const ciphertext = data.subarray(12, data.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** Returns the remembered private key for this key id, or null. */
export function load(keyId) {
  if (!enabled()) {
    debug("cache disabled (" + ((WINDOWS || LINUX) ? "--trustme-cache=false" : "not Windows or Linux") + ")");
    return null;
  }
  const path = fileFor(keyId);
  if (!existsSync(path)) {
    debug("no cached key at " + path);
    return null;
  }
  try {
    const key = WINDOWS ? dpapi("Unprotect", readFileSync(path)) : linuxUnseal(readFileSync(path));
    debug("using cached key from " + path);
    return key;
  } catch (err) {
    process.stderr.write("TrustMe: cached key at " + path + " could not be read ("
      + err.message + "); asking for the password.\n");
    return null;
  }
}

/** Remembers an unlocked private key. Failure is reported, never fatal. */
export function store(keyId, privateKey) {
  if (!enabled()) return;
  const path = fileFor(keyId);
  try {
    const dir = directory();
    mkdirSync(dir, { recursive: true });
    if (!WINDOWS) chmodSync(dir, 0o700);
    const sealed = WINDOWS ? dpapi("Protect", privateKey) : linuxSeal(privateKey);
    writeFileSync(path, sealed, WINDOWS ? undefined : { mode: 0o600 });
    if (!WINDOWS) chmodSync(path, 0o600); // in case the file already existed with looser permissions
    debug("remembered key at " + path);
  } catch (err) {
    process.stderr.write("TrustMe: could not remember the key on this machine ("
      + err.message + "). You will be asked for the password on every run.\n");
  }
}

/** Forgets one remembered key. Returns true if something was removed. */
export function forget(keyId) {
  const path = fileFor(keyId);
  if (!existsSync(path)) return false;
  unlinkSync(path);
  return true;
}
