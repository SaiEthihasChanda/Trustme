import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// Remembers an unlocked private key for this Windows account, sealed with DPAPI
// under CurrentUser scope. Node has no DPAPI binding, so the call goes through
// PowerShell's ProtectedData, which every Windows install has. Key material is
// passed over stdin and never appears on a command line.
//
// On anything other than Windows the cache is disabled and every run asks.

const WINDOWS = process.platform === "win32";

function argOption(name) {
  const flag = "--" + name + "=";
  const hit = process.argv.slice(2).find((a) => a.startsWith(flag));
  return hit ? hit.slice(flag.length) : undefined;
}

const DEBUG = argOption("trustme-debug") !== undefined;
const debug = (m) => { if (DEBUG) process.stderr.write("TrustMe: " + m + "\n"); };

export function enabled() {
  if (!WINDOWS) return false;
  return (argOption("trustme-cache") ?? "true").toLowerCase() !== "false";
}

function directory() {
  return join(process.env.LOCALAPPDATA || homedir(), "TrustMe", "keys");
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

/** Returns the remembered private key for this key id, or null. */
export function load(keyId) {
  if (!enabled()) {
    debug("cache disabled (" + (WINDOWS ? "--trustme-cache=false" : "not Windows") + ")");
    return null;
  }
  const path = fileFor(keyId);
  if (!existsSync(path)) {
    debug("no cached key at " + path);
    return null;
  }
  try {
    const key = dpapi("Unprotect", readFileSync(path));
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
    mkdirSync(directory(), { recursive: true });
    writeFileSync(path, dpapi("Protect", privateKey));
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
