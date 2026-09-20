# trustme-secrets

Read application secrets from [TrustMe](https://trustme-33ab7.web.app) with a
single call.

```js
import trustme from "trustme-secrets";

const key = await trustme.get("STRIPE_API_KEY");
```

Node 18 or later. ESM only.

## How it works

Your application holds one `.TM` file containing an ECDSA P-256 private key,
encrypted at rest with a password only you know. The library unlocks that key in
your own process, signs a 60-second single-use assertion, and sends only the
signature. The private key is never transmitted and the password never reaches
the server, so a breach of the TrustMe database cannot forge a request for your
application.

## Pointing at a key file

```js
const tm = await trustme.using("C:/Users/you/.trustme/billing-service.TM");
const key = await tm.fetch("STRIPE_API_KEY");
```

Or at the run command with `--trustme-key-file=<path>`. A single `.TM` file in
the working directory is used without asking.

## Supplying the password

Run your application normally and it asks:

```
$ node app.js
TrustMe key file password: ********
```

For pipelines, pass it at the run command:

```
cat pw | node app.js                                     # stdin, not in the process list
node app.js --trustme-password-file=/run/secrets/tm      # a file, only the path is visible
node app.js --trustme-password=...                       # inline, visible in ps
```

**Prefer stdin or a password file.** A value passed inline is visible to anyone
who can list processes on the machine.

## Unlocking once per machine (Windows)

The first run asks for the password. The unlocked key is then remembered for your
Windows account, sealed with DPAPI, so later runs start without a prompt. Any
process running as you can use it - the same bargain `ssh-agent` makes. Turn it
off with `--trustme-cache=false`, or clear it:

```js
await trustme.forget("C:/path/app.TM");
```

If caching ever fails you are told why on stderr, and `--trustme-debug` traces
each lookup. On macOS and Linux there is no cache and every run asks.

## Errors

Every failure names the secret and the application:

```
Secret "JWT_SECRET" does not exist in application "billing-abc123". Add it in the TrustMe console.
```

## Licence

MIT
