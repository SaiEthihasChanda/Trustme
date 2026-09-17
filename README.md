# TrustMe client libraries

Read application secrets from [TrustMe](https://trustme-33ab7.web.app) with a
single call, in Java, Python or JavaScript.

```java
String key = TrustMe.get("STRIPE_API_KEY");
```

Your application holds one `.TM` file containing an ECDSA P-256 private key,
encrypted at rest with a password only you know. The library unlocks that key in
your own process, signs a 60-second single-use assertion, and sends only the
signature. The private key is never transmitted, and the password never reaches
the server — so a breach of the TrustMe database cannot forge a request for your
application.

## Install

**Java** (11+)

```xml
<dependency>
  <groupId>io.github.saiethihaschanda</groupId>
  <artifactId>trustme</artifactId>
  <version>0.2.1</version>
</dependency>
```

**Python** (3.9+)

```
pip install trustme-secrets
```

**JavaScript** (Node 18+)

```
npm install trustme-secrets
```

## Use

```java
import app.trustme.TrustMe;
String key = TrustMe.get("STRIPE_API_KEY");
```

```python
import trustme
key = trustme.get("STRIPE_API_KEY")
```

```js
import trustme from "trustme-secrets";
const key = await trustme.get("STRIPE_API_KEY");
```

## Spring Boot

Add the starter instead of the plain library:

```xml
<dependency>
  <groupId>io.github.saiethihaschanda</groupId>
  <artifactId>trustme-spring</artifactId>
  <version>0.1.0</version>
</dependency>
```

Then refer to secrets directly in `application.properties`:

```properties
trustme.key-file=C:/Users/you/.trustme/billing-service.TM

jwt.secret=${trustme.secret.JWT_SECRET}
spring.datasource.password=${trustme.secret.DB_PASSWORD}
```

Existing `@Value("${jwt.secret}")` injection needs no change, including in
constructors: the secrets are installed before any bean is created.

Only the secrets you actually reference are fetched. Anything already set in
application.properties, the environment or on the command line still wins, so a
local override works without touching TrustMe. `trustme.enabled=false` turns the
whole thing off.

Because this runs before the Spring banner, a password prompt appears there too.
For unattended services supply it the usual way, for example
`-Dtrustme.password-file=/run/secrets/tm`.

## Supplying the key file and password

Run your application normally and the library asks for anything it is missing:

```
$ java -jar billing-service.jar
Path to your .TM key file: ./billing-service.TM
TrustMe key file password: ********
```

If exactly one `.TM` file sits in the working directory it is used without
asking. There are no environment variables to set.

For pipelines, pass the password at the run command. Three ways, in order of
preference:

| | Java | Python | JavaScript |
| --- | --- | --- | --- |
| stdin | `cat pw \| java -jar app.jar` | `cat pw \| python app.py` | `cat pw \| node app.js` |
| file | `-Dtrustme.password-file=<path>` | `-X trustme_password_file=<path>` | `--trustme-password-file=<path>` |
| inline | `-Dtrustme.password=<value>` | `-X trustme_password=<value>` | `--trustme-password=<value>` |

The key file works the same way: `-Dtrustme.keyfile`, `-X trustme_keyfile`, or
`--trustme-key-file`.

**Prefer stdin or a password file.** A value passed inline is visible to anyone
who can list processes on the machine — on Linux `/proc/<pid>/cmdline` is world
readable. Piping it or pointing at a file keeps it out of the process list.

Python also accepts `--trustme-password=` on the command line, but `-X` is safer
because it never collides with your own argument parsing.

### Jenkins

```groovy
withCredentials([string(credentialsId: 'trustme-billing', variable: 'TM_PASS')]) {
  sh 'echo "$TM_PASS" | java -Dtrustme.keyfile=app.TM -jar billing-service.jar'
}
```

The password reaches the process through stdin only: not the environment, not the
process list, not a file on disk.

The key file and password are resolved once per process, so stdin is read at most
once no matter how many secrets you fetch.

## Unlocking once per machine (Windows and Linux)

In all three languages, the first run asks for the password. The unlocked key is
then remembered for your account, so later runs start without a prompt:

```
$ java -jar billing-service.jar
TrustMe key file password: ********      <- first run only

$ java -jar billing-service.jar          <- no prompt
```

**On Windows** the key is sealed with DPAPI under CurrentUser scope and written to
`%LOCALAPPDATA%\TrustMe\keys\`. Java uses JNA, Python calls DPAPI through
`ctypes`, and Node goes through PowerShell's ProtectedData - none of them add a
dependency you did not already have. Another Windows account cannot read it, and
copying the file to another machine yields nothing.

**On Linux** there is no OS-backed secret store guaranteed to be present - no
desktop session, no keyring daemon, especially headless or in a container - so
the key is instead sealed with AES-256-GCM under a key derived from
`/etc/machine-id` (falling back to `/var/lib/dbus/machine-id`), and written to
`$XDG_CACHE_HOME/trustme/keys/` (or `~/.cache/trustme/keys/`) with the directory
and file both restricted to `0600`/`0700`. Copying the file to another machine
still yields nothing, since the machine id it was sealed under won't match. But
unlike DPAPI, the boundary against another account on the same machine is only
the filesystem permission, not an OS secret store - so it's weaker in the face
of anyone who can read past that permission (root, a misconfigured umask, a
backup that preserves file contents but not modes). If no machine id is present
at all, the cache is silently disabled for that run rather than falling back to
something weaker.

**Understand what this trades away, on either platform.** A decrypted key now
sits on disk, usable by any process running as you, with no password. That is
the same bargain `ssh-agent` makes, and it is weaker than being asked every
time. Turn it off with `-Dtrustme.cache=false` / `-X trustme_cache=false` /
`--trustme-cache=false`, or clear it with `forget(path)` in any of the three.

If caching ever fails you are told why on stderr, and the debug flag
(`-Dtrustme.debug=true`, `-X trustme_debug`, `--trustme-debug`) traces each
lookup. On macOS there is no cache and every run asks.

Caching generally isn't useful inside ephemeral containers, since there's
nothing "next run" to remember across — a fresh container is a fresh cache. It
matters more on a persistent Linux dev machine or server. In Docker, prefer
supplying the password via `-Dtrustme.password-file=...` (or the `-X`/`--`
equivalent) pointed at a mounted secret, so no run ever prompts at all.

## How it works

1. The library reads the `.TM` file and derives a key from your password with Argon2id.
2. It decrypts the private key with AES-256-GCM. A wrong password fails on the
   authentication tag rather than producing plausible-looking rubbish.
3. It signs a short-lived assertion (ES256) carrying the application id, key id
   and a random single-use identifier.
4. The server verifies the signature against the public half it stored, rejects
   replays and expired assertions, then returns the secret.

Replacing or revoking a key file in the console blocks the old one on its next
request. The `.TM` format is deliberately public: security rests on the
Argon2id-derived key protecting the file, not on the format being secret.

## Layout

| Path | |
| --- | --- |
| `java/` | published to Maven Central |
| `spring/` | Spring Boot starter, published to Maven Central |
| `python/` | published to PyPI |
| `javascript/` | published to npm |

## Licence

MIT — see [LICENSE](LICENSE).
