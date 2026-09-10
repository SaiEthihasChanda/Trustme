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
  <version>0.1.0</version>
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
| `python/` | published to PyPI |
| `javascript/` | published to npm |

## Licence

MIT — see [LICENSE](LICENSE).
