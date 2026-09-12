# trustme-secrets

Read application secrets from [TrustMe](https://trustme-33ab7.web.app) with a
single call.

```python
import trustme_secrets

key = trustme_secrets.get("STRIPE_API_KEY")
```

The import name is `trustme_secrets`, not `trustme` — the latter is an unrelated
TLS-certificate library that has been on PyPI for years.

## How it works

Your application holds one `.TM` file containing an ECDSA P-256 private key,
encrypted at rest with a password only you know. The library unlocks that key in
your own process, signs a 60-second single-use assertion, and sends only the
signature. The private key is never transmitted and the password never reaches
the server, so a breach of the TrustMe database cannot forge a request for your
application.

## Pointing at a key file

From code:

```python
import trustme_secrets

trustme_secrets.use_key_file("C:/Users/you/.trustme/billing-service.TM")
key = trustme_secrets.get("STRIPE_API_KEY")
```

Or open one directly:

```python
tm = trustme_secrets.using("C:/Users/you/.trustme/billing-service.TM")
key = tm.fetch("STRIPE_API_KEY")
```

Or at the run command, with either spelling:

```
python -X trustme_keyfile=C:/path/app.TM app.py
python app.py --trustme-key-file=C:/path/app.TM
```

## Unlocking once per machine (Windows)

The first run asks for the password. The unlocked key is then remembered for your
Windows account, so later runs start without a prompt:

```
$ python app.py
TrustMe key file password: ********      <- first run only

$ python app.py                          <- no prompt
```

The key is sealed with DPAPI under CurrentUser scope, called directly through
`ctypes`, and written to `%LOCALAPPDATA%\TrustMe\keys\`. Another account cannot
read it, and copying the file to another machine yields nothing.

**Understand what this trades away.** A decrypted key now sits on disk, usable by
any process running as you, with no password. That is the same bargain
`ssh-agent` makes. Turn it off with `-X trustme_cache=false`, or clear it:

```python
trustme_secrets.forget("C:/path/app.TM")
```

If caching ever fails you are told why on stderr, and `-X trustme_debug` traces
each lookup. On macOS and Linux there is no cache and every run asks.

## Supplying the key file and password

Run your application normally and it asks for anything it is missing:

```
$ python app.py
Path to your .TM key file: ./billing-service.TM
TrustMe key file password: ********
```

A single `.TM` file in the working directory is used without asking. There are
no environment variables to set.

For pipelines, pass the password at the run command:

```
cat pw | python app.py                                  # stdin, not in the process list
python -X trustme_password_file=/run/secrets/tm app.py  # a file, only the path is visible
python -X trustme_password=... app.py                   # inline, visible in ps
```

The key file works the same way, via `-X trustme_keyfile=<path>` or
`--trustme-key-file=<path>`.

**Prefer stdin or a password file.** A value passed inline is visible to anyone
who can list processes — on Linux `/proc/<pid>/cmdline` is world readable.

`--trustme-password=` on the command line also works, but `-X` is safer because
it never collides with your own argument parsing.

The key file is resolved once per process, and the password only when the
machine cache has nothing for it, so stdin is read at most once.

## Licence

MIT
