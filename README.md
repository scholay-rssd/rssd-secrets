# rssd-secrets

Schema, resolver and demo values for the secrets RSSD needs. This repository
never contains a real value.

RSSD code reads secrets only from environment variables. `rssd-secrets`
decides where each value comes from and injects it into the process that needs
it, so the code never knows (or hard-codes) a location.

## Schema

[`schema.json`](schema.json) declares every secret: name, type, components,
whether it is required, and its purpose. Types:

| Type | Meaning |
|---|---|
| `value` | The environment variable holds the secret itself. |
| `file` | The environment variable holds a path to a private file. |
| `location` | A directory path; taken from the environment only. |
| `runtime` | Generated per session by the running app; never stored. |

`group` marks alternatives (for example `SCHOLAY_TODAY_TOKEN` or
`SCHOLAY_TODAY_TOKEN_FILE`); a required group is satisfied by any member.

CI fails when RSSD reads a secret-like variable the schema does not declare
(`node scripts/coverage.mjs <rssd checkout>`).

## Resolution order

1. The process environment.
2. A values directory (`--dir` or `RSSD_SECRETS_DIR`): one file per secret,
   named after it. For `file` secrets the file's path is used.
3. The OS credential store: macOS Keychain or Windows Credential Manager,
   service `rssd-secrets`, account = secret name. Store multi-line values as
   `base64:<encoded>`.
4. A server directory (`--server-dir`, `RSSD_SECRETS_SERVER_DIR`, default
   `/etc/rssd/secrets` on Linux). Files must not be accessible by group or
   others.

`file` secrets found in a credential store are written to a private temporary
directory for the duration of `exec` and removed afterwards.

## Usage

Node.js 24+, no dependencies.

```sh
node bin/rssd-secrets.mjs list --component admin-worker
node bin/rssd-secrets.mjs check --component desktop-release      # sources only, never values
node bin/rssd-secrets.mjs exec --component admin-cli -- node admin/cli.mjs import items.json year
```

`exec` refuses to start when a required secret is missing (`--allow-missing`
overrides). Store a value in the macOS Keychain without exposing it in shell
history:

```sh
security add-generic-password -U -s rssd-secrets -a SCHOLAY_INGEST_TOKEN -w
```

## Demo

[`examples/demo`](examples/demo) holds fake values for running the public
version with the synthetic `rssd-examples` fixtures.

## Real values

Real values live outside this repository (a private values directory, the OS
credential store or the server directory). Keep any repository that holds real
values private, owner-only and never referenced by a public repository or its
CI. If exposure is suspected, rotate every value: deleting files does not remove
them from history.
