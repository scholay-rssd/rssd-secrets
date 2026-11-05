# Demo values

Fake values that satisfy the schema so the public RSSD version can start its
services without accounts. They authenticate nothing real. Pair them with the
synthetic fixtures from `rssd-examples` (`npm run demo:build` in an RSSD
checkout).

From an RSSD checkout with `rssd-secrets` next to it:

```sh
node ../rssd-secrets/bin/rssd-secrets.mjs check --dir ../rssd-secrets/examples/demo --component admin-worker
node ../rssd-secrets/bin/rssd-secrets.mjs exec --dir ../rssd-secrets/examples/demo --component admin -- npm run admin
```

Each file is named after a schema entry and holds one value. Never add a real
value here.
