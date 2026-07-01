# Importing & migrating

[← README](../README.md) · related: [Commands](COMMANDS.md) · [Configuration](CONFIGURATION.md)

arca takes values on **stdin**, so anything that can emit secrets pipes straight in. There are
three ingest shapes:

| Shape | Command | Use it for |
|-------|---------|-----------|
| dotenv lines | `arca import` | `KEY=value` streams (`.env`, sops, `printenv`) |
| JSON object | `arca import --json` | `{"KEY":"value"}` — what most secret stores emit |
| a single value | `arca set NAME < file` | one secret, including multi-line blobs (PEM keys, a service-account JSON) |

`import` validates every name (`[A-Za-z_][A-Za-z0-9_]*`) and **skips** anything else, and each
imported secret is recorded in the audit log like any other write. With `--json`, string values
pass through verbatim (a JSON-escaped multi-line key round-trips), numbers and booleans are
stringified, and `null`/nested values are skipped.

By default `import` **skips a name that already exists** (so a re-run never silently clobbers a
secret); pass `--overwrite` to replace them. A few flags shape the load:

| Flag | Effect |
|------|--------|
| `--dry-run` | Print what would be imported (new vs overwrite vs skip) and write nothing |
| `--overwrite` | Replace existing secrets instead of skipping them |
| `--prefix P` | Prepend `P` to every imported name (e.g. `--prefix STRIPE_`) |
| `--tag t` | Attach tags to every imported secret (repeatable or comma-separated) |

```sh
# dotenv — a plain file, or decrypted from sops
arca import < .env
sops -d ~/.dotfiles/secrets/secrets.env | arca import

# JSON — straight from a cloud secret store, no jq gymnastics
aws secretsmanager get-secret-value --secret-id prod/app --query SecretString --output text \
  | arca import --json
gcloud secrets versions access latest --secret=prod-app | arca import --json
vault kv get -format=json secret/prod/app | jq '.data.data' | arca import --json
op item get prod-app --format json | jq '[.fields[]|select(.value)|{(.label):.value}]|add' \
  | arca import --json

# any KEY=value source via dotenv
pass show prod/env | arca import
printenv | grep '^APP_' | arca import

# preview first, then namespace + tag a load
arca import --json --dry-run < secrets.json
arca import --prefix STRIPE_ --tag billing,prod < stripe.env
arca import --overwrite < refreshed.env          # replace existing (default skips them)

# one secret, multi-line, as a single value (not dotenv)
arca set TLS_KEY < server.key
arca set GCP_SA_JSON < service-account.json
```

> A non-JSON source whose values span lines (a raw PEM, a certificate) doesn't fit dotenv —
> import it as one named secret with `set NAME < file`, or wrap it in a JSON object and use
> `--json`.
