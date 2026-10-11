# configuration

configuration is loaded with koanf. settings can come from YAML, environment
variables, or both. environment keys override YAML before defaults and validation
are applied.

## files

`-config /path/to/config.yaml` selects a file. `GOPHERSTORAGE_CONFIG` sets the
default file path. without either, an existing `config.yaml` in the current
directory is used. if there is no default file, configuration comes from the
environment. an explicitly selected missing file is an error.

use `-config ''` or an empty `GOPHERSTORAGE_CONFIG` to use only environment keys.
config files must be regular files, no larger than 1 MiB, and not group- or
world-writable. unknown configuration keys are rejected.

## environment keys

prefix each YAML field path with `GOPHERSTORAGE_`, uppercase it, and join nested
components with underscores. underscores within field names stay unchanged:

| YAML field | environment key |
| --- | --- |
| `listen` | `GOPHERSTORAGE_LISTEN` |
| `public_url` | `GOPHERSTORAGE_PUBLIC_URL` |
| `data_dir` | `GOPHERSTORAGE_DATA_DIR` |
| `oidc.issuer` | `GOPHERSTORAGE_OIDC_ISSUER` |
| `oidc.client_id` | `GOPHERSTORAGE_OIDC_CLIENT_ID` |
| `oidc.client_secret` | `GOPHERSTORAGE_OIDC_CLIENT_SECRET` |
| `oidc.allowed_groups` | `GOPHERSTORAGE_OIDC_ALLOWED_GROUPS` |
| `session.secret` | `GOPHERSTORAGE_SESSION_SECRET` |
| `storage.backend` | `GOPHERSTORAGE_STORAGE_BACKEND` |
| `storage.s3.bucket` | `GOPHERSTORAGE_STORAGE_S3_BUCKET` |
| `storage.s3.secret_key` | `GOPHERSTORAGE_STORAGE_S3_SECRET_KEY` |
| `storage.max_document_bytes` | `GOPHERSTORAGE_STORAGE_MAX_DOCUMENT_BYTES` |
| `tokens.ttl` | `GOPHERSTORAGE_TOKENS_TTL` |
| `view.url` | `GOPHERSTORAGE_VIEW_URL` |
| `http.request_timeout` | `GOPHERSTORAGE_HTTP_REQUEST_TIMEOUT` |

all leaf settings in [config.example.yaml](../config.example.yaml) follow this
rule. `GOPHERSTORAGE_CONFIG` selects the file rather than a YAML setting. unknown
keys with the `GOPHERSTORAGE_` prefix are rejected to catch spelling mistakes.

strings are literal values, so secrets do not need YAML quoting. integers are
base-10 counts or bytes, booleans use `true` or `false`, and durations use Go
syntax such as `5m`, `12h` or `0s`. lists use JSON string arrays such as
`["storage-users","storage-admins"]`. `[]` clears the configured list, though the
application's normal defaults still apply to fields such as `oidc.scopes`.

an unset key leaves the YAML value unchanged. a set empty string overrides it.
required fields still have to pass validation. explicit zero document and quota
limits remain unlimited, and a zero token TTL disables expiry. other zero values
follow their existing application defaults and bounds.

for environment-only configuration:

```sh
export GOPHERSTORAGE_PUBLIC_URL=https://storage.example.com
export GOPHERSTORAGE_DATA_DIR=/var/lib/gopherstorage
export GOPHERSTORAGE_OIDC_ISSUER=https://id.example.com
export GOPHERSTORAGE_OIDC_CLIENT_ID=...
export GOPHERSTORAGE_OIDC_CLIENT_SECRET=...
export GOPHERSTORAGE_SESSION_SECRET=$(openssl rand -hex 32)
export GOPHERSTORAGE_OIDC_ADMIN_GROUPS='["storage-admins"]'
gopherstorage -config '' -check
gopherstorage -config ''
```

keep the session secret across restarts. the default listener is loopback, so
configure a reverse proxy or override `GOPHERSTORAGE_LISTEN` for your deployment.

## secret references

YAML string values can still reference `${VAR}` from the environment. the example
config uses names such as `GS_SESSION_SECRET` and `GS_OIDC_CLIENT_SECRET`. these
names are references chosen by that file, not direct setting keys.

a direct `GOPHERSTORAGE_` setting takes precedence over the YAML value, including
any reference in that value. referenced variables must be set for values that are
still used. substitution is literal and does not create new YAML keys.

use runtime secret files or the deployment's secret manager to supply secret
values. the NixOS module supports credential files and environment files. see
[NixOS deployment](nixos.md).
