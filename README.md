# gopherstorage

this is a self-hosted [remoteStorage](https://remotestorage.io) server, built on
[anime.bike/remotestorage](https://github.com/elee1766/remotestorage).

targets draft-dejong-remotestorage-27, including the optional PKCE auth code flow.

users sign in with OpenID Connect. apps connect using a storage address like
`alice@storage.example.com` and get access to the modules the user approves.
metadata lives in SQLite, and document contents go to the filesystem or an S3
compatible bucket.

## running

```sh
cp config.example.yaml config.yaml
# edit the public URL, OIDC issuer and storage settings
export GS_OIDC_CLIENT_ID=... GS_OIDC_CLIENT_SECRET=...
export GS_SESSION_SECRET=$(openssl rand -hex 32)
go run ./cmd/gopherstorage -config config.yaml
```

keep the session secret across restarts. the local module replacement requires a
sibling `../remotestorage` checkout.

open `/account`, sign in, and enter your storage address in a remoteStorage app.
`gopherstorage -check -config config.yaml` validates the config without starting
the server. settings are documented in [config.example.yaml](config.example.yaml).

koanf also loads direct environment keys such as `GOPHERSTORAGE_PUBLIC_URL` and
`GOPHERSTORAGE_STORAGE_S3_BUCKET`, which override YAML. use `-config ''` for
environment-only configuration. see [configuration](docs/configuration.md) for
key names, types and secret references.

HTTPS is required outside loopback unless `allow_insecure_http` is explicitly
set for development. the default listener is `127.0.0.1:8080`. serve webfinger on
the host used in storage addresses.

for Nix builds, run `nix build .#gopherstorage`. the flake also provides a NixOS
module with `services.gopherstorage.settings` and runtime secret files. see
[Nix and NixOS](docs/nixos.md).

for containers, compose supplies the sibling library as a named build context.
to build directly:

```sh
docker build --build-context remotestorage=../remotestorage -t gopherstorage .
```

## oidc

[Pocket ID](https://pocket-id.org) works as the login provider. create a
confidential OIDC client with these URLs, using your `public_url`:

- callback: `https://storage.example.com/auth/callback`
- logout callback: `https://storage.example.com/`
- back-channel logout: `https://storage.example.com/auth/backchannel-logout`

set `oidc.issuer` and supply the client ID and secret through the environment.
`allowed_groups` limits who can log in, and `admin_groups` selects administrators.
for Pocket ID to send logout notifications when access is removed, also enable
group restriction on the client and select its allowed groups.

accounts are keyed by OIDC subject. storage names come from `preferred_username`,
lowercased, with 1-64 characters from `a-z 0-9 . _ -`. renaming a user changes
their storage address.

local logout revokes the browser session. subject-level back-channel logout and
account disable revoke browser sessions, app credentials and personal API tokens.
administrator operations require an OIDC login within the last 15 minutes.

## account

`/account` shows the storage address, usage, connected apps, shared files and API
tokens. users can disconnect apps and unpublish shared files. administrators can
set quotas and disable accounts.

apps use S256 PKCE by default. the legacy implicit flow requires
`tokens.allow_implicit: true`. approving narrower access does not revoke an app's
older tokens. disconnecting the app revokes its tokens and pending codes.

`/api/v1/` provides account operations for scripts. create a personal API token
on the account page:

```sh
curl -H "Authorization: Bearer gsk_..." https://storage.example.com/api/v1/account
```

- `/api/v1/account` - address, usage and quota
- `/api/v1/grants` - list apps, `DELETE /{id}` to disconnect
- `/api/v1/shared` - list public files, `DELETE ?path=/public/...` to unpublish
- `/api/v1/tokens` - list API tokens, `DELETE /{id}` to revoke
- `/api/v1/admin/users` - list users, `PUT /{id}/quota` or `PUT /{id}/access` to update
- `DELETE /api/v1/admin/users/{id}/credentials` - revoke a user's credentials
- `DELETE /api/v1/account/credentials` - revoke your own credentials

quota updates accept `{"quota_bytes": n}`, with 0 selecting the default. access
updates accept `{"disabled": true}` or `false`. errors use `{"error": "..."}`.

personal API tokens only work on the account API, not the storage protocol. they
cannot read or write document contents or create more tokens, but can unpublish
public files. use a remoteStorage client for file operations.

## sharing

documents under `/public/` are anonymously readable. `/view/<user>/<path>` serves
the corresponding public document for sharing and embedding, with range requests
and conditional reads.

active formats and PDFs download by default on the account origin. set `view.url`
to a separate host for sandboxed inline rendering. HTML and SVG use a sandbox CSP,
and responses use `nosniff`. `?download` forces a download.

unpublishing deletes the public document, not copies someone already downloaded.
disabled accounts lose anonymous public access as well.

## storage

writes stage an immutable blob, then commit the document tree, ETags and quota in
a SQLite transaction. interrupted uploads and replaced blobs are tracked for
garbage collection.

uploads reserve capacity before reading the body. defaults are 64 MiB per
document, 1 GiB per user, eight uploads per user and 2 GiB of global staging.
metadata and folder listings are bounded too. see
[storage limits](docs/storage-limits.md) for configuration and recovery behavior.

`pkg/blob` defines the shared storage interface. implementations live in
`pkg/blob/filesystem` and `pkg/blob/s3`. both constructors accept
`blob.WithSharder(func(string) string)` to choose a layout. the default is
`ab/cd/<key>`. callbacks must return canonical relative paths ending in the
unchanged key, be deterministic and safe for concurrent calls. `tmp/` is reserved.
this is a Go constructor option, not YAML configuration. changing the function
does not move existing blobs.

stop the daemon before an import:

```sh
gopherstorage -config config.yaml -import /srv/migration/alice \
  -import-user alice -import-prefix /photos/ -import-dry-run
```

imports stream into an existing account through the storage layer. existing
documents are skipped so runs can resume. remove `-import-dry-run` to copy files.
replacement and public publication require explicit flags. see
[bulk import](docs/import.md).

## packages

- `pkg/auth` - OIDC login, browser sessions and back-channel logout
- `pkg/oauth` - app consent and scoped remoteStorage credentials
- `pkg/meta` - SQLite metadata, migrations and capacity reservations
- `pkg/blob` - shared blob interface and layout options
- `pkg/blob/filesystem`, `pkg/blob/s3` - blob backends
- `pkg/storage` - remoteStorage backend over metadata and blobs
- `pkg/server` - discovery, storage, sharing and account routes
- `pkg/ui` - templ components, htmx actions and CSP Alpine.js
- `pkg/config` - koanf configuration from YAML and environment keys
- `pkg/gopherstorage` - reusable daemon, configuration check and offline import runner
- `pkg/importer` - offline migration
- `cmd/gopherstorage` - signal-aware executable shim

## development

```sh
go test ./...
go generate ./pkg/ui
./scripts/supply-chain-check.sh
```

templ output is committed. htmx and Alpine are vendored, so there is no JS build
step. `pkg/storage` runs the library's black-box protocol conformance suite against
SQLite and the blob backends. to include S3 tests:

```sh
GS_TEST_S3_ENDPOINT=http://127.0.0.1:8333 GS_TEST_S3_BUCKET=test \
GS_TEST_S3_ACCESS_KEY=... GS_TEST_S3_SECRET_KEY=... go test ./pkg/...
```

see [deployment security](docs/deployment-security.md), the
[security audit](docs/security-audit-2026-10-10.md) and
[performance notes](docs/performance-notes.md) for operational constraints and
verification details.
