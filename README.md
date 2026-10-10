# gopherstorage

A [remoteStorage](https://remotestorage.io) server
([draft-dejong-remotestorage-27](https://datatracker.ietf.org/doc/draft-dejong-remotestorage/)).
remoteStorage apps (built with [remoteStorage.js](https://remotestoragejs.readthedocs.io)
or any other client) keep their data in your server instead of their own.

- Users sign in with OpenID Connect, for example [Pocket ID](https://pocket-id.org).
- Apps connect with the user's address (`alice@storage.example.com`), are shown a
  consent page, and get a scoped token. Implicit grant and PKCE code flow are supported.
- Metadata (the document tree, ETags, tokens, quotas) lives in SQLite.
  Document contents go to a local directory or any S3 compatible bucket.
- The account page shows the storage address, usage, and connected apps,
  which can be disconnected. Admins can set per-user quotas.

The protocol layer is [anime.bike/remotestorage](https://github.com/elee1766/remotestorage).

## Quick start

```sh
cp config.example.yaml config.yaml   # edit it
export GS_OIDC_CLIENT_ID=... GS_OIDC_CLIENT_SECRET=... GS_SESSION_SECRET=$(openssl rand -hex 32)
go run ./cmd/gopherstorage -config config.yaml
```

Open the server, sign in, copy your address, and enter it in a remoteStorage
app (for example from <https://remotestorage.io/apps/>).

`gopherstorage -check -config config.yaml` validates a config without starting.

## Pocket ID setup

1. In Pocket ID, **OIDC Clients → Add OIDC Client**, name it `gopherstorage`.
2. Callback URL: `https://storage.example.com/auth/callback` (your `public_url` + `/auth/callback`).
   Logout callback URL (optional): `https://storage.example.com/`.
3. Keep it confidential (not public). PKCE can be on.
4. Put the client ID and secret into `GS_OIDC_CLIENT_ID` and `GS_OIDC_CLIENT_SECRET`,
   and set `oidc.issuer` to the Pocket ID URL.
5. Optional: create groups such as `storage-users` and `storage-admins` and use them
   in `allowed_groups` and `admin_groups`.

The username comes from `preferred_username`, lowercased. It must be 1-64 characters of
`a-z 0-9 . _ -`. Accounts are keyed by the OIDC subject, so renaming a user in Pocket ID
renames their storage address.

## Endpoints

| path | purpose |
| --- | --- |
| `/.well-known/webfinger` | discovery for `acct:user@host` |
| `/storage/<user>/...` | the remoteStorage API |
| `/oauth/authorize` | app authorization (implicit and PKCE) with a consent page |
| `/oauth/token` | PKCE token endpoint |
| `/` | account page |

WebFinger must be served on the host of the user address. If `public_url` is not the
apex of your domain, proxy `https://example.com/.well-known/webfinger` to gopherstorage
and keep `public_url` matching that host, or use a dedicated host such as
`storage.example.com` for both.

## Storage

Each document is a row in `meta.db` plus an immutable blob named by a random key.
Writes upload the blob first, then commit the metadata (conditions, ancestor
folder ETags, quota) in one SQLite transaction, then delete the replaced blob.
Blobs from failed or interrupted writes are recorded before upload and removed
by an hourly collector, so a crash never leaves the tree pointing at missing data.

Back up `meta.db` (SQLite online backup, `sqlite3 meta.db .backup`, or Litestream)
together with the blob directory or bucket.

## Security notes

- Tokens are random 256-bit values. Only their SHA-256 hash is stored.
- Apps are identified by the origin of their `redirect_uri` (no client registration,
  as in the spec). Plain `http` redirect URIs are only accepted for localhost.
- The consent form is bound to the user and request with an HMAC, and cross-origin
  POSTs to the UI are rejected.
- Run behind TLS. Session cookies are `Secure` when `public_url` is https.

## Development

```sh
go test ./...
# blob store and full conformance against S3:
GS_TEST_S3_ENDPOINT=http://127.0.0.1:8333 GS_TEST_S3_BUCKET=test \
GS_TEST_S3_ACCESS_KEY=... GS_TEST_S3_SECRET_KEY=... go test ./internal/...
```

`internal/storage` runs the protocol conformance suite from
`anime.bike/remotestorage/pkg/rsserver/rstest` against SQLite plus each blob backend.
