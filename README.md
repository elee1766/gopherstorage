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
- The account page shows the storage address, usage, connected apps (which can be
  disconnected), shared files and API tokens. Admins can set per-user quotas.
- A JSON account API (`/api/v1/`) does the same for scripts and CLIs, with personal
  API tokens created on the account page.

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
| `/view/<user>/<path>` | shows `/public/<path>` in browsers, for sharing and embedding |
| `/oauth/authorize` | app authorization (implicit and PKCE) with a consent page |
| `/oauth/token` | PKCE token endpoint |
| `/` | account page |
| `/api/v1/...` | account API for scripts, see below |

WebFinger must be served on the host of the user address. If `public_url` is not the
apex of your domain, proxy `https://example.com/.well-known/webfinger` to gopherstorage
and keep `public_url` matching that host, or use a dedicated host such as
`storage.example.com` for both.

## Sharing

Anything an app stores under `/public/` can be read by anyone (that is the
remoteStorage model). `/view/` presents those documents for people rather than apps:

- the stored `Content-Type`, or one derived from the file extension when an app
  stored `application/octet-stream`
- `Content-Disposition: inline` with the file name for images, audio, video, PDF and
  text; other types download (`?download` forces a download)
- `Range` requests for seeking in audio and video, `ETag` / `Last-Modified` with 304s
- CORS and `Cross-Origin-Resource-Policy: cross-origin`, so media can be embedded
  in other sites and read by `fetch`
- HTML and SVG render inside a CSP `sandbox` (no scripts, opaque origin), and all
  responses send `X-Content-Type-Options: nosniff`

Set `view.url` to a separate host (for example `share.example.com`, pointed at the
same server) to keep shared files off the account origin. The account page lists
shared documents with copyable links.

Example: `PUT /storage/alice/public/photos/cat.jpg` is shown at
`https://share.example.com/view/alice/photos/cat.jpg`.

## Account API

Create a token under "API tokens" on the account page, then:

```sh
curl -H "Authorization: Bearer gsk_..." https://storage.example.com/api/v1/account
```

| method and path | |
| --- | --- |
| `GET /api/v1/account` | address, storage root, usage, quota |
| `GET /api/v1/grants` | connected apps |
| `DELETE /api/v1/grants/{id}` | disconnect an app |
| `GET /api/v1/shared?limit=n` | documents under `/public/` with their share links |
| `GET /api/v1/tokens` | your API tokens (`current` marks the one in use) |
| `DELETE /api/v1/tokens/{id}` | delete an API token |
| `GET /api/v1/admin/users` | admins: all users |
| `PUT /api/v1/admin/users/{id}/quota` | admins: `{"quota_bytes": n}`, 0 for the default |

Errors are `{"error": "..."}` with a matching status. API tokens are separate from the
tokens apps get: they work only on `/api/v1/`, never on `/storage/`, so they cannot
read or change documents. Use a remoteStorage client such as `rscli` for files. Tokens
can only be created in the browser, so a leaked token cannot mint new ones. Admin
rights come from the OIDC groups at the user's last login.

Grant scopes describe all unexpired app tokens and pending authorization codes,
not just the latest consent. A narrower new token does not revoke older tokens.
Disconnect the app to revoke every token and pending code for that origin.
Each user may hold at most 50 personal API tokens.

## Storage

Each document is a row in `meta.db` plus an immutable blob named by a random key.
Writes upload the blob first, then commit the metadata (conditions, ancestor
folder ETags, quota) in one SQLite transaction, then delete the replaced blob.
Blobs from failed or interrupted writes are recorded before upload and removed
by an hourly collector. Collection claims a pending blob before deletion, and a
claimed upload cannot publish its metadata.

Uploads have a five-minute body read deadline. Known lengths that exceed the
user's remaining quota are rejected before staging. Streaming uploads stop at
the observed quota allowance, including the size of a document being replaced.
Concurrent in-flight uploads are not reserved against this allowance, so use
proxy concurrency limits as well as finite document and user quotas.

Back up `meta.db` (SQLite online backup, `sqlite3 meta.db .backup`, or Litestream)
together with the blob directory or bucket.

## Security notes

See the [2026-10-10 security audit](docs/security-audit-2026-10-10.md) for findings,
repairs, verification and remaining deployment risks.

- Tokens are random 256-bit values. Only their SHA-256 hash is stored.
- Apps are identified by the origin of their `redirect_uri` (no client registration,
  as in the spec). Plain `http` redirect URIs are only accepted for localhost.
- The consent form is bound to the user and request with an HMAC, and cross-origin
  POSTs to the UI are rejected.
- The account UI runs under a CSP with `script-src 'self'` and no `unsafe-eval` or
  `unsafe-inline`: htmx is configured not to eval, and Alpine is the CSP build.
  UI actions also require the `HX-Request` header. The JSON API ignores cookies.
- Run behind TLS. Session cookies are `Secure` when `public_url` is https.
- Set finite `max_document_bytes` and quotas for untrusted users. Zero remains
  unlimited. Apply request rate and concurrency limits at the reverse proxy.
- OIDC roles refresh at login. IdP offboarding does not automatically revoke
  local sessions or bearer tokens, so credential revocation is a separate step.

## Development

```sh
go test ./...
# blob store and full conformance against S3:
GS_TEST_S3_ENDPOINT=http://127.0.0.1:8333 GS_TEST_S3_BUCKET=test \
GS_TEST_S3_ACCESS_KEY=... GS_TEST_S3_SECRET_KEY=... go test ./internal/...
```

`internal/storage` runs the protocol conformance suite from
`anime.bike/remotestorage/pkg/rsserver/rstest` against SQLite plus each blob backend.

The web UI is in `internal/ui`: [templ](https://templ.guide) components rendered on the
server, [htmx](https://htmx.org) for actions (each returns the HTML fragment to swap),
and the CSP build of [Alpine.js](https://alpinejs.dev) for small client state. htmx and
Alpine are vendored in `internal/ui/static`, so there is no JS build step. After
editing a `.templ` file, regenerate the Go code (it is committed):

```sh
go generate ./internal/ui    # runs go tool templ generate
```
