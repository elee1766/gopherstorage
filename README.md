# gopherstorage

A self-hosted file storage server. Files live on a local filesystem or in any
S3 compatible bucket. Users sign in through an OpenID Connect provider such as
[Pocket ID](https://pocket-id.org).

- Filesystem and S3 backends behind one interface, mixed freely.
- Mounts with read and write rules by user, email, subject or OIDC group.
- Per-user mounts (`users/{username}`) give each user a private directory.
- Web UI for browsing, upload (including drag and drop), folders, rename and delete.
- JSON/HTTP API usable from scripts with a bearer token.
- Single static binary, config in one YAML file, no database.

## Quick start

```sh
cp config.example.yaml config.yaml   # then edit it
export GS_OIDC_CLIENT_ID=... GS_OIDC_CLIENT_SECRET=... GS_SESSION_SECRET=$(openssl rand -hex 32)
go run ./cmd/gopherstorage -config config.yaml
```

`gopherstorage -check -config config.yaml` validates a config without starting.

With Docker: `docker compose up -d` (see `docker-compose.yml`).

## Pocket ID setup

1. In Pocket ID, go to **OIDC Clients → Add OIDC Client**.
2. Name it `gopherstorage` and set the callback URL to
   `https://files.example.com/auth/callback` (your `public_url` plus `/auth/callback`).
   Optionally add `https://files.example.com/` as a logout callback URL.
3. Keep it a confidential (non-public) client. PKCE can be on; gopherstorage always sends it.
4. Copy the client ID and secret into `GS_OIDC_CLIENT_ID` and `GS_OIDC_CLIENT_SECRET`.
5. Set `oidc.issuer` to your Pocket ID URL (its `APP_URL`).
6. Create user groups in Pocket ID (for example `storage-admins`) and reference
   them in `admin_groups`, `allowed_groups` or `group:` mount rules.

You can also restrict the client to specific groups in Pocket ID with
"Allowed user groups". `oidc.allowed_groups` does the same check on the
gopherstorage side.

Other providers (Authelia, Authentik, Keycloak, Zitadel, ...) work the same way.
Adjust `username_claim` and `groups_claim` if they use different claim names.

## Configuration

See [`config.example.yaml`](config.example.yaml) for every option.

### Backends

| type | notes |
| --- | --- |
| `filesystem` | All access goes through `os.Root`, so symlinks cannot escape `path`. Writes go to a temp file and are renamed into place. |
| `s3` | Uses `aws-sdk-go-v2`. Leave `endpoint` empty for AWS S3, set it for other providers. Directories are key prefixes. Empty folders are stored as zero byte `dir/` marker objects. Moving a directory is copy then delete, so it is not atomic. Set `path_style: true` for most self-hosted servers. |

The S3 backend is tested against SeaweedFS, RustFS and VersityGW.

### Access rules

Each mount has `read` and `write` rule lists. Rules are `*`, `user:<name>`,
`email:<addr>`, `sub:<id>` or `group:<name>`. Write implies read. Members of
`oidc.admin_groups` can access every mount. Mounts a user cannot read are
hidden from them.

## API

Authenticate with the session cookie (web UI) or `Authorization: Bearer <token>`.
Bearer tokens must be JWTs signed by the issuer with the client ID in their
audience. Pocket ID ID tokens and access tokens issued to this client both work.

| request | effect |
| --- | --- |
| `GET /api/me` | Current user and visible mounts. |
| `GET /api/files/{mount}/{path}` | Directory: JSON listing. File: contents (supports `Range`). `?download` sets attachment disposition, `?stat` returns metadata. |
| `PUT /api/files/{mount}/{path}` | Upload the request body. Parent folders are created. `?overwrite=false` refuses to replace. |
| `POST /api/files/{mount}/{path}?op=mkdir` | Create a folder. |
| `POST /api/files/{mount}/{path}?op=move` | Body `{"to": "new/path"}`. Moves within the mount. |
| `DELETE /api/files/{mount}/{path}` | Delete a file or empty folder. `?recursive=true` deletes a folder tree. |

```sh
TOKEN=...   # an ID or access token from your provider for this client
curl -H "Authorization: Bearer $TOKEN" -T report.pdf https://files.example.com/api/files/home/reports/report.pdf
curl -H "Authorization: Bearer $TOKEN" https://files.example.com/api/files/home/reports
```

Errors are JSON: `{"error": "..."}` with status 400, 401, 403, 404, 409 or 413.

## Security notes

- Session cookies are AES-GCM encrypted with a key derived from `session.secret`,
  `HttpOnly`, `SameSite=Lax`, and `Secure` when `public_url` is https.
- Cross-origin state changing requests are rejected (`http.CrossOriginProtection`).
- Files are served with `Content-Security-Policy: sandbox`, so an uploaded HTML
  file cannot run scripts with access to the app.
- Changing `session.secret` signs everyone out.
- Run behind a TLS terminating reverse proxy in production.

## Development

```sh
go test ./...
# S3 conformance against a real server:
GS_TEST_S3_ENDPOINT=http://127.0.0.1:8333 GS_TEST_S3_BUCKET=test \
GS_TEST_S3_ACCESS_KEY=... GS_TEST_S3_SECRET_KEY=... go test ./internal/storage
```
