# Security audit: 2026-10-10

## Scope and method

Reviewed `gopherstorage` at `a76bb09` and `anime.bike/remotestorage` at `532de1c`, including the templ/htmx/Alpine UI, account API, OIDC login, OAuth authorization server, remoteStorage handler, CLI, SQLite metadata, filesystem blobs, S3 blobs and garbage collection.

This was a source audit with focused regressions and dependency scanning, not an external penetration test or a guarantee that no vulnerabilities remain. Findings below describe the pre-audit code. Severity assumes an Internet-facing deployment with untrusted users or remoteStorage apps. Local CLI findings require a login listener to be running.

## Confirmed findings and repairs

| ID | Severity | Finding | Repair |
| --- | --- | --- | --- |
| A1 | Medium | The UI trusted the admin flag in a sealed session after the database role had changed. An old admin cookie could still list users and set quotas. | UI authorization and account rendering use the current database role, like the account API. |
| A2 | Medium | CLI OAuth callbacks listened on every interface. The implicit flow had no state binding and accepted bearer tokens from GET query parameters. Unsolicited callbacks could supply credentials, interrupt login or leave handlers blocked on unbuffered channels. | Loopback-only listeners are opened before the browser. Both flows validate state before accepting results, reject unrelated requests and use bounded, nonblocking result delivery. Implicit credentials travel in a bounded POST body. |
| A3 | Medium | The CLI implicit callback page inserted untrusted fragment/error data with `innerHTML` and printed token-bearing data to the console. | Static HTML and `textContent` replace HTML interpolation. Token debugging is removed. |
| A4 | Medium | Every authenticated storage request launched a detached grant-update goroutine. A valid app token could create an unbounded queue behind SQLite's single writer, even after requests ended. | Grant bookkeeping runs synchronously with the request context. |
| A5 | Medium | Upload quota checks occurred after the complete blob was staged. A user with a small quota could repeatedly stage much larger bodies, consuming temporary disk/S3 capacity. Request bodies also had no transport deadline. | Known over-quota lengths fail before upload. Streaming bodies stop at the observed allowance, including replacement credit. Failed uploads are cleaned up. The server has a five-minute body read deadline. |
| A6 | Medium | S3 multipart buffer sizing trusted the claimed object length without a memory ceiling. Large lengths could trigger huge allocations when configured document/quota limits allowed them. The small-object overflow probe ignored reader errors and could report a truncated upload as successful. | Multipart allocation is bounded and excessive known sizes are rejected. Non-EOF reader errors propagate. Multipart aborts have a cleanup deadline. |
| A7 | Low | GC selected pending uploads without claiming them. If an upload exceeded the grace period, collection could race publication and delete a blob referenced by a newly committed node. | Collection claims pending blobs in a writer transaction. Publication must consume an unclaimed upload entry in its own transaction. A claimed upload cannot publish. |
| A8 | Low | GET logout allowed a third-party navigation to clear a user's session. An OIDC callback with the wrong state also deleted the legitimate login-flow cookie. | Logout is POST-only behind cross-origin protection. Invalid-state callbacks leave the existing flow intact. |
| A9 | Low | Reconsent overwrote the displayed grant scope, while older tokens retained their previously authorized scopes. The account page could understate an app's access. | Grant lists show the union of scopes from unexpired tokens and pending codes. New narrower tokens remain narrow. Disconnecting the app revokes all its credentials. |
| A10 | Low | The UI's token-count check and token insert were separate transactions. Concurrent requests could exceed the 50-token limit. Expired personal tokens were never pruned. | The count and insertion share a writer transaction. Creation and periodic maintenance prune expired personal tokens. |

A1 does not mean that removing an IdP group immediately changes the local database. The role still refreshes at the next successful OIDC login. The repair ensures an old cookie cannot override a role that has already been refreshed locally.

A9 is a permission-display bug, not proof that reconsent grants unauthorized access. Old tokens had genuinely received the broader consent. Narrower reconsent does not silently revoke them.

### Additional hardening

- Private documents and authenticated folder listings use private cache directives. Anonymous public documents remain publicly cacheable.
- The UI disables htmx history caching and excludes sensitive account content from history snapshots.
- Control-plane request bodies are capped at 64 KiB without applying that limit to document uploads.
- Expiry checks reject credentials at the expiration boundary.
- The library's `golang.org/x/text` dependency was raised from v0.23.0 to v0.41.0. The initial scan reported GO-2026-5970 and GO-2026-6629 only at package/module level, with no reachable vulnerable symbols. This is dependency hardening, not evidence of a reachable application exploit.

## Verification

Passed on the coordinated changes:

- `go test -race ./...`, `go vet ./...`, `go build ./...` and `git diff --check` in both repositories.
- `govulncheck ./...` in both repositories: no vulnerabilities found after the dependency update, including no remaining package/module advisory results.
- `TestS3Store` and `TestConformanceS3` against a real loopback VersityGW endpoint. This covers single-part and multipart objects, unknown lengths, ranges, paths, scopes, isolation and post-run blob collection. SeaweedFS and RustFS were not rerun during this audit.
- Existing filesystem, protocol, account UI/API and public-view tests, including the strict document/browser headers.
- `TestAccountUIAndAPI`: stale admin denial, POST-only logout, bounded forms, live-scope aggregation and expiry, pending-code redemption, atomic token cap and deletion/expiry freeing capacity. `TestCallbackBadStateKeepsFlowCookie` covers OIDC flow preservation. `TestLogoutPreservesProviderLogoutWithoutExternalFormRedirect` covers JS and non-JS provider logout.
- `TestQuotaStopsStreamingAtAvailableBytes` and `TestGCClaimPreventsPublishingAgedPendingBlob`: real SQLite/filesystem regressions. The pre-fix implementations respectively consumed the entire 10-byte body instead of stopping at quota plus one byte and allowed publication after collection selection. Both repaired paths pass.
- A scratch replay of the original CLI implicit login accepted a query-string token from an unsolicited POST and returned HTTP 200. The retained callback regression rejects query tokens, wrong/missing state, oversized bodies and untrusted hosts while accepting a valid bounded POST. The replay used a different loopback port because port 8765 was occupied.
- A scratch S3 overlay restoring only the old ignored-reader-error probe failed the live test with a nil error instead of the injected reader failure. The repaired source passed immediately afterward. Typed size rejection and absence of an object after a failed read are also checked.

These are behavior regressions, not provider mocks. Temporary baseline reproductions stay outside the repositories and are not committed. No scaffolding tests were added to either final checkout.

The first audit pass did not repeat a full Pocket ID browser login. The follow-up below includes a new real-provider browser run. Each deployment must still validate its own provider and proxy configuration.

### Source map

- A1: `internal/server/ui.go` (`uiHandler`, `accountView`).
- A2/A3: library `cmd/rscli/main.go` (`pkceLogin`, `implicitLogin`, `implicitCallbackHandler`).
- A4: `internal/server/server.go` (`authenticate`).
- A5: `internal/storage/storage.go` (`Put`, `countingHasher.Read`) and `cmd/gopherstorage/main.go`.
- A6: `internal/blob/s3.go` (`Put`).
- A7: `internal/meta/nodes.go` (`CollectableBlobs`, `PutDocument`).
- A8: `internal/auth/auth.go` (`Callback`, `Logout`) and logout routing in `internal/server/server.go`.
- A9: `internal/meta/oauth.go` (`ListGrants`).
- A10: `internal/meta/apitokens.go` (`CreateAPIToken`) and `internal/meta/oauth.go` (`PruneExpired`).

## Follow-up: closure of actionable residuals

The follow-up starts from server `e9e75ad` and library `251b2c5`. The original findings above remain a record of the first audit. The following implementation changes address its remaining controllable risks.

| Original residual | Follow-up control |
| --- | --- |
| TLS and proxy exposure | Configuration rejects non-loopback plaintext public/OIDC/view URLs unless development is explicitly opted in. The default listener is loopback. Request hosts are allowlisted, HTTPS origins receive HSTS, and sensitive responses default to no-store. Compose exposes only a loopback port. |
| Unlimited and concurrent resource use | Omitted document/quota settings now default to 64 MiB and 1 GiB. Explicit zero preserves the documented opt-in. SQLite reserves upload capacity before any body read, prevents duplicate replacement credit, tracks orphan debt, and retains reservations when cleanup fails. Staging, upload slots, nodes, folder children and paths have finite limits. |
| Stateless sessions and offboarding | Browser sessions have hashed server-side identifiers, expiry and bounded counts. Logout invalidates copied cookies. Account disable atomically revokes sessions, grants, codes, app tokens and personal tokens, blocks login and hides anonymous content. Signed OIDC back-channel logout supports provider-driven revocation. Admin operations require an OIDC login within 15 minutes. Credential-reset API endpoints are available for users and administrators. |
| Implicit OAuth | S256 PKCE is the default. Fragment-based implicit authorization requires an explicit `tokens.allow_implicit` opt-in. Consent identifies the redirect origin as an unverified publisher and explains retained older scopes. Session, grant, token and pending-code counts are bounded transactionally. |
| Public-content exposure | Active formats and PDFs download on the account origin by default. A separate view origin supports sandboxed inline rendering. Same-origin active rendering requires an explicit opt-in. The UI and account API can unpublish individual public files. |
| Networking and slow consumers | Global request concurrency, peer-IP rates, bounded rate-key state, request contexts, write/read/header deadlines and header size are enforced. OIDC and S3 use finite downstream operations. S3 collection aborts abandoned multipart uploads for the exact tracked object key without changing shared bucket policies. |
| Local files and backup consistency | Dedicated data paths, owner-only metadata/blobs and non-writable configuration requirements reduce accidental exposure. Filesystem staging uses the pending blob key, so crash GC can locate partial bytes. A bounded migration cleanup handles aged legacy temporary names. The offline backup command shares an exclusive data-directory lock with the server, snapshots SQLite and copies referenced blobs into an atomically published destination. Credentials are scrubbed from snapshots by default, with secure deletion and compaction of the copied database, to avoid both revocation rollback and recovery from free pages. |
| Supply-chain gaps | The vendored browser bundles have an exact npm manifest/lockfile, byte comparison against locked tarballs and an advisory scan command. Builder/runtime container references are digest-pinned. Build contexts exclude local secrets, and the runtime drops capabilities, disallows privilege escalation and uses a read-only root filesystem. |

See `docs/storage-limits.md`, `docs/backup.md` and `docs/deployment-security.md` for limits, migration recovery and operation of these controls. Starting an upgraded server invalidates old stateless browser cookies. Existing explicitly configured unlimited quotas, nonexpiring tokens and legacy-flow opt-ins remain operator choices, not hidden defaults.

### Follow-up verification

- The pre-fix server accepted a remote plain-HTTP configuration and retained an actual subprocess-interrupted filesystem upload after GC deletion. Both reproductions fail against the archived baseline and pass with the repairs.
- A pre-fix real SQLite/filesystem concurrent-upload reproduction accepted a second full body instead of rejecting it before reading. The repaired cross-Store reservation test passes under the race detector.
- Real SQLite/filesystem checks cover copied-cookie revocation, disabled-account denial, atomic credential caps, quota/staging reservations, cancellation, restart GC, orphan debt, folder bounds and portable snapshots. Backup coverage includes identical-content replacement, truncated source rejection and credential scrubbing without changing the live database.
- Both repositories passed `go test -race ./...`, `go vet ./...`, `go build ./...`, `govulncheck ./...` and `git diff --check`. The follow-up scans reported no vulnerabilities.
- Chromium with a real Pocket ID 2.18 instance completed OIDC login, S256 consent and code redemption. The live checks verified cookie-only API denial, HTML/PDF upload and same-origin attachment policy, UI unpublication followed by a 404, and rejection of a copied browser cookie after local logout.
- A real Pocket ID group-restricted client emitted a signed subject-level back-channel notification after the test user lost its allowed group. The callback returned 200. Before removal, the fresh app token could write private storage, the API token returned 200 and the browser session was authenticated. Afterward, all three credentials returned 401 and the sessions, grants, tokens, codes and API-token tables were empty. This used host networking for the isolated provider to avoid the machine's Docker-bridge-to-host routing restriction, with the canonical application Host preserved.
- The final server race suite was rerun with live VersityGW S3 tests enabled. `TestS3Store` and `TestConformanceS3` passed, including exact-key abandoned-multipart cleanup and neighboring-object isolation.
- `./scripts/supply-chain-check.sh` confirmed byte-for-byte matches against the locked npm packages and reported zero known npm vulnerabilities.
- `docker compose build --no-cache gopherstorage` and Compose configuration validation passed with the restricted build contexts. After the last source changes, the image was rebuilt and scanned from its Docker archive using Grype 0.120.1 with database v6.1.10, built October 10, 2026 at 06:30:01 UTC. The result was zero matches. Scanned image configuration digest: `sha256:87226e93de728da3dccdd2b4e77da2a4c48ec7da10ec7f8d81061e3fe136d856` (Docker image index `sha256:21bb09e7732ad29822a2c10e8773be6c06c45baba2ee946e61c7b7fb833a7e11`).
- The real offline `-backup` command produced a private final snapshot with two referenced blobs. Both matched the live store byte-for-byte, and the snapshot's sessions, API tokens, OAuth tokens, codes, grants and logout-replay tables were empty. The manifest reported `credentials_included:false`. The live database retained its accepted logout replay marker while the copied snapshot scrubbed it.
- A scratch overlay restoring the old WebFinger background-context lookup returned 200 for a canceled request and failed the retained real-handler assertion. The repaired resolver passes the request context into SQLite and the full race suite passes. Scratch-only baseline reproductions and browser scripts are outside the repositories, with no scaffolding tests committed.

## Operating assumptions that code cannot eliminate

These are not open implementation findings:

1. The proxy must terminate TLS and preserve the configured Host. Forwarded-IP headers are deliberately not trusted. Multiple clients behind one peer share its rate budget unless the proxy supplies its own per-user policy. Do not log credentials or cache authenticated responses outside the application.
2. Capacity alarms, backup retention and an operator-managed S3 incomplete-multipart lifecycle rule remain necessary for service outages and provider billing. Reservations bound temporary application work, not the sum of all users' permanent quotas, filesystem overhead or externally written objects. Unknown legacy pending capacity fails closed until collection succeeds.
3. Provider-driven revocation depends on a configured, reachable back-channel endpoint and a provider that emits the relevant notification. The local disable API provides immediate application-side offboarding. No relying party can infer an undelivered external identity change. Requests already transmitting bytes cannot retrieve them from a client.
4. Public data can be copied before unpublication, and downloads can contain hostile content. Sandboxing and attachment defaults are not malware scanning or browser patching. Deleting a public document does not erase downloaded or externally cached copies.
5. An attacker who controls the host, database, mounted data, secret files or trusted identity/storage provider is outside API-scope isolation. Offline snapshots are not encrypted and must be protected. Explicitly retaining credentials in a snapshot can resurrect them on restore.
6. Advisory and image scans are time-bounded checks of known vulnerabilities. Pinning versions does not prove that dependencies are benign or that undisclosed defects do not exist. Development examples are not the deployed authorization server.

## References

- OAuth security best current practice: <https://www.rfc-editor.org/rfc/rfc9700.html>
- Native-app loopback redirects: <https://www.rfc-editor.org/rfc/rfc8252.html>
- Go cross-origin protection implementation: <https://go.dev/src/net/http/csrf.go>
- Go vulnerability scanning: <https://go.dev/doc/security/vuln/>
- OIDC back-channel logout, including logout-token validation: <https://openid.net/specs/openid-connect-backchannel-1_0.html>
- AWS SDK retry and operation timeout configuration: <https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-retries-timeouts.html>
- AWS SDK HTTP transport configuration: <https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-http.html>
- Dependency advisories: <https://pkg.go.dev/vuln/GO-2026-5970>, <https://pkg.go.dev/vuln/GO-2026-6629>
