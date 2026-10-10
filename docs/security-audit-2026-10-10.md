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

No new full Pocket ID browser-login run was performed during this audit. HTTP integration and provider-logout response checks do not replace an end-to-end login test in each deployment.

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

## Remaining deployment and design risks

1. **TLS is an operator requirement.** Run the public endpoint and OIDC provider over HTTPS. Keep the plain HTTP listener behind a trusted proxy or on loopback. `Secure` cookies depend on `public_url` being HTTPS. Do not allow a proxy to cache authenticated responses or log token-bearing headers, bodies or OAuth callback parameters.
2. **Zero limits remain unlimited.** `max_document_bytes: 0` and a zero effective quota retain their documented meaning. Set finite limits for untrusted users. Per-request upload ceilings do not reserve capacity across concurrent in-flight uploads, and quotas count document bytes rather than metadata, filesystem overhead or S3 multipart state. Use proxy concurrency/rate limits, storage capacity alarms and an S3 lifecycle rule for abandoned multipart uploads.
3. **Offboarding is not automatic.** OIDC group membership is checked at login, not on every request. Removing a user from Pocket ID does not instantly invalidate existing local session cookies or app/API tokens. Revoke credentials as part of offboarding. Stateless sessions cannot be revoked individually after theft, and logout clears the browser cookie rather than every copy of it. Session-secret rotation invalidates all sealed sessions.
4. **Implicit OAuth remains for remoteStorage compatibility.** Prefer S256 PKCE where supported. Public-client identification is by redirect origin rather than registration. The displayed origin is the identity the user is approving, not a verified publisher name. Previously issued tokens keep their scopes until expiry or explicit revocation.
5. **Public means public.** Anything in `/public/` is anonymously readable. Removing app access does not unpublish files. Use a separate `view.url` host to reduce coupling with the account origin. HTML/SVG sandboxing, CSP and MIME checks do not replace browser security updates or malware scanning. PDFs and other downloadable media can still be hostile content.
6. **Network cancellation is not a complete resource policy.** Inbound reads and cleanup are bounded, but OIDC/S3/provider operations also depend on downstream networking and proxy timeouts. Slow consumers, many requests and very large folder listings require deployment-level controls.
7. **Local data and configuration are trusted.** Protect the session secret, OIDC/S3 credentials, metadata database and blob directory. A local attacker who can modify those files is outside the isolation provided by API scopes and `os.Root`. SQLite metadata and blobs must be backed up consistently.
8. **No exhaustive supply-chain audit.** `govulncheck` covers the Go advisory database and static reachability. The vendored htmx and Alpine bundles were inspected for their configured use, but this is not a transitive JavaScript or container-image vulnerability scan. Development examples such as `cmd/myrs` are not a production authentication service and were not treated as the deployed authorization server.

## References

- OAuth security best current practice: <https://www.rfc-editor.org/rfc/rfc9700.html>
- Native-app loopback redirects: <https://www.rfc-editor.org/rfc/rfc8252.html>
- Go cross-origin protection implementation: <https://go.dev/src/net/http/csrf.go>
- Go vulnerability scanning: <https://go.dev/doc/security/vuln/>
- Dependency advisories: <https://pkg.go.dev/vuln/GO-2026-5970>, <https://pkg.go.dev/vuln/GO-2026-6629>
