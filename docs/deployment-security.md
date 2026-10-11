# Deployment security

This document describes operator controls for production deployments. It does not make public user content safe to open, and it does not protect against an attacker who can modify the host, container runtime, mounted data, or configuration.

## Network and identity

- Terminate public traffic and the OIDC provider over HTTPS. Bind the application's plain HTTP listener to loopback or a trusted private network behind a TLS-terminating proxy.
- Set `public_url` to the externally visible HTTPS origin. Configure the proxy not to cache authenticated responses and not to log authorization headers, cookies, request bodies, or OAuth callback query values.
- Default HTTP admission allows at most 128 concurrent requests and 600 requests per minute per peer IP, with a burst of 120. The request deadline, server read timeout, and write timeout are each capped at five minutes. The limiter does not trust forwarded-IP headers, so account for the proxy's address when sizing limits and configure proxy-level rate and connection controls as needed.
- Upload defaults allow eight concurrent uploads per user and reserve up to 2 GiB of aggregate in-flight staging capacity across the service. Reservations are recorded in SQLite and survive process restarts. These limits are separate from the 64 MiB default per-document maximum and 1 GiB default per-user stored-data quota. Configure finite document limits and quotas for untrusted users. A configured zero document limit or zero quota means unlimited.
- OIDC group membership is refreshed at login; removing a group does not by itself immediately disable a local account. Configure Pocket ID's Back-Channel Logout URL as `https://<public-host>/auth/backchannel-logout`. For group-removal notifications, enable group restriction on that OIDC client and select the allowed access groups. Setting its group list without enabling restriction, or setting only `oidc.allowed_groups` in this server, is not equivalent. A subject-only logout event revokes that user's sessions, app grants/tokens, and API tokens. For immediate administrator-driven offboarding, disable the account through the admin UI/API, which revokes those credentials. Sensitive admin API actions require a sign-in within the last 15 minutes.

## S3-compatible storage

Use a dedicated bucket where possible, or a unique `storage.s3.prefix` reserved for this service. Do not share the configured prefix with unrelated applications. Give the runtime identity only the object read/write/delete actions it needs under that prefix, plus `s3:ListBucketMultipartUploads` on the bucket and `s3:AbortMultipartUpload` on the service's object resources. Check the exact action/resource support of the S3-compatible provider before deployment.

The application does not change bucket lifecycle configuration. It tracks pending blob keys in metadata and, when collecting an abandoned pending blob, lists multipart uploads by that blob's canonical key and aborts only entries whose returned object key exactly matches. The pending record is retained if listing, abort, or object deletion fails. The runtime identity therefore needs multipart-list and abort permissions. When a non-empty application prefix is configured, startup probes multipart-list access under that prefix and fails with a diagnostic if the probe fails. With an empty prefix, startup skips the probe to avoid listing a shared bucket; cleanup still requires those permissions. Providers that do not implement these APIs need operator intervention and cannot safely use app-driven multipart cleanup.

Configure an operator-managed `AbortIncompleteMultipartUpload` lifecycle rule as a second line of defense, preferably scoped to this application's unique prefix. A one-day threshold is the maximum recommended age here, and a shorter threshold can interrupt slow valid writes. The rule is asynchronous and protects against process, metadata-store, credential, or provider failures that prevent application cleanup. Never have the application install or replace lifecycle rules on a shared bucket.

S3 uploads are bounded by request contexts, transport connection/header timeouts, and a finite SDK retry count. Those bounds limit duration, not provider billing or total bucket capacity. Monitor incomplete multipart storage and failed cleanup logs.

## Container and host

The Compose build uses the sibling `../remotestorage` checkout as a named BuildKit context for the local Go module replacement. The Dockerfile copies only its `go.mod`, `go.sum`, and `pkg/` source into the builder, not the sibling checkout's Git history or other files. Keep that checkout available at the expected path when building with Compose. Docker Compose 2.17 or later is required for `additional_contexts`.

The Compose example binds port 8080 to loopback only. Put it behind a trusted TLS proxy. The runtime image uses the nonroot account, read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, and a restricted temporary filesystem. The builder and runtime image references are pinned to OCI index digests. Review and refresh those pins as part of routine updates, then rebuild and scan the resulting image in CI or your registry. A digest pin makes an image reference immutable, not vulnerability-free.

The Compose bind mount `./data:/var/lib/gopherstorage` contains SQLite metadata and filesystem blobs when that backend is selected. Restrict host access to this directory and configuration, including S3 and OIDC credentials. Ensure the mounted data directory is writable by the image's nonroot runtime UID (UID 65532 for the pinned distroless nonroot image). Do not make it world-writable. The container's read-only root filesystem does not make mounted volumes read-only.

## Backups and recovery

Gopherstorage does not provide backup or restore commands. Maintain operator-managed backups of metadata, blobs and deployment configuration using procedures appropriate to the selected backend. Plan for a consistent snapshot, restrict access to backup data, and store secrets separately under the operator's secret-management process. Test restoration independently of the application.

## Vendored JavaScript and supply chain

Run `./scripts/supply-chain-check.sh` to install the exact locked npm package tarballs in a temporary directory, compare their distributed browser bundles byte-for-byte with the checked-in files, and run `npm audit` over the locked dependency tree. Update the manifest and lockfile deliberately, review npm audit output, refresh the vendored files from those exact package versions, and review the upstream release notes before changing the static assets.

This check depends on npm registry availability and advisory data. A clean audit is not proof that packages are benign, that no undisclosed vulnerability exists, or that browser-executed public content is safe. Container image vulnerability scanning is not performed by this script.
