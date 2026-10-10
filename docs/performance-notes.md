# Performance review

These are code-level candidates, not measured bottlenecks. No performance changes
were made as part of the backend/sharding refactor. Benchmark representative
small-document sync traffic, concurrent uploads, and large/range downloads before
claiming a speedup.

## 1. Avoid unnecessary grant activity write transactions

`pkg/server/server.go` calls `TouchGrant` on every authenticated storage request.
`pkg/meta/oauth.go` limits updates to once per minute in SQL, but still opens an
immediate write transaction for every call. These transactions share the single
writer with document publication, upload reservations, and credential changes.

Return `last_used_at` in the existing token lookup join and skip the touch when it
is recent, keeping the conditional SQL update for races. Do not cache token
validity, user enabled state, or permissions: revocation must remain immediate.
The API token lookup already gates its activity update using its selected timestamp.

Measure concurrent authenticated GET latency and write-pool wait time. Expect a
benefit for read-heavy sync workloads, not necessarily for a lightly used server.

## 2. Retain more idle S3 connections

The transport in `pkg/blob/s3/s3.go` sets the global idle connection limit but not
`MaxIdleConnsPerHost`. Go's default is two idle connections per host. That is an
idle-retention limit, not a limit on active requests.

Set an explicit, bounded per-host idle limit appropriate to upload/request
concurrency. This can reduce connection and TLS setup churn for bursty HTTP/1.1
S3 traffic. HTTP/2 multiplexing and workloads that close partially consumed range
responses change the benefit, so benchmark the actual S3-compatible service.
Keep the existing downstream deadlines and retry bounds.

## 3. Reduce buffers for small unknown-length S3 uploads

The S3 upload path allocates an initial 16 MiB buffer when the incoming length is
unknown, even when the document ends after a few bytes. Known small documents
already allocate only their announced size.

Grow the first buffer from a smaller probe up to the multipart part size, rather
than allocating the full part immediately. Preserve single-object retries,
reader-error propagation, one-byte overflow checks, multipart size requirements,
and the existing maximum buffer/object limits. A pool that permanently retains
many large buffers is not automatically an improvement.

Measure allocations and peak heap during concurrent small unknown-length writes.

## 4. Preserve the HTTP streaming fast path through request logging

The `statusWriter` in `pkg/server/server.go` wraps `http.ResponseWriter` for
logging, but does not implement `io.ReaderFrom`. `io.CopyN` used by Go's
`http.ServeContent` cannot discover the underlying response writer's `ReadFrom`
through this wrapper. `Unwrap` supports response control but does not provide
that interface forwarding for `io.Copy`.

Add a `ReadFrom` implementation that preserves status tracking, delegates when
the underlying writer supports it, and uses a nonrecursive fallback otherwise.
This can expose the HTTP server's optimized file-transfer path. It is not a
promise of zero-copy under TLS, arbitrary readers, or every platform.

Measure CPU and allocations for large filesystem downloads and validate ranges,
HEAD, conditional responses, errors, and logged status codes.

## Deferred tuning

- Bound and size SQLite's read pool based on measured concurrency and `DB.Stats`.
  The current writer remains a single connection. Do not add writers expecting
  WAL to permit simultaneous SQLite write transactions.
- Do not add an authorization cache, unbounded upload parallelism, or weaker
  durability settings merely to improve a benchmark.
- The backend subpackage split and injectable sharding enable independent
  implementations. They are organization/extension changes, not measured speedups.

The Go 1.27.2 `net/http` transport/server source and `io` copy implementation were
checked directly for the connection defaults and streaming behavior above.
