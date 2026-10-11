# Storage limits and recovery

The storage limits apply before an upload body is read where its length is known, and while streaming when it is unknown. SQLite reservations are serialized across connections and processes.

## Defaults

| setting | default | zero behavior |
| --- | ---: | --- |
| `storage.max_document_bytes` | 64 MiB | unlimited document size |
| `storage.default_quota_bytes` | 1 GiB per user | unlimited user quota |
| `storage.max_concurrent_uploads` | 8 per user | uses the safe default |
| `storage.max_staging_bytes` | 2 GiB globally | uses the safe default |
| `storage.max_nodes` | 100,000 per user | uses the safe default |
| `storage.max_folder_children` | 10,000 | uses the safe default |

The configuration loader supplies these defaults when settings are omitted. A directly constructed storage service also receives finite concurrency, staging, and metadata defaults. Its `MaxDocumentBytes` and effective quota retain zero-as-unlimited semantics.

The metadata tree additionally limits paths to 4,096 bytes and 64 levels. The folder-child limit is checked on writes and listings. Listings return an error rather than a partial result. Replacing an existing document remains allowed if a folder has become over-limit after an administrator lowers the configured cap; new children are rejected until the folder is brought back under the limit.

## Reservations and cleanup

Known-size uploads reserve their declared bytes before reading. Unknown-size uploads reserve a bounded allowance before reading and stop at that allowance plus a one-byte overflow probe. Per-user upload slots and aggregate staging bytes are reserved in the SQLite writer transaction. A unique reservation per user/path prevents two simultaneous replacements from crediting the same old document.

A replacement reserves both the incoming upload allowance and headroom for the old blob that will become an orphan. Deletions and replacements move uncollected blob bytes into durable pending-blob accounting. Failed deletion or multipart abort keeps the pending row and its reservation/debt. GC releases the accounting only after blob deletion succeeds.

Migration `00003_upload_reservations` marks pending blobs created by older versions as unknown-size. Upload admission fails closed while any such row remains. The collector removes orphan rows immediately and upload rows after the configured upload grace period. Run the service maintenance collector and allow it to finish before expecting uploads to resume. Do not manually delete pending rows to bypass this behavior.

## Capacity not included in the limits

The staging budget accounts for active reservations and known pending orphan bytes. It is not a filesystem quota and does not include filesystem block rounding, database/WAL growth, S3 multipart buffers or provider-side multipart remnants, snapshots created by operator-managed backup processes, or other processes writing to the same storage volume. Leave disk headroom, monitor actual filesystem/S3 capacity, and configure an S3 lifecycle rule for abandoned multipart uploads. Gopherstorage does not provide backup or restore support.
