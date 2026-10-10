# Backups

Create a snapshot while the service is stopped:

```sh
gopherstorage -config /path/to/config.yaml -backup /safe/path/snapshot
```

The destination must not exist, and its parent directory must already exist. The command obtains the same nonblocking exclusive lock used by the server before opening metadata. If another server or backup owns the data directory, it exits without modifying the destination. Start the server again after the command exits. Persisted login sessions, OAuth grants/tokens/codes, personal API tokens, and logout replay records are removed from the snapshot by default. The copied SQLite database is securely deleted and compacted after scrubbing. Add `-include-credentials` only when a restore must retain them, and treat that snapshot as credential material.

A snapshot contains `meta.db`, a portable `blobs/` tree with only the immutable blob objects referenced by documents in the metadata snapshot, and `manifest.json`. Files are mode 0600 and the snapshot directory is mode 0700. For filesystem storage, this copies the exact referenced objects. For S3 storage, the command streams each referenced object to the snapshot, so network access and read permission to those objects are required. The running service itself remains offline during backup. Each copied object is bounded to the metadata-recorded size, and short or oversized sources fail the backup. A failed backup removes only its private staging directory; a completed destination is published by an atomic no-overwrite rename.

## Restore

1. Stop the service and wait for it to exit.
2. Preserve the existing data directory separately before replacing anything.
3. Copy the snapshot's `meta.db` and `blobs/` into a newly created dedicated data directory, preserving the directory layout. Configure filesystem storage to use that `blobs/` path. Do not point the service at the snapshot itself as a live data directory.
4. Ensure the restored files are owned by the service account and remain private (directory mode 0700, files mode 0600).
5. Start the service and verify documents before removing the previous data directory.

The snapshot includes account records and document metadata. By default, persisted bearer credentials and browser sessions are excluded, so restoring does not reinstate revoked or offboarded credentials. If `-include-credentials` was used, the snapshot also contains OAuth grants and tokens, authorization codes, personal API tokens, and server-side sessions. Treat it as highly sensitive. After restoring a credential-inclusive snapshot, rotate `session.secret` and revoke any credentials that should no longer work. The snapshot does not contain the OIDC provider, configuration file, or session secret.

The backup is a data snapshot, not a complete deployment backup. Save configuration and secret material separately using an appropriate secure process. A snapshot taken from S3 is portable because object contents are copied into the filesystem snapshot; it does not preserve S3 version history, bucket policy, or other bucket objects.
