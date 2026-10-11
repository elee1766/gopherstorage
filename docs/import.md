# Importing existing files

The operator CLI imports a local directory into an existing user's remoteStorage
account. It works with either filesystem or S3 blob storage. Directory imports
currently require Linux.

## Prepare

1. Have the user sign in once so their account exists. Disabled accounts cannot
   receive imports. Use the storage username, not the OIDC subject or email.
2. Export or mount the old storage as a local directory, then stop changes to that
   source. The importer does not take a source snapshot. Per-file identity, size
   and timestamp checks detect many file changes, but cannot reliably detect
   directory entries added, removed or renamed during the run. Use a quiesced
   export or a filesystem snapshot for a complete migration.
3. Check the user's quota and the configured document, staging, node and folder
   limits. Import does not bypass them. See [storage limits](storage-limits.md).
4. Make an operator-managed backup using a process appropriate to the storage
   backend. Gopherstorage does not provide backup or restore support. Stop
   gopherstorage before importing. Import takes the same exclusive
   data-directory lock as the daemon.

Use the same configuration and operating-system account as the daemon. The
command validates configuration but does not contact the OIDC provider or require
an administrator browser session. Access to the server's configuration, metadata
and blob credentials is the authority for this offline operation.

The source cannot contain, be contained by, or equal the configured data directory
or filesystem blob directory. Symlink aliases are resolved for this check.

## Preview and import

For example, import an exported photo directory below `/photos/`:

```sh
gopherstorage -config config.yaml \
  -import /srv/migration/alice-photos -import-user alice \
  -import-prefix /photos/ -import-dry-run

gopherstorage -config config.yaml \
  -import /srv/migration/alice-photos -import-user alice \
  -import-prefix /photos/
```

`vacation/cat.jpg` becomes `/photos/vacation/cat.jpg`. The prefix must be an
absolute canonical folder path with a trailing slash. The default prefix is `/`.
Files are copied, not moved, and the source is never modified. Empty directories
are not represented. Content types come from extensions or content sniffing.
Ownership, permissions and original modification times are not preserved. The
stored modification time is the import time.

A directory export is not an application-format converter. remoteStorage apps
may require their own document schemas and module paths. Import a remoteStorage
export preserving those paths, or prepare the directory layout for the intended
client before importing.

Symlinks, FIFOs, sockets and other special files are skipped and reported as
`unsupported`. Regular hidden files are included. Invalid remoteStorage paths,
read errors and storage-limit failures stop the import.

Dry run checks traversal, destination paths, existing-file policy and configured
maximum document size using read-only metadata. It does not initialize blob
storage, migrate the database, publish documents or run garbage collection. The
lock file and SQLite sidecar files may still be created. A successful preview is
not a reservation or a guarantee of available aggregate quota, staging capacity,
node count or folder capacity.

## Existing files and interruptions

The default `-import-existing skip` leaves existing documents untouched. It does
not compare their contents. Rerun the same command to skip documents already
committed before an interruption.

- `-import-existing error` stops when an existing document is encountered.
- `-import-existing replace` replaces existing documents using the version
  observed immediately before the write. A conflicting version fails rather
  than being overwritten silently.

Imports commit one file at a time. Failure or cancellation does not roll back
completed files. Other in-flight files may finish before cancellation takes
effect. SIGINT and SIGTERM cancel the operation. Failed upload cleanup may take
additional time, and completed documents remain available after restart.
Before a real import, the offline command collects abandoned uploads and
unreferenced blobs so an interrupted run can release staging reservations. This
recovery requires exclusive access to the data directory.

## Public files

Paths under `/public/` are anonymously readable. They require explicit opt-in,
including when the source itself contains a `public` directory:

```sh
gopherstorage -config config.yaml \
  -import /srv/migration/public-photos -import-user alice \
  -import-prefix /public/photos/ -import-allow-public
```

Without `-import-allow-public`, a public destination fails. For a mixed source
with the default root prefix, private files may have committed before traversal
encounters a public path. Use a preview first. The flag only acknowledges public
visibility. It does not change existing-file policy or storage limits.

## Progress and concurrency

Output is newline-delimited JSON. By default, progress is reported after every
1,000 completed entries or after five seconds when an entry completes. Failed
and unsupported entries are always reported. `-import-verbose` reports each file.
After processing starts, the final summary includes imported, planned, skipped,
unsupported and failed counts, completed bytes and elapsed time. Errors also
appear on stderr and return a nonzero exit status.

`-import-workers N` controls concurrent files. The default is four, or the
configured per-user upload-slot limit if smaller. Zero selects that default.
Nonzero values must be 1-64 and cannot exceed the configured slot limit. Memory
and traversal queues are bounded rather than loading the whole tree. Large files
are streamed through the normal storage layer. Each file operation has a
five-minute deadline, and normal backend multipart limits still apply.

Restart the daemon after import and verify the documents with a remoteStorage
client. Keep the source export until that verification is complete.
