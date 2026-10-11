# Nix and NixOS

## Build

```sh
nix build .#gopherstorage
./result/bin/gopherstorage -h
nix run . -- -check -config config.yaml
nix develop
nix flake check
```

The flake provides packages and development shells for `x86_64-linux` and
`aarch64-linux`, an app, an overlay, and `nixosModules.default` (also named
`nixosModules.gopherstorage`). The package builds with Go 1.27.2, disables cgo,
and runs the full Go test suite in the Nix sandbox. The flake check also evaluates
the NixOS module and checks its generated configuration and credential wrapper
with the built server. It does not deploy a service or test a live OIDC login.

Nix builds do not need a sibling checkout: the flake pins the published
remoteStorage source and applies the cache-control security repair currently
present only in the local library checkout. `go.mod` is not rewritten. Ordinary
`go` commands in the development shell still use the existing
`../remotestorage` replacement and need that sibling checkout. The development
shell provides the pinned compiler, not a source-tree rewrite.

Keep `flake.lock` committed. After changing Go dependencies or the library
input, update the `vendorHash` in `nix/package.nix`. Setting it temporarily to
`pkgs.lib.fakeHash` and running a build reports the new hash. Remove or update
the library patch when the corresponding fix is published upstream.

## Deploy

Add the input and module to your host flake:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    gopherstorage.url = "github:elee1766/gopherstorage";
  };

  outputs = { nixpkgs, gopherstorage, ... }: {
    nixosConfigurations.storage = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./configuration.nix
        gopherstorage.nixosModules.default
        {
          services.gopherstorage = {
            enable = true;
            settings = {
              listen = "127.0.0.1:8080";
              public_url = "https://storage.example.com";
              oidc = {
                issuer = "https://id.example.com";
                client_id = "gopherstorage";
                client_secret = "\${GS_OIDC_CLIENT_SECRET}";
                admin_groups = [ "storage-admins" ];
              };
              storage = {
                backend = "filesystem";
                default_quota_bytes = 1073741824;
                max_document_bytes = 67108864;
              };
            };
            credentials = {
              GS_SESSION_SECRET = "/run/secrets/gopherstorage-session";
              GS_OIDC_CLIENT_SECRET = "/run/secrets/gopherstorage-oidc";
            };
          };
        }
      ];
    };
  };
}
```

Provision the credential files with your secret manager, then apply your host
configuration with your usual `nixos-rebuild` workflow. The module does not
create secrets, register an OIDC client, configure a reverse proxy or open
firewall ports. Use TLS at a reverse proxy, preserving the configured public
host. Register the callback and back-channel URLs described in the README.

## Options and state

- `services.gopherstorage.enable`: enable the service.
- `package`: override the executable package.
- `settings`: application configuration rendered as YAML. Keys match
  `config.example.yaml`, including OIDC, storage/S3, token, view and HTTP settings.
  Unknown application keys fail the pre-start configuration check.
- `credentials`: environment variable names mapped to absolute runtime secret
  files, delivered with systemd `LoadCredential`.
- `environmentFile`: optional absolute path to a systemd environment file.
- `user` and `group`: dedicated service account names, default `gopherstorage`.

The module defaults to loopback port 8080, `/var/lib/gopherstorage` for metadata,
and its `blobs` subdirectory for filesystem contents. It supplies a literal
`${GS_SESSION_SECRET}` reference for `session.secret`. Other settings retain the
application's defaults unless overridden.

The service creates owner-only state and runtime directories and checks its
configuration before starting. It runs without root or capabilities, with a
read-only system filesystem and writable access to the configured data and blob
directories. Custom directories must be dedicated canonical absolute paths,
without whitespace, trailing slashes, dot components or systemd specifiers.
Broad system directories and paths under `/home`, `/root` or `/nix/store` are
rejected. Do not point these options at unrelated existing data: managed
directories are assigned to the service account with mode 0700.

For S3, set `settings.storage.backend = "s3"` and configure
`settings.storage.s3` using the same keys as the YAML example. Reference access
and secret keys through runtime variables, or use the AWS credential chain.
Metadata still needs a persistent data directory. The service account uses
`/var/empty` as its home and `/` as its working directory, separately from
storage because the application rejects either location as a data directory.
Existing state must be owned
by the configured user before migrating to this service.

## Secrets

**Do not put secret values in `settings` or Nix expressions.** The generated
configuration and unit scripts live in the world-readable Nix store. Use escaped
references such as `"\${GS_OIDC_CLIENT_SECRET}"` in Nix strings, not the actual
secret. Credential source paths must be outside the store.

Credential files contain the raw value. The service wrapper reads them and
exports the matching variable before both the configuration check and server
start. Credential values take precedence over the same keys in an environment
file. The application currently consumes secrets as environment variables, so
`LoadCredential` keeps the source out of the store but does not remove secrets
from the running process's environment.

Alternatively, set `environmentFile = "/run/secrets/gopherstorage.env"` and
provision a root-owned mode-0600 file using systemd EnvironmentFile syntax:

```sh
GS_SESSION_SECRET=a-random-persistent-secret-of-at-least-32-characters
GS_OIDC_CLIENT_SECRET=your-client-secret
```

Do not commit this file. Keep the session secret persistent across deployments.
Missing referenced variables fail the pre-start configuration check. The module
does not automatically restart the service when the contents of a secret file
change, so restart it after rotating credentials.

Direct `GOPHERSTORAGE_` environment keys also override generated YAML. Keep
`data_dir` and `storage.path` in `settings`, rather than overriding their paths
through the environment, so the module creates and permits the right writable
directories. See [configuration](configuration.md) for key names and types.

Gopherstorage does not provide backup or restore support. Use an operator-managed
backup process appropriate to the storage backend and coordinate it with the
service to obtain a consistent snapshot. For imports, stop the systemd service
first and use an operator configuration with access to the same runtime secrets.
The application's exclusive data-directory lock prevents an import from running
concurrently with the daemon. See [bulk import](import.md).
