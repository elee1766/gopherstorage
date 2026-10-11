{
  pkgs,
  nixpkgs,
  module,
  package,
}:
let
  makeSystem =
    extra:
    nixpkgs.lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      modules = [
        module
        {
          system.stateVersion = "26.05";
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
          };
          services.gopherstorage = {
            enable = true;
            inherit package;
            settings = {
              public_url = "https://storage.example.test";
              oidc = {
                issuer = "https://identity.example.test";
                client_id = "configuration-check";
                client_secret = "\${GS_OIDC_SECRET}";
              };
              storage.path = "/srv/gopherstorage/blobs";
            };
          };
        }
        extra
      ];
    };
  credentialsSystem = makeSystem {
    services.gopherstorage.credentials = {
      GS_SESSION_SECRET = "/run/secrets/gopherstorage-session";
      GS_OIDC_SECRET = "/run/secrets/gopherstorage-oidc";
    };
  };
  environmentSystem = makeSystem {
    services.gopherstorage = {
      environmentFile = "/run/secrets/gopherstorage.env";
      settings.storage = {
        backend = "s3";
        s3.bucket = "configuration-check";
      };
    };
  };
  unsafeDirectoriesRejected =
    builtins.all
      (
        path:
        builtins.any (a: !a.assertion)
          (makeSystem {
            services.gopherstorage.settings.data_dir = path;
          }).config.assertions
      )
      [
        "/var/lib/"
        "/srv/../var/lib"
        "/var/lib/%i"
      ];
  credentialsService = credentialsSystem.config.systemd.services.gopherstorage;
  environmentService = environmentSystem.config.systemd.services.gopherstorage;
  checked =
    system:
    assert builtins.all (a: a.assertion) system.config.assertions;
    system.config.systemd.services.gopherstorage.serviceConfig.ExecStartPre;
in
assert unsafeDirectoriesRejected;
pkgs.runCommand "gopherstorage-nixos-config-check" { } ''
  mkdir -p "$TMPDIR/credentials"
  export CREDENTIALS_DIRECTORY="$TMPDIR/credentials"
  printf '%s' 'test-only-session-secret-at-least-32-characters' > "$CREDENTIALS_DIRECTORY/GS_SESSION_SECRET"
  printf '%s' 'test-only-client-secret' > "$CREDENTIALS_DIRECTORY/GS_OIDC_SECRET"
  export HOME=${nixpkgs.lib.escapeShellArg credentialsSystem.config.users.users.gopherstorage.home}
  cd ${nixpkgs.lib.escapeShellArg credentialsService.serviceConfig.WorkingDirectory}
  ${checked credentialsSystem}

  export GS_SESSION_SECRET='test-only-session-secret-at-least-32-characters'
  export GS_OIDC_SECRET='test-only-client-secret'
  export HOME=${nixpkgs.lib.escapeShellArg environmentSystem.config.users.users.gopherstorage.home}
  cd ${nixpkgs.lib.escapeShellArg environmentService.serviceConfig.WorkingDirectory}
  ${checked environmentSystem}

  unset GS_SESSION_SECRET
  export GOPHERSTORAGE_SESSION_SECRET='test-only-direct-session-secret-at-least-32-characters'
  export GOPHERSTORAGE_STORAGE_S3_BUCKET='environment-override'
  ${checked environmentSystem}
  unset GOPHERSTORAGE_SESSION_SECRET GOPHERSTORAGE_STORAGE_S3_BUCKET
  if ${checked environmentSystem}; then
    echo 'Missing runtime session secret was accepted' >&2
    exit 1
  fi
  touch "$out"
''
