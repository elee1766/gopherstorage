{ defaultPackage }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.services.gopherstorage;
  yamlFormat = pkgs.formats.yaml { };
  settingsType = types.submodule (
    { ... }: {
      freeformType = yamlFormat.type;
      options = {
        listen = mkOption {
          type = types.str;
          default = "127.0.0.1:8080";
        };
        data_dir = mkOption {
          type = types.str;
          default = "/var/lib/gopherstorage";
        };
        session.secret = mkOption {
          type = types.str;
          default = "\${GS_SESSION_SECRET}";
        };
        storage.backend = mkOption {
          type = types.str;
          default = "filesystem";
        };
        storage.path = mkOption {
          type = types.str;
          default = "${cfg.settings.data_dir}/blobs";
        };
      };
    }
  );
  dataDir = cfg.settings.data_dir;
  storagePath = lib.attrByPath [ "storage" "path" ] "${dataDir}/blobs" cfg.settings;
  credentialNames = builtins.attrNames cfg.credentials;
  credentialExports = lib.concatMapStringsSep "\n" (name: ''
    export "${name}=$(${pkgs.coreutils}/bin/cat -- "$CREDENTIALS_DIRECTORY/${name}")"
  '') credentialNames;
  credentialWrapper = pkgs.writeShellScript "gopherstorage-with-credentials" ''
    set -eu
    ${credentialExports}
    exec "$@"
  '';
  generatedConfig = yamlFormat.generate "gopherstorage.yaml" cfg.settings;
  escapeTmpfilesPath =
    path: lib.replaceStrings [ "\\" " " "\t" "\n" ] [ "\\x5c" "\\x20" "\\x09" "\\x0a" ] path;
  tmpfiles =
    paths: map (path: "d ${escapeTmpfilesPath path} 0700 ${cfg.user} ${cfg.group} - -") paths;
in
{
  options.services.gopherstorage = {
    enable = mkEnableOption "gopherstorage";

    package = mkOption {
      type = types.package;
      default = defaultPackage pkgs;
      defaultText = lib.literalExpression "defaultPackage pkgs";
      description = "The gopherstorage package to run.";
    };

    settings = mkOption {
      type = settingsType;
      default = { };
      defaultText = lib.literalExpression ''
        {
          listen = "127.0.0.1:8080";
          data_dir = "/var/lib/gopherstorage";
          session.secret = "''${GS_SESSION_SECRET}";
          storage.backend = "filesystem";
          storage.path = "/var/lib/gopherstorage/blobs";
        }
      '';
      description = ''
        Freeform YAML settings for gopherstorage. Do not put secrets here:
        values are serialized into the Nix store. Use environmentFile or
        credentials for secrets. The default session secret is an environment
        variable reference resolved by gopherstorage at runtime.
      '';
    };

    environmentFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/secrets/gopherstorage.env";
      description = ''
        Optional systemd EnvironmentFile path, read at service start. Keep this
        file outside the Nix store and make it readable only by root.
      '';
    };

    credentials = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = {
        GS_SESSION_SECRET = "/run/secrets/gopherstorage-session";
      };
      description = ''
        Map environment variable names to runtime credential file paths. Files
        are passed with systemd LoadCredential and exported only inside the
        service process. Paths must not point into the Nix store.
      '';
    };

    user = mkOption {
      type = types.strMatching "[a-z_][a-z0-9_-]*";
      default = "gopherstorage";
      description = "User account under which gopherstorage runs.";
    };

    group = mkOption {
      type = types.strMatching "[a-z_][a-z0-9_-]*";
      default = "gopherstorage";
      description = "Group under which gopherstorage runs.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.isString dataDir && lib.hasPrefix "/" dataDir;
        message = "services.gopherstorage.settings.data_dir must be an absolute path.";
      }
      {
        assertion =
          builtins.all
            (
              path:
              !(builtins.elem path [
                "/"
                "/etc"
                "/dev"
                "/home"
                "/nix"
                "/nix/store"
                "/proc"
                "/root"
                "/run"
                "/srv"
                "/sys"
                "/tmp"
                "/usr"
                "/usr/local"
                "/var"
                "/var/lib"
                "/var/log"
                "/var/cache"
                "/var/spool"
                "/mnt"
                "/opt"
              ])
            )
            [
              dataDir
              storagePath
            ]
          &&
            builtins.all
              (
                path:
                !(builtins.any (prefix: lib.hasPrefix prefix path) [
                  "/nix/"
                  "/home/"
                  "/root/"
                  "/etc/"
                  "/usr/"
                  "/dev/"
                  "/proc/"
                  "/sys/"
                ])
              )
              [
                dataDir
                storagePath
              ];
        message = "gopherstorage data and storage paths must be dedicated directories, not system roots or paths under /home, /root, or /nix/store.";
      }
      {
        assertion =
          builtins.all
            (
              path:
              builtins.isString path
              && lib.hasPrefix "/" path
              && !(lib.hasInfix "//" path)
              && !(lib.hasInfix "/../" "/${path}/")
              && !(lib.hasInfix "/./" "/${path}/")
              && !(lib.hasSuffix "/" path)
              && builtins.all (char: !(lib.hasInfix char path)) [
                " "
                "\t"
                "\n"
                "\r"
                "%"
                "\\"
              ]
            )
            [
              dataDir
              storagePath
            ];
        message = "gopherstorage data_dir and storage.path must be dedicated canonical absolute paths without whitespace, trailing slashes or systemd specifiers.";
      }
      {
        assertion = cfg.user != "root";
        message = "gopherstorage must run as a dedicated non-root user.";
      }
      {
        assertion = builtins.all (
          name: builtins.match "[A-Za-z_][A-Za-z0-9_]*" name != null
        ) credentialNames;
        message = "services.gopherstorage.credentials keys must be valid environment variable names.";
      }
      {
        assertion =
          builtins.all
            (path: builtins.isString path && lib.hasPrefix "/" path && !(lib.hasPrefix "/nix/store/" path))
            (
              builtins.attrValues cfg.credentials
              ++ lib.optional (cfg.environmentFile != null) cfg.environmentFile
            );
        message = "environmentFile and credential source paths must be absolute runtime paths outside the Nix store.";
      }
    ];

    users.groups.${cfg.group} = { };
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = dataDir;
      createHome = false;
      description = "gopherstorage service user";
    };

    systemd.tmpfiles.rules = tmpfiles (
      lib.unique [
        dataDir
        storagePath
      ]
    );

    systemd.services.gopherstorage = {
      description = "Gopherstorage remote storage server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      wants = [ "network.target" ];
      environment = {
        GOPHERSTORAGE_CONFIG = generatedConfig;
      };
      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        WorkingDirectory = dataDir;
        StateDirectory = "gopherstorage";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "gopherstorage";
        RuntimeDirectoryMode = "0700";
        LoadCredential = lib.mapAttrsToList (name: path: "${name}:${path}") cfg.credentials;
        ExecStartPre = "${credentialWrapper} ${cfg.package}/bin/gopherstorage -config ${generatedConfig} -check";
        ExecStart = "${credentialWrapper} ${cfg.package}/bin/gopherstorage -config ${generatedConfig}";
        Restart = "on-failure";
        RestartSec = "5s";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        CapabilityBoundingSet = "";
        ReadWritePaths = lib.unique [
          dataDir
          storagePath
        ];
      }
      // lib.optionalAttrs (cfg.environmentFile != null) {
        EnvironmentFile = cfg.environmentFile;
      };
    };
  };
}
