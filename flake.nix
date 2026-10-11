{
  description = "gopherstorage remoteStorage server and NixOS service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    remotestorage = {
      url = "github:elee1766/remotestorage/532de1c3760a7404986779ee35ca1646e481f8c0";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      remotestorage,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      packageFor =
        pkgs:
        pkgs.callPackage ./nix/package.nix {
          inherit remotestorage;
          source = nixpkgs.lib.fileset.toSource {
            root = ./.;
            fileset = nixpkgs.lib.fileset.unions [
              ./go.mod
              ./go.sum
              ./cmd
              ./pkg
            ];
          };
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          package = packageFor (import nixpkgs { inherit system; });
        in
        {
          default = package;
          gopherstorage = package;
        }
      );
      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/gopherstorage";
          meta.description = "Run the gopherstorage server";
        };
      });
      overlays.default = final: prev: { gopherstorage = packageFor final; };
      nixosModules.default = import ./nix/module.nix {
        defaultPackage = pkgs: self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      };
      nixosModules.gopherstorage = self.nixosModules.default;
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          package = self.packages.${system}.default;
        in
        {
          default = pkgs.mkShell {
            packages = [
              package.passthru.go
              pkgs.git
            ];
            GOTOOLCHAIN = "local";
          };
        }
      );
      checks = forAllSystems (system: {
        package = self.packages.${system}.default;
        nixos-config = import ./nix/check.nix {
          pkgs = import nixpkgs { inherit system; };
          inherit nixpkgs;
          module = self.nixosModules.default;
          package = self.packages.${system}.default;
        };
      });
      formatter = forAllSystems (system: (import nixpkgs { inherit system; }).nixfmt);
    };
}
