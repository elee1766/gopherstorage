{
  lib,
  buildGo127Module,
  go_1_27,
  fetchurl,
  runCommand,
  patch,
  source,
  remotestorage,
}:
let
  go = go_1_27.overrideAttrs (_: {
    version = "1.27.2";
    src = fetchurl {
      url = "https://go.dev/dl/go1.27.2.src.tar.gz";
      hash = "sha256-A0ldorpkiU1A9cSZLklFT6eLUGkGBP+Stq//UIG3bmI=";
    };
  });
  buildGoModule = buildGo127Module.override { inherit go; };
  combinedSource = runCommand "gopherstorage-source" { nativeBuildInputs = [ patch ]; } ''
    mkdir -p "$out/gopherstorage" "$out/remotestorage"
    cp -r ${source}/. "$out/gopherstorage/"
    cp -r ${remotestorage}/. "$out/remotestorage/"
    chmod -R u+w "$out"
    cd "$out/remotestorage"
    patch -p1 < ${./remotestorage-cache-control.patch}
  '';
in
buildGoModule {
  pname = "gopherstorage";
  version = "0-unstable";
  src = combinedSource;
  modRoot = "gopherstorage";
  vendorHash = "sha256-dX7xcnHKOBteSUBOR8f+g3zSBRypLtwoqCTsnW0Ef3s=";
  subPackages = [ "cmd/gopherstorage" ];
  env.CGO_ENABLED = 0;
  checkPhase = ''
    runHook preCheck
    go test ./...
    runHook postCheck
  '';
  ldflags = [
    "-s"
    "-w"
  ];
  passthru = { inherit go; };
  meta = {
    description = "Self-hosted remoteStorage server with OIDC authentication";
    homepage = "https://github.com/elee1766/gopherstorage";
    mainProgram = "gopherstorage";
    platforms = lib.platforms.linux;
  };
}
