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
  # GO-2026-6859 (net/http MaxBytesReader header race) is fixed in go1.27.4.
  # nixpkgs-unstable still ships 1.27.3, so pin the fix; use nixpkgs' go when it
  # is new enough so the binary cache still applies.
  go =
    if lib.versionAtLeast go_1_27.version "1.27.4" then
      go_1_27
    else
      go_1_27.overrideAttrs (_: {
        version = "1.27.4";
        src = fetchurl {
          url = "https://go.dev/dl/go1.27.4.src.tar.gz";
          hash = "sha256-c8+4VxrsDAEXdofbhxY9Rqog6XeWcncokaoXZU2aYJk=";
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
  vendorHash = "sha256-g5+3icvLYnnlhKx2FxR/y12Pz1Z2JV/er64v1dRW2lw=";
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
