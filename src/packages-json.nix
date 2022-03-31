# Queries list of available packages. Adapted version from make-tarball.nix.
{ nixpkgs ? <nixpkgs> }:

with import (fetchTarball "channel:nixos-unstable") {};

let
  src = lib.cleanSource nixpkgs;
  pkgConfig = builtins.toFile "package-config.nix" ''
    {
      # Ensures no aliases are in the results.
      allowAliases = false;

      # Prevent recursion into areas for which we won't report anyway.
      packageOverrides = super: {
        vimPlugins = {};
      };
    }
  '';

in
runCommand "packages.json"
  { buildInputs = with pkgs; [ nix jq ]; }
  ''
    set -o pipefail
    export NIX_STATE_DIR=$TMPDIR
    header "generating packages.json"
    (
      echo -n '{"version":2,"packages":'
      nix-env -f '<nixpkgs>' -I nixpkgs=${src} -qa --meta --json --arg config 'import ${pkgConfig}'
      echo '}'
    ) | sed "s|${src}/||" | jq -c > $out
  ''
