# Queries list of available packages. Adapted version from make-tarball.nix.
{ nixpkgsStable ? lib.cleanSource <nixpkgs>
, pkgs ? import <nixpkgs> {}
, lib ? pkgs.lib
}:

with lib;

let
  src = nixpkgsStable;
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
pkgs.runCommand "packages-json"
  { buildInputs = with pkgs; [ nix jq git ripgrep ]; }
  ''
    export NIX_DB_DIR=$TMPDIR
    export NIX_STATE_DIR=$TMPDIR
    echo -n '{"commit":"00000000000","packages":' > tmp
    nix-env -I nixpkgs=${src} -f '<nixpkgs>' -qa --json --arg config 'import ${pkgConfig}' >> tmp
    echo '}' >> tmp
    mkdir $out
    < tmp sed "s|${src}/||g" | jq . > $out/packages.json
  ''
