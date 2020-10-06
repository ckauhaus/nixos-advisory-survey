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

      # Enable recursion into attribute sets that nix-env normally doesn't look into
      # so that we can get a more complete picture of the available packages for the
      # purposes of the index.
      packageOverrides = super: {
        # haskellPackages = super.recurseIntoAttrs super.haskellPackages;
        # rPackages = super.recurseIntoAttrs super.rPackages;
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

    # Validate we don't keep references.
    # The [^/] part of the expression could be changed for a better
    # representation of a nix store path.
    if rg '/nix/store/[^/]+/' $out/packages.json; then
      echo "Errant nix store paths in packages.json output." >&2
      exit 1
    fi
  ''
