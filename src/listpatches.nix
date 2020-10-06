{ allPackages }:

with builtins;

let
  pkgs = import <nixpkgs> {
    overlays = [ (self: super: {
      # work around https://github.com/NixOS/nixpkgs/issues/99286
      suil-qt5 = null;
    })
    ];
  };

  patchName =
    p: (if p ? name then p.name else if p ? outPath then p.outPath else toString p);

in
  listToAttrs (
    map
    (a: {
      name = a.name;
      value =
        let patches = a.patches or [];
        in
        if isList patches
        then (map patchName patches)
        else [ (patchName patches) ];
    })
    (filter (a: a ? name) (import allPackages { inherit pkgs; })))
