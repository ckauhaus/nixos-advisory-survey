{ pkgs ? import <nixpkgs> {}
, allPackages
}:

with builtins;

let
  patchName =
    p: (if p ? name then p.name else if p ? outPath then p.outPath else toString p);

in
  listToAttrs (
    map
    (a: {
      name = a.name;
      value =
        if isList a.patches
        then (map patchName a.patches)
        else [ (patchName a.patches) ];
    })
    (filter (a: a ? name) (import allPackages { inherit pkgs; })))
