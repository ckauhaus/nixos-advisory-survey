{ changedattrsjson }:

with builtins;

let
  pkgs = import ./. {};

  changedattrs = fromJSON (readFile changedattrsjson);

  enrichedAttrs = map
    (path: {
      path = path;
      name = concatStringsSep "." path;
    })
    changedattrs;

  validPackageAttributes = filter
    (pkg:
      if (pkgs.lib.attrsets.hasAttrByPath pkg.path pkgs)
      then (if (tryEval (pkgs.lib.attrsets.attrByPath pkg.path null pkgs)).success
        then true
        else trace "Failed to access ${pkg.name} even though it exists" false)
      else trace "Failed to locate ${pkg.name}." false
    )
    enrichedAttrs;

  attrsWithPackages = map
    (pkg: pkg // { package = pkgs.lib.attrsets.attrByPath pkg.path null pkgs; })
    validPackageAttributes;

  attrsWithMaintainers = map
    (pkg: pkg // { maintainers = (pkg.package.meta or {}).maintainers or []; })
    attrsWithPackages;

  listToPing = listToAttrs
    (map
    (pkg: {
      name = pkg.name;
      value = {
        name = pkg.package.name;
        maintainers = pkgs.lib.flatten (
          map (maint: maint.github or []) pkg.maintainers);
      };
    })
    attrsWithMaintainers);

in listToPing

# Example input:
# [["binutils"], ["dnsutils"], ["systemd"], ["python3Packages", "acoustics"]]
#
# Example output:
# {
#   "binutils": {
#     "maintainers": [
#       "ericson2314"
#     ],
#     "name": "binutils-wrapper-2.31.1"
#   },
#   "dnsutils": {
#     "maintainers": [
#       "peti",
#       "globin"
#     ],
#     "name": "bind-9.14.12"
#   },
#   "python3Packages.acoustics": {
#     "maintainers": [
#       "fridh"
#     ],
#     "name": "python3.7-acoustics-0.2.4"
#   },
#   "systemd": {
#     "maintainers": [
#       "andir",
#       "edolstra",
#       "flokli",
#       "mic92"
#     ],
#     "name": "systemd-243.7"
#   }
# }
