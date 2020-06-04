{ changedattrsjson }:

let
  pkgs = import ./. {};

  changedattrs = builtins.fromJSON (builtins.readFile changedattrsjson);

  enrichedAttrs = builtins.map
    (path: {
      path = path;
      name = builtins.concatStringsSep "." path;
    })
    changedattrs;

  validPackageAttributes = builtins.filter
    (pkg:
      if (pkgs.lib.attrsets.hasAttrByPath pkg.path pkgs)
      then (if (builtins.tryEval (pkgs.lib.attrsets.attrByPath pkg.path null pkgs)).success
        then true
        else builtins.trace "Failed to access ${pkg.name} even though it exists" false)
      else builtins.trace "Failed to locate ${pkg.name}." false
    )
    enrichedAttrs;

  attrsWithPackages = builtins.map
    (pkg: pkg // { package = pkgs.lib.attrsets.attrByPath pkg.path null pkgs; })
    validPackageAttributes;

  attrsWithMaintainers = builtins.map
    (pkg: pkg // { maintainers = (pkg.package.meta or {}).maintainers or []; })
    attrsWithPackages;

  attrsWeCanPing = builtins.filter
    (pkg: if (builtins.length pkg.maintainers) > 0
      then true
      else builtins.trace "Package has no maintainers: ${pkg.name}" false
    )
    attrsWithMaintainers;

  listToPing = pkgs.lib.lists.flatten
    (builtins.map
      (pkg:
        builtins.map (maintainer: {
          handle = pkgs.lib.toLower maintainer.github;
          pkgName = pkg.name;
        })
        pkg.maintainers
      )
      attrsWithMaintainers);

  byMaintainer = pkgs.lib.lists.foldr
    (ping: collector: collector // {
      "${ping.handle}" = [ { inherit (ping) pkgName; } ] ++ (collector."${ping.handle}" or []);
    })
    {}
    listToPing;

  packagesPerMaintainer = pkgs.lib.attrsets.mapAttrs
    (maintainer: packages:
      builtins.map (pkg: pkg.pkgName)
      packages)
    byMaintainer;

in listToPing
