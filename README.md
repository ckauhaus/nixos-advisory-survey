NixOS Advisory Survey
=====================

Tools to generate NixOS vulnerability roundups.

Directory structure
-------------------

A work dir is expected which contains `iterations` and `whitelists`
directories. For each vulnerability roundup iteration, a new subdir inside
`iterations` is created. This iteration subdir contains JSON vulnix output as
well as the generated tickets.

The `whitelists` directory contains a vulnix whitelist for each scanned NixOS
release.

Example:

    .
    ├── iterations
    │   ├── …
    │   ├── 69
    │   │   ├── ticket.binutils-2.31.1.md
    │   │   ├── ticket.bubblewrap-0.3.1.md
    │   │   ├── …
    │   │   ├── vulnix.nixos-19.03.json
    │   │   └── vulnix.nixos-unstable.json
    │   ├── …
    └── whitelists
        ├── nixos-19.09.toml
        ├── nixos-20.03.toml
        └── nixos-unstable.toml

Usage
-----

1. Create a work dir as outlined above. The one used for official NixOS
   vulnerability roundups can be found at
   https://github.com/ckauhaus/nixos-vulnerability-roundup/.
2. Check out nixpkgs-channels and pull all relevant release branches
3. Build vulnix
4. Pick a new iteration number
5. Run `survey` in issue creation mode and push updated whitelists.
