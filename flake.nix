{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.cargo-audit
            pkgs.clippy
            pkgs.rust-analyzer
            pkgs.rustc
            pkgs.rustfmt
          ];
        };

        packages = {
          default = self.packages.${system}.miko;
          miko = pkgs.rustPlatform.buildRustPackage {
            pname = "miko";
            version = "git";
            src =
              let
                fs = pkgs.lib.fileset;
              in
              fs.toSource {
                root = ./.;
                fileset = fs.intersection (fs.gitTracked ./.) (
                  fs.unions [
                    ./src
                    ./Cargo.toml
                    ./Cargo.lock
                    ./README.md
                  ]
                );
              };
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = [
              pkgs.installShellFiles
            ];
            postInstall = ''
              installShellCompletion --cmd miko \
                --bash <(_MIKO_GENERATE_COMPLETION=bash $out/bin/miko _) \
                --zsh <(_MIKO_GENERATE_COMPLETION=zsh $out/bin/miko _) \
                --fish <(_MIKO_GENERATE_COMPLETION=fish $out/bin/miko _)
            '';
          };
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
