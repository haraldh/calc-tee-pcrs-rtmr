{
  description = "Precompute PCR and RTMR registers for TPM and TDX";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    let
      mkPackage = pkgs:
        let
          rustVersion = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustVersion;
            rustc = rustVersion;
          };

          filterCargoSources = path: type:
            let base = baseNameOf path;
            in type == "directory"
              || pkgs.lib.hasSuffix ".rs" base
              || pkgs.lib.hasSuffix ".toml" base
              || base == "Cargo.lock"
              || (baseNameOf (dirOf path) == ".cargo" && base == "config");

          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = filterCargoSources;
            name = "calc-tee-pcrs-rtmr-source"; # Be reproducible, regardless of the directory name
          };
        in
        rustPlatform.buildRustPackage {
          pname = "calc-tee-pcrs-rtmr";
          version = "1.0.0";
          inherit src;
          cargoLock.lockFile = ./Cargo.lock;
          meta = with pkgs.lib; {
            description = "Precompute PCR and RTMR registers for TPM and TDX";
            homepage = "https://github.com/haraldh/calc-tee-pcrs-rtmr";
            license = licenses.asl20;
            maintainers = [ "harald@hoyer.xyz" ];
            mainProgram = "calc-tee-pcrs-rtmr";
          };
        };
    in
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          package = mkPackage pkgs;
        in
        {
          packages.default = package;
          packages.calc-tee-pcrs-rtmr = package;

          devShells.default = pkgs.mkShell {
            inputsFrom = [ package ];
            packages = with pkgs; [ rustfmt clippy rust-analyzer ];
          };

          apps.default = {
            type = "app";
            program = "${package}/bin/calc-tee-pcrs-rtmr";
          };
        }
      ) // {
      overlays.default = final: prev:
        let pkgsWithRust = prev.extend rust-overlay.overlays.default;
        in { calc-tee-pcrs-rtmr = mkPackage pkgsWithRust; };
    };
}
