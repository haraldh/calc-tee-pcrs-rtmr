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
      # Overlay that can be imported into other flakes
      overlay = final: prev: {
        calc-tee-pcrs-rtmr = mkPackage final;
      };

      rustPlatform = pkgs:
        let
          rustVersion = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        in
        pkgs.makeRustPlatform {
          cargo = rustVersion;
          rustc = rustVersion;
        };

      # Function to create the package for a given system
      mkPackage = pkgs:
        (rustPlatform pkgs).buildRustPackage {
          pname = "calc-tee-pcrs-rtmr";
          version = "1.0.0";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          meta = with pkgs.lib; {
            description = "Precompute PCR and RTMR registers for TPM and TDX";
            homepage = "https://github.com/haraldh/calc-tee-pcrs-rtmr";
            license = licenses.asl20;
            maintainers = [ ];
            mainProgram = "calc-tee-pcrs-rtmr";
            platforms = [ "x86_64-linux" "aarch64-linux" ];
          };
        };
    in
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ]
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              overlay
              (import rust-overlay)
            ];
          };
        in
        {
          packages = {
            default = mkPackage pkgs;
            calc-tee-pcrs-rtmr = mkPackage pkgs;
          };

          # Development shell with Rust toolchain
          devShells.default = pkgs.mkShell {
            inputsFrom = [ (mkPackage pkgs) ];
            packages = with pkgs; [
              rustfmt
              clippy
              rust-analyzer
            ];
          };

          # Allow running the package directly with `nix run`
          apps.default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/calc-tee-pcrs-rtmr";
          };
        }
      ) // {
      # Make the overlay available for other flakes
      overlays.default = overlay;
    };
}
