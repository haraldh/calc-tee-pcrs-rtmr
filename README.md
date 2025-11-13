# calc-tee-pcrs-rtmr

Precompute TPM PCRs (Platform Configuration Registers) and TDX RTMRs (Runtime Measurement Registers) for Unified Kernel
Images (UKI).

## Overview

This tool calculates the expected TPM PCR and TDX RTMR values for a boot sequence involving Unified Kernel Images,
allowing you to predict attestation measurements before actually booting. This is particularly useful for:

- Pre-calculating attestation quotes for remote attestation scenarios
- Validating boot configurations before deployment
- Debugging attestation failures in confidential computing environments
- Testing secure boot and measured boot configurations

The tool implements the measurement specifications from:

- TCG PC Client Platform Firmware Profile Specification
- Unified Kernel Image (UKI) specification
- TDX (Trust Domain Extensions) architecture

Originally based on [aws/NitroTPM-Tools](https://github.com/aws/NitroTPM-Tools).

## Measured Components

The tool measures and extends the following PCRs/RTMRs:

### PCR4 - Boot Manager Code and Boot Attempts

- EFI boot applications (UKI images)
- Kernel images (from `.linux` section when applicable)
- Boot manager actions

### PCR5 - Boot Services

- GPT (GUID Partition Table) measurements
- Exit Boot Services events

### PCR7 - Secure Boot Policy

- SecureBoot variable state
- Platform Key (PK)
- Key Exchange Key (KEK)
- Signature database (db)
- Signature denylist (dbx)
- Certificate authorities used for image validation

### PCR11 - Unified Kernel Image Sections

- `.linux` - Kernel image
- `.osrel` - OS release information
- `.cmdline` - Kernel command line
- `.initrd` - Initial RAM disk
- `.uname` - Kernel version
- `.sbat` - SBAT revocation metadata

## Installation

### Using Nix Flakes

```bash
# Run directly
nix run github:haraldh/calc-tee-pcrs-rtmr -- --help

# Install to profile
nix profile install github:haraldh/calc-tee-pcrs-rtmr

# Add to your flake.nix
{
  inputs = {
    calc-tee-pcrs-rtmr.url = "github:haraldh/calc-tee-pcrs-rtmr";
  };
}
```

### Using Cargo

```bash
cargo install --git https://github.com/haraldh/calc-tee-pcrs-rtmr
```

### From Source

```bash
git clone https://github.com/haraldh/calc-tee-pcrs-rtmr
cd calc-tee-pcrs-rtmr
cargo build --release
```

## Usage

```bash
calc-tee-pcrs-rtmr \
  --uki /path/to/unified-kernel.efi \
  --disk-image /path/to/disk.img \
  --PK /path/to/PK.auth \
  --KEK /path/to/KEK.auth \
  --db /path/to/db.auth \
  --dbx /path/to/dbx.auth
```

### Options

- `--uki`, `-u` - Path to EFI image file (UKI). Can be specified multiple times for multiple images. The order must
  match the boot load order.
- `--disk-image` - Disk image to measure the GPT table from
- `--PK` - Path to Platform Key (PK) database file (optional)
- `--KEK` - Path to Key Exchange Key (KEK) database file (optional)
- `--db` - Path to signature database file (optional)
- `--dbx` - Path to signature denylist database file (optional)

### Example Output

```
{
  "PCR00": "",
  "PCR01": "",
  "PCR02": "",
  "PCR03": "",
  "PCR04": "d881e4226a838dde6dc85b18e00be7903427388ae29bc933d61726bd6df5d242d761d5b4bcaf96a50a42df65e24b3aec",
  "PCR05": "dc7bf0e11e47489ac1fc4ba8877fd65822cc36de85b52233c3ae61ee0b438d215a59bb278ec9880addf77232adaf893b",
  "PCR06": "518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4",
  "PCR07": "384a798e98b5369727295c5b2889e1e015c65b3add6d78dce4e457c164865ee2af7b6d53ac7cbcd092eaf5fa1a76ea18",
  "PCR08": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "PCR09": "",
  "PCR10": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "PCR11": "ecea3dc8f90742410fd20ee40eb27e48cea54496d61e09d433828232aa1fd95d117d13ebab8ac695ce4c94d0116845f8",
  "PCR12": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "PCR13": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "PCR14": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "PCR15": "",
  "PCR16": "",
  "RTMR1": "34296b5838ae4f921862aac0849f948c3633c33b0879a78d05365ace468ce9e71aaa347ccddd74bea7aeb85e763863bb",
  "RTMR2": "ecea3dc8f90742410fd20ee40eb27e48cea54496d61e09d433828232aa1fd95d117d13ebab8ac695ce4c94d0116845f8"
}
```

## Use Cases

### Remote Attestation

Pre-calculate expected PCR values to validate attestation quotes from confidential VMs or enclaves running on TDX or
TPM-enabled platforms.

### CI/CD Integration

Validate that kernel image updates produce expected attestation measurements before deploying to production
environments.

### Debugging Boot Issues

Compare calculated PCR values with actual runtime measurements to identify which component is causing attestation
failures.

### Secure Boot Testing

Verify that secure boot configurations will produce the expected measurements without requiring actual hardware.

## Nix Flake Features

The project provides a comprehensive Nix flake with:

- **Multi-platform support**: `x86_64-linux` and `aarch64-linux`
- **Overlay**: Import `calc-tee-pcrs-rtmr` into your nixpkgs
- **Development shell**: Includes Rust toolchain and development tools
- **Binary cache**: Fast builds using the Nix cache

### Using the Overlay

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    calc-tee-pcrs-rtmr.url = "github:haraldh/calc-tee-pcrs-rtmr";
  };

  outputs = { self, nixpkgs, calc-tee-pcrs-rtmr }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ calc-tee-pcrs-rtmr.overlays.default ];
      };
    in {
      # calc-tee-pcrs-rtmr is now available in pkgs
      packages.${system}.default = pkgs.calc-tee-pcrs-rtmr;
    };
}
```

### Development Shell

```bash
nix develop
```

This provides:

- Rust compiler and Cargo
- rustfmt and clippy
- rust-analyzer for IDE integration

## Building

### With Cargo

```bash
cargo build --release
```

### With Nix

```bash
nix build
```

The binary will be available at `./result/bin/calc-tee-pcrs-rtmr`.

## Technical Details

- **Hash Algorithm**: SHA-384 (as per TPM 2.0 and TDX specifications)
- **PE/COFF Parsing**: Supports 64-bit PE files and authenticode signatures
- **Systemd-stub**: Handles different stub versions (252+, 258+) and their measurement behaviors
- **GPT Measurement**: Measures partition table headers and partition entries

## License

Apache-2.0

## Authors

- Marius Knaust <mknaust@amazon.com>
- Harald Hoyer <harald@hoyer.xyz>

## Contributing

Contributions are welcome! Please submit pull requests or open issues on GitHub.

## Related Projects

- [aws/NitroTPM-Tools](https://github.com/aws/NitroTPM-Tools) - Original implementation
- [systemd/systemd](https://github.com/systemd/systemd) - Unified Kernel Image specification
- [Confidential Computing Consortium](https://confidentialcomputing.io/) - Industry standards
