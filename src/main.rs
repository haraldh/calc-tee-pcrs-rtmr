// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright (c) Subzero Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// originally based on https://github.com/aws/NitroTPM-Tools

mod build_info;
mod esl;
mod hasher;
mod pcr;

use anyhow::Context as _;
use build_info::Tpm;
use hasher::Hasher;
use std::io::{Read, Seek};
use crate::build_info::{pcr_only, rtmr_only};

/// Precompute TPM PCRs and TDX RTMRs of a unified kernel image (UKI)
#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    /// Path of an EFI image file (UKI)
    ///
    /// When multiple images are provided, the argument order has to match the load order.
    #[arg(long, short)]
    uki: Vec<std::path::PathBuf>,
    /// Disk image to measure the GPT table from
    #[arg(long)]
    disk_image: std::path::PathBuf,
    #[command(flatten)]
    secure_boot: SecureBootArguments,
}

#[derive(clap::Parser)]
struct SecureBootArguments {
    /// Path of the platform key (PK) database file
    #[arg(long = "PK")]
    platform_key: Option<std::path::PathBuf>,
    /// Path of the key exchange key (KEK) database file
    #[arg(long = "KEK")]
    key_exchange_key: Option<std::path::PathBuf>,
    /// Path of the signature (db) database file
    #[arg(long = "db")]
    signature_database: Option<std::path::PathBuf>,
    /// Path of the signature denylist (dbx) database file
    #[arg(long = "dbx")]
    signature_denylist_database: Option<std::path::PathBuf>,
}

impl SecureBootArguments {
    fn secure_boot_enabled(&self) -> bool {
        // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/how-uefi-secure-boot-works.html
        // When the PK is set, UEFI Secure Boot is enabled and the SetupMode is exited.
        self.platform_key.is_some()
    }

    fn secure_boot(&self) -> &[u8] {
        if !self.secure_boot_enabled() {
             &[]
        } else {
             &[1u8; 1]
        }
    }

    fn platform_key(&self) -> Result<Vec<u8>, std::io::Error> {
        self.platform_key
            .as_ref()
            .map(std::fs::read)
            .transpose()
            .map(Option::unwrap_or_default)
    }

    fn key_exchange_key(&self) -> Result<Vec<u8>, std::io::Error> {
        self.key_exchange_key
            .as_ref()
            .map(std::fs::read)
            .transpose()
            .map(Option::unwrap_or_default)
    }

    fn signature_database(&self) -> Result<Vec<u8>, std::io::Error> {
        self.signature_database
            .as_ref()
            .map(std::fs::read)
            .transpose()
            .map(Option::unwrap_or_default)
    }

    fn signature_denylist_database(&self) -> Result<Vec<u8>, std::io::Error> {
        self.signature_denylist_database
            .as_ref()
            .map(std::fs::read)
            .transpose()
            .map(Option::unwrap_or_default)
    }
}

fn main() -> anyhow::Result<()> {
    const ALGORITHM: &aws_lc_rs::digest::Algorithm = &aws_lc_rs::digest::SHA384;

    env_logger::init();

    let arguments: Arguments = clap::Parser::parse();
    let images = arguments
        .uki
        .iter()
        .map(|path| {
            std::fs::read(path)
                .with_context(|| format!("Could not read image from {}", path.display()))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let images = arguments
        .uki
        .iter()
        .zip(images.iter())
        .map(|(path, image)| {
            object::read::pe::PeFile64::parse(image.as_slice())
                .with_context(|| format!("Could not parse 64-bit PE file from {}", path.display()))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut tpm = Tpm::new(ALGORITHM);

    ev_secure_boot(&mut tpm, ALGORITHM, &arguments.secure_boot, &images)?;

    ev_boot_efi(&mut tpm, ALGORITHM, &arguments.secure_boot, &images,&arguments.disk_image)?;

    ev_bootloader(&mut tpm, ALGORITHM, &images)?;

    let action_hash =
        aws_lc_rs::digest::digest(ALGORITHM, b"Exit Boot Services Invocation");

    log::debug!("[PCR5] EV_EFI_ACTION: {action_hash:?}");
    tpm.extend(5, &action_hash)?;

    let action_hash =
        aws_lc_rs::digest::digest(ALGORITHM, b"Exit Boot Services Returned with Success");

    log::debug!("[PCR5] EV_EFI_ACTION: {action_hash:?}");
    tpm.extend(5, &action_hash)?;


    println!("{tpm}");

    Ok(())
}

/// TCG PC Client Platform Firmware Profile Specification
/// 3.3.4.5 PCR[4] – Boot Manager Code and Boot Attempts
fn ev_boot_efi<'a, Image>(
    tpm: &mut Tpm,
    algorithm: &'static aws_lc_rs::digest::Algorithm,
    secure_boot_arguments: &SecureBootArguments,
    images: &'a [Image],
    disk_image_path: &std::path::Path,
) -> anyhow::Result<()>
where
    Image: object::Object<'a> + authenticode::PeTrait,
{

    // Platform Firmware MUST record the EV_EFI_ACTION event “Calling EFI Application from Boot
    // Option”
    let action_hash =
        aws_lc_rs::digest::digest(algorithm, b"Calling EFI Application from Boot Option");

    log::debug!("[PCR4] EV_EFI_ACTION: {action_hash:?}");
    tpm.extend(4, &action_hash)?;

    // an EV_SEPARATOR event MUST be recorded in the event log for PCR[0-7] prior to the first
    // invocation of the first Ready to Boot call
    let seperator_hash = seperator_hash(algorithm);

    for i in 0..7 {
        log::debug!("[PCR{i}] EV_SEPARATOR: {seperator_hash:?}");
        tpm.extend(pcr_only(i), &seperator_hash)?;
    }
    tpm.extend(rtmr_only(1), &seperator_hash)?;

    let gpt_hash_bytes = measure_gpt(disk_image_path)?;

    tpm.extend(5, &gpt_hash_bytes)?;

    // For the UEFI application code PE/COFF image described by the boot variable, Platform Firmware
    // MUST record the EV_EFI_BOOT_SERVICES_APPLICATION into PCR[4].
    for image in images {
        let image_hash = pe_hash(algorithm, image)?;

        log::debug!("[PCR4] EV_EFI_BOOT_SERVICES_APPLICATION: {image_hash:?}");
        tpm.extend(4, &image_hash)?;

        let linux_section = object::Object::section_by_name(image, ".linux");

        // https://uapi-group.org/specifications/specs/unified_kernel_image/
        // Only the .linux section is required for the image to be considered a Unified Kernel Image
        if let Some(linux_section) = linux_section {
            let al2023_stub_major_version = object::Object::section_by_name(image, ".osrel")
                .as_ref()
                .map(object::ObjectSection::data)
                .transpose()?
                .map(std::str::from_utf8)
                .transpose()?
                .filter(|osrel| {
                    osrel.contains("NAME=\"Amazon Linux\"") && osrel.contains("VERSION=\"2023\"")
                })
                .map(|_| 252);
            let stub_major_version = object::Object::section_by_name(image, ".sdmagic")
                .context("Could not find .sdmagic section of UKI")
                .and_then(|sdmagic| {
                    Ok(std::str::from_utf8(object::ObjectSection::data(&sdmagic)?)?
                        .trim_end_matches('\0')
                        .strip_prefix("#### LoaderInfo: systemd-stub ")
                        .and_then(|string| string.strip_suffix(" ####"))
                        .and_then(|version_string| {
                            version_string
                                .split(|character: char| !character.is_ascii_digit())
                                .next()
                        })
                        .context("Unexpected .sdmagic section format")?
                        .parse::<u32>()?)
                })
                // AL2023 on aarch64 UKIs currently come without the .sdmagic section
                .or_else(|error| al2023_stub_major_version.ok_or(error))?;
            let skip_kernel_measurement =
                    // https://github.com/systemd/systemd/pull/37372
                    // Systemd-stub version 258 starts to load and run the kernel image directly
                    stub_major_version >= 258
                    // https://github.com/systemd/systemd/pull/24777
                    // Systemd-stub version 252 starts to bypasses the security protocol to allow
                    // loading unsigned kernel images
                    || stub_major_version >= 252 && secure_boot_arguments.secure_boot_enabled();

            if skip_kernel_measurement {
                continue;
            }

            let linux =
                object::read::pe::PeFile64::parse(object::ObjectSection::data(&linux_section)?)
                    .context("Could not parse .linux section as 64-bit PE file")?;
            let linux_hash = pe_hash(algorithm, &linux)?;

            log::debug!("[PCR4] EV_EFI_BOOT_SERVICES_APPLICATION: {linux_hash:?}");
            tpm.extend(4, &linux_hash)?;
        }
    }

    Ok(())
}

/// TCG PC Client Platform Firmware Profile Specification
/// 3.3.4.8 PCR[7] – Secure Boot Policy Measurements
fn ev_secure_boot<'a, Image>(
    tpm: &mut Tpm,
    algorithm: &'static aws_lc_rs::digest::Algorithm,
    secure_boot_arguments: &SecureBootArguments,
    images: &'a [Image],
) -> anyhow::Result<()>
where
    Image: object::Object<'a> + authenticode::PeTrait,
{
    const EFI_GLOBAL_VARIABLE_GUID: uuid::Uuid =
        uuid::uuid!("8be4df61-93ca-11d2-aa0d-00e098032b8c");
    const IMAGE_SECURITY_DATABASE_GUID: uuid::Uuid =
        uuid::uuid!("d719b2cb-3d3a-4596-a3bc-dad00e67656f");
    const EFI_CERT_X509_GUID: uuid::Uuid = uuid::uuid!("a5c059a1-94e4-4aa7-87b5-ab155c2bf072");

    // 1. The contents of the SecureBoot variable
    let secure_boot_hash = variable_hash(
        algorithm,
        &EFI_GLOBAL_VARIABLE_GUID,
        "SecureBoot",
        &secure_boot_arguments.secure_boot(),
    );

    log::debug!("[PCR7] EV_EFI_VARIABLE_DRIVER_CONFIG: {secure_boot_hash:?}");
    tpm.extend(7, &secure_boot_hash)?;

    // 2. The contents of the PK variable
    let pk_hash = variable_hash(
        algorithm,
        &EFI_GLOBAL_VARIABLE_GUID,
        "PK",
        &secure_boot_arguments.platform_key()?,
    );

    log::debug!("[PCR7] EV_EFI_VARIABLE_DRIVER_CONFIG: {pk_hash:?}");
    tpm.extend(7, &pk_hash)?;

    // 3. The contents of the KEK variable
    let kek_hash = variable_hash(
        algorithm,
        &EFI_GLOBAL_VARIABLE_GUID,
        "KEK",
        &secure_boot_arguments.key_exchange_key()?,
    );

    log::debug!("[PCR7] EV_EFI_VARIABLE_DRIVER_CONFIG: {kek_hash:?}");
    tpm.extend(7, &kek_hash)?;

    // 4. The contents of the UEFI_IMAGE_SECURITY_DATABASE_GUID /EFI_IMAGE_SECURITY_DATABASE
    // variable (the DB)
    let signature_database = secure_boot_arguments.signature_database()?;
    let db_hash = variable_hash(
        algorithm,
        &IMAGE_SECURITY_DATABASE_GUID,
        "db",
        &signature_database,
    );

    log::debug!("[PCR7] EV_EFI_VARIABLE_DRIVER_CONFIG: {db_hash:?}");
    tpm.extend(7, &db_hash)?;

    // 5. The contents of the UEFI_IMAGE_SECURITY_DATABASE_GUID /EFI_IMAGE_SECURITY_DATABASE1
    // variable (the DBX)
    let dbx_hash = variable_hash(
        algorithm,
        &IMAGE_SECURITY_DATABASE_GUID,
        "dbx",
        &secure_boot_arguments.signature_denylist_database()?,
    );

    log::debug!("[PCR7] EV_EFI_VARIABLE_DRIVER_CONFIG: {dbx_hash:?}");
    tpm.extend(7, &dbx_hash)?;

    // The system SHALL measure the EV_SEPARATOR event in PCR[7]
    let seperator_hash = seperator_hash(algorithm);

    log::debug!("[PCR7] EV_SEPARATOR: {seperator_hash:?}");
    tpm.extend(7, &seperator_hash)?;

    // The EV_EFI_VARIABLE_AUTHORITY measurement in step 6 is not required if the value of the
    // SecureBoot variable is 00h (off).
    if !secure_boot_arguments.secure_boot_enabled() {
        return Ok(());
    }

    // the UEFI firmware SHALL determine if the entry in the UEFI_IMAGE_SECURITY_DATABASE_GUID/
    // EFI_IMAGE_SECURITY_DATABASE variable that was used to validate the UEFI image has previously
    // been measured in PCR[7]. If it has not been, it MUST be measured into PCR[7]. If it has been
    // measured previously, it MUST NOT be measured again.
    let efi_signature_data = esl::try_from(&signature_database)
        .context("Could not parse signature database file")?
        .into_iter()
        // We only support X.509 certificates
        .filter(|efi_signature_list| efi_signature_list.signature_type == EFI_CERT_X509_GUID)
        .flat_map(|efi_signature_list| efi_signature_list.signatures.into_iter())
        .collect::<Vec<_>>();

    let mut seen_efi_signature_data = std::collections::HashSet::new();
    let measured_efi_signature_data = images
        .iter()
        .map(|image| {
            // Look for a matching image signature
            authenticode::AttributeCertificateIterator::new(image)?
                .into_iter()
                .flatten()
                .map(|attribute_certificate| {
                    // Walk the certificate chain
                    Ok::<_, anyhow::Error>(
                        attribute_certificate?
                            .get_authenticode_signature()?
                            .certificates()
                            .map(x509_cert::der::Encode::to_der)
                            .find_map(|certificate| {
                                // Look up the certificate in the signature database
                                // Note: This does not validate the signature, validation is left to
                                // secure boot. Same is true for exclusions of items from the signature
                                // deny list.
                                certificate
                                    .map(|certificate| {
                                        efi_signature_data.iter().find(|efi_signature_data| {
                                            certificate == efi_signature_data.signature_data
                                        })
                                    })
                                    .transpose()
                            })
                            .transpose()?,
                    )
                })
                .find_map(Result::transpose)
                .transpose()
        })
        .filter_map(Result::transpose)
        .filter(|efi_signature_data| {
            efi_signature_data
                .as_ref()
                .map(|efi_signature_data| seen_efi_signature_data.insert(*efi_signature_data))
                .unwrap_or(true)
        });

    for efi_signature_data in measured_efi_signature_data {
        let efi_signature_data = efi_signature_data?;
        let efi_signature_data_hash = variable_hash(
            algorithm,
            &IMAGE_SECURITY_DATABASE_GUID,
            "db",
            &[
                efi_signature_data.signature_owner.to_bytes_le().as_slice(),
                efi_signature_data.signature_data.as_slice(),
            ]
            .concat(),
        );

        log::debug!("[PCR7] EV_EFI_VARIABLE_AUTHORITY: {efi_signature_data_hash:?}");
        tpm.extend(7, &efi_signature_data_hash)?;
    }

    Ok(())
}


/// PCR[11] – Unified Kernel Image (UKI) Sections
/// Measures UKI section names and contents (.linux, .osrel, .cmdline, .initrd, .uname, .sbat)
fn ev_bootloader<'a, Image>(
    tpm: &mut Tpm,
    algorithm: &'static aws_lc_rs::digest::Algorithm,
    images: &'a [Image],
) -> anyhow::Result<()>
where
    Image: object::Object<'a>,
{
    let sections = [".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"];
    
    for image in images {
        for section_name in &sections {
            // Hash the section name
            let mut name_hasher_data = section_name.as_bytes().to_vec();
            name_hasher_data.push(0u8); // null terminator
            let name_hash = aws_lc_rs::digest::digest(algorithm, &name_hasher_data);
            log::debug!("[PCR11] Section name hash ({}): {:?}", section_name, name_hash);
            tpm.extend(11, &name_hash)?;

            // Hash the section data
            if let Some(section) = object::Object::section_by_name(image, section_name) {
                let section_data = object::ObjectSection::data(&section)?;
                let data_hash = aws_lc_rs::digest::digest(algorithm, section_data);

                log::debug!("[PCR11] Section data hash ({}): {:?} ({} bytes)",
                    section_name, data_hash, section_data.len());
                tpm.extend(11, &data_hash)?;
            } else {
                log::warn!("[PCR11] Section {} not found in image", section_name);
                // If section not found, extend with hash of empty data
                let empty_hash = aws_lc_rs::digest::digest(algorithm, &[]);
                tpm.extend(11, &empty_hash)?;
            }
        }
    }

    Ok(())
}

fn seperator_hash(algorithm: &'static aws_lc_rs::digest::Algorithm) -> aws_lc_rs::digest::Digest {
    aws_lc_rs::digest::digest(algorithm, &[0u8; 4])
}

fn variable_hash(
    algorithm: &'static aws_lc_rs::digest::Algorithm,
    uuid: &uuid::Uuid,
    variable_name: &str,
    data: &[u8],
) -> aws_lc_rs::digest::Digest {
    let variable_name_utf16_bytes: Vec<u8> = variable_name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();

    aws_lc_rs::digest::digest(
        algorithm,
        &[
            uuid.to_bytes_le().as_slice(),
            variable_name.len().to_le_bytes().as_slice(),
            (data.len() as u64).to_le_bytes().as_slice(),
            variable_name_utf16_bytes.as_slice(),
            data,
        ]
        .concat(),
    )
}

fn pe_hash(
    algorithm: &'static aws_lc_rs::digest::Algorithm,
    pe: &dyn authenticode::PeTrait,
) -> anyhow::Result<aws_lc_rs::digest::Digest> {
    let mut hasher = Hasher::new(algorithm);

    authenticode::authenticode_digest(pe, &mut hasher)?;

    Ok(hasher.finalize())
}

/// Measure GPT (GUID Partition Table) from disk image
fn measure_gpt(disk_image_path: &std::path::Path) -> anyhow::Result<aws_lc_rs::digest::Digest> {
    const ALGORITHM: &aws_lc_rs::digest::Algorithm = &aws_lc_rs::digest::SHA384;

    let cfg = gpt::GptConfig::new().writable(false);
    let disk = cfg.open(disk_image_path)
        .with_context(|| format!("Could not open disk image: {}", disk_image_path.display()))?;

    let header = disk.primary_header()
        .context("Failed to read primary GPT header")?;
    let lb_size = *disk.logical_block_size();

    log::debug!("[GPT] Logical block size: {}", lb_size);
    log::debug!("[GPT] Partition start: {}", header.part_start);
    log::debug!("[GPT] Number of partitions: {}", header.num_parts);

    let mut msr = Vec::<u8>::new();

    // Read header (92 bytes starting at LB 1)
    let mut file = std::fs::File::open(disk_image_path)?;
    file.seek(std::io::SeekFrom::Start(lb_size.into()))?;
    let mut buf = [0u8; 92];
    file.read_exact(&mut buf)?;
    msr.extend_from_slice(&buf);

    // Read partition entries
    let lb_size_u64: u64 = lb_size.into();
    let pstart = header
        .part_start
        .checked_mul(lb_size_u64)
        .ok_or_else(|| anyhow::anyhow!("Partition overflow - start offset"))?;
    file.seek(std::io::SeekFrom::Start(pstart))?;

    anyhow::ensure!(header.part_size == 128, "Expected partition size of 128 bytes");
    anyhow::ensure!(header.num_parts < u32::from(u8::MAX), "Too many partitions");

    let empty_bytes = [0u8; 128];
    let partitions = disk.partitions();

    // Add partition count
    msr.extend_from_slice(&partitions.len().to_le_bytes());

    // Read all partition entries, but only include non-empty ones
    for _ in 0..header.num_parts {
        let mut bytes = empty_bytes;
        file.read_exact(&mut bytes)?;
        if !bytes.eq(&empty_bytes) {
            msr.extend_from_slice(&bytes);
        }
    }

    // Hash the MSR data
    let hash = aws_lc_rs::digest::digest(ALGORITHM, &msr);

    Ok(hash)
}
