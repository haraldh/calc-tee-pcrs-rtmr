// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::pcr::Pcr;

pub(crate) struct Tpm {
    pcr: [Pcr; 16],
    rtmr: [Pcr; 4],
    /// Whether PCR 7 was computed from real Secure Boot inputs. Unset when
    /// the caller passed no PK/KEK/db/dbx — in that case the extension chain
    /// is meaningless and PCR 7 is omitted from the output.
    pcr7_measured: bool,
}

#[derive(serde::Serialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) struct TpmDisplay {
    pcr0: String,
    pcr1: String,
    pcr2: String,
    pcr3: String,
    pcr4: String,
    pcr5: String,
    pcr6: String,
    pcr7: String,
    pcr8: String,
    pcr9: String,
    pcr10: String,
    pcr11: String,
    pcr12: String,
    pcr13: String,
    pcr14: String,
    pcr15: String,
    pcr16: String,
    rtmr1: String,
    rtmr2: String,
}

impl From<&Tpm> for TpmDisplay {
    fn from(tpm: &Tpm) -> Self {
        let null = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string();
        let mut display = Self {
            pcr4: format!("{:x}", tpm.pcr[4]),
            pcr5: format!("{:x}", tpm.pcr[5]),
            // PCR 6 is "Host Platform Manufacturer Specific" — its real value
            // depends on firmware-specific UEFI events we can't reproduce
            // here (Hyper-V extends vendor events beyond the spec minimum),
            // so leave it blank rather than the misleading separator-only
            // digest.
            pcr8: null.clone(),
            pcr10: null.clone(),
            pcr11: format!("{:x}", tpm.pcr[11]),
            pcr12: null.clone(),
            pcr13: null.clone(),
            pcr14: null.clone(),
            rtmr1: format!("{:x}", tpm.rtmr[1]),
            rtmr2: format!("{:x}", tpm.rtmr[2]),
            ..Default::default()
        };
        // PCR 7 is only reproducible when the caller supplies the Secure Boot
        // variable contents (PK/KEK/db/dbx). Without them the extension chain
        // is modelling bare unprovisioned UEFI (matches OVMF with no SB keys,
        // but not Hyper-V which ships with MS defaults). Emit only when real
        // inputs were provided; otherwise leave blank like PCR 6.
        if tpm.pcr7_measured {
            display.pcr7 = format!("{:x}", tpm.pcr[7]);
        }
        display
    }
}

pub(crate) fn pcr_only(i: usize) -> usize {
    i + 1000
}

pub(crate) fn rtmr_only(i: usize) -> usize {
    i + 2000
}

impl Tpm {
    pub(crate) fn new(algorithm: &'static aws_lc_rs::digest::Algorithm) -> Self {
        Self {
            pcr: [Pcr::new(algorithm); 16],
            rtmr: [Pcr::new(algorithm); 4],
            pcr7_measured: false,
        }
    }

    pub(crate) fn set_pcr7_measured(&mut self, measured: bool) {
        self.pcr7_measured = measured;
    }

    pub(crate) fn extend(
        &mut self,
        index: usize,
        digest: &aws_lc_rs::digest::Digest,
    ) -> anyhow::Result<()> {
        if (1000..2000).contains(&index) {
            let index = index - 1000;

            if index > 15 {
                return Ok(());
            }
            if index < 4 {
                return Ok(());
            }

            log::debug!("[PCR{index}] extend with digest: {:?}", digest);

            self.pcr
                .get_mut(index)
                .ok_or_else(|| anyhow::anyhow!("PCR{index} not found"))?
                .extend(digest);
            return Ok(());
        }

        if (2000..3000).contains(&index) {
            let index = index - 2000;

            log::debug!("[RTMR{index}] extend with digest: {:?}", digest);

            self.rtmr
                .get_mut(index)
                .ok_or_else(|| anyhow::anyhow!("RTMR{index} not found"))?
                .extend(digest);
            return Ok(());
        }

        if index > 15 {
            return Ok(());
        }
        if index < 4 {
            return Ok(());
        }

        log::debug!("[PCR{index}] extend with digest: {:?}", digest);

        self.pcr
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("PCR{index} not found"))?
            .extend(digest);

        if index == 11 {
            self.rtmr[2].extend(digest);
        }
        if index == 4 || index == 5 {
            self.rtmr[1].extend(digest);
        }

        Ok(())
    }
}

impl std::fmt::Display for Tpm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display = TpmDisplay::from(self);
        let json = serde_json::to_string_pretty(&display).map_err(|_| std::fmt::Error)?;
        write!(formatter, "{json}")
    }
}
