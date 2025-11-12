// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::pcr::Pcr;

pub(crate) struct Tpm {
    pcr: [Pcr; 16],
    rtmr: [Pcr; 4],
}

#[derive(serde::Serialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) struct TpmDisplay {
    pcr00: String,
    pcr01: String,
    pcr02: String,
    pcr03: String,
    pcr04: String,
    pcr05: String,
    pcr06: String,
    pcr07: String,
    pcr08: String,
    pcr09: String,
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
        Self {
            pcr04: format!("{:x}", tpm.pcr[4]),
            pcr05: format!("{:x}", tpm.pcr[5]),
            pcr06: format!("{:x}", tpm.pcr[6]),
            pcr07: format!("{:x}", tpm.pcr[7]),
            pcr08: null.clone(),
            pcr10: null.clone(),
            pcr11: format!("{:x}", tpm.pcr[11]),
            pcr12: null.clone(),
            pcr13: null.clone(),
            pcr14: null.clone(),
            rtmr1: format!("{:x}", tpm.rtmr[1]),
            rtmr2: format!("{:x}", tpm.rtmr[2]),
            ..Default::default()
        }
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
        }
    }

    pub(crate) fn extend(&mut self, index: usize, digest: &aws_lc_rs::digest::Digest) -> anyhow::Result<()> {
        if (1000..2000).contains(&index) {
            let index = index - 1000;

            if index > 15 { return Ok(());}
            if index < 4 { return Ok(());}

            log::debug!("[PCR{index}] extend with digest: {:?}", digest);

            self.pcr.get_mut(index) .ok_or_else(|| anyhow::anyhow!("PCR{index} not found"))?.extend(digest);
            return Ok(());
        }

        if (2000..3000).contains(&index)  {
            let index = index - 2000;

            log::debug!("[RTMR{index}] extend with digest: {:?}", digest);

            self.rtmr.get_mut(index) .ok_or_else(|| anyhow::anyhow!("RTMR{index} not found"))?.extend(digest);
            return Ok(());
        }

        if index > 15 { return Ok(());}
        if index < 4 { return Ok(());}

        log::debug!("[PCR{index}] extend with digest: {:?}", digest);

        self.pcr.get_mut(index) .ok_or_else(|| anyhow::anyhow!("PCR{index} not found"))?.extend(digest);

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
