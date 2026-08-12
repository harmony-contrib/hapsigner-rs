use std::str::FromStr;

use crate::{signing_block, SignError};

/// Signature algorithms accepted by OpenHarmony `hap-sign-tool` local signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningAlgorithm {
    EcdsaSha256,
    RsaPssSha256,
}

impl SigningAlgorithm {
    pub(crate) const fn id(self) -> u32 {
        match self {
            Self::EcdsaSha256 => signing_block::ALG_ECDSA_SHA256,
            Self::RsaPssSha256 => signing_block::ALG_RSA_PSS_SHA256,
        }
    }

    /// Canonical algorithm spelling used by Hvigor's signing configuration.
    pub const fn hvigor_name(self) -> &'static str {
        match self {
            Self::EcdsaSha256 => "SHA256withECDSA",
            Self::RsaPssSha256 => "SHA256withRSA/PSS",
        }
    }
}

impl FromStr for SigningAlgorithm {
    type Err = SignError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "SHA256withECDSA" | "ECDSA_WITH_SHA256" => Ok(Self::EcdsaSha256),
            "SHA256withRSA/PSS" | "SHA256withRSAANDMGF1" => Ok(Self::RsaPssSha256),
            _ => Err(SignError::UnsupportedAlgorithm(value.to_owned())),
        }
    }
}
