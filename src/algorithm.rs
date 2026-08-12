use std::str::FromStr;

use crate::{signing_block, SignError};

/// Content-digest algorithms used by the HAP chunk digest and CMS attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentDigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl ContentDigestAlgorithm {
    pub const fn output_size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub(crate) fn digest(self, bytes: &[u8]) -> Vec<u8> {
        use sha2::Digest;

        match self {
            Self::Sha256 => sha2::Sha256::digest(bytes).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(bytes).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(bytes).to_vec(),
        }
    }
}

/// Signature algorithms accepted by OpenHarmony `hap-sign-tool` local signing.
///
/// This mirrors `SignProvider.VALID_SIGN_ALG_NAME` and
/// `ParamProcessUtil.getSignatureAlgorithm` from upstream hapsigner. The
/// `...ANDMGF1` spellings are parsed as aliases for the RSA-PSS variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningAlgorithm {
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
}

impl SigningAlgorithm {
    pub(crate) const fn from_id(id: u32) -> Option<Self> {
        match id {
            signing_block::ALG_ECDSA_SHA256 => Some(Self::EcdsaSha256),
            signing_block::ALG_ECDSA_SHA384 => Some(Self::EcdsaSha384),
            signing_block::ALG_ECDSA_SHA512 => Some(Self::EcdsaSha512),
            signing_block::ALG_RSA_PSS_SHA256 => Some(Self::RsaPssSha256),
            signing_block::ALG_RSA_PSS_SHA384 => Some(Self::RsaPssSha384),
            signing_block::ALG_RSA_PSS_SHA512 => Some(Self::RsaPssSha512),
            _ => None,
        }
    }

    pub(crate) const fn id(self) -> u32 {
        match self {
            Self::EcdsaSha256 => signing_block::ALG_ECDSA_SHA256,
            Self::EcdsaSha384 => signing_block::ALG_ECDSA_SHA384,
            Self::EcdsaSha512 => signing_block::ALG_ECDSA_SHA512,
            Self::RsaPssSha256 => signing_block::ALG_RSA_PSS_SHA256,
            Self::RsaPssSha384 => signing_block::ALG_RSA_PSS_SHA384,
            Self::RsaPssSha512 => signing_block::ALG_RSA_PSS_SHA512,
        }
    }

    pub(crate) const fn content_digest(self) -> ContentDigestAlgorithm {
        match self {
            Self::EcdsaSha256 | Self::RsaPssSha256 => ContentDigestAlgorithm::Sha256,
            Self::EcdsaSha384 | Self::RsaPssSha384 => ContentDigestAlgorithm::Sha384,
            Self::EcdsaSha512 | Self::RsaPssSha512 => ContentDigestAlgorithm::Sha512,
        }
    }

    /// Canonical algorithm spelling used by Hvigor's signing configuration.
    pub const fn hvigor_name(self) -> &'static str {
        match self {
            Self::EcdsaSha256 => "SHA256withECDSA",
            Self::EcdsaSha384 => "SHA384withECDSA",
            Self::EcdsaSha512 => "SHA512withECDSA",
            Self::RsaPssSha256 => "SHA256withRSA/PSS",
            Self::RsaPssSha384 => "SHA384withRSA/PSS",
            Self::RsaPssSha512 => "SHA512withRSA/PSS",
        }
    }
}

impl FromStr for SigningAlgorithm {
    type Err = SignError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_uppercase().as_str() {
            "SHA256WITHECDSA" | "ECDSA_WITH_SHA256" => Ok(Self::EcdsaSha256),
            "SHA384WITHECDSA" | "ECDSA_WITH_SHA384" => Ok(Self::EcdsaSha384),
            "SHA512WITHECDSA" | "ECDSA_WITH_SHA512" => Ok(Self::EcdsaSha512),
            "SHA256WITHRSA/PSS" | "SHA256WITHRSAANDMGF1" => Ok(Self::RsaPssSha256),
            "SHA384WITHRSA/PSS" | "SHA384WITHRSAANDMGF1" => Ok(Self::RsaPssSha384),
            "SHA512WITHRSA/PSS" | "SHA512WITHRSAANDMGF1" => Ok(Self::RsaPssSha512),
            _ => Err(SignError::UnsupportedAlgorithm(value.to_owned())),
        }
    }
}
