use std::sync::Arc;

use crate::{SignError, SigningAlgorithm, SigningKey};

/// Rust counterpart of official hapsigner's `ISigner` extension point.
///
/// Official hapsigner does not define a remote protocol. It loads an external
/// provider which signs the DER authenticated attributes and supplies its
/// certificate chain and optional CRLs. Integrations should implement this
/// trait rather than baking a transport into the signing core.
pub trait ExternalSigner: Send + Sync {
    fn sign(
        &self,
        authenticated_attributes_der: &[u8],
        algorithm: SigningAlgorithm,
    ) -> Result<Vec<u8>, SignError>;

    fn certificates(&self) -> Result<Vec<Vec<u8>>, SignError>;

    fn crls(&self) -> Result<Vec<Vec<u8>>, SignError> {
        Ok(Vec::new())
    }
}

pub(crate) enum SigningIdentity {
    Local(SigningKey),
    External {
        signer: Arc<dyn ExternalSigner>,
        certificates: Vec<Vec<u8>>,
        crls: Vec<Vec<u8>>,
    },
}

impl SigningIdentity {
    pub(crate) fn from_external(signer: Arc<dyn ExternalSigner>) -> Result<Self, SignError> {
        let certificates = signer.certificates()?;
        if certificates.is_empty() {
            return Err(SignError::NoCertificate);
        }
        let certificates = SigningKey::normalize_certificate_chain(certificates)?;
        let crls = signer.crls()?;
        Ok(Self::External {
            signer,
            certificates,
            crls,
        })
    }

    pub(crate) fn certificates(&self) -> &[Vec<u8>] {
        match self {
            Self::Local(signing_key) => &signing_key.cert_chain,
            Self::External { certificates, .. } => certificates,
        }
    }
}
