use std::sync::Arc;

use crate::remote::SigningIdentity;
use crate::{pkcs7, ExternalSigner, SignError, SigningAlgorithm, SigningKey};

/// Signs an unsigned provisioning-profile JSON document using the attached CMS
/// representation produced by official `sign-profile`.
pub struct ProfileSigner {
    signing_identity: SigningIdentity,
    algorithm: SigningAlgorithm,
}

impl ProfileSigner {
    pub fn new(signing_key: SigningKey, algorithm: SigningAlgorithm) -> Self {
        Self {
            signing_identity: SigningIdentity::Local(signing_key),
            algorithm,
        }
    }

    pub fn from_external(
        signer: Arc<dyn ExternalSigner>,
        algorithm: SigningAlgorithm,
    ) -> Result<Self, SignError> {
        Ok(Self {
            signing_identity: SigningIdentity::from_external(signer)?,
            algorithm,
        })
    }

    pub fn sign(&self, unsigned_profile: &[u8]) -> Result<Vec<u8>, SignError> {
        if unsigned_profile.is_empty() {
            return Err(SignError::EmptyMaterial("unsigned profile"));
        }
        pkcs7::build_cms_signed_data_with_identity(
            unsigned_profile,
            &self.signing_identity,
            self.algorithm.id(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileVerification {
    pub content: Vec<u8>,
    pub certificates: Vec<Vec<u8>>,
    pub algorithm: SigningAlgorithm,
}

/// Cryptographically verifies the CMS signature and embedded content produced
/// by official `sign-profile` or by [`ProfileSigner`].
pub struct ProfileVerifier;

impl ProfileVerifier {
    pub fn verify(signed_profile: &[u8]) -> Result<ProfileVerification, SignError> {
        let verified = pkcs7::verify_cms_signed_data(signed_profile)?;
        let certificates = SigningKey::normalize_profile_certificate_chain_at(
            verified.certificates,
            verified
                .signing_time
                .unwrap_or_else(std::time::SystemTime::now),
        )?;
        Ok(ProfileVerification {
            content: verified.content,
            certificates,
            algorithm: verified.algorithm,
        })
    }
}
