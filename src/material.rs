use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::{SignError, SigningAlgorithm, SigningKey};

/// Fully loaded signing material consumed by [`crate::HapSigner`].
///
/// The core signer does not discover files or read project configuration. Build
/// systems may load or decrypt material however they need and inject the final
/// PKCS#8 key, certificate chain, and signed provisioning profile here.
pub struct SigningMaterial {
    pub(crate) signing_key: SigningKey,
    pub(crate) signed_profile: Vec<u8>,
    pub(crate) algorithm: SigningAlgorithm,
}

/// Borrowed PKCS#12 inputs corresponding to Hvigor's local signing parameters.
pub struct Pkcs12Material<'a> {
    pub pkcs12: &'a [u8],
    pub store_password: &'a str,
    pub key_alias: &'a str,
    pub key_password: &'a str,
    pub app_certificate_chain: &'a [u8],
    pub signed_profile: Vec<u8>,
    pub algorithm: SigningAlgorithm,
}

impl SigningMaterial {
    /// Construct material from caller-owned DER/CMS bytes.
    pub fn from_der(
        private_key_der: Vec<u8>,
        certificate_chain_der: Vec<Vec<u8>>,
        signed_profile: Vec<u8>,
        algorithm: SigningAlgorithm,
    ) -> Result<Self, SignError> {
        Self::validate_non_empty(&private_key_der, &certificate_chain_der, &signed_profile)?;
        Ok(Self {
            signing_key: SigningKey {
                private_key_der,
                cert_chain: certificate_chain_der,
            },
            signed_profile,
            algorithm,
        })
    }

    /// Load a PKCS#12 key while accepting the app certificate chain and signed
    /// profile as caller-provided bytes.
    ///
    /// This mirrors Hvigor's `sign-app -mode localSign` inputs without tying the
    /// library to `build-profile.json5` or a particular filesystem layout.
    pub fn from_pkcs12(input: Pkcs12Material<'_>) -> Result<Self, SignError> {
        if input.signed_profile.is_empty() {
            return Err(SignError::EmptyMaterial("signed profile"));
        }
        let mut signing_key = SigningKey::from_pkcs12(
            input.pkcs12,
            input.store_password,
            input.key_alias,
            input.key_password,
        )?;
        signing_key.cert_chain = SigningKey::cert_chain_from_bytes(input.app_certificate_chain)?;
        Ok(Self {
            signing_key,
            signed_profile: input.signed_profile,
            algorithm: input.algorithm,
        })
    }

    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    pub fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.signing_key.cert_chain
    }

    pub fn signed_profile(&self) -> &[u8] {
        &self.signed_profile
    }

    fn validate_non_empty(
        private_key_der: &[u8],
        certificate_chain_der: &[Vec<u8>],
        signed_profile: &[u8],
    ) -> Result<(), SignError> {
        if private_key_der.is_empty() {
            return Err(SignError::EmptyMaterial("private key"));
        }
        if certificate_chain_der.is_empty()
            || certificate_chain_der
                .iter()
                .any(|certificate| certificate.is_empty())
        {
            return Err(SignError::EmptyMaterial("certificate chain"));
        }
        if signed_profile.is_empty() {
            return Err(SignError::EmptyMaterial("signed profile"));
        }
        Ok(())
    }
}

/// Filesystem-backed convenience loader corresponding to Hvigor's
/// `keystoreFile`, `profileFile`, and `appCertFile` parameters.
///
/// Password decryption remains the build system's responsibility. This loader
/// accepts plaintext values so consumers are not forced into DevEco's storage
/// convention.
pub struct FileSigningMaterial {
    pub keystore_path: PathBuf,
    pub profile_path: PathBuf,
    pub certificate_path: PathBuf,
    pub key_alias: Box<str>,
    pub store_password: Box<str>,
    pub key_password: Box<str>,
    pub algorithm: SigningAlgorithm,
}

impl Drop for FileSigningMaterial {
    fn drop(&mut self) {
        self.store_password.zeroize();
        self.key_password.zeroize();
    }
}

impl FileSigningMaterial {
    pub fn load(&self) -> Result<SigningMaterial, SignError> {
        let pkcs12 = self.read(&self.keystore_path)?;
        let profile = self.read(&self.profile_path)?;
        let certificates = self.read(&self.certificate_path)?;
        SigningMaterial::from_pkcs12(Pkcs12Material {
            pkcs12: &pkcs12,
            store_password: &self.store_password,
            key_alias: &self.key_alias,
            key_password: &self.key_password,
            app_certificate_chain: &certificates,
            signed_profile: profile,
            algorithm: self.algorithm,
        })
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, SignError> {
        fs_err::read(path).map_err(|source| SignError::IoPath {
            path: path.to_path_buf(),
            source,
        })
    }
}
