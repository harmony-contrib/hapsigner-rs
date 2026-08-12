use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroize;

use crate::remote::SigningIdentity;
use crate::{ExternalSigner, SignError, SigningAlgorithm, SigningKey};

/// Fully loaded signing material consumed by [`crate::HapSigner`].
///
/// The core signer does not discover files or read project configuration. Build
/// systems may load or decrypt material however they need and inject the final
/// PKCS#8 key, certificate chain, and signed provisioning profile here.
pub struct SigningMaterial {
    pub(crate) signing_identity: SigningIdentity,
    pub(crate) signed_profile: Vec<u8>,
    pub(crate) profile_signed: bool,
    pub(crate) property: Option<Vec<u8>>,
    pub(crate) proof_of_rotation: Option<Vec<u8>>,
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

/// Borrowed JKS-or-PKCS#12 inputs corresponding to official local-sign
/// parameters. The keystore format is detected from its binary header rather
/// than from a platform-specific filename string.
pub struct KeystoreMaterial<'a> {
    pub keystore: &'a [u8],
    pub store_password: &'a str,
    pub key_alias: &'a str,
    pub key_password: &'a str,
    pub app_certificate_chain: &'a [u8],
    pub profile: Vec<u8>,
    pub profile_signed: bool,
    pub algorithm: SigningAlgorithm,
}

impl SigningMaterial {
    /// Construct material for the official ELF-only mode where `profileFile`
    /// is omitted. ZIP/HAP and BIN signing reject this material because those
    /// formats require a profile.
    pub fn without_profile(signing_key: SigningKey, algorithm: SigningAlgorithm) -> Self {
        Self {
            signing_identity: SigningIdentity::Local(signing_key),
            signed_profile: Vec::new(),
            profile_signed: true,
            property: None,
            proof_of_rotation: None,
            algorithm,
        }
    }

    /// Construct material from caller-owned DER/CMS bytes.
    pub fn from_der(
        private_key_der: Vec<u8>,
        certificate_chain_der: Vec<Vec<u8>>,
        signed_profile: Vec<u8>,
        algorithm: SigningAlgorithm,
    ) -> Result<Self, SignError> {
        Self::validate_non_empty(&private_key_der, &certificate_chain_der, &signed_profile)?;
        Ok(Self {
            signing_identity: SigningIdentity::Local(SigningKey {
                private_key_der,
                cert_chain: certificate_chain_der,
            }),
            signed_profile,
            profile_signed: true,
            property: None,
            proof_of_rotation: None,
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
            signing_identity: SigningIdentity::Local(signing_key),
            signed_profile: input.signed_profile,
            profile_signed: true,
            property: None,
            proof_of_rotation: None,
            algorithm: input.algorithm,
        })
    }

    /// Load either JKS or PKCS#12 local signing material.
    pub fn from_keystore(input: KeystoreMaterial<'_>) -> Result<Self, SignError> {
        if input.profile.is_empty() {
            return Err(SignError::EmptyMaterial("profile"));
        }
        let mut signing_key = SigningKey::from_keystore(
            input.keystore,
            input.store_password,
            input.key_alias,
            input.key_password,
        )?;
        signing_key.cert_chain = SigningKey::cert_chain_from_bytes(input.app_certificate_chain)?;
        let material = Self {
            signing_identity: SigningIdentity::Local(signing_key),
            signed_profile: input.profile,
            profile_signed: input.profile_signed,
            property: None,
            proof_of_rotation: None,
            algorithm: input.algorithm,
        };
        crate::profile_content::ProfileContent::from_profile(
            &material.signed_profile,
            material.profile_signed,
        )?;
        Ok(material)
    }

    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// Select the application-signing algorithm after the key and certificate
    /// material has been loaded. Key compatibility is validated when the CMS
    /// signer is constructed, matching official local-sign processing.
    pub fn with_algorithm(mut self, algorithm: SigningAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn certificate_chain(&self) -> &[Vec<u8>] {
        self.signing_identity.certificates()
    }

    /// Construct signing material backed by the same externally injected
    /// signer contract used by official `remoteSign` plugins.
    pub fn from_external(
        signer: Arc<dyn ExternalSigner>,
        profile: Vec<u8>,
        profile_signed: bool,
        algorithm: SigningAlgorithm,
    ) -> Result<Self, SignError> {
        if profile.is_empty() {
            return Err(SignError::EmptyMaterial("profile"));
        }
        crate::profile_content::ProfileContent::from_profile(&profile, profile_signed)?;
        Ok(Self {
            signing_identity: SigningIdentity::from_external(signer)?,
            signed_profile: profile,
            profile_signed,
            property: None,
            proof_of_rotation: None,
            algorithm,
        })
    }

    pub fn signed_profile(&self) -> &[u8] {
        &self.signed_profile
    }

    pub(crate) fn validate_profile_for_application_signing(&self) -> Result<(), SignError> {
        if self.signed_profile.is_empty() {
            return Err(SignError::EmptyMaterial("profile"));
        }
        crate::profile_content::ProfileContent::from_profile(
            &self.signed_profile,
            self.profile_signed,
        )?
        .validate_for_application_signing()
    }

    pub(crate) fn validate_optional_elf_profile(&self) -> Result<(), SignError> {
        if self.signed_profile.is_empty() {
            return Ok(());
        }
        self.validate_profile_for_application_signing()
    }

    /// Mark the supplied provisioning profile as unsigned JSON
    /// (`hap-sign-tool -profileSigned 0`).
    pub fn with_unsigned_profile(mut self) -> Result<Self, SignError> {
        crate::profile_content::ProfileContent::from_profile(&self.signed_profile, false)?;
        self.profile_signed = false;
        Ok(self)
    }

    /// Inject the optional property block supplied through official
    /// `hap-sign-tool -property`.
    pub fn with_property(mut self, property: Vec<u8>) -> Result<Self, SignError> {
        if property.is_empty() {
            return Err(SignError::EmptyMaterial("property block"));
        }
        self.property = Some(property);
        Ok(self)
    }

    /// Inject an upstream-compatible proof-of-rotation block. Official
    /// hapsigner loads this file verbatim; it does not synthesize it.
    pub fn with_proof_of_rotation(mut self, proof: Vec<u8>) -> Result<Self, SignError> {
        if proof.is_empty() {
            return Err(SignError::EmptyMaterial("proof-of-rotation block"));
        }
        self.proof_of_rotation = Some(proof);
        Ok(self)
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
    pub profile_signed: bool,
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
        SigningMaterial::from_keystore(KeystoreMaterial {
            keystore: &pkcs12,
            store_password: &self.store_password,
            key_alias: &self.key_alias,
            key_password: &self.key_password,
            app_certificate_chain: &certificates,
            profile,
            profile_signed: self.profile_signed,
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
