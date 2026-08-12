//! Development/QEMU signing adapter built on the reusable signing core.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use cms::builder::{create_signing_time_attribute, SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use der::asn1::Any;
use der::{Decode, Encode, EncodePem, Tag};
use p256::ecdsa::{DerSignature, SigningKey as EcdsaSigningKey};
use p256::pkcs8::DecodePrivateKey;
use serde_json::json;
use spki::AlgorithmIdentifierOwned;
use uuid::Uuid;
use x509_cert::Certificate;

use crate::{HapSigner, SignError, SignOptions, SigningAlgorithm, SigningMaterial};

const APP_KEY: &[u8] = include_bytes!("assets/app-key.pk8");
const PROFILE_KEY: &[u8] = include_bytes!("assets/profile-key.pk8");
const APP_LEAF: &[u8] = include_bytes!("assets/app-leaf.der");
const PROFILE_LEAF: &[u8] = include_bytes!("assets/profile-leaf.der");
const APP_CA: &[u8] = include_bytes!("assets/app-ca.der");
const APP_ROOT: &[u8] = include_bytes!("assets/app-root.der");

/// Parameters used to create the embedded debug provisioning profile.
#[derive(Clone, Debug)]
pub struct DevelopmentProfileOptions {
    pub bundle_name: String,
    pub apl: String,
    pub app_feature: String,
    pub allowed_acls: Vec<String>,
    pub restricted_permissions: Vec<String>,
    pub device_ids: Vec<String>,
    pub valid_days: u64,
}

impl Default for DevelopmentProfileOptions {
    fn default() -> Self {
        Self {
            bundle_name: String::new(),
            apl: "normal".into(),
            app_feature: "hos_normal_app".into(),
            allowed_acls: Vec::new(),
            restricted_permissions: Vec::new(),
            device_ids: vec!["*".into()],
            valid_days: 3650,
        }
    }
}

/// QEMU/local-development signer using the repository's public test identity.
///
/// The public credentials are intentionally isolated from [`HapSigner`].
/// Production consumers construct [`SigningMaterial`] from their own identity.
pub struct DevelopmentSigner {
    signer: HapSigner,
}

impl DevelopmentSigner {
    pub fn new(
        profile_options: DevelopmentProfileOptions,
        sign_options: SignOptions,
    ) -> Result<Self, SignError> {
        let material = DevelopmentMaterialBuilder::new(profile_options).build()?;
        Ok(Self {
            signer: HapSigner::new(material, sign_options),
        })
    }

    pub fn sign(&self, input: &[u8]) -> Result<Vec<u8>, SignError> {
        self.signer.sign(input)
    }

    pub fn sign_owned(&self, input: Vec<u8>) -> Result<Vec<u8>, SignError> {
        self.signer.sign_owned(input)
    }

    pub fn sign_file(&self, input: &Path, output: &Path) -> Result<(), SignError> {
        self.signer.sign_file(input, output)
    }
}

/// Creates injected [`SigningMaterial`] from the public OpenHarmony test
/// identity. This is useful for QEMU tooling and tests that exercise the same
/// reusable core as production callers.
pub struct DevelopmentMaterialBuilder {
    profile_options: DevelopmentProfileOptions,
}

impl DevelopmentMaterialBuilder {
    pub fn new(profile_options: DevelopmentProfileOptions) -> Self {
        Self { profile_options }
    }

    pub fn build(self) -> Result<SigningMaterial, SignError> {
        let profile_builder = DevelopmentProfileBuilder::new(self.profile_options);
        profile_builder.validate()?;
        let profile_json = profile_builder.build()?;
        let signed_profile =
            DevelopmentCmsSigner::new(PROFILE_KEY, PROFILE_LEAF).sign_attached(&profile_json)?;
        SigningMaterial::from_der(
            APP_KEY.to_vec(),
            vec![APP_LEAF.to_vec(), APP_CA.to_vec(), APP_ROOT.to_vec()],
            signed_profile,
            SigningAlgorithm::EcdsaSha256,
        )
    }
}

struct DevelopmentProfileBuilder {
    options: DevelopmentProfileOptions,
}

impl DevelopmentProfileBuilder {
    fn new(options: DevelopmentProfileOptions) -> Self {
        Self { options }
    }

    fn validate(&self) -> Result<(), SignError> {
        if self.options.bundle_name.trim().is_empty() {
            return Err(SignError::Config("bundle name must not be empty".into()));
        }
        if !matches!(
            self.options.apl.as_str(),
            "normal" | "system_basic" | "system_core"
        ) {
            return Err(SignError::Config(
                "APL must be normal, system_basic, or system_core".into(),
            ));
        }
        if !matches!(
            self.options.app_feature.as_str(),
            "hos_normal_app" | "hos_system_app"
        ) {
            return Err(SignError::Config(
                "app feature must be hos_normal_app or hos_system_app".into(),
            ));
        }
        if self.options.valid_days == 0 || self.options.valid_days > 3650 {
            return Err(SignError::Config(
                "valid days must be between 1 and 3650".into(),
            ));
        }
        if self.options.device_ids.is_empty()
            || self
                .options
                .device_ids
                .iter()
                .any(|device_id| device_id.trim().is_empty())
        {
            return Err(SignError::Config(
                "at least one non-empty device ID is required".into(),
            ));
        }
        Ok(())
    }

    fn build(self) -> Result<Vec<u8>, SignError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| SignError::Config(format!("invalid system clock: {error}")))?
            .as_secs();
        let validity = self
            .options
            .valid_days
            .checked_mul(86_400)
            .ok_or_else(|| SignError::Config("profile validity overflow".into()))?;
        let not_after = now
            .checked_add(validity)
            .ok_or_else(|| SignError::Config("profile validity overflow".into()))?;
        let application_certificate = Certificate::from_der(APP_LEAF)
            .and_then(|certificate| certificate.to_pem(der::pem::LineEnding::LF))
            .map_err(|error| SignError::DerError(error.to_string()))?;
        let allowed_acls = Self::non_empty_json_array(self.options.allowed_acls);
        let restricted_permissions =
            Self::non_empty_json_array(self.options.restricted_permissions);

        serde_json::to_vec(&json!({
            "version-name": "2.0.0",
            "version-code": 2,
            "uuid": Uuid::new_v4().to_string(),
            "validity": {
                "not-before": now.saturating_sub(300),
                "not-after": not_after
            },
            "type": "debug",
            "bundle-info": {
                "developer-id": "OpenHarmony",
                "development-certificate": application_certificate,
                "bundle-name": self.options.bundle_name,
                "apl": self.options.apl,
                "app-feature": self.options.app_feature
            },
            "acls": { "allowed-acls": allowed_acls },
            "permissions": { "restricted-permissions": restricted_permissions },
            "debug-info": {
                "device-ids": self.options.device_ids,
                "device-id-type": "udid"
            },
            "issuer": "pki_internal"
        }))
        .map_err(|error| SignError::Config(format!("serialize development profile: {error}")))
    }

    fn non_empty_json_array(values: Vec<String>) -> Vec<String> {
        if values.is_empty() {
            vec![String::new()]
        } else {
            values
        }
    }
}

struct DevelopmentCmsSigner<'a> {
    private_key: &'a [u8],
    leaf_certificate: &'a [u8],
}

impl<'a> DevelopmentCmsSigner<'a> {
    fn new(private_key: &'a [u8], leaf_certificate: &'a [u8]) -> Self {
        Self {
            private_key,
            leaf_certificate,
        }
    }

    fn sign_attached(&self, content: &[u8]) -> Result<Vec<u8>, SignError> {
        let secret = p256::SecretKey::from_pkcs8_der(self.private_key)
            .map_err(|error| SignError::Pkcs8Error(error.to_string()))?;
        let signer = EcdsaSigningKey::from(secret);
        let leaf = Certificate::from_der(self.leaf_certificate)
            .map_err(|error| SignError::DerError(error.to_string()))?;
        let ca = Certificate::from_der(APP_CA)
            .map_err(|error| SignError::DerError(error.to_string()))?;
        let root = Certificate::from_der(APP_ROOT)
            .map_err(|error| SignError::DerError(error.to_string()))?;
        let encapsulated = EncapsulatedContentInfo {
            econtent_type: const_oid::db::rfc5911::ID_DATA,
            econtent: Some(
                Any::new(Tag::OctetString, content.to_vec())
                    .map_err(|error| SignError::DerError(error.to_string()))?,
            ),
        };
        let digest_algorithm = AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };
        let signer_identifier = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: leaf.tbs_certificate.issuer.clone(),
            serial_number: leaf.tbs_certificate.serial_number.clone(),
        });
        let mut signer_info = SignerInfoBuilder::new(
            &signer,
            signer_identifier,
            digest_algorithm.clone(),
            &encapsulated,
            None,
        )
        .map_err(Self::cms_error)?;
        signer_info
            .add_signed_attribute(create_signing_time_attribute().map_err(Self::cms_error)?)
            .map_err(Self::cms_error)?;

        let mut builder = SignedDataBuilder::new(&encapsulated);
        builder
            .add_digest_algorithm(digest_algorithm)
            .map_err(Self::cms_error)?;
        for certificate in [leaf, ca, root] {
            builder
                .add_certificate(CertificateChoices::Certificate(certificate))
                .map_err(Self::cms_error)?;
        }
        builder
            .add_signer_info::<EcdsaSigningKey, DerSignature>(signer_info)
            .map_err(Self::cms_error)?;
        builder
            .build()
            .map_err(Self::cms_error)?
            .to_der()
            .map_err(|error| SignError::DerError(error.to_string()))
    }

    fn cms_error(error: cms::builder::Error) -> SignError {
        SignError::SigningFailed(error.to_string())
    }
}
