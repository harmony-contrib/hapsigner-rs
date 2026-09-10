//! X.509 certificate construction matching official `CertBuilder` and `CertTools`.
//!
//! The extension set, its ordering, and its criticality are reproduced from
//! upstream rather than from RFC 5280 defaults, so certificates produced here
//! are interchangeable with `hap-sign-tool.jar` output.
//!
//! Two upstream quirks are deliberately *not* reproduced, because every
//! official call path makes them unobservable:
//!
//! - `CertBuilder.withBasicConstraints` passes the *criticality* flag where the
//!   CA flag belongs for end-entity certificates. `CertTools.generateEndCert`
//!   always passes `false`, so end-entity certificates always carry a bare,
//!   non-critical `BasicConstraints` sequence. This module encodes that
//!   outcome directly.
//! - `CertTools.generateCert` is called with `CertLevel.ROOT_CA`, so
//!   `withAuthorityKeyIdentifier` is a no-op and the certificate carries no
//!   `authorityKeyIdentifier`. This module reproduces that by only emitting an
//!   authority key identifier for [`CertificateLevel::SubCa`].

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use const_oid::db::rfc5912::{ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512};
use const_oid::db::rfc5912::{
    SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use const_oid::ObjectIdentifier;
use der::asn1::{BitString, GeneralizedTime, OctetString, UtcTime};
use der::Encode;
use sha1::{Digest, Sha1};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use crate::error::SignError;

/// Vendor extension carrying the OpenHarmony signing capability.
pub const CERTIFICATE_SIGNING_CAPABILITY_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2011.2.376.1.3");

/// Payload of the signing-capability extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningCapability {
    /// `SignToolServiceImpl.APP_SIGNING_CAPABILITY`.
    Application,
    /// `SignToolServiceImpl.PROFILE_SIGNING_CAPABILITY`.
    Profile,
}

impl SigningCapability {
    /// The raw extension value, already DER encoded upstream.
    pub const fn value(self) -> &'static [u8] {
        match self {
            Self::Application => &[0x30, 0x06, 0x02, 0x01, 0x01, 0x0a, 0x01, 0x00],
            Self::Profile => &[0x30, 0x06, 0x02, 0x01, 0x01, 0x0a, 0x01, 0x01],
        }
    }
}

/// Certificate role, mirroring official `CertLevel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateLevel {
    /// Self-signed trust anchor.
    RootCa,
    /// Intermediate CA issued by another CA.
    SubCa,
    /// End-entity certificate.
    EndEntity,
}

/// Signature algorithm accepted by `CertUtils.createFixedContentSigner`.
///
/// This is distinct from [`crate::SigningAlgorithm`]: certificate and CSR
/// issuance uses RSA PKCS#1 v1.5, while HAP signing uses RSA-PSS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateSignatureAlgorithm {
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    RsaSha256,
    RsaSha384,
    RsaSha512,
}

impl CertificateSignatureAlgorithm {
    /// Canonical `SHA256withECDSA` spelling used on the command line.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaSha256 => "SHA256withECDSA",
            Self::EcdsaSha384 => "SHA384withECDSA",
            Self::EcdsaSha512 => "SHA512withECDSA",
            Self::RsaSha256 => "SHA256withRSA",
            Self::RsaSha384 => "SHA384withRSA",
            Self::RsaSha512 => "SHA512withRSA",
        }
    }

    /// Algorithm identifier placed in the TBS and `Certificate` signatures.
    ///
    /// BouncyCastle emits an absent `parameters` field for the ECDSA
    /// identifiers and an explicit NULL for RSA PKCS#1 v1.5.
    pub fn algorithm_identifier(self) -> AlgorithmIdentifierOwned {
        let oid = match self {
            Self::EcdsaSha256 => ECDSA_WITH_SHA_256,
            Self::EcdsaSha384 => ECDSA_WITH_SHA_384,
            Self::EcdsaSha512 => ECDSA_WITH_SHA_512,
            Self::RsaSha256 => SHA_256_WITH_RSA_ENCRYPTION,
            Self::RsaSha384 => SHA_384_WITH_RSA_ENCRYPTION,
            Self::RsaSha512 => SHA_512_WITH_RSA_ENCRYPTION,
        };
        AlgorithmIdentifierOwned {
            oid,
            parameters: Some(der::Any::from(der::asn1::Null)).filter(|_| !self.is_ecdsa()),
        }
    }

    pub const fn is_ecdsa(self) -> bool {
        matches!(
            self,
            Self::EcdsaSha256 | Self::EcdsaSha384 | Self::EcdsaSha512
        )
    }

    /// Reproduce `CertUtils.createFixedContentSigner`'s silent correction of a
    /// signature algorithm that does not match the signing key's type.
    pub fn corrected_for(self, key: &SigningKeyKind) -> Self {
        match (key, self.is_ecdsa()) {
            (SigningKeyKind::Ecc, false) => match self {
                Self::RsaSha256 => Self::EcdsaSha256,
                Self::RsaSha384 => Self::EcdsaSha384,
                Self::RsaSha512 => Self::EcdsaSha512,
                ecdsa => ecdsa,
            },
            (SigningKeyKind::Rsa, true) => match self {
                Self::EcdsaSha256 => Self::RsaSha256,
                Self::EcdsaSha384 => Self::RsaSha384,
                Self::EcdsaSha512 => Self::RsaSha512,
                rsa => rsa,
            },
            _ => self,
        }
    }
}

impl std::fmt::Display for CertificateSignatureAlgorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CertificateSignatureAlgorithm {
    type Err = SignError;

    /// Only the `SHAxxxwithECDSA` / `SHAxxxwithRSA` shape accepted by
    /// `CertUtils.SIGN_ALGORITHM_PATTERN` parses here.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "SHA256withECDSA" => Ok(Self::EcdsaSha256),
            "SHA384withECDSA" => Ok(Self::EcdsaSha384),
            "SHA512withECDSA" => Ok(Self::EcdsaSha512),
            "SHA256withRSA" => Ok(Self::RsaSha256),
            "SHA384withRSA" => Ok(Self::RsaSha384),
            "SHA512withRSA" => Ok(Self::RsaSha512),
            other => Err(SignError::UnsupportedAlgorithm(other.to_owned())),
        }
    }
}

/// Public-key family of a signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKeyKind {
    Rsa,
    Ecc,
}

/// A private key capable of issuing certificates and certification requests.
pub struct IssuingKey {
    kind: SigningKeyKind,
    material: IssuingKeyMaterial,
}

enum IssuingKeyMaterial {
    EcdsaP256(Box<p256::ecdsa::SigningKey>),
    EcdsaP384(Box<p384::ecdsa::SigningKey>),
    Rsa(Box<rsa::RsaPrivateKey>),
}

impl IssuingKey {
    /// Wrap an existing PKCS#8 DER private key.
    pub fn from_pkcs8_der(private_key_der: &[u8]) -> Result<Self, SignError> {
        use pkcs8::DecodePrivateKey;

        let info = pkcs8::PrivateKeyInfo::try_from(private_key_der)
            .map_err(|error| SignError::Pkcs8Error(error.to_string()))?;
        let algorithm = info.algorithm.oid;

        if algorithm == const_oid::db::rfc5912::RSA_ENCRYPTION {
            let key = rsa::RsaPrivateKey::from_pkcs8_der(private_key_der)
                .map_err(|error| SignError::Pkcs8Error(error.to_string()))?;
            return Ok(Self {
                kind: SigningKeyKind::Rsa,
                material: IssuingKeyMaterial::Rsa(Box::new(key)),
            });
        }
        if algorithm == const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
            let curve = info
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
                .ok_or_else(|| {
                    SignError::Pkcs8Error(
                        "EC private key without named-curve parameters".to_owned(),
                    )
                })?;
            if curve == const_oid::db::rfc5912::SECP_256_R_1 {
                let key = p256::SecretKey::from_pkcs8_der(private_key_der)
                    .map_err(|error| SignError::Pkcs8Error(error.to_string()))?;
                return Ok(Self {
                    kind: SigningKeyKind::Ecc,
                    material: IssuingKeyMaterial::EcdsaP256(Box::new(key.into())),
                });
            }
            if curve == const_oid::db::rfc5912::SECP_384_R_1 {
                let key = p384::SecretKey::from_pkcs8_der(private_key_der)
                    .map_err(|error| SignError::Pkcs8Error(error.to_string()))?;
                return Ok(Self {
                    kind: SigningKeyKind::Ecc,
                    material: IssuingKeyMaterial::EcdsaP384(Box::new(key.into())),
                });
            }
            return Err(SignError::Pkcs8Error(format!(
                "unsupported EC curve {curve}"
            )));
        }
        Err(SignError::Pkcs8Error(format!(
            "unsupported private key algorithm {algorithm}"
        )))
    }

    pub fn kind(&self) -> SigningKeyKind {
        self.kind
    }

    /// The corresponding SubjectPublicKeyInfo, used for key identifiers.
    pub fn public_key_der(&self) -> Result<Vec<u8>, SignError> {
        use pkcs8::EncodePublicKey;

        let der = match &self.material {
            IssuingKeyMaterial::EcdsaP256(key) => key
                .verifying_key()
                .to_public_key_der()
                .map_err(|error| SignError::DerError(error.to_string()))?,
            IssuingKeyMaterial::EcdsaP384(key) => key
                .verifying_key()
                .to_public_key_der()
                .map_err(|error| SignError::DerError(error.to_string()))?,
            IssuingKeyMaterial::Rsa(key) => rsa::RsaPublicKey::from(key.as_ref())
                .to_public_key_der()
                .map_err(|error| SignError::DerError(error.to_string()))?,
        };
        Ok(der.as_bytes().to_vec())
    }

    pub(crate) fn sign(
        &self,
        message: &[u8],
        algorithm: CertificateSignatureAlgorithm,
    ) -> Result<Vec<u8>, SignError> {
        use signature::Signer;

        match &self.material {
            IssuingKeyMaterial::EcdsaP256(key) => {
                let signature: p256::ecdsa::DerSignature = key
                    .try_sign(message)
                    .map_err(|error| SignError::SigningFailed(error.to_string()))?;
                Ok(signature.to_bytes().to_vec())
            }
            IssuingKeyMaterial::EcdsaP384(key) => {
                let signature: p384::ecdsa::DerSignature = key
                    .try_sign(message)
                    .map_err(|error| SignError::SigningFailed(error.to_string()))?;
                Ok(signature.to_bytes().to_vec())
            }
            IssuingKeyMaterial::Rsa(key) => {
                use sha2::Digest;

                // `RsaPrivateKey::sign` consumes a DigestInfo-prefixed digest,
                // so the message is hashed here.
                let (padding, digest) = match algorithm {
                    CertificateSignatureAlgorithm::RsaSha256 => (
                        rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                        sha2::Sha256::digest(message).to_vec(),
                    ),
                    CertificateSignatureAlgorithm::RsaSha384 => (
                        rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                        sha2::Sha384::digest(message).to_vec(),
                    ),
                    CertificateSignatureAlgorithm::RsaSha512 => (
                        rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
                        sha2::Sha512::digest(message).to_vec(),
                    ),
                    ecdsa => {
                        return Err(SignError::SigningFailed(format!(
                            "RSA key cannot sign with {ecdsa}"
                        )));
                    }
                };
                key.sign(padding, &digest)
                    .map_err(|error| SignError::SigningFailed(error.to_string()))
            }
        }
    }
}

/// Everything needed to issue one certificate.
pub struct CertificateParameters {
    pub level: CertificateLevel,
    /// Signature algorithm before key-type correction.
    pub signature_algorithm: CertificateSignatureAlgorithm,
    pub issuer: Name,
    pub subject: Name,
    pub subject_public_key: SubjectPublicKeyInfoOwned,
    pub validity_days: u64,
    /// Random 32-bit serial when absent, matching `CertUtils.randomSerial()`.
    pub serial_number: Option<Vec<u8>>,
    /// Issuer public key, required for and only used by [`CertificateLevel::SubCa`].
    pub authority_public_key: Option<SubjectPublicKeyInfoOwned>,
    pub basic_constraints_critical: bool,
    pub basic_constraints_ca: bool,
    /// `None` omits `pathLenConstraint`; official callers always supply `0`.
    pub basic_constraints_path_len: Option<u32>,
    pub key_usage: KeyUsage,
    pub key_usage_critical: bool,
    /// `None` omits the extension; `Some(vec![])` emits an empty one, which is
    /// what `generate-cert` does when `-extKeyUsage` is not given.
    pub extended_key_usage: Option<Vec<ObjectIdentifier>>,
    pub extended_key_usage_critical: bool,
    pub signing_capability: Option<SigningCapability>,
}

/// Issue a certificate with the issuer's private key.
pub fn build_certificate(
    parameters: &CertificateParameters,
    issuer_key: &IssuingKey,
) -> Result<Vec<u8>, SignError> {
    let signature_algorithm = parameters
        .signature_algorithm
        .corrected_for(&issuer_key.kind());
    let algorithm_identifier = signature_algorithm.algorithm_identifier();

    let serial_number = match &parameters.serial_number {
        Some(serial) => serial.clone(),
        None => crate::cert_tools::random_serial_bytes()
            .map_err(|error| SignError::CertificateBuild(error.to_string()))?,
    };
    let serial_number = SerialNumber::new(&serial_number)
        .map_err(|error| SignError::CertificateBuild(format!("serial number: {error}")))?;

    let now = SystemTime::now();
    let not_after = now
        .checked_add(Duration::from_secs(
            parameters
                .validity_days
                .checked_mul(86_400)
                .ok_or_else(|| SignError::CertificateBuild("validity overflow".to_owned()))?,
        ))
        .ok_or_else(|| SignError::CertificateBuild("validity overflow".to_owned()))?;
    let validity = Validity {
        not_before: rfc5280_time(now)?,
        not_after: rfc5280_time(not_after)?,
    };

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number,
        signature: algorithm_identifier.clone(),
        issuer: parameters.issuer.clone(),
        validity,
        subject: parameters.subject.clone(),
        subject_public_key_info: parameters.subject_public_key.clone(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(build_extensions(parameters)?),
    };

    let tbs_der = tbs
        .to_der()
        .map_err(|error| SignError::CertificateBuild(error.to_string()))?;
    let signature = issuer_key.sign(&tbs_der, signature_algorithm)?;

    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm_identifier,
        signature: BitString::from_bytes(&signature)
            .map_err(|error| SignError::CertificateBuild(error.to_string()))?,
    }
    .to_der()
    .map_err(|error| SignError::CertificateBuild(error.to_string()))
}

fn build_extensions(parameters: &CertificateParameters) -> Result<Vec<Extension>, SignError> {
    let mut extensions = Vec::with_capacity(6);

    // `CertBuilder`'s constructor always adds subjectKeyIdentifier first.
    extensions.push(extension(
        const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
        false,
        &x509_cert::ext::pkix::SubjectKeyIdentifier(
            OctetString::new(key_identifier(&parameters.subject_public_key)?)
                .map_err(|error| SignError::CertificateBuild(error.to_string()))?,
        )
        .to_der()
        .map_err(|error| SignError::CertificateBuild(error.to_string()))?,
    )?);

    // `withAuthorityKeyIdentifier` is a no-op for every level except SUB_CA.
    if parameters.level == CertificateLevel::SubCa {
        let issuer_public_key = parameters.authority_public_key.as_ref().ok_or_else(|| {
            SignError::CertificateBuild(
                "a sub-CA certificate requires the issuer public key".into(),
            )
        })?;
        extensions.push(extension(
            const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
            false,
            &AuthorityKeyIdentifier {
                key_identifier: Some(
                    OctetString::new(key_identifier(issuer_public_key)?)
                        .map_err(|error| SignError::CertificateBuild(error.to_string()))?,
                ),
                ..Default::default()
            }
            .to_der()
            .map_err(|error| SignError::CertificateBuild(error.to_string()))?,
        )?);
    }

    let basic_constraints = match parameters.level {
        CertificateLevel::EndEntity => BasicConstraints {
            ca: false,
            path_len_constraint: None,
        },
        // `BasicConstraints(int pathLenConstraint)` sets CA:TRUE implicitly, so
        // supplying a path length overrides the `basicConstraintsCa` flag the
        // way upstream's `pathLen == null ? ... : ...` branch does.
        _ => match parameters.basic_constraints_path_len {
            Some(path_len) => BasicConstraints {
                ca: true,
                path_len_constraint: Some(u8::try_from(path_len).map_err(|_| {
                    SignError::CertificateBuild(format!(
                        "basicConstraints path length {path_len} exceeds 255"
                    ))
                })?),
            },
            None => BasicConstraints {
                ca: parameters.basic_constraints_ca,
                path_len_constraint: None,
            },
        },
    };
    extensions.push(extension(
        const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
        parameters.basic_constraints_critical,
        &basic_constraints
            .to_der()
            .map_err(|error| SignError::CertificateBuild(error.to_string()))?,
    )?);

    extensions.push(extension(
        const_oid::db::rfc5280::ID_CE_KEY_USAGE,
        parameters.key_usage_critical,
        &parameters
            .key_usage
            .to_der()
            .map_err(|error| SignError::CertificateBuild(error.to_string()))?,
    )?);

    if let Some(extended) = &parameters.extended_key_usage {
        extensions.push(extension(
            const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE,
            parameters.extended_key_usage_critical,
            &ExtendedKeyUsage(extended.clone())
                .to_der()
                .map_err(|error| SignError::CertificateBuild(error.to_string()))?,
        )?);
    }

    if let Some(capability) = parameters.signing_capability {
        extensions.push(extension(
            CERTIFICATE_SIGNING_CAPABILITY_OID,
            false,
            capability.value(),
        )?);
    }

    Ok(extensions)
}

fn extension(oid: ObjectIdentifier, critical: bool, value: &[u8]) -> Result<Extension, SignError> {
    Ok(Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value)
            .map_err(|error| SignError::CertificateBuild(error.to_string()))?,
    })
}

/// RFC 5280 method (1): SHA-1 over the `subjectPublicKey` BIT STRING bits.
fn key_identifier(public_key: &SubjectPublicKeyInfoOwned) -> Result<Vec<u8>, SignError> {
    let mut hasher = Sha1::new();
    hasher.update(public_key.subject_public_key.raw_bytes());
    Ok(hasher.finalize().to_vec())
}

/// Encode a timestamp the way RFC 5280 requires: UTCTime through 2049,
/// GeneralizedTime beyond. `Time::try_from(SystemTime)` always produces
/// GeneralizedTime, so the conversion is applied here.
fn rfc5280_time(value: SystemTime) -> Result<Time, SignError> {
    let generalized = GeneralizedTime::try_from(value)
        .map_err(|error| SignError::CertificateBuild(format!("validity: {error}")))?;
    let date_time = generalized.to_date_time();
    if date_time.year() <= UtcTime::MAX_YEAR {
        return Ok(Time::UtcTime(UtcTime::from_date_time(date_time).map_err(
            |error| SignError::CertificateBuild(format!("validity: {error}")),
        )?));
    }
    Ok(Time::GeneralTime(generalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_the_official_signature_algorithm_shape() {
        assert_eq!(
            CertificateSignatureAlgorithm::from_str("SHA256withECDSA").unwrap(),
            CertificateSignatureAlgorithm::EcdsaSha256
        );
        // `CertUtils.SIGN_ALGORITHM_PATTERN` rejects PSS and MGf1 spellings.
        for rejected in [
            "SHA256withRSA/PSS",
            "SHA256withRSAANDMGF1",
            "sha256withecdsa",
        ] {
            assert!(
                CertificateSignatureAlgorithm::from_str(rejected).is_err(),
                "{rejected} must be rejected"
            );
        }
    }

    #[test]
    fn corrects_signature_algorithm_for_the_signing_key_type() {
        assert_eq!(
            CertificateSignatureAlgorithm::RsaSha256.corrected_for(&SigningKeyKind::Ecc),
            CertificateSignatureAlgorithm::EcdsaSha256
        );
        assert_eq!(
            CertificateSignatureAlgorithm::EcdsaSha384.corrected_for(&SigningKeyKind::Rsa),
            CertificateSignatureAlgorithm::RsaSha384
        );
        assert_eq!(
            CertificateSignatureAlgorithm::EcdsaSha256.corrected_for(&SigningKeyKind::Ecc),
            CertificateSignatureAlgorithm::EcdsaSha256
        );
    }

    #[test]
    fn signing_capability_payloads_match_upstream() {
        assert_eq!(
            SigningCapability::Application.value(),
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x0a, 0x01, 0x00]
        );
        assert_eq!(
            SigningCapability::Profile.value(),
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x0a, 0x01, 0x01]
        );
    }

    #[test]
    fn rfc5280_time_uses_utc_time_before_2050() {
        let time = rfc5280_time(std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000))
            .expect("timestamp");
        assert!(matches!(time, Time::UtcTime(_)));
    }

    #[test]
    fn rejects_a_private_key_that_is_not_pkcs8() {
        let error = IssuingKey::from_pkcs8_der(&[0x30, 0x00])
            .err()
            .expect("malformed PKCS#8 must be rejected");
        assert!(matches!(error, SignError::Pkcs8Error(_)));
    }
}
