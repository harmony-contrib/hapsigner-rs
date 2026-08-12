//! Build a CMS SignedData DER structure for HAP signing.
//!
//! Built manually using the `der` crate's `Encode` trait for x509 types.
//! The `cms` builder feature is intentionally avoided to keep dependency
//! surface small.
//!
//! Reference: RFC 5652 (CMS), `developtools_hapsigner` `BcPkcs7Generator.java`.

use crate::error::SignError;
use crate::remote::SigningIdentity;
use crate::{ContentDigestAlgorithm, SigningAlgorithm};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use sha2::{Sha256, Sha384, Sha512};
use std::sync::Arc;
use std::time::SystemTime;
use x509_cert::Certificate;

// ---------------------------------------------------------------------------
// Hard-coded OID DER bytes (tag 0x06 + length + content)
// These are verbatim BER/DER encodings of the well-known OIDs.
// ---------------------------------------------------------------------------

/// `id-data` (1.2.840.113549.1.7.1)
const OID_ID_DATA: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
];

/// `id-signedData` (1.2.840.113549.1.7.2)
const OID_ID_SIGNED_DATA: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
];

/// `id-sha256` (2.16.840.1.101.3.4.2.1)
const OID_SHA256: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];

/// `id-sha384` (2.16.840.1.101.3.4.2.2)
const OID_SHA384: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
];

/// `id-sha512` (2.16.840.1.101.3.4.2.3)
const OID_SHA512: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
];

/// `id-ecdsaWithSHA256` (1.2.840.10045.4.3.2)
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// `id-ecdsaWithSHA384` (1.2.840.10045.4.3.3)
const OID_ECDSA_WITH_SHA384: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

/// `id-ecdsaWithSHA512` (1.2.840.10045.4.3.4)
const OID_ECDSA_WITH_SHA512: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];

/// `id-RSASSA-PSS` (1.2.840.113549.1.1.10)
const OID_RSASSA_PSS: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
];

/// `id-mgf1` (1.2.840.113549.1.1.8)
const OID_MGF1: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
];

/// `id-contentType` (1.2.840.113549.1.9.3)
const OID_CONTENT_TYPE: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03,
];

/// `id-signingTime` (1.2.840.113549.1.9.5)
const OID_SIGNING_TIME: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05,
];

/// `id-messageDigest` (1.2.840.113549.1.9.4)
const OID_MESSAGE_DIGEST: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
];

/// hapsigner code-sign ownerID (1.3.6.1.4.1.2011.2.376.1.4.1)
const OID_CODE_SIGN_OWNER_ID: &[u8] = &[
    0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x01, 0x04, 0x01,
];

/// hapsigner code-sign pluginId (1.3.6.1.4.1.2011.2.376.1.4.2)
const OID_CODE_SIGN_PLUGIN_ID: &[u8] = &[
    0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x01, 0x04, 0x02,
];

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const ID_CODE_SIGN_OWNER_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2011.2.376.1.4.1");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const ID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const ID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ID_ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ID_ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

#[derive(Debug, Clone, Copy)]
struct CodeSignAttributes<'a> {
    owner_id: Option<&'a str>,
    plugin_id: Option<&'a str>,
}

pub(crate) struct CodeSignSignedDataBuilder {
    signer: CmsSigningContext,
}

struct CmsSigningContext {
    issuer_and_serial: Vec<u8>,
    certificates: Vec<u8>,
    signature_algorithm: Vec<u8>,
    signature_source: CmsSignatureSource,
    verifier: SignatureVerifier,
    algorithm: SigningAlgorithm,
    crls: Option<Vec<u8>>,
}

enum CmsPrivateKey {
    EcdsaP256(p256::ecdsa::SigningKey),
    EcdsaP384(p384::ecdsa::SigningKey),
    RsaPss(Box<rsa::RsaPrivateKey>),
}

enum CmsSignatureSource {
    Local(CmsPrivateKey),
    External(Arc<dyn crate::ExternalSigner>),
}

enum SignatureVerifier {
    EcdsaP256(p256::ecdsa::VerifyingKey),
    EcdsaP384(p384::ecdsa::VerifyingKey),
    RsaPss(rsa::RsaPublicKey),
}

pub(crate) struct VerifiedCms {
    pub(crate) content: Vec<u8>,
    pub(crate) certificates: Vec<Vec<u8>>,
    pub(crate) algorithm: SigningAlgorithm,
    pub(crate) signing_time: Option<SystemTime>,
    pub(crate) owner_id: Option<String>,
}

// ---------------------------------------------------------------------------
// DER helper namespace
// ---------------------------------------------------------------------------

/// Namespace for DER primitive helpers and signing helpers.
///
/// All methods are static (no `self`); the struct is never instantiated.
struct Der;

impl Der {
    // -----------------------------------------------------------------------
    // ASN.1 / DER primitives
    // -----------------------------------------------------------------------

    /// Encode an ASN.1 length field.
    fn encode_length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len <= 0xFF {
            vec![0x81, len as u8]
        } else if len <= 0xFFFF {
            vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
        } else if len <= 0xFFFFFF {
            vec![
                0x83,
                (len >> 16) as u8,
                (len >> 8) as u8,
                (len & 0xFF) as u8,
            ]
        } else {
            vec![
                0x84,
                (len >> 24) as u8,
                (len >> 16) as u8,
                (len >> 8) as u8,
                (len & 0xFF) as u8,
            ]
        }
    }

    /// Wrap `data` in a DER TLV with the given tag.
    fn tlv(tag: u8, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + 4 + data.len());
        result.push(tag);
        result.extend_from_slice(&Der::encode_length(data.len()));
        result.extend_from_slice(data);
        result
    }

    /// Build a SEQUENCE TLV.
    #[inline]
    fn sequence(inner: &[u8]) -> Vec<u8> {
        Der::tlv(0x30, inner)
    }

    /// Build a SET TLV.
    #[inline]
    fn set(inner: &[u8]) -> Vec<u8> {
        Der::tlv(0x31, inner)
    }

    /// Build a context-tagged IMPLICIT TLV (e.g., `[0] IMPLICIT`).
    #[inline]
    fn implicit_ctx(tag_num: u8, inner: &[u8]) -> Vec<u8> {
        Der::tlv(0xA0 | tag_num, inner)
    }

    /// Build a context-tagged EXPLICIT TLV (e.g., `[0] EXPLICIT`).
    #[inline]
    fn explicit_ctx(tag_num: u8, inner: &[u8]) -> Vec<u8> {
        // Explicit: constructed bit (0x20) + context class (0x80) + tag number
        Der::tlv(0xA0 | 0x20 | tag_num, inner)
    }

    /// Encode an OCTET STRING TLV.
    #[inline]
    fn octet_string(bytes: &[u8]) -> Vec<u8> {
        Der::tlv(0x04, bytes)
    }

    /// Encode a DER UTF8String TLV.
    #[inline]
    fn utf8_string(value: &str) -> Vec<u8> {
        Der::tlv(0x0c, value.as_bytes())
    }

    /// Encode `INTEGER 1` as DER.
    fn integer_one() -> Vec<u8> {
        vec![0x02, 0x01, 0x01]
    }

    fn integer_u8(value: u8) -> Vec<u8> {
        vec![0x02, 0x01, value]
    }

    /// Concatenate multiple byte slices.
    fn concat(parts: &[&[u8]]) -> Vec<u8> {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut result = Vec::with_capacity(total);
        for p in parts {
            result.extend_from_slice(p);
        }
        result
    }

    // -----------------------------------------------------------------------
    // UTC time formatting (no external dependency)
    // -----------------------------------------------------------------------

    /// Format the current UTC time as a DER UTCTime TLV (tag 0x17).
    fn current_utctime_der() -> Vec<u8> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (year, month, day, hour, min, sec) = Der::unix_secs_to_utc(secs);
        let yy = year % 100;
        let s = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            yy, month, day, hour, min, sec
        );
        Der::tlv(0x17, s.as_bytes())
    }

    fn unix_secs_to_utc(mut secs: u64) -> (u32, u8, u8, u8, u8, u8) {
        let second = (secs % 60) as u8;
        secs /= 60;
        let minute = (secs % 60) as u8;
        secs /= 60;
        let hour = (secs % 24) as u8;
        let mut days = (secs / 24) as u32;

        let mut year = 1970u32;
        loop {
            let diy = Der::days_in_year(year);
            if days < diy {
                break;
            }
            days -= diy;
            year += 1;
        }

        let leap = Der::is_leap_year(year);
        let month_lens: [u32; 12] = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let mut month = 1u8;
        for (i, &ml) in month_lens.iter().enumerate() {
            if days < ml {
                month = (i + 1) as u8;
                break;
            }
            days -= ml;
        }
        let day = (days + 1) as u8;
        (year, month, day, hour, minute, second)
    }

    fn is_leap_year(y: u32) -> bool {
        y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
    }

    fn days_in_year(y: u32) -> u32 {
        if Der::is_leap_year(y) {
            366
        } else {
            365
        }
    }

    // -----------------------------------------------------------------------
    // Signing
    // -----------------------------------------------------------------------

    fn digest_oid(algorithm: ContentDigestAlgorithm) -> &'static [u8] {
        match algorithm {
            ContentDigestAlgorithm::Sha256 => OID_SHA256,
            ContentDigestAlgorithm::Sha384 => OID_SHA384,
            ContentDigestAlgorithm::Sha512 => OID_SHA512,
        }
    }

    fn digest_algorithm_identifier(algorithm: ContentDigestAlgorithm) -> Vec<u8> {
        Der::sequence(&Der::concat(&[Self::digest_oid(algorithm), &[0x05, 0x00]]))
    }

    fn rsa_pss_params(algorithm: ContentDigestAlgorithm) -> Vec<u8> {
        let digest_algorithm = Self::digest_algorithm_identifier(algorithm);
        let mgf1_algorithm = Der::sequence(&Der::concat(&[OID_MGF1, &digest_algorithm]));
        Der::sequence(&Der::concat(&[
            &Der::explicit_ctx(0, &digest_algorithm),
            &Der::explicit_ctx(1, &mgf1_algorithm),
            &Der::explicit_ctx(2, &Der::integer_u8(algorithm.output_size() as u8)),
        ]))
    }

    fn digest(algorithm: ContentDigestAlgorithm, content: &[u8]) -> Vec<u8> {
        algorithm.digest(content)
    }
}

impl CodeSignSignedDataBuilder {
    pub(crate) fn from_identity(
        identity: &SigningIdentity,
        alg_id: u32,
    ) -> Result<Self, SignError> {
        Ok(Self {
            signer: CmsSigningContext::from_identity(identity, alg_id)?,
        })
    }

    pub(crate) fn build(
        &self,
        content: &[u8],
        owner_id: Option<&str>,
        plugin_id: Option<&str>,
    ) -> Result<Vec<u8>, SignError> {
        self.signer.build_signed_data(
            content,
            false,
            Some(CodeSignAttributes {
                owner_id,
                plugin_id,
            }),
        )
    }
}

impl CmsSigningContext {
    fn new(private_key_der: &[u8], cert_chain: &[Vec<u8>], alg_id: u32) -> Result<Self, SignError> {
        let algorithm = SigningAlgorithm::from_id(alg_id).ok_or_else(|| {
            SignError::Config(format!(
                "unsupported HAP signature algorithm id: 0x{alg_id:x}"
            ))
        })?;
        let private_key = Self::load_private_key(private_key_der, algorithm)?;
        Self::from_source(
            CmsSignatureSource::Local(private_key),
            cert_chain,
            &[],
            algorithm,
        )
    }

    fn from_identity(identity: &SigningIdentity, alg_id: u32) -> Result<Self, SignError> {
        let algorithm = SigningAlgorithm::from_id(alg_id).ok_or_else(|| {
            SignError::Config(format!(
                "unsupported HAP signature algorithm id: 0x{alg_id:x}"
            ))
        })?;
        match identity {
            SigningIdentity::Local(signing_key) => Self::new(
                &signing_key.private_key_der,
                &signing_key.cert_chain,
                alg_id,
            ),
            SigningIdentity::External {
                signer,
                certificates,
                crls,
            } => Self::from_source(
                CmsSignatureSource::External(Arc::clone(signer)),
                certificates,
                crls,
                algorithm,
            ),
        }
    }

    fn from_source(
        signature_source: CmsSignatureSource,
        cert_chain: &[Vec<u8>],
        crls: &[Vec<u8>],
        algorithm: SigningAlgorithm,
    ) -> Result<Self, SignError> {
        if cert_chain.is_empty() {
            return Err(SignError::NoCertificate);
        }

        let leaf_cert = Certificate::from_der(&cert_chain[0])
            .map_err(|e| SignError::DerError(format!("cert parse: {e}")))?;
        let issuer_der = leaf_cert
            .tbs_certificate
            .issuer
            .to_der()
            .map_err(|e| SignError::DerError(format!("issuer encode: {e}")))?;
        let serial_der = leaf_cert
            .tbs_certificate
            .serial_number
            .to_der()
            .map_err(|e| SignError::DerError(format!("serial encode: {e}")))?;
        let issuer_and_serial = Der::sequence(&Der::concat(&[&issuer_der, &serial_der]));

        let mut certs_inner = Vec::new();
        for cert_der in cert_chain {
            certs_inner.extend_from_slice(cert_der);
        }
        let certificates = Der::implicit_ctx(0, &certs_inner);

        let signature_algorithm = match algorithm {
            SigningAlgorithm::RsaPssSha256
            | SigningAlgorithm::RsaPssSha384
            | SigningAlgorithm::RsaPssSha512 => Der::sequence(&Der::concat(&[
                OID_RSASSA_PSS,
                &Der::rsa_pss_params(algorithm.content_digest()),
            ])),
            SigningAlgorithm::EcdsaSha256 => Der::sequence(OID_ECDSA_WITH_SHA256),
            SigningAlgorithm::EcdsaSha384 => Der::sequence(OID_ECDSA_WITH_SHA384),
            SigningAlgorithm::EcdsaSha512 => Der::sequence(OID_ECDSA_WITH_SHA512),
        };

        Ok(Self {
            issuer_and_serial,
            certificates,
            signature_algorithm,
            signature_source,
            verifier: Self::load_verifier(&leaf_cert, algorithm)?,
            algorithm,
            crls: if crls.is_empty() {
                None
            } else {
                let mut crls = crls.to_vec();
                crls.sort();
                Some(Der::implicit_ctx(
                    1,
                    &Der::concat(&crls.iter().map(Vec::as_slice).collect::<Vec<_>>()),
                ))
            },
        })
    }

    fn load_private_key(
        private_key_der: &[u8],
        algorithm: SigningAlgorithm,
    ) -> Result<CmsPrivateKey, SignError> {
        match algorithm {
            SigningAlgorithm::EcdsaSha256
            | SigningAlgorithm::EcdsaSha384
            | SigningAlgorithm::EcdsaSha512 => {
                use p256::pkcs8::DecodePrivateKey;

                if let Ok(signing_key) = p256::ecdsa::SigningKey::from_pkcs8_der(private_key_der) {
                    return Ok(CmsPrivateKey::EcdsaP256(signing_key));
                }
                p384::ecdsa::SigningKey::from_pkcs8_der(private_key_der)
                    .map(CmsPrivateKey::EcdsaP384)
                    .map_err(|error| {
                        SignError::Pkcs8Error(format!(
                            "ECDSA key is neither P-256 nor P-384: {error}"
                        ))
                    })
            }
            SigningAlgorithm::RsaPssSha256
            | SigningAlgorithm::RsaPssSha384
            | SigningAlgorithm::RsaPssSha512 => {
                use rsa::pkcs8::DecodePrivateKey;

                let rsa_key = rsa::RsaPrivateKey::from_pkcs8_der(private_key_der)
                    .map_err(|e| SignError::Pkcs8Error(format!("RSA key load: {e}")))?;
                Ok(CmsPrivateKey::RsaPss(Box::new(rsa_key)))
            }
        }
    }

    fn load_verifier(
        leaf_cert: &Certificate,
        algorithm: SigningAlgorithm,
    ) -> Result<SignatureVerifier, SignError> {
        match algorithm {
            SigningAlgorithm::EcdsaSha256
            | SigningAlgorithm::EcdsaSha384
            | SigningAlgorithm::EcdsaSha512 => {
                let public_key = leaf_cert
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| {
                        SignError::DerError(
                            "leaf certificate public key has unused bits".to_string(),
                        )
                    })?
                    .to_vec();
                match public_key.len() {
                    65 => p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key)
                        .map(SignatureVerifier::EcdsaP256)
                        .map_err(|error| {
                            SignError::DerError(format!("leaf P-256 public key parse: {error}"))
                        }),
                    97 => p384::ecdsa::VerifyingKey::from_sec1_bytes(&public_key)
                        .map(SignatureVerifier::EcdsaP384)
                        .map_err(|error| {
                            SignError::DerError(format!("leaf P-384 public key parse: {error}"))
                        }),
                    len => Err(SignError::SigningFailed(format!(
                        "unsupported ECDSA public key length: {len}"
                    ))),
                }
            }
            SigningAlgorithm::RsaPssSha256
            | SigningAlgorithm::RsaPssSha384
            | SigningAlgorithm::RsaPssSha512 => {
                use rsa::pkcs8::DecodePublicKey;

                let spki_der = leaf_cert
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .map_err(|e| SignError::DerError(format!("leaf SPKI encode: {e}")))?;
                let public_key = rsa::RsaPublicKey::from_public_key_der(&spki_der)
                    .map_err(|e| SignError::DerError(format!("leaf RSA public key parse: {e}")))?;
                Ok(SignatureVerifier::RsaPss(public_key))
            }
        }
    }

    fn build_signed_data(
        &self,
        content: &[u8],
        embed_content: bool,
        code_sign_attributes: Option<CodeSignAttributes<'_>>,
    ) -> Result<Vec<u8>, SignError> {
        build_cms_signed_data_internal(content, self, embed_content, code_sign_attributes)
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        let digest = Der::digest(self.algorithm.content_digest(), data);
        match &self.signature_source {
            CmsSignatureSource::External(signer) => signer.sign(data, self.algorithm),
            CmsSignatureSource::Local(CmsPrivateKey::EcdsaP256(signing_key)) => {
                use signature::hazmat::PrehashSigner;

                let sig: p256::ecdsa::DerSignature = signing_key
                    .sign_prehash(&digest)
                    .map_err(|error| SignError::SigningFailed(error.to_string()))?;
                Ok(sig.as_bytes().to_vec())
            }
            CmsSignatureSource::Local(CmsPrivateKey::EcdsaP384(signing_key)) => {
                use signature::hazmat::PrehashSigner;

                let sig: p384::ecdsa::DerSignature = signing_key
                    .sign_prehash(&digest)
                    .map_err(|error| SignError::SigningFailed(error.to_string()))?;
                Ok(sig.as_bytes().to_vec())
            }
            CmsSignatureSource::Local(CmsPrivateKey::RsaPss(private_key)) => {
                use signature::{RandomizedSigner, SignatureEncoding};

                let signature = match self.algorithm {
                    SigningAlgorithm::RsaPssSha256 => {
                        rsa::pss::SigningKey::<Sha256>::new(private_key.as_ref().clone())
                            .sign_with_rng(&mut rand::rngs::OsRng, data)
                            .to_vec()
                    }
                    SigningAlgorithm::RsaPssSha384 => {
                        rsa::pss::SigningKey::<Sha384>::new(private_key.as_ref().clone())
                            .sign_with_rng(&mut rand::rngs::OsRng, data)
                            .to_vec()
                    }
                    SigningAlgorithm::RsaPssSha512 => {
                        rsa::pss::SigningKey::<Sha512>::new(private_key.as_ref().clone())
                            .sign_with_rng(&mut rand::rngs::OsRng, data)
                            .to_vec()
                    }
                    _ => {
                        return Err(SignError::SigningFailed(
                            "RSA key selected for an ECDSA algorithm".to_owned(),
                        ));
                    }
                };
                Ok(signature)
            }
        }
    }

    fn verify_generated_signature(
        &self,
        data: &[u8],
        signature_bytes: &[u8],
    ) -> Result<(), SignError> {
        self.verifier.verify(self.algorithm, data, signature_bytes)
    }
}

impl SignatureVerifier {
    fn from_certificate(
        leaf_cert: &Certificate,
        algorithm: SigningAlgorithm,
    ) -> Result<Self, SignError> {
        CmsSigningContext::load_verifier(leaf_cert, algorithm)
    }

    fn verify(
        &self,
        algorithm: SigningAlgorithm,
        data: &[u8],
        signature_bytes: &[u8],
    ) -> Result<(), SignError> {
        let digest = Der::digest(algorithm.content_digest(), data);
        match self {
            SignatureVerifier::EcdsaP256(verifier) => {
                use signature::hazmat::PrehashVerifier;

                let signature = p256::ecdsa::DerSignature::from_bytes(signature_bytes)
                    .map_err(|error| SignError::SigningFailed(error.to_string()))?;
                verifier.verify_prehash(&digest, &signature).map_err(|_| {
                    SignError::SigningFailed(
                        "generated ECDSA signature did not verify with leaf certificate"
                            .to_string(),
                    )
                })
            }
            SignatureVerifier::EcdsaP384(verifier) => {
                use signature::hazmat::PrehashVerifier;

                let signature = p384::ecdsa::DerSignature::from_bytes(signature_bytes)
                    .map_err(|error| SignError::SigningFailed(error.to_string()))?;
                verifier.verify_prehash(&digest, &signature).map_err(|_| {
                    SignError::SigningFailed(
                        "generated ECDSA signature did not verify with leaf certificate"
                            .to_string(),
                    )
                })
            }
            SignatureVerifier::RsaPss(public_key) => {
                use signature::Verifier;

                let signature = rsa::pss::Signature::try_from(signature_bytes).map_err(|e| {
                    SignError::SigningFailed(format!("RSA-PSS signature parse: {e}"))
                })?;
                let result = match algorithm {
                    SigningAlgorithm::RsaPssSha256 => {
                        rsa::pss::VerifyingKey::<Sha256>::new(public_key.clone())
                            .verify(data, &signature)
                    }
                    SigningAlgorithm::RsaPssSha384 => {
                        rsa::pss::VerifyingKey::<Sha384>::new(public_key.clone())
                            .verify(data, &signature)
                    }
                    SigningAlgorithm::RsaPssSha512 => {
                        rsa::pss::VerifyingKey::<Sha512>::new(public_key.clone())
                            .verify(data, &signature)
                    }
                    _ => {
                        return Err(SignError::SigningFailed(
                            "RSA verifier selected for an ECDSA algorithm".to_owned(),
                        ));
                    }
                };
                result.map_err(|e| {
                    SignError::SigningFailed(format!(
                        "generated RSA-PSS signature did not verify with leaf certificate: {e}"
                    ))
                })
            }
        }
    }
}

struct CmsVerifier;

impl CmsVerifier {
    fn verify(cms_der: &[u8], detached_content: Option<&[u8]>) -> Result<VerifiedCms, SignError> {
        let content_info = ContentInfo::from_der(cms_der)
            .map_err(|error| SignError::DerError(format!("CMS ContentInfo: {error}")))?;
        if content_info.content_type != ID_SIGNED_DATA {
            return Err(SignError::DerError(format!(
                "CMS content type is {}, expected signedData",
                content_info.content_type
            )));
        }
        let signed_data_der = content_info
            .content
            .to_der()
            .map_err(|error| SignError::DerError(format!("CMS SignedData wrapper: {error}")))?;
        let signed_data = SignedData::from_der(&signed_data_der)
            .map_err(|error| SignError::DerError(format!("CMS SignedData: {error}")))?;
        let attached_content = signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .map(|content| content.value());
        let content = attached_content
            .or(detached_content)
            .ok_or_else(|| {
                SignError::DerError("CMS has detached content but none was supplied".to_owned())
            })?
            .to_vec();
        let certificates = Self::certificates(&signed_data)?;
        let signer = signed_data
            .signer_infos
            .0
            .iter()
            .next()
            .ok_or_else(|| SignError::DerError("CMS has no signer information".to_owned()))?;
        let algorithm = Self::algorithm(signer.digest_alg.oid, signer.signature_algorithm.oid)?;
        let certificate = Self::signing_certificate(&certificates, &signer.sid)?;
        let signed_attributes = signer
            .signed_attrs
            .as_ref()
            .ok_or_else(|| SignError::DerError("CMS signer has no signed attributes".to_owned()))?;
        let message_digest = signed_attributes
            .iter()
            .find(|attribute| attribute.oid == ID_MESSAGE_DIGEST)
            .and_then(|attribute| attribute.values.iter().next())
            .ok_or_else(|| SignError::DerError("CMS has no messageDigest attribute".to_owned()))?
            .value();
        let expected_digest = Der::digest(algorithm.content_digest(), &content);
        if message_digest != expected_digest {
            return Err(SignError::VerificationFailed(
                "CMS messageDigest does not match embedded content".to_owned(),
            ));
        }
        let signed_attributes_der = signed_attributes
            .to_der()
            .map_err(|error| SignError::DerError(format!("CMS signed attributes: {error}")))?;
        SignatureVerifier::from_certificate(certificate, algorithm)?.verify(
            algorithm,
            &signed_attributes_der,
            signer.signature.as_bytes(),
        )?;
        let signing_time = Self::signing_time(signed_attributes)?;
        let owner_id = Self::utf8_attribute(signed_attributes, ID_CODE_SIGN_OWNER_ID)?;
        let certificate_der = certificates
            .iter()
            .map(|certificate| {
                certificate
                    .to_der()
                    .map_err(|error| SignError::DerError(format!("CMS certificate: {error}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedCms {
            content,
            certificates: certificate_der,
            algorithm,
            signing_time,
            owner_id,
        })
    }

    fn signing_time(
        attributes: &x509_cert::attr::Attributes,
    ) -> Result<Option<SystemTime>, SignError> {
        let Some(value) = attributes
            .iter()
            .find(|attribute| attribute.oid == ID_SIGNING_TIME)
            .and_then(|attribute| attribute.values.iter().next())
        else {
            return Ok(None);
        };
        if let Ok(time) = value.decode_as::<der::asn1::UtcTime>() {
            return Ok(Some(time.into()));
        }
        if let Ok(time) = value.decode_as::<der::asn1::GeneralizedTime>() {
            return Ok(Some(time.into()));
        }
        Err(SignError::DerError(
            "CMS signingTime is neither UTCTime nor GeneralizedTime".to_owned(),
        ))
    }

    fn utf8_attribute(
        attributes: &x509_cert::attr::Attributes,
        oid: ObjectIdentifier,
    ) -> Result<Option<String>, SignError> {
        let Some(value) = attributes
            .iter()
            .find(|attribute| attribute.oid == oid)
            .and_then(|attribute| attribute.values.iter().next())
        else {
            return Ok(None);
        };
        let value = value
            .decode_as::<der::asn1::Utf8StringRef<'_>>()
            .map_err(|error| SignError::DerError(format!("CMS UTF8 attribute: {error}")))?;
        Ok(Some(value.as_str().to_owned()))
    }

    fn certificates(signed_data: &SignedData) -> Result<Vec<Certificate>, SignError> {
        let certificate_set = signed_data
            .certificates
            .as_ref()
            .ok_or_else(|| SignError::DerError("CMS has no certificates".to_owned()))?;
        let certificates = certificate_set
            .0
            .iter()
            .filter_map(|choice| match choice {
                CertificateChoices::Certificate(certificate) => Some(certificate.clone()),
                CertificateChoices::Other(_) => None,
            })
            .collect::<Vec<_>>();
        if certificates.is_empty() {
            return Err(SignError::DerError(
                "CMS has no X.509 certificates".to_owned(),
            ));
        }
        Ok(certificates)
    }

    fn signing_certificate<'a>(
        certificates: &'a [Certificate],
        signer: &SignerIdentifier,
    ) -> Result<&'a Certificate, SignError> {
        let certificate = certificates.iter().find(|certificate| match signer {
            SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial) => {
                certificate.tbs_certificate.issuer == issuer_and_serial.issuer
                    && certificate.tbs_certificate.serial_number == issuer_and_serial.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(identifier) => certificate
                .tbs_certificate
                .get::<x509_cert::ext::pkix::SubjectKeyIdentifier>()
                .ok()
                .flatten()
                .is_some_and(|(_, subject_key_identifier)| {
                    subject_key_identifier.0.as_bytes() == identifier.0.as_bytes()
                }),
        });
        certificate.ok_or_else(|| {
            SignError::VerificationFailed(
                "CMS signer certificate was not found in the certificate set".to_owned(),
            )
        })
    }

    fn algorithm(
        digest_oid: ObjectIdentifier,
        signature_oid: ObjectIdentifier,
    ) -> Result<SigningAlgorithm, SignError> {
        let digest = match digest_oid {
            ID_SHA256 => ContentDigestAlgorithm::Sha256,
            ID_SHA384 => ContentDigestAlgorithm::Sha384,
            ID_SHA512 => ContentDigestAlgorithm::Sha512,
            _ => {
                return Err(SignError::UnsupportedAlgorithm(format!(
                    "CMS digest OID {digest_oid}"
                )));
            }
        };
        let algorithm = match signature_oid {
            ID_ECDSA_WITH_SHA256 if digest == ContentDigestAlgorithm::Sha256 => {
                SigningAlgorithm::EcdsaSha256
            }
            ID_ECDSA_WITH_SHA384 if digest == ContentDigestAlgorithm::Sha384 => {
                SigningAlgorithm::EcdsaSha384
            }
            ID_ECDSA_WITH_SHA512 if digest == ContentDigestAlgorithm::Sha512 => {
                SigningAlgorithm::EcdsaSha512
            }
            ID_RSASSA_PSS => match digest {
                ContentDigestAlgorithm::Sha256 => SigningAlgorithm::RsaPssSha256,
                ContentDigestAlgorithm::Sha384 => SigningAlgorithm::RsaPssSha384,
                ContentDigestAlgorithm::Sha512 => SigningAlgorithm::RsaPssSha512,
            },
            _ => {
                return Err(SignError::UnsupportedAlgorithm(format!(
                    "CMS signature OID {signature_oid} with digest OID {digest_oid}"
                )));
            }
        };
        Ok(algorithm)
    }
}

pub(crate) fn verify_cms_signed_data(cms_der: &[u8]) -> Result<VerifiedCms, SignError> {
    CmsVerifier::verify(cms_der, None)
}

pub(crate) fn verify_detached_cms_signed_data(
    cms_der: &[u8],
    content: &[u8],
) -> Result<VerifiedCms, SignError> {
    CmsVerifier::verify(cms_der, Some(content))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub(crate) fn build_cms_signed_data_with_identity(
    content: &[u8],
    identity: &SigningIdentity,
    alg_id: u32,
) -> Result<Vec<u8>, SignError> {
    let signer = CmsSigningContext::from_identity(identity, alg_id)?;
    signer.build_signed_data(content, true, None)
}

fn build_cms_signed_data_internal(
    content: &[u8],
    signer: &CmsSigningContext,
    embed_content: bool,
    code_sign_attributes: Option<CodeSignAttributes<'_>>,
) -> Result<Vec<u8>, SignError> {
    // -----------------------------------------------------------------------
    // 1. digestAlgorithms SET
    // -----------------------------------------------------------------------
    let content_digest_algorithm = signer.algorithm.content_digest();
    let digest_algorithm_identifier = Der::digest_algorithm_identifier(content_digest_algorithm);
    let digest_algorithms = Der::set(&digest_algorithm_identifier);

    // -----------------------------------------------------------------------
    // 2. encapContentInfo
    // -----------------------------------------------------------------------
    // ContentInfo { OID(id-data), [0] EXPLICIT { OCTET STRING(content) } }
    // hapsigner code signing uses detached content:
    // `new ContentInfo(PKCSObjectIdentifiers.data, null)`.
    let econtent_inner = if embed_content {
        Der::concat(&[
            OID_ID_DATA,
            &Der::explicit_ctx(0, &Der::octet_string(content)),
        ])
    } else {
        OID_ID_DATA.to_vec()
    };
    let encap_content_info = Der::sequence(&econtent_inner);

    // -----------------------------------------------------------------------
    // 3. Certificates ([0] IMPLICIT set of DER certs)
    // -----------------------------------------------------------------------
    let certificates = &signer.certificates;

    // -----------------------------------------------------------------------
    // 4. Signed attributes (for computing signature)
    // -----------------------------------------------------------------------
    let content_digest = Der::digest(content_digest_algorithm, content);

    // Attribute: contentType = id-data
    let attr_content_type =
        Der::sequence(&Der::concat(&[OID_CONTENT_TYPE, &Der::set(OID_ID_DATA)]));

    // Attribute: signingTime = UTCTime(now)
    let signing_time = Der::current_utctime_der();
    let attr_signing_time =
        Der::sequence(&Der::concat(&[OID_SIGNING_TIME, &Der::set(&signing_time)]));

    // Attribute: messageDigest = SHA-256(content)
    let attr_message_digest = Der::sequence(&Der::concat(&[
        OID_MESSAGE_DIGEST,
        &Der::set(&Der::octet_string(&content_digest)),
    ]));

    // Java hapsigner uses `new DERSet(new AttributeTable(tab).toASN1EncodableVector())`.
    // DER SET elements are sorted by their full DER encoding before signing.
    let mut signed_attrs = vec![attr_content_type, attr_signing_time, attr_message_digest];
    if let Some(attributes) = code_sign_attributes {
        if let Some(owner_id) = attributes.owner_id {
            signed_attrs.push(Der::sequence(&Der::concat(&[
                OID_CODE_SIGN_OWNER_ID,
                &Der::set(&Der::utf8_string(owner_id)),
            ])));
        }
        if let Some(plugin_id) = attributes.plugin_id {
            signed_attrs.push(Der::sequence(&Der::concat(&[
                OID_CODE_SIGN_PLUGIN_ID,
                &Der::set(&Der::utf8_string(plugin_id)),
            ])));
        }
    }
    signed_attrs.sort();
    let signed_attr_parts = signed_attrs.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let signed_attrs_inner = Der::concat(&signed_attr_parts);

    // For signing: encode as SET (tag 0x31)
    let signed_attrs_for_signing = Der::set(&signed_attrs_inner);

    // For embedding in SignerInfo: encode as [0] IMPLICIT (tag 0xA0)
    let signed_attrs_encoded = Der::implicit_ctx(0, &signed_attrs_inner);

    // -----------------------------------------------------------------------
    // 5. Compute signature
    // -----------------------------------------------------------------------
    let signature_bytes = signer.sign(&signed_attrs_for_signing)?;
    signer.verify_generated_signature(&signed_attrs_for_signing, &signature_bytes)?;

    // -----------------------------------------------------------------------
    // 8. SignerInfo
    // -----------------------------------------------------------------------
    let digest_alg_for_signer = digest_algorithm_identifier;

    let signer_info_inner = Der::concat(&[
        &Der::integer_one(),                  // version
        &signer.issuer_and_serial,            // sid: IssuerAndSerialNumber
        &digest_alg_for_signer,               // digestAlgorithm
        &signed_attrs_encoded,                // signedAttrs [0] IMPLICIT
        &signer.signature_algorithm,          // signatureAlgorithm
        &Der::octet_string(&signature_bytes), // signature
    ]);
    let signer_info = Der::sequence(&signer_info_inner);

    // -----------------------------------------------------------------------
    // 9. SignedData
    // -----------------------------------------------------------------------
    let signer_infos = Der::set(&signer_info);

    let version = Der::integer_one();
    let mut signed_data_parts = vec![
        version.as_slice(),
        digest_algorithms.as_slice(),
        encap_content_info.as_slice(),
        certificates.as_slice(),
    ];
    if let Some(crls) = &signer.crls {
        signed_data_parts.push(crls);
    }
    signed_data_parts.push(&signer_infos);
    let signed_data_inner = Der::concat(&signed_data_parts);
    let signed_data = Der::sequence(&signed_data_inner);

    // -----------------------------------------------------------------------
    // 10. ContentInfo wrapping
    // -----------------------------------------------------------------------
    let content_info_inner =
        Der::concat(&[OID_ID_SIGNED_DATA, &Der::explicit_ctx(0, &signed_data)]);
    let content_info = Der::sequence(&content_info_inner);

    Ok(content_info)
}
