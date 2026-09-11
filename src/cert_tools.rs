//! Certificate-authority operations, mirroring official `CertTools` and
//! `SignToolServiceImpl`.
//!
//! Each function corresponds to one `hap-sign-tool` command and preserves the
//! upstream extension choices, validity defaults, and output formats:
//!
//! | function | command | default validity |
//! | --- | --- | --- |
//! | [`generate_key_pair_entry`] | `generate-keypair` | placeholder: 100 years |
//! | [`generate_csr`] | `generate-csr` | — |
//! | [`generate_root_ca`] / [`generate_sub_ca`] | `generate-ca` | 3650 days |
//! | [`generate_certificate`] | `generate-cert` | 1095 days |
//! | [`generate_end_certificate`] | `generate-app-cert` / `generate-profile-cert` | 1095 days |

use const_oid::db::rfc5280::{
    ID_KP_CLIENT_AUTH, ID_KP_CODE_SIGNING, ID_KP_EMAIL_PROTECTION, ID_KP_OCSP_SIGNING,
    ID_KP_SERVER_AUTH, ID_KP_TIME_STAMPING,
};
use const_oid::ObjectIdentifier;
use der::flagset::FlagSet;
use der::Decode;
use rand::RngCore;
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
use x509_cert::name::Name;

use crate::certificate::{
    build_certificate, CertificateLevel, CertificateParameters, CertificateSignatureAlgorithm,
    IssuingKey, SigningCapability,
};
use crate::csr::build_certificate_request;
use crate::error::SignError;
use crate::keypair::{generate_key_pair, GeneratedKeyPair, KeySize};
use crate::keystore_write::{write_keystore, KeystoreEntry, KeystoreFormat};

/// Default validity for CA certificates (`CertTools.TEN_YEAR_DAY`).
pub const CA_VALIDITY_DAYS: u64 = 3650;
/// Default validity for end-entity certificates (`CertTools.THREE_YEAR_DAY`).
pub const END_CERTIFICATE_VALIDITY_DAYS: u64 = 1095;

/// Validity of the self-signed placeholder certificate written by
/// `generate-keypair` (`KeyStoreHelper.createKeyOnly`, one hundred years).
const KEY_ONLY_VALIDITY_DAYS: u64 = 36_525;

/// `1.3.6.1.4.1.311.20.2.2`, the Microsoft smart-card logon purpose.
const ID_KP_SMARTCARD_LOGON: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.20.2.2");

/// Key usages accepted by official `-keyUsage`, in `CertUtils.parseKeyUsage`
/// order.
const KEY_USAGE_NAMES: [(&str, KeyUsages); 9] = [
    ("digitalSignature", KeyUsages::DigitalSignature),
    ("nonRepudiation", KeyUsages::NonRepudiation),
    ("keyEncipherment", KeyUsages::KeyEncipherment),
    ("dataEncipherment", KeyUsages::DataEncipherment),
    ("keyAgreement", KeyUsages::KeyAgreement),
    ("certificateSignature", KeyUsages::KeyCertSign),
    ("crlSignature", KeyUsages::CRLSign),
    ("encipherOnly", KeyUsages::EncipherOnly),
    ("decipherOnly", KeyUsages::DecipherOnly),
];

/// Extended key usages accepted by official `-extKeyUsage`, in
/// `CertUtils.parseExtKeyUsage` order.
const EXTENDED_KEY_USAGE_NAMES: [(&str, ObjectIdentifier); 7] = [
    ("clientAuthentication", ID_KP_CLIENT_AUTH),
    ("serverAuthentication", ID_KP_SERVER_AUTH),
    ("codeSignature", ID_KP_CODE_SIGNING),
    ("emailProtection", ID_KP_EMAIL_PROTECTION),
    ("smartCardLogin", ID_KP_SMARTCARD_LOGON),
    ("timestamp", ID_KP_TIME_STAMPING),
    ("ocspSignature", ID_KP_OCSP_SIGNING),
];

/// Parse `CertUtils.parseKeyUsage`: every recognised name found anywhere in the
/// comma-separated list contributes its bit.
///
/// Upstream uses `String.contains` rather than a token comparison, so a name
/// embedded in a longer word also matches; `hap-sign` gates the list against
/// [`key_usage_names`] before calling this.
pub fn parse_key_usage(value: &str) -> KeyUsage {
    let mut flags: Option<FlagSet<KeyUsages>> = None;
    for (name, flag) in KEY_USAGE_NAMES {
        if value.contains(name) {
            flags = Some(match flags {
                Some(existing) => existing | flag,
                None => flag.into(),
            });
        }
    }
    KeyUsage(flags.unwrap_or(FlagSet::new(0).expect("zero sets no unknown bits")))
}

/// Parse `CertUtils.parseExtKeyUsage`, preserving the upstream ordering.
pub fn parse_extended_key_usage(value: &str) -> Vec<ObjectIdentifier> {
    EXTENDED_KEY_USAGE_NAMES
        .iter()
        .filter(|(name, _)| value.contains(name))
        .map(|(_, oid)| *oid)
        .collect()
}

/// Names accepted by `-keyUsage`, for command-line validation.
pub fn key_usage_names() -> impl Iterator<Item = &'static str> {
    KEY_USAGE_NAMES.iter().map(|(name, _)| *name)
}

/// Validate a comma-separated key-usage list against the names upstream
/// accepts, then parse it.
///
/// `CmdUtil.verifyType` performs this check on the command line; upstream's
/// parser itself silently ignores anything it does not recognise.
pub fn parse_key_usage_checked(value: &str) -> Result<KeyUsage, SignError> {
    for name in usage_tokens(value) {
        if !KEY_USAGE_NAMES.iter().any(|(known, _)| *known == name) {
            return Err(SignError::UnsupportedKeyUsage(name.to_owned()));
        }
    }
    Ok(parse_key_usage(value))
}

/// Validate a comma-separated extended key-usage list, then parse it.
pub fn parse_extended_key_usage_checked(value: &str) -> Result<Vec<ObjectIdentifier>, SignError> {
    for name in usage_tokens(value) {
        if !EXTENDED_KEY_USAGE_NAMES
            .iter()
            .any(|(known, _)| *known == name)
        {
            return Err(SignError::UnsupportedKeyUsage(name.to_owned()));
        }
    }
    Ok(parse_extended_key_usage(value))
}

/// `CmdUtil.verifyType` splits on commas, trims each token, and skips empties,
/// so an absent `-extKeyUsage` never fails validation.
fn usage_tokens(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

/// Names accepted by `-extKeyUsage`, for command-line validation.
pub fn extended_key_usage_names() -> impl Iterator<Item = &'static str> {
    EXTENDED_KEY_USAGE_NAMES.iter().map(|(name, _)| *name)
}

/// `CertUtils.randomSerial()`: a positive 32-bit integer, minimally encoded.
///
/// Upstream draws from `new BigInteger(32, SecureRandom)`, which yields a
/// non-negative value; zero is excluded here because RFC 5280 requires a
/// positive serial number.
pub(crate) fn random_serial_bytes() -> Result<Vec<u8>, SignError> {
    let mut bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut bytes);
    let significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut serial = bytes[significant..].to_vec();
    if serial.iter().all(|byte| *byte == 0) {
        serial[0] = 1;
    }
    // A high bit would read as a negative INTEGER, so a sign octet is added.
    if serial[0] & 0x80 != 0 {
        serial.insert(0, 0);
    }
    Ok(serial)
}

/// Parameters for `generate-keypair`.
pub struct KeyPairParameters<'a> {
    pub alias: &'a str,
    pub size: KeySize,
    pub key_password: &'a str,
    pub store_password: &'a str,
    pub format: KeystoreFormat,
}

/// Create a keystore holding a new key pair and its self-signed placeholder
/// certificate, as official `generate-keypair` does.
///
/// Upstream calls `KeyStoreHelper.store` with a null chain, which synthesizes a
/// `CN=<alias>` certificate valid for one hundred years and signed with
/// `SHA256withRSA` (silently rewritten for an EC key). The same placeholder is
/// produced here so the entry is immediately usable by Java tooling.
pub fn generate_key_pair_entry(parameters: &KeyPairParameters<'_>) -> Result<Vec<u8>, SignError> {
    let pair = generate_key_pair(parameters.size)?;
    let placeholder = placeholder_certificate(&pair, parameters.alias)?;
    write_keystore(
        parameters.format,
        parameters.store_password,
        &KeystoreEntry {
            alias: parameters.alias,
            key_password: parameters.key_password,
            private_key_der: pair.private_key_der(),
            certificate_chain: &[placeholder],
        },
    )
}

/// The self-signed placeholder certificate `generate-keypair` stores, matching
/// `KeyStoreHelper.createKeyOnly`: subject and issuer `CN=<alias>`, one hundred
/// years of validity, and a `SHA256withRSA` request that
/// `CertUtils.createFixedContentSigner` rewrites for an EC key.
pub fn placeholder_certificate(pair: &GeneratedKeyPair, alias: &str) -> Result<Vec<u8>, SignError> {
    let subject = crate::dn::parse_distinguished_name(&format!("CN={alias}"))?;
    build_certificate(
        &CertificateParameters {
            level: CertificateLevel::RootCa,
            signature_algorithm: CertificateSignatureAlgorithm::RsaSha256,
            issuer: subject.clone(),
            subject,
            subject_public_key: public_key_of(pair)?,
            validity_days: KEY_ONLY_VALIDITY_DAYS,
            serial_number: None,
            authority_public_key: None,
            basic_constraints_critical: false,
            basic_constraints_ca: false,
            basic_constraints_path_len: None,
            key_usage: KeyUsage(KeyUsages::DigitalSignature.into()),
            key_usage_critical: false,
            extended_key_usage: None,
            extended_key_usage_critical: false,
            signing_capability: None,
        },
        &IssuingKey::from_pkcs8_der(pair.private_key_der())?,
    )
}

/// Parse a SubjectPublicKeyInfo from its DER encoding.
pub fn public_key_from_der(public_key_der: &[u8]) -> Result<SubjectPublicKeyInfoOwned, SignError> {
    SubjectPublicKeyInfoOwned::from_der(public_key_der)
        .map_err(|error| SignError::DerError(format!("subject public key: {error}")))
}

fn public_key_of(pair: &GeneratedKeyPair) -> Result<SubjectPublicKeyInfoOwned, SignError> {
    public_key_from_der(pair.public_key_der())
}

/// Parameters shared by the certificate-issuing commands.
///
/// The subject's public key is supplied directly; upstream obtains it by
/// round-tripping a CSR through `CertBuilder`, which has no observable effect
/// on the issued certificate.
pub struct IssuanceParameters<'a> {
    pub subject: Name,
    pub issuer: Name,
    pub subject_public_key: SubjectPublicKeyInfoOwned,
    /// Private key of the issuing certificate.
    pub issuer_key: &'a IssuingKey,
    /// Public key of the issuing certificate, used for sub-CA key identifiers.
    pub issuer_public_key: Option<SubjectPublicKeyInfoOwned>,
    pub signature_algorithm: CertificateSignatureAlgorithm,
    pub validity_days: u64,
}

/// Parameters for `generate-csr`.
pub struct CsrParameters<'a> {
    pub subject: Name,
    pub public_key: SubjectPublicKeyInfoOwned,
    pub signing_key: &'a IssuingKey,
    pub signature_algorithm: CertificateSignatureAlgorithm,
}

/// Build a DER-encoded PKCS#10 request (official `generate-csr`).
pub fn generate_csr(parameters: &CsrParameters<'_>) -> Result<Vec<u8>, SignError> {
    build_certificate_request(
        parameters.subject.clone(),
        parameters.public_key.clone(),
        parameters.signing_key,
        parameters.signature_algorithm,
    )
}

/// Issue a self-signed root CA certificate (official `generate-ca` without
/// `-issuerKeyAlias`).
///
/// Upstream passes `CertLevel.ROOT_CA`, which makes
/// `withAuthorityKeyIdentifier` a no-op, and hardcodes a critical
/// `BasicConstraints` with `CA:TRUE` plus `keyCertSign | cRLSign`.
pub fn generate_root_ca(
    parameters: &IssuanceParameters<'_>,
    basic_constraints_path_len: Option<u32>,
) -> Result<Vec<u8>, SignError> {
    build_certificate(
        &CertificateParameters {
            level: CertificateLevel::RootCa,
            signature_algorithm: parameters.signature_algorithm,
            issuer: parameters.issuer.clone(),
            subject: parameters.subject.clone(),
            subject_public_key: parameters.subject_public_key.clone(),
            validity_days: parameters.validity_days,
            serial_number: None,
            authority_public_key: None,
            basic_constraints_critical: true,
            basic_constraints_ca: true,
            basic_constraints_path_len,
            key_usage: KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
            key_usage_critical: true,
            // `generate-ca` passes a null extKeyUsage array, so no extension.
            extended_key_usage: None,
            extended_key_usage_critical: false,
            signing_capability: None,
        },
        parameters.issuer_key,
    )
}

/// Issue a subordinate CA certificate (official `generate-ca` with
/// `-issuerKeyAlias`), the only level that carries an authority key identifier.
pub fn generate_sub_ca(
    parameters: &IssuanceParameters<'_>,
    basic_constraints_path_len: Option<u32>,
) -> Result<Vec<u8>, SignError> {
    build_certificate(
        &CertificateParameters {
            level: CertificateLevel::SubCa,
            signature_algorithm: parameters.signature_algorithm,
            issuer: parameters.issuer.clone(),
            subject: parameters.subject.clone(),
            subject_public_key: parameters.subject_public_key.clone(),
            validity_days: parameters.validity_days,
            serial_number: None,
            authority_public_key: parameters.issuer_public_key.clone(),
            basic_constraints_critical: true,
            basic_constraints_ca: true,
            basic_constraints_path_len,
            key_usage: KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
            key_usage_critical: true,
            extended_key_usage: None,
            extended_key_usage_critical: false,
            signing_capability: None,
        },
        parameters.issuer_key,
    )
}

/// Per-extension flags for `generate-cert`, mirroring `CertBuilder`'s builder
/// methods.
pub struct CertificateOptions {
    pub key_usage: KeyUsage,
    pub key_usage_critical: bool,
    /// An empty list still emits an empty `extendedKeyUsage` extension, which
    /// is what official `generate-cert` does without `-extKeyUsage`.
    pub extended_key_usage: Vec<ObjectIdentifier>,
    pub extended_key_usage_critical: bool,
    pub basic_constraints_critical: bool,
    pub basic_constraints_ca: bool,
    /// `None` omits `pathLenConstraint`. Official `generate-cert` always
    /// supplies a value, defaulting to `0`.
    pub basic_constraints_path_len: Option<u32>,
}

impl Default for CertificateOptions {
    fn default() -> Self {
        Self {
            key_usage: KeyUsage(FlagSet::new(0).expect("zero sets no unknown bits")),
            key_usage_critical: true,
            extended_key_usage: Vec::new(),
            // `LocalizationAdapter.isExtKeyUsageCritical` defaults to true,
            // despite the help text claiming false.
            extended_key_usage_critical: true,
            basic_constraints_critical: false,
            basic_constraints_ca: false,
            basic_constraints_path_len: Some(0),
        }
    }
}

/// Issue a general-purpose certificate (official `generate-cert`).
///
/// Upstream routes this through `CertLevel.ROOT_CA`, so the certificate never
/// carries an `authorityKeyIdentifier`, and `basicConstraints` reports
/// `CA:TRUE` with a path length whenever one is supplied, because
/// `LocalizationAdapter` boxes a primitive `int` that is never null.
pub fn generate_certificate(
    parameters: &IssuanceParameters<'_>,
    options: &CertificateOptions,
) -> Result<Vec<u8>, SignError> {
    build_certificate(
        &CertificateParameters {
            level: CertificateLevel::RootCa,
            signature_algorithm: parameters.signature_algorithm,
            issuer: parameters.issuer.clone(),
            subject: parameters.subject.clone(),
            subject_public_key: parameters.subject_public_key.clone(),
            validity_days: parameters.validity_days,
            serial_number: None,
            authority_public_key: None,
            basic_constraints_critical: options.basic_constraints_critical,
            basic_constraints_ca: options.basic_constraints_ca,
            basic_constraints_path_len: options.basic_constraints_path_len,
            key_usage: options.key_usage,
            key_usage_critical: options.key_usage_critical,
            extended_key_usage: Some(options.extended_key_usage.clone()),
            extended_key_usage_critical: options.extended_key_usage_critical,
            signing_capability: None,
        },
        parameters.issuer_key,
    )
}

/// Issue an application or profile certificate (official `generate-app-cert`
/// and `generate-profile-cert`).
///
/// Always an end entity, with a non-critical `basicConstraints`, a critical
/// `digitalSignature` key usage, a non-critical `codeSigning` extended key
/// usage, and the vendor signing-capability extension.
pub fn generate_end_certificate(
    parameters: &IssuanceParameters<'_>,
    capability: SigningCapability,
) -> Result<Vec<u8>, SignError> {
    build_certificate(
        &CertificateParameters {
            level: CertificateLevel::EndEntity,
            signature_algorithm: parameters.signature_algorithm,
            issuer: parameters.issuer.clone(),
            subject: parameters.subject.clone(),
            subject_public_key: parameters.subject_public_key.clone(),
            validity_days: parameters.validity_days,
            serial_number: None,
            authority_public_key: None,
            basic_constraints_critical: false,
            basic_constraints_ca: false,
            basic_constraints_path_len: None,
            key_usage: KeyUsage(KeyUsages::DigitalSignature.into()),
            key_usage_critical: true,
            extended_key_usage: Some(vec![ID_KP_CODE_SIGNING]),
            extended_key_usage_critical: false,
            signing_capability: Some(capability),
        },
        parameters.issuer_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_usage_names_like_upstream() {
        let usage = parse_key_usage("digitalSignature,keyEncipherment");
        assert!(usage.digital_signature());
        assert!(usage.key_encipherment());
        assert!(!usage.key_cert_sign());

        // `certificateSignature` maps to keyCertSign, `crlSignature` to cRLSign.
        let ca_usage = parse_key_usage("certificateSignature,crlSignature");
        assert!(ca_usage.key_cert_sign());
        assert!(ca_usage.crl_sign());
    }

    #[test]
    fn an_unrecognised_usage_yields_an_empty_bit_string() {
        let usage = parse_key_usage("");
        assert!(!usage.digital_signature());
        assert!(!usage.key_cert_sign());
    }

    #[test]
    fn checked_parsers_reject_unknown_names() {
        assert!(parse_key_usage_checked("digitalSignature,keyEncipherment").is_ok());
        assert!(parse_key_usage_checked("digitalSignature,notAUsage").is_err());
        // An empty list is valid: `generate-cert` sends it for `-extKeyUsage`.
        assert!(parse_key_usage_checked("").is_ok());
        assert!(parse_extended_key_usage_checked("codeSignature").is_ok());
        assert!(parse_extended_key_usage_checked("codeSignature,nope").is_err());
        assert!(parse_extended_key_usage_checked("").is_ok());
    }

    #[test]
    fn parses_extended_key_usage_in_upstream_order() {
        assert_eq!(
            parse_extended_key_usage("codeSignature"),
            vec![ID_KP_CODE_SIGNING]
        );
        assert_eq!(
            parse_extended_key_usage("clientAuthentication,codeSignature"),
            vec![ID_KP_CLIENT_AUTH, ID_KP_CODE_SIGNING]
        );
        assert!(parse_extended_key_usage("").is_empty());
    }

    #[test]
    fn serial_numbers_are_positive_and_minimal() {
        for _ in 0..256 {
            let serial = random_serial_bytes().expect("serial");
            assert!(!serial.is_empty());
            assert!(serial.len() <= 5, "serial {serial:?} is too long");
            assert_eq!(serial[0] & 0x80, 0, "serial {serial:?} is negative");
            assert!(
                serial.iter().any(|byte| *byte != 0),
                "serial {serial:?} is zero"
            );
            // A leading zero octet is only legal as a sign octet.
            if serial[0] == 0 {
                assert!(serial.len() >= 2, "serial {serial:?} is redundant");
                assert_ne!(serial[1] & 0x80, 0, "serial {serial:?} is not minimal");
            }
        }
    }
}
